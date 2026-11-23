//! 会话状态机。
//!
//! ```text
//!   Locked ──open(password)──> Unlocked ──lock()/autolock──> Locked
//!      │                          │
//!      └──create(password)────────┘
//! ```
//!
//! 设计约束：
//! - `Unlocked` 里持有 `xz_core::Vault`，它内部的主密钥 drop 时自动 zeroize。
//! - 自动锁定靠**单调时钟**判断闲置，不依赖前端定时器（前端可以被挂起）。
//! - 任何一次前端交互都刷 `last_activity`，所以「正在用」永远不会被锁掉。

use std::time::Instant;

/// 两次活跃刷新之间的最小间隔。前端节流是 6 秒，这里取 4 秒留余量。
const MIN_TOUCH_GAP: std::time::Duration = std::time::Duration::from_secs(4);

/// 默认的闲置锁定时长。用户可以在设置里改（1..=120 分钟）。
const DEFAULT_AUTOLOCK_MINUTES: u32 = 5;

/// 从用户设置里读闲置锁定时长。
///
/// 读不到就用默认值。`None` 表示不自动锁 —— 当前界面上不提供这个选项，
/// 保留它是因为 `Unlocked::auto_lock` 的类型本来就是 `Option`。
fn auto_lock_setting() -> Option<std::time::Duration> {
    let minutes = crate::machine::autolock_minutes();
    let minutes = if minutes == 0 {
        DEFAULT_AUTOLOCK_MINUTES
    } else {
        minutes
    };
    Some(std::time::Duration::from_secs(u64::from(minutes) * 60))
}

/// 单个解锁会话的绝对寿命：到点必须重新输密码。
///
/// 自动锁定管的是「闲置」，这条管的是「一直在用」——不设上限的话，
/// 一台开着的机器可以几十年不重新验证身份。
const MAX_SESSION: std::time::Duration = std::time::Duration::from_secs(8 * 3600);

use xz_core::vault::{Vault, VaultStats};

/// 会话状态。
pub enum Session {
    /// 未解锁。
    Locked,
    /// 已解锁。
    Unlocked(Box<Unlocked>),
}

/// 已解锁会话的数据。
pub struct Unlocked {
    /// 库本体。
    pub vault: Vault,
    /// 最后一次交互（单调时钟，防系统改时间绕过）。
    pub last_activity: Instant,
    /// 会话开始时间。用来兜底「绝对上限」——见 `touch` 的说明。
    pub started_at: Instant,
    /// 闲置多久自动锁，`None` 表示不自动锁。
    pub auto_lock: Option<std::time::Duration>,
}

impl Session {
    /// 初始状态。
    #[must_use]
    pub fn locked() -> Self {
        Session::Locked
    }

    /// 是否已解锁。
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Session::Unlocked(_))
    }

    /// 取已解锁会话，未解锁时返回 `None`。
    pub fn un(&mut self) -> Option<&mut Unlocked> {
        match self {
            Session::Unlocked(u) => Some(u.as_mut()),
            Session::Locked => None,
        }
    }

    /// 接管一个已经建好的 `Vault`（建库流程用）。
    ///
    /// KDF 在锁外跑完了，这里只做状态切换。
    pub fn adopt(&mut self, vault: Vault) {
        *self = Session::Unlocked(Box::new(Unlocked {
            vault,
            last_activity: Instant::now(),
            started_at: Instant::now(),
            auto_lock: auto_lock_setting(),
        }));
    }

    /// 用已经算好的主密钥装配会话（快，几毫秒）。
    ///
    /// 慢的 KDF 在锁外跑完了，这里只做解密和解析，可以安全地持锁。
    pub fn install(
        &mut self,
        path: &std::path::Path,
        bytes: &[u8],
        key: xz_core::secure::SecretBytes,
    ) -> xz_core::Result<()> {
        let mut vault = Vault::open_bound_with_key(bytes, key)?;
        vault.set_path(path.to_path_buf());
        *self = Session::Unlocked(Box::new(Unlocked {
            vault,
            last_activity: Instant::now(),
            started_at: Instant::now(),
            auto_lock: auto_lock_setting(),
        }));
        Ok(())
    }

    /// 锁定：擦除密钥、清空明文。
    /// 锁定会话。返回锁前落盘的结果。
    ///
    /// 落盘失败时**仍然锁定**（安全优先：不能因为写不进去就让库停在解锁态），
    /// 但把错误交回调用方 —— 调用方必须让用户看见，否则用户以为「改了、存了」，
    /// 实际上那些改动随锁定一起消失了。
    ///
    /// 返回 `Ok(())` 表示「本来就没脏数据」或「脏数据已成功落盘」。
    pub fn lock(&mut self) -> Result<(), String> {
        let mut save_err = None;
        if let Session::Unlocked(u) = self {
            // 锁之前先把脏数据落盘。
            //
            // 为什么需要这一步：`record_use` 只把 dirty 置 true 不落盘（那是对的，
            // 用一次热键就写一次盘太重），但 `Vault::lock()` 会清掉 dirty。
            // 于是「解锁期间用过几次 → 自动锁定」这条路径下，使用计数全丢，
            // 热度榜越用越不准，而 Ctrl+Shift+1..9 正是靠热度排序。
            if u.vault.is_dirty() && u.vault.path().is_some() {
                if let Err(e) = u.vault.save() {
                    save_err = Some(format!("锁定前没能保存改动：{e}"));
                }
            }
            u.vault.lock();
        }
        *self = Session::Locked;
        match save_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// 刷新活跃时间。
    ///
    /// `touch_activity` 这条 IPC 对同机任何进程可达，所以不能让人靠无限
    /// 调用它把库永久钉在解锁态。两道闸：
    ///
    /// 1. **最小间隔**：距上次刷新不足 `MIN_TOUCH_GAP` 的直接忽略；
    /// 2. **绝对上限**：从解锁起算超过 `MAX_SESSION` 一律不再续期，
    ///    到期由 `check_autolock` 收走。
    ///
    /// 返回是否真的刷新了（前端可据此判断会话是否还能续）。
    pub fn touch(&mut self) -> bool {
        if let Session::Unlocked(u) = self {
            // 绝对上限：会话最长活这么久，到点不续
            if u.started_at.elapsed() >= MAX_SESSION {
                return false;
            }
            // 最小间隔：挡掉高频刷新的滥用
            if u.last_activity.elapsed() < MIN_TOUCH_GAP {
                return false;
            }
            u.last_activity = Instant::now();
            return true;
        }
        false
    }

    /// 检查是否需要自动锁定。
    ///
    /// 返回 `(是否刚锁定, 锁定前落盘的错误)`。
    ///
    /// 为什么要带第二项：自动锁定是**没人看着**的时候触发的，如果那一次
    /// 落盘失败（磁盘满、权限被改），改动就随锁定一起消失了。而调用方
    /// （前端定时轮询）原本只收到一个 bool，什么都不用报 —— 于是用户
    /// 以为「改完就存上了」，其实没有。这条错误必须交上去，让界面说清楚。
    pub fn check_autolock(&mut self) -> (bool, Option<String>) {
        // 免密码模式下不自动锁定。
        //
        // 锁定之后本机没有密码可输（用户开这个模式往往就是不想记/不想输），
        // 界面会停在密码框前面等人 —— 那与「免密码」的承诺正好相反。
        // 这里连会话绝对上限一起豁免，否则 8 小时后会出现同样的僵局。
        //
        // 代价是内存里的主密钥常驻到关窗口。那正是选择这个模式时接受的东西：
        // 它的定位是「不需要安全性，只要打开就能用」。
        if crate::machine::auto_unlock_enabled() {
            return (false, None);
        }
        let should_lock = match self {
            Session::Unlocked(u) => {
                // 闲置超时，或者会话已达绝对上限
                u.started_at.elapsed() >= MAX_SESSION
                    || u.auto_lock
                        .is_some_and(|limit| u.last_activity.elapsed() >= limit)
            }
            Session::Locked => false,
        };
        if !should_lock {
            return (false, None);
        }
        // 落盘失败时仍然锁定（安全优先），但把错误交回调用方。
        (true, self.lock().err())
    }

    /// 改闲置锁定时长，立即生效。
    ///
    /// `minutes == 0` 表示取消自动锁定 —— 界面上暂时不提供这个选项，
    /// 但内部保留，方便将来做成「长期办公机不锁」。
    pub fn set_auto_lock(&mut self, minutes: u32) {
        if let Session::Unlocked(u) = self {
            u.auto_lock = if minutes == 0 {
                None
            } else {
                Some(std::time::Duration::from_secs(u64::from(minutes) * 60))
            };
            // 改了锁定时长之后，当前这一轮闲置计时从「现在」重新算，
            // 否则刚设成 30 分钟就会被上一轮的 5 分钟倒计时提前锁掉。
            u.last_activity = Instant::now();
        }
    }

    /// 距离自动锁定还有多少秒。未解锁或不自动锁时返回 `None`。
    #[must_use]
    pub fn seconds_until_lock(&self) -> Option<u64> {
        match self {
            Session::Unlocked(u) => u
                .auto_lock
                .map(|limit| limit.saturating_sub(u.last_activity.elapsed()).as_secs()),
            Session::Locked => None,
        }
    }

    /// 统计信息。
    pub fn stats(&mut self, now: i64) -> Option<VaultStats> {
        self.un().map(|u| u.vault.stats(now))
    }
}
