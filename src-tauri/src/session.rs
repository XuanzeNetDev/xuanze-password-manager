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

use std::path::PathBuf;
use std::time::Instant;

/// 两次活跃刷新之间的最小间隔。前端节流是 6 秒，这里取 4 秒留余量。
const MIN_TOUCH_GAP: std::time::Duration = std::time::Duration::from_secs(4);

/// 单个解锁会话的绝对寿命：到点必须重新输密码。
///
/// 自动锁定管的是「闲置」，这条管的是「一直在用」——不设上限的话，
/// 一台开着的机器可以几十年不重新验证身份。
const MAX_SESSION: std::time::Duration = std::time::Duration::from_secs(8 * 3600);

use xz_core::kdf::KdfParams;
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

    /// 新建库并进入解锁态。
    pub fn create(&mut self, password: &str, params: KdfParams) -> xz_core::Result<()> {
        // 建库时就绑到本机：之后的 pepper 缺失或换了机器都打不开
        let pepper =
            crate::machine::pepper().map_err(|_| xz_core::Error::Corrupt("机器绑定失败"))?;
        let vault = Vault::create_bound(password, params, &pepper)?;
        *self = Session::Unlocked(Box::new(Unlocked {
            vault,
            last_activity: Instant::now(),
            started_at: Instant::now(),
            auto_lock: Some(std::time::Duration::from_secs(300)),
        }));
        Ok(())
    }

    /// 接管一个已经建好的 `Vault`（建库流程用）。
    ///
    /// KDF 在锁外跑完了，这里只做状态切换。
    pub fn adopt(&mut self, vault: Vault) {
        *self = Session::Unlocked(Box::new(Unlocked {
            vault,
            last_activity: Instant::now(),
            started_at: Instant::now(),
            auto_lock: Some(std::time::Duration::from_secs(300)),
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
            auto_lock: Some(std::time::Duration::from_secs(300)),
        }));
        Ok(())
    }

    /// 打开库并进入解锁态。
    pub fn open(&mut self, path: &PathBuf, password: &str) -> xz_core::Result<()> {
        let pepper =
            crate::machine::pepper().map_err(|_| xz_core::Error::Corrupt("机器绑定失败"))?;
        let bytes = std::fs::read(path).map_err(xz_core::Error::Io)?;
        let mut vault = Vault::open_bound(&bytes, password, &pepper)?;
        vault.set_path(path.to_path_buf());
        *self = Session::Unlocked(Box::new(Unlocked {
            vault,
            last_activity: Instant::now(),
            started_at: Instant::now(),
            auto_lock: Some(std::time::Duration::from_secs(300)),
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

    /// 检查是否需要自动锁定。返回是否刚刚锁了。
    pub fn check_autolock(&mut self) -> bool {
        let should_lock = match self {
            Session::Unlocked(u) => {
                // 闲置超时，或者会话已达绝对上限
                u.started_at.elapsed() >= MAX_SESSION
                    || u.auto_lock
                        .is_some_and(|limit| u.last_activity.elapsed() >= limit)
            }
            Session::Locked => false,
        };
        if should_lock {
            // 自动锁定由定时器触发，没有人在等返回值。落盘失败只能记日志 ——
            // 但至少不再是彻底静默：debug 构建下会打出来。
            if let Err(e) = self.lock() {
                #[cfg(debug_assertions)]
                eprintln!("[autolock] {e}");
                let _ = &e;
            }
        }
        should_lock
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
