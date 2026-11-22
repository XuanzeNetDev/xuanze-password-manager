//! 璇泽密钥库 · 性能基准
//!
//! 跑三组数据：
//! - KDF：三档 Argon2id 参数的实际耗时（打开 vault 的固定成本）
//! - 高频路径：搜索 / 取秘密 / 索引更新（必须快到无感）
//! - 全链路：1k / 10k 条 vault 的打开、封存、落盘
//!
//! 用法：`cargo run --release -p xz-bench`

use std::time::{Duration, Instant};

use xz_core::entry::{Entry, EntryKind, Field};
use xz_core::kdf::{self, KdfParams};
use xz_core::search;
use xz_core::vault::Vault;

fn main() {
    println!("璇泽密钥库 · 性能基准");
    println!("{}", "=".repeat(64));
    println!("{}", platform_line());
    println!("{}", "=".repeat(64));

    bench_kdf();
    bench_hot_paths();
    bench_full_pipeline(1_000);
    bench_full_pipeline(10_000);
    bench_full_pipeline(50_000);

    println!("\n备注：release 构建（opt-level=3, lto=fat, codegen-units=1, panic=abort）");
}

fn platform_line() -> String {
    format!(
        "平台 {} / Rust {} / {} 逻辑核",
        std::env::consts::OS,
        rustc_version(),
        std::thread::available_parallelism().map_or(0, |n| n.get())
    )
}

fn rustc_version() -> &'static str {
    option_env!("CARGO_PKG_RUST_VERSION").unwrap_or("unknown")
}

fn bench_kdf() {
    println!("\n[1] KDF —— 打开 vault 的固定成本（Argon2id）");
    let salt = [0u8; 32];
    for (label, params) in [
        ("light    (19 MiB ×2)", KdfParams::light()),
        ("balanced (64 MiB ×3)", KdfParams::balanced()),
        ("paranoid (256 MiB ×4)", KdfParams::paranoid()),
    ] {
        let mut samples = Vec::new();
        for _ in 0..3 {
            let t = Instant::now();
            let _ = kdf::derive_master_key(b"bench-password", &salt, params);
            samples.push(t.elapsed());
        }
        println!("  {label:<24} 中位 {:>8}", fmt_dur(median(&mut samples)));
    }
}

fn bench_hot_paths() {
    println!("\n[2] 高频路径 —— 打开之后的每一次操作");

    let mut v = Vault::create("bench", KdfParams::light()).expect("create");
    let entries = make_entries(10_000);
    for e in entries {
        let _ = v.insert(e);
    }

    // 搜索：空查询（热度榜）
    let t = Instant::now();
    for _ in 0..1000 {
        let _ = search::search(v.index(), "", 20);
    }
    println!(
        "  {:<24} {:>9}/次",
        "搜索·空查询(热度榜)",
        fmt_dur(t.elapsed() / 1000)
    );

    // 搜索：精确命中
    let t = Instant::now();
    for _ in 0..1000 {
        let _ = search::search(v.index(), "key-004242", 20);
    }
    println!(
        "  {:<24} {:>9}/次",
        "搜索·精确命中",
        fmt_dur(t.elapsed() / 1000)
    );

    // 搜索：全库无命中（最坏情况：每条都跑完所有打分阶段）
    let t = Instant::now();
    for _ in 0..1000 {
        let _ = search::search(v.index(), "zzzzzzzz-not-exist", 20);
    }
    println!(
        "  {:<24} {:>9}/次",
        "搜索·全库无命中(最坏)",
        fmt_dur(t.elapsed() / 1000)
    );

    // 搜索：子序列模糊（靠后的兜底分支）
    let t = Instant::now();
    for _ in 0..1000 {
        let _ = search::search(v.index(), "k4242", 20);
    }
    println!(
        "  {:<24} {:>9}/次",
        "搜索·子序列模糊",
        fmt_dur(t.elapsed() / 1000)
    );

    // 搜索：中文 —— 分两档测，才能看出「窄化路径」到底有没有生效。
    // 这一库是 ASCII 为主，属于窄化路径的目标场景。
    let t = Instant::now();
    for _ in 0..1000 {
        let _ = search::search(v.index(), "服务凭据", 20);
    }
    println!(
        "  {:<24} {:>9}/次",
        "搜索·中文(ASCII 库)",
        fmt_dur(t.elapsed() / 1000)
    );

    // 中文为主的库：窄化路径会主动放弃，退回全量扫描。
    // 这是最坏情况，也是中文用户真实会遇到的一档。
    let mut cv = Vault::create("bench", KdfParams::light()).expect("create");
    for e in make_cjk_entries(10_000) {
        let _ = cv.insert(e);
    }
    let t = Instant::now();
    for _ in 0..100 {
        let _ = search::search(cv.index(), "服务凭据", 20);
    }
    println!(
        "  {:<24} {:>9}/次",
        "搜索·中文(中文库)",
        fmt_dur(t.elapsed() / 100)
    );
    let t = Instant::now();
    for _ in 0..100 {
        let _ = search::search(cv.index(), "银行", 20);
    }
    println!(
        "  {:<24} {:>9}/次",
        "搜索·中文短词(中文库)",
        fmt_dur(t.elapsed() / 100)
    );

    // 搜索：模糊前缀
    let t = Instant::now();
    for _ in 0..1000 {
        let _ = search::search(v.index(), "ke", 20);
    }
    println!(
        "  {:<24} {:>9}/次",
        "搜索·模糊前缀(1万条)",
        fmt_dur(t.elapsed() / 1000)
    );

    // 取秘密
    let id = v.index().all_sorted()[0].id.clone();
    let t = Instant::now();
    for _ in 0..100_000 {
        let _ = v.reveal_secret(&id);
    }
    println!(
        "  {:<24} {:>9}/次",
        "取主秘密",
        fmt_dur(t.elapsed() / 100_000)
    );

    // 记一次使用（索引增量更新）
    let t = Instant::now();
    for _ in 0..10_000 {
        let _ = v.record_use(&id, 1);
    }
    println!(
        "  {:<24} {:>9}/次",
        "记录使用(索引更新)",
        fmt_dur(t.elapsed() / 10_000)
    );

    // 热度榜
    let t = Instant::now();
    for _ in 0..1000 {
        let _ = v.index().hot(9);
    }
    println!(
        "  {:<24} {:>9}/次",
        "热度榜 top9",
        fmt_dur(t.elapsed() / 1000)
    );
}

fn bench_full_pipeline(n: usize) {
    println!("\n[3] 全链路 —— {n} 条条目");

    let pw = "bench-password";
    let mut v = Vault::create(pw, KdfParams::light()).expect("create");
    for e in make_entries(n) {
        let _ = v.insert(e);
    }

    // 封存（序列化 + 加密）
    let t = Instant::now();
    let sealed = v.seal().expect("seal");
    let seal_dur = t.elapsed();

    // 打开（含 KDF）—— 分开记录，才能看出 KDF 之后真正的解析成本
    let t = Instant::now();
    let v2 = Vault::open_from_bytes(&sealed, pw).expect("open");
    let open_dur = t.elapsed();

    // 单独量一次 KDF，用来算「净解析耗时」
    let t = Instant::now();
    let _ = kdf::derive_master_key(pw.as_bytes(), &[0u8; 32], KdfParams::light());
    let kdf_dur = t.elapsed();
    let parse_dur = open_dur.saturating_sub(kdf_dur);

    // 落盘
    let dir = std::env::temp_dir().join("xz-bench");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("bench-{n}.xzvlt"));
    let mut v3 = v2;
    v3.set_path(&path);
    let t = Instant::now();
    v3.save().expect("save");
    let save_dur = t.elapsed();
    let size = std::fs::metadata(&path).map_or(0, |m| m.len());
    let _ = std::fs::remove_file(&path);

    println!("  vault 大小（含 KDF+SHA，不含缓存）  {}", human(size));
    println!("  封存 seal()                      {}", fmt_dur(seal_dur));
    println!("  打开 open()（含 KDF）             {}", fmt_dur(open_dur));
    println!(
        "  打开 open()（扣掉 KDF 的净耗时）    {}  ← 解析+解密+建索引",
        fmt_dur(parse_dur)
    );
    println!("  KDF 单独计时                      {}", fmt_dur(kdf_dur));
    println!("  保存 save()（含 fsync）           {}", fmt_dur(save_dur));
    println!(
        "  端到端（seal+open+save）          {}",
        fmt_dur(seal_dur + open_dur + save_dur)
    );
}

fn make_entries(n: usize) -> Vec<Entry> {
    let tags = [
        "api", "cloud", "work", "personal", "prod", "staging", "infra",
    ];
    (0..n)
        .map(|i| Entry {
            id: format!("{i:032x}"),
            kind: match i % 5 {
                0 => EntryKind::Login,
                1 => EntryKind::ApiKey,
                2 => EntryKind::Note,
                3 => EntryKind::Credential,
                _ => EntryKind::Card,
            },
            name: format!("key-{i:05} 服务凭据"),
            username: format!("user{i}@example.com"),
            secret: format!("bench-secret-{i:08}"),
            url: format!("https://api{}.example.com/v1", i % 97),
            fields: vec![
                Field::secret("org", format!("org-{}", i % 13)),
                Field::plain("region", "ap-east-1"),
            ],
            tags: vec![tags[i % tags.len()].to_owned()],
            notes: if i % 7 == 0 {
                "轮换周期 90 天".to_owned()
            } else {
                String::new()
            },
            created_at: 1_700_000_000 + i as i64,
            updated_at: 1_700_000_000 + i as i64,
            expires_at: if i % 11 == 0 { 1_800_000_000 } else { 0 },
            use_count: (i % 37) as u32,
            last_used_at: 1_700_000_000 + i as i64,
        })
        .collect()
}

/// 中文为主的条目集，用来测「窄化路径失效」时最坏的一档。
fn make_cjk_entries(n: usize) -> Vec<Entry> {
    let prefix = [
        "阿里云",
        "腾讯云",
        "华为云",
        "自建机房",
        "银行",
        "支付",
        "邮箱",
        "服务器",
    ];
    let suffix = ["访问密钥", "登录密码", "接口令牌", "数据库口令", "证书私钥"];
    (0..n)
        .map(|i| Entry {
            id: format!("{:032x}", i as u64 + 0x8000_0000u64),
            kind: EntryKind::ApiKey,
            name: format!(
                "{} {}号 {}",
                prefix[i % prefix.len()],
                i,
                suffix[i % suffix.len()]
            ),
            username: format!("账号{}", i % 500),
            secret: format!("key-中文-{:08}", i),
            url: format!("https://内网{}.示例.中国/api", i % 89),
            fields: vec![Field::plain("机房", "华东一区")],
            tags: vec![prefix[i % prefix.len()].to_owned()],
            notes: String::new(),
            created_at: 1_700_000_000 + i as i64,
            updated_at: 1_700_000_000 + i as i64,
            expires_at: 0,
            use_count: (i % 23) as u32,
            last_used_at: 1_700_000_000 + i as i64,
        })
        .collect()
}

fn median(v: &mut [Duration]) -> Duration {
    v.sort_unstable();
    v[v.len() / 2]
}

fn fmt_dur(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us < 1.0 {
        format!("{:.0} ns", us * 1000.0)
    } else if us < 1000.0 {
        format!("{us:.1} µs")
    } else if us < 1_000_000.0 {
        format!("{:.2} ms", us / 1000.0)
    } else {
        format!("{:.2} s", us / 1e6)
    }
}

fn human(n: u64) -> String {
    const KB: u64 = 1024;
    if n < KB {
        format!("{n} B")
    } else if n < KB * KB {
        format!("{:.1} KiB", n as f64 / KB as f64)
    } else {
        format!("{:.2} MiB", n as f64 / (KB * KB) as f64)
    }
}
