//! 璇泽密钥库 · 命令行工具 `xzc`
//!
//! 作用有两个：
//! 1. 给不装 GUI 的场景兜底（服务器、脚本、CI）。
//! 2. **作为 GUI 的对照实现**：GUI 出的任何问题，都能在 CLI 上复现，
//!    排除掉前端因素。这也是开源项目里「可验证」的一部分。

use std::path::{Path, PathBuf};

use xz_core::entry::{Entry, EntryKind, Field};
use xz_core::kdf::KdfParams;
use xz_core::search;
use xz_core::vault::Vault;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        print_help();
        return;
    }

    let cmd = args[0].as_str();
    let rest = &args[1..];

    let result = match cmd {
        "init" => cmd_init(rest),
        "list" => cmd_list(rest),
        "add" => cmd_add(rest),
        "show" => cmd_show(rest),
        "rm" => cmd_rm(rest),
        "find" => cmd_find(rest),
        "export" => cmd_export(rest),
        "passwd" => cmd_passwd(rest),
        other => {
            eprintln!("未知命令：{other}");
            print_help();
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("错误：{e}");
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        r#"璇泽密钥库 CLI

用法：
  xzc init   <vault> --password <pw> [--level light|balanced|paranoid]
  xzc list   <vault> --password <pw>
  xzc find   <vault> --password <pw> <关键词>
  xzc add    <vault> --password <pw> --name <名称> [--secret <值>] [--username <值>]
             [--url <值>] [--kind login|api-key|note|card|credential] [--tag <标签>]...
  xzc show   <vault> --password <pw> <id> [--reveal]
  xzc rm     <vault> --password <pw> <id>
  xzc passwd <vault> --password <旧密码> --new-password <新密码>
  xzc export <vault> --password <pw> [--out <文件>]

约定：
  --password - 表示从环境变量 XZ_PASSWORD 读取，避免密码进 shell 历史。
"#
    );
}

fn parse_flags(args: &[String]) -> (Vec<String>, std::collections::HashMap<String, Vec<String>>) {
    let mut positional = Vec::new();
    let mut flags: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(key) = a.strip_prefix("--") {
            let val = args.get(i + 1).cloned().unwrap_or_default();
            flags.entry(key.to_owned()).or_default().push(val);
            i += 2;
        } else {
            positional.push(a.clone());
            i += 1;
        }
    }
    (positional, flags)
}

fn flag(flags: &std::collections::HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    flags.get(key).and_then(|v| v.first()).cloned()
}

fn password(flags: &std::collections::HashMap<String, Vec<String>>, key: &str) -> Result<String, String> {
    match flag(flags, key) {
        Some(p) if p == "-" => {
            std::env::var("XZ_PASSWORD").map_err(|_| format!("--{key} - 要求设置环境变量 XZ_PASSWORD"))
        }
        Some(p) => Ok(p),
        None => Err(format!("缺少 --{key}")),
    }
}

fn kdf_from(level: Option<String>) -> KdfParams {
    match level.as_deref() {
        Some("light") => KdfParams::light(),
        Some("paranoid") => KdfParams::paranoid(),
        _ => KdfParams::balanced(),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn cmd_init(args: &[String]) -> Result<(), xz_core::Error> {
    let (pos, flags) = parse_flags(args);
    let path = pos.first().ok_or(xz_core::Error::Invalid("缺少 vault 路径"))?;
    let pw = password(&flags, "password").map_err(|_| xz_core::Error::Invalid("缺少 --password"))?;
    let mut v = Vault::create(&pw, kdf_from(flag(&flags, "level")))?;
    v.save_as(PathBuf::from(path))?;
    println!("已创建 {path}");
    Ok(())
}

fn cmd_list(args: &[String]) -> Result<(), xz_core::Error> {
    let (pos, flags) = parse_flags(args);
    let path = pos.first().ok_or(xz_core::Error::Invalid("缺少 vault 路径"))?;
    let pw = password(&flags, "password").map_err(|_| xz_core::Error::Invalid("缺少 --password"))?;
    let v = Vault::open(Path::new(path), &pw)?;
    println!("{:<20} {:<10} {:<28} {}", "ID", "类型", "名称", "用户名");
    for item in v.index().all_sorted() {
        let kind = EntryKind::from_code(item.kind).map_or("?", kind_name);
        println!(
            "{:<20} {:<10} {:<28} {}",
            truncate(&item.id, 20),
            kind,
            truncate(&item.name, 28),
            truncate(&item.username, 30)
        );
    }
    println!("共 {} 条", v.len());
    Ok(())
}

fn cmd_find(args: &[String]) -> Result<(), xz_core::Error> {
    let (pos, flags) = parse_flags(args);
    let path = pos.first().ok_or(xz_core::Error::Invalid("缺少 vault 路径"))?;
    let pw = password(&flags, "password").map_err(|_| xz_core::Error::Invalid("缺少 --password"))?;
    let q = pos.get(1).cloned().unwrap_or_default();
    let v = Vault::open(Path::new(path), &pw)?;
    let t = std::time::Instant::now();
    let hits = search::search(v.index(), &q, 50);
    let elapsed = t.elapsed();
    for h in &hits {
        println!("{:>4}  {:<28} {}", h.score, truncate(&h.item.name, 28), h.item.id);
    }
    println!(
        "{} 条结果，耗时 {:.3} ms（纯内存）",
        hits.len(),
        elapsed.as_secs_f64() * 1000.0
    );
    Ok(())
}

fn cmd_add(args: &[String]) -> Result<(), xz_core::Error> {
    let (pos, flags) = parse_flags(args);
    let path = pos.first().ok_or(xz_core::Error::Invalid("缺少 vault 路径"))?;
    let pw = password(&flags, "password").map_err(|_| xz_core::Error::Invalid("缺少 --password"))?;
    let name = flag(&flags, "name").ok_or(xz_core::Error::Invalid("缺少 --name"))?;

    let mut v = Vault::open(Path::new(path), &pw)?;
    let ts = now();
    let entry = Entry {
        id: new_id(),
        kind: match flag(&flags, "kind").as_deref() {
            Some("login") => EntryKind::Login,
            Some("note") => EntryKind::Note,
            Some("card") => EntryKind::Card,
            Some("credential") => EntryKind::Credential,
            _ => EntryKind::ApiKey,
        },
        name,
        username: flag(&flags, "username").unwrap_or_default(),
        secret: flag(&flags, "secret").unwrap_or_default(),
        url: flag(&flags, "url").unwrap_or_default(),
        fields: Vec::<Field>::new(),
        tags: flags.get("tag").cloned().unwrap_or_default(),
        notes: String::new(),
        created_at: ts,
        updated_at: ts,
        expires_at: 0,
        use_count: 0,
        last_used_at: 0,
    };
    let id = v.insert(entry)?;
    v.save()?;
    println!("已添加 {id}");
    Ok(())
}

fn cmd_show(args: &[String]) -> Result<(), xz_core::Error> {
    let (pos, flags) = parse_flags(args);
    let path = pos.first().ok_or(xz_core::Error::Invalid("缺少 vault 路径"))?;
    let pw = password(&flags, "password").map_err(|_| xz_core::Error::Invalid("缺少 --password"))?;
    let id = pos.get(1).ok_or(xz_core::Error::Invalid("缺少条目 id"))?;
    let v = Vault::open(Path::new(path), &pw)?;
    let e = v
        .get(id)
        .ok_or_else(|| xz_core::Error::EntryNotFound(id.clone()))?;
    println!("名称   {}", e.name);
    println!("类型   {}", kind_name(e.kind));
    println!("用户名 {}", e.username);
    println!("网址   {}", e.url);
    println!("标签   {}", e.tags.join(", "));
    if flags.contains_key("reveal") {
        println!("秘密   {}", e.secret);
    } else {
        println!("秘密   {}（加 --reveal 显示）", "*".repeat(e.secret.len().min(24)));
    }
    Ok(())
}

fn cmd_rm(args: &[String]) -> Result<(), xz_core::Error> {
    let (pos, flags) = parse_flags(args);
    let path = pos.first().ok_or(xz_core::Error::Invalid("缺少 vault 路径"))?;
    let pw = password(&flags, "password").map_err(|_| xz_core::Error::Invalid("缺少 --password"))?;
    let id = pos.get(1).ok_or(xz_core::Error::Invalid("缺少条目 id"))?;
    let mut v = Vault::open(Path::new(path), &pw)?;
    v.remove(id)?;
    v.save()?;
    println!("已删除 {id}");
    Ok(())
}

fn cmd_passwd(args: &[String]) -> Result<(), xz_core::Error> {
    let (pos, flags) = parse_flags(args);
    let path = pos.first().ok_or(xz_core::Error::Invalid("缺少 vault 路径"))?;
    let old = password(&flags, "password").map_err(|_| xz_core::Error::Invalid("缺少 --password"))?;
    let new = flag(&flags, "new-password").ok_or(xz_core::Error::Invalid("缺少 --new-password"))?;
    let mut v = Vault::open(Path::new(path), &old)?;
    v.change_password(&new, None)?;
    v.save()?;
    println!("主密码已更新");
    Ok(())
}

fn cmd_export(args: &[String]) -> Result<(), xz_core::Error> {
    let (pos, flags) = parse_flags(args);
    let path = pos.first().ok_or(xz_core::Error::Invalid("缺少 vault 路径"))?;
    let pw = password(&flags, "password").map_err(|_| xz_core::Error::Invalid("缺少 --password"))?;
    let v = Vault::open(Path::new(path), &pw)?;
    let mut out = String::from("name,kind,username,secret,url,tags\n");
    for item in v.index().all_sorted() {
        if let Some(e) = v.get(&item.id) {
            out.push_str(&format!(
                "{},{},{},{},{},{}\n",
                csv_escape(&e.name),
                kind_name(e.kind),
                csv_escape(&e.username),
                csv_escape(&e.secret),
                csv_escape(&e.url),
                csv_escape(&e.tags.join("|"))
            ));
        }
    }
    match flag(&flags, "out") {
        Some(p) => {
            std::fs::write(&p, out)?;
            println!("已导出到 {p}（明文，请立刻处理掉）");
        }
        None => print!("{out}"),
    }
    Ok(())
}

fn kind_name(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Login => "登录",
        EntryKind::ApiKey => "密钥",
        EntryKind::Note => "笔记",
        EntryKind::Card => "卡片",
        EntryKind::Credential => "凭据",
    }
}

fn truncate(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= n {
        s.to_owned()
    } else {
        let mut out: String = chars[..n.saturating_sub(1)].iter().collect();
        out.push('…');
        out
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// 生成 32 位十六进制 id。用核心库的 CSPRNG。
fn new_id() -> String {
    let b: [u8; 16] = xz_core::kdf::random_bytes::<16>();
    let mut s = String::with_capacity(32);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}
