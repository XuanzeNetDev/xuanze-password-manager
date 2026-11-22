//! Excel（xlsx）导出。
//!
//! 按专辑分工作表：左侧栏里每一个标签对应一张 sheet，另有一张「全部」。
//! 一条条目若属于多个专辑，会同时出现在这几张表里 —— 这和左侧栏的筛选行为一致。
//!
//! 写作前会要求再输一次主密码（在 `commands.rs` 里校验），因为导出的内容是明文，
//! 一旦落盘就绕开了本产品的全部防护。
//!
//! 手写最小 OOXML 而不是引第三方 xlsx 库：只需要「一行一条、全部内联字符串」，
//! 几百行代码换更小的安装包和更少的信任面。

use std::io::Write;

use xz_core::entry::Entry;

/// 一张工作表的原始数据。
pub struct Sheet {
    /// 表名（专辑名，或「全部」）。
    pub name: String,
    /// 表头。
    pub headers: Vec<&'static str>,
    /// 每行数据。
    pub rows: Vec<Vec<String>>,
}

/// 表头：账号密码场景下该有的列，加上密钥库特有的几列。
pub const HEADERS: [&str; 9] = [
    "名称",
    "类型",
    "账号",
    "密码 / 密钥",
    "网址",
    "专辑",
    "备注",
    "更新时间",
    "自定义字段",
];

/// 把一个条目摊成一行。
pub fn entry_to_row(e: &Entry) -> Vec<String> {
    let kind = match e.kind {
        xz_core::entry::EntryKind::Login => "登录",
        xz_core::entry::EntryKind::ApiKey => "密钥",
        xz_core::entry::EntryKind::Note => "笔记",
        xz_core::entry::EntryKind::Card => "银行卡",
        xz_core::entry::EntryKind::Credential => "凭据",
    };
    let extras = e
        .fields
        .iter()
        .map(|f| format!("{}={}", f.name, f.value))
        .collect::<Vec<_>>()
        .join("; ");
    vec![
        e.name.clone(),
        kind.to_owned(),
        e.username.clone(),
        e.secret.clone(),
        e.url.clone(),
        e.tags.join(", "),
        e.notes.clone(),
        fmt_ts(e.updated_at),
        extras,
    ]
}

/// Unix 秒 → `YYYY-MM-DD HH:MM`。
fn fmt_ts(ts: i64) -> String {
    if ts <= 0 {
        return String::new();
    }
    // 简单的手写转换：只用于展示，不追求时区精度（按 UTC）。
    let days = ts / 86_400;
    let secs = ts % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// Howard Hinnant 的 civil_from_days 算法。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 把若干张表写成一个 xlsx。
pub fn write_xlsx(path: &std::path::Path, sheets: &[Sheet]) -> Result<(), String> {
    if sheets.is_empty() {
        return Err("没有可导出的内容".to_owned());
    }

    let file = std::fs::File::create(path).map_err(|e| format!("建不了文件：{e}"))?;
    let mut zip = zip::ZipWriter::new(std::io::BufWriter::new(file));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let put = |zip: &mut zip::ZipWriter<std::io::BufWriter<std::fs::File>>,
               name: &str,
               data: &str|
     -> Result<(), String> {
        zip.start_file(name, opts).map_err(|e| e.to_string())?;
        zip.write_all(data.as_bytes()).map_err(|e| e.to_string())
    };

    // [Content_Types].xml —— 每张表都要登记
    let mut ct = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>"#,
    );
    for i in 0..sheets.len() {
        ct.push_str(&format!(
            r#"<Override PartName="/xl/worksheets/sheet{}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"#,
            i + 1
        ));
    }
    ct.push_str("</Types>");

    let rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;

    // 工作表清单
    let mut wb = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>"#,
    );
    for (i, s) in sheets.iter().enumerate() {
        wb.push_str(&format!(
            r#"<sheet name="{}" sheetId="{}" r:id="rId{}"/>"#,
            xml_escape(&sheet_name(&s.name)),
            i + 1,
            i + 1
        ));
    }
    wb.push_str("</sheets></workbook>");

    let mut wb_rels = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for i in 0..sheets.len() {
        wb_rels.push_str(&format!(
            r#"<Relationship Id="rId{}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{}.xml"/>"#,
            i + 1,
            i + 1
        ));
    }
    wb_rels.push_str("</Relationships>");

    put(&mut zip, "[Content_Types].xml", &ct)?;
    put(&mut zip, "_rels/.rels", rels)?;
    put(&mut zip, "xl/workbook.xml", &wb)?;
    put(&mut zip, "xl/_rels/workbook.xml.rels", &wb_rels)?;

    for (i, s) in sheets.iter().enumerate() {
        let xml = sheet_xml(s);
        put(&mut zip, &format!("xl/worksheets/sheet{}.xml", i + 1), &xml)?;
    }

    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

/// 生成一张表的 XML。
fn sheet_xml(s: &Sheet) -> String {
    let mut x = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#,
    );

    // 表头
    x.push_str(&row_xml(
        1,
        &s.headers
            .iter()
            .map(|h| (*h).to_owned())
            .collect::<Vec<_>>(),
    ));
    // 数据行
    for (i, r) in s.rows.iter().enumerate() {
        x.push_str(&row_xml(i + 2, r));
    }

    x.push_str("</sheetData></worksheet>");
    x
}

fn row_xml(idx: usize, cells: &[String]) -> String {
    let mut r = format!(r#"<row r="{idx}">"#);
    for (ci, v) in cells.iter().enumerate() {
        let col = col_name(ci);
        // inlineStr 保留原始文本，不会被 Excel 当成数字或公式
        r.push_str(&format!(
            r#"<c r="{col}{idx}" t="inlineStr"><is><t xml:space="preserve">{}</t></is></c>"#,
            xml_escape(v)
        ));
    }
    r.push_str("</row>");
    r
}

/// 列序号 → Excel 列名（0 → A，26 → AA）。
fn col_name(mut i: usize) -> String {
    let mut s = String::new();
    loop {
        s.insert(0, (b'A' + (i % 26) as u8) as char);
        if i < 26 {
            break;
        }
        i = i / 26 - 1;
    }
    s
}

/// 表名最长 31 字符，且不能含 `: \ / ? * [ ]`。
fn sheet_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| match c {
            ':' | '\\' | '/' | '?' | '*' | '[' | ']' => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return "未命名".to_owned();
    }
    trimmed.chars().take(31).collect()
}

/// XML 转义。顺带把 Excel 不接受的 ASCII 控制字符剔掉。
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 不允许的控制字符，直接丢弃
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {}
            c => out.push(c),
        }
    }
    out
}

// ───────────────────────── 读取（导入用） ─────────────────────────

/// 从 xlsx 读回来的一组行。
pub struct ImportedSheet {
    /// 工作表名（即专辑名）。
    pub name: String,
    /// 数据行（不含表头）。
    pub rows: Vec<Vec<String>>,
}

/// 读取 xlsx。
///
/// 只认本产品导出的那套结构：每张表第一行必须是 [`HEADERS`]，否则整表跳过。
/// 不去猜列顺序 —— 表头对不上就说明这个文件不是我们导出的，
/// 硬猜只会把数据塞进错误的字段。
pub fn read_xlsx(path: &std::path::Path) -> Result<Vec<ImportedSheet>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("打不开文件：{e}"))?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|e| format!("这不是有效的 Excel 文件：{e}"))?;

    // 1. 读 workbook.xml 拿到工作表名与顺序
    let names = read_sheet_names(&mut zip)?;
    // 2. 逐表读内容
    let mut out = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let part = format!("xl/worksheets/sheet{}.xml", i + 1);
        let xml = match read_entry(&mut zip, &part) {
            Ok(s) => s,
            Err(_) => continue, // 缺表就跳过，不整体失败
        };
        let mut rows = parse_sheet_xml(&xml);
        // 首行必须是我们的表头
        if rows.is_empty() {
            continue;
        }
        let head = rows.remove(0);
        if head.len() < HEADERS.len() || head[..HEADERS.len()] != HEADERS[..] {
            continue;
        }
        if !rows.is_empty() {
            out.push(ImportedSheet {
                name: name.clone(),
                rows,
            });
        }
    }

    if out.is_empty() {
        return Err(
            "文件里没有可以导入的表。首行表头必须是：名称 / 类型 / 账号 / 密码 / 网址 / 专辑 / 备注 / 更新时间 / 自定义字段"
                .to_owned(),
        );
    }
    Ok(out)
}

fn read_entry<R: std::io::Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    name: &str,
) -> Result<String, String> {
    use std::io::Read as _;
    let mut f = zip.by_name(name).map_err(|e| e.to_string())?;
    let mut s = String::new();
    f.read_to_string(&mut s).map_err(|e| e.to_string())?;
    Ok(s)
}

/// 从 `xl/workbook.xml` 里按顺序取出工作表名。
fn read_sheet_names<R: std::io::Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
) -> Result<Vec<String>, String> {
    let wb = read_entry(zip, "xl/workbook.xml")?;
    let mut names = Vec::new();
    let mut rest = wb.as_str();
    while let Some(pos) = rest.find("<sheet ") {
        rest = &rest[pos + 7..];
        let end = rest.find("/>").unwrap_or(rest.len());
        let tag = &rest[..end];
        if let Some(s) = attr(tag, "name") {
            names.push(xml_unescape(&s));
        }
        rest = &rest[end..];
    }
    if names.is_empty() {
        return Err("Excel 文件里没有工作表".to_owned());
    }
    Ok(names)
}

fn attr(tag: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=\"");
    let start = tag.find(&pat)? + pat.len();
    let rest = &tag[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// 把一张表的 XML 解析成二维字符串。
///
/// 只处理我们自己写出的形态（`<c t="inlineStr"><is><t>…</t></is></c>`），
/// 遇到共享字符串表之类的结构会读成空 —— 那说明不是本产品导出的文件。
fn parse_sheet_xml(xml: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();

    for row_xml in split_all(xml, "<row ", "</row>") {
        let mut cells: Vec<String> = Vec::new();
        for cell in split_all(&row_xml, "<c ", "</c>") {
            // 只认内联字符串（我们自己写出的形态）：<c ...><is><t>文本</t></is></c>
            let text = match cell.find("<t") {
                Some(tp) => {
                    let after = &cell[tp..];
                    let open_end = after.find('>').map_or(after.len(), |x| x + 1);
                    let body = &after[open_end..];
                    let close = body.find("</t>").unwrap_or(body.len());
                    xml_unescape(&body[..close])
                }
                None => String::new(),
            };
            cells.push(text);
        }
        rows.push(cells);
    }
    rows
}

/// 按开闭标签切出每一段内部内容。
///
/// 单独写这个是因为「跳固定字节数」的做法必错：`</c>` 是 4 字节，
/// `</row>` 是 6 字节，稍一走神就多跳或少跳两个字符，
/// 下一个标签会被截断，表现为「表头少了几列」这种极难定位的现象。
fn split_all(src: &str, open: &str, close: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;

    while let Some(op) = rest.find(open) {
        // 跳过 "<row " 本身，定位到其后的 ">"
        let after_open = &rest[op..];
        let Some(gt) = after_open.find('>') else {
            break;
        };
        let inner_start = op + gt + 1;
        let tail = &rest[inner_start..];
        let Some(cp) = tail.find(close) else {
            break;
        };
        out.push(tail[..cp].to_owned());
        rest = &tail[cp + close.len()..];
    }
    out
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// 把一行数据还原成条目需要的字段。
pub struct ParsedRow {
    pub name: String,
    pub kind: xz_core::entry::EntryKind,
    pub username: String,
    pub secret: String,
    pub url: String,
    pub tags: Vec<String>,
    pub notes: String,
}

/// 列序与 [`HEADERS`] 一一对应。
pub fn row_to_entry(row: &[String], sheet_name: &str) -> Option<ParsedRow> {
    let get = |i: usize| row.get(i).cloned().unwrap_or_default();

    let name = get(0);
    if name.trim().is_empty() {
        return None;
    }

    let kind = match get(1).trim() {
        "登录" => xz_core::entry::EntryKind::Login,
        "密钥" => xz_core::entry::EntryKind::ApiKey,
        "笔记" => xz_core::entry::EntryKind::Note,
        "银行卡" => xz_core::entry::EntryKind::Card,
        "凭据" => xz_core::entry::EntryKind::Credential,
        _ => xz_core::entry::EntryKind::Login,
    };

    // 专辑列和所属工作表都算来源，合并去重
    let mut tags: Vec<String> = get(5)
        .split(',')
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .collect();
    if sheet_name != "全部" && !tags.iter().any(|t| t == sheet_name) {
        tags.push(sheet_name.to_owned());
    }

    Some(ParsedRow {
        name: name.trim().to_owned(),
        kind,
        username: get(2),
        secret: get(3),
        url: get(4),
        tags,
        notes: get(6),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    #[test]
    fn col_names() {
        assert_eq!(super::col_name(0), "A");
        assert_eq!(super::col_name(25), "Z");
        assert_eq!(super::col_name(26), "AA");
        assert_eq!(super::col_name(27), "AB");
        assert_eq!(super::col_name(51), "AZ");
        assert_eq!(super::col_name(52), "BA");
    }

    #[test]
    fn sheet_name_is_sanitized() {
        assert_eq!(super::sheet_name("prod"), "prod");
        assert_eq!(super::sheet_name("a:b/c"), "a_b_c");
        assert_eq!(super::sheet_name("  "), "未命名");
        let long = "x".repeat(50);
        assert_eq!(super::sheet_name(&long).chars().count(), 31);
    }

    #[test]
    fn xml_escape_handles_specials() {
        assert_eq!(super::xml_escape("a<b>&c"), "a&lt;b&gt;&amp;c");
        assert_eq!(super::xml_escape("tab\there"), "tab\there");
        // 控制字符被丢掉
        assert_eq!(super::xml_escape("a\u{1}b"), "ab");
    }

    /// 写出去再读回来，字段必须一模一样。
    ///
    /// 这是导入/导出两个方向唯一能自动化验证的东西：界面上点来点去验证不了
    /// 「表头对不对得上」「专辑有没有丢」，而这两件正是导入最容易出错的地方。
    #[test]
    fn roundtrip_preserves_rows() {
        use xz_core::entry::{Entry, EntryKind};

        let e = Entry {
            id: "abc".into(),
            kind: EntryKind::ApiKey,
            name: "测试条目".into(),
            username: "user@example.com".into(),
            secret: "sk-test-123".into(),
            url: "https://example.com".into(),
            fields: vec![],
            tags: vec!["prod".into(), "api".into()],
            notes: "含特殊字符 <>&\"'".into(),
            created_at: 1,
            updated_at: 1_700_000_000,
            expires_at: 0,
            use_count: 0,
            last_used_at: 0,
        };

        let sheet = super::Sheet {
            name: "prod".into(),
            headers: super::HEADERS.to_vec(),
            rows: vec![super::entry_to_row(&e)],
        };

        let dir = std::env::temp_dir().join(format!("xz-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("roundtrip.xlsx");
        super::write_xlsx(&path, &[sheet]).unwrap();

        let back = match super::read_xlsx(&path) {
            Ok(v) => v,
            Err(e) => panic!("read_xlsx 失败: {e}"),
        };
        assert_eq!(back.len(), 1, "应该读回一张表");
        assert_eq!(back[0].name, "prod");
        assert_eq!(back[0].rows.len(), 1);

        let row = &back[0].rows[0];
        assert_eq!(row[0], "测试条目");
        assert_eq!(row[1], "密钥");
        assert_eq!(row[2], "user@example.com");
        assert_eq!(row[3], "sk-test-123");
        assert_eq!(row[4], "https://example.com");
        // 特殊字符必须原样回来（这是 XML 转义最容易漏的地方）
        assert_eq!(row[6], "含特殊字符 <>&\"'");

        // 再走一遍 row_to_entry，确认能还原成条目
        let p = super::row_to_entry(row, &back[0].name).unwrap();
        assert_eq!(p.name, "测试条目");
        assert_eq!(p.secret, "sk-test-123");
        assert!(p.tags.contains(&"prod".to_owned()));
        assert!(p.tags.contains(&"api".to_owned()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 表头不对时必须跳过整张表，而不是把数据硬塞进去。
    #[test]
    fn wrong_header_is_rejected() {
        let dir = std::env::temp_dir().join(format!("xz-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.xlsx");

        let bad = super::Sheet {
            name: "x".into(),
            headers: vec!["错的表头", "第二列"],
            rows: vec![vec!["a".into(), "b".into()]],
        };
        super::write_xlsx(&path, &[bad]).unwrap();

        // 表头对不上 → 全部被过滤 → 报错
        assert!(super::read_xlsx(&path).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
