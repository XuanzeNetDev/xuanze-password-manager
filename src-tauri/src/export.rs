//! Excel（xlsx）导出与导入。
//!
//! 按专辑分工作表：左侧栏里每一个标签对应一张 sheet，另有一张「全部」。
//! 一条条目若属于多个专辑，会同时出现在这几张表里 —— 这和左侧栏的筛选行为一致。
//!
//! 写作前会要求再输一次主密码（在 `commands.rs` 里校验），因为导出的内容是明文，
//! 一旦落盘就绕开了本产品的全部防护。
//!
//! 手写最小 OOXML 而不是引第三方 xlsx 库：只需要「一行一条、全部内联字符串」，
//! 几百行代码换更小的安装包和更少的信任面。
//!
//! # 这份表格是灾备，不是快照
//!
//! 导出的 xlsx 承担两个职责：
//!
//! 1. **人看** —— 用 Excel 打开、翻查、打印。
//! 2. **机器读回** —— 换机器 / 重装系统之后，靠它把数据导回来。
//!
//! 第 2 条决定了「什么都不能丢」。因此这里的读取端刻意做得比写入端宽：
//!
//! - 按单元格自己的地址（`r="B3"`）定位列，不按出现顺序 —— 用户用 Excel
//!   打开、改一格、保存之后，空单元格会被省略，按顺序读会整行左移，
//!   密码就落到「网址」列里去了。
//! - 认 `sharedStrings.xml` 和 `<v>`。Excel 重新保存会把内联字符串改写成
//!   共享字符串表，只认内联字符串的话，二次编辑过的文件直接读成空。
//! - 列按表头名字对位，所以列顺序变了、多了几列手写批注都还能读。
//!   只有「名称」列是必需的，其余缺列一律按空值处理 —— 老版本导出的
//!   9 列文件仍然可以导入。

use std::io::Write;

use xz_core::entry::{Entry, Field};

/// 表头：账号密码场景下该有的列，加上密钥库特有的几列。
///
/// 前 9 列的顺序是**格式的一部分**（老文件照这个顺序导出），只能往后追加。
/// 追加的三列（创建时间 / 过期时间 / 使用次数）是为了让「导出 → 导入」
/// 真的能完整还原一条条目，而不是只还原一半。
pub const HEADERS: [&str; 12] = [
    "名称",
    "类型",
    "账号",
    "密码 / 密钥",
    "网址",
    "专辑",
    "备注",
    "更新时间",
    "自定义字段",
    "创建时间",
    "过期时间",
    "使用次数",
];

/// 一张工作表的原始数据。
pub struct Sheet {
    /// 表名（专辑名，或「全部」）。
    pub name: String,
    /// 表头。
    pub headers: Vec<&'static str>,
    /// 每行数据。
    pub rows: Vec<Vec<String>>,
}

/// 落盘之后把明文擦掉。
///
/// 这张表里全是明文（密码、密钥、备注）。写盘完就不再需要它了，
/// 但 `String` 被 drop 之后，那段堆内存里的字节还留着 ——
/// 全仓别处都在用 `SecretBytes` / `Zeroizing`，导出这一环不该是例外。
impl Drop for Sheet {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for row in &mut self.rows {
            for cell in row.iter_mut() {
                cell.zeroize();
            }
        }
    }
}

/// 把一个条目摊成一行。
pub fn entry_to_row(e: &Entry) -> Vec<String> {
    let kind = match e.kind {
        xz_core::entry::EntryKind::Login => "登录",
        xz_core::entry::EntryKind::ApiKey => "密钥",
        xz_core::entry::EntryKind::Note => "笔记",
        xz_core::entry::EntryKind::Card => "银行卡",
        xz_core::entry::EntryKind::Credential => "凭据",
    };
    vec![
        e.name.clone(),
        kind.to_owned(),
        e.username.clone(),
        e.secret.clone(),
        e.url.clone(),
        e.tags.join(", "),
        e.notes.clone(),
        fmt_ts(e.updated_at),
        encode_fields(&e.fields),
        fmt_ts(e.created_at),
        fmt_ts(e.expires_at),
        e.use_count.to_string(),
    ]
}

// ───────────────────── 自定义字段的编码 ─────────────────────

/// 把自定义字段编码成一列文本。
///
/// 形态：`name=value; name2=value2`，敏感字段名前加 `!`。
///
/// 为什么不能直接 `format!("{}={}", f.name, f.value).join("; ")`：
/// 值里本来就可能出现 `;`（多行私钥、连接串参数）和 `=`，
/// 直接拼出来的串再拆回去就不再是原来的东西了 —— 静默改数据比丢数据更坏。
/// 所以这里做最小转义：`\` → `\\`，`;` → `\;`，字段名里的 `=` → `\=`。
pub fn encode_fields(fields: &[Field]) -> String {
    let mut out = String::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        if f.secret {
            out.push('!');
        }
        for c in f.name.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                ';' => out.push_str("\\;"),
                '=' => out.push_str("\\="),
                c => out.push(c),
            }
        }
        out.push('=');
        for c in f.value.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                ';' => out.push_str("\\;"),
                c => out.push(c),
            }
        }
    }
    out
}

/// [`encode_fields`] 的逆运算。解不出来的段直接跳过，不猜。
pub fn decode_fields(raw: &str) -> Vec<Field> {
    // 这一列的内容来自表格，长度不受 `Entry::validate` 管（那时还没解析成
    // Entry 呢）。用户手滑粘进来一大段、或者有人递一个恶意 xlsx，
    // 底下就会分配上百万个 String。先按字符边界安全截断，再限段数。
    const MAX_RAW: usize = 1 << 20;
    const MAX_SEGMENTS: usize = 1024;

    let raw = if raw.len() > MAX_RAW {
        let mut end = MAX_RAW;
        while end > 0 && !raw.is_char_boundary(end) {
            end -= 1;
        }
        &raw[..end]
    } else {
        raw
    };

    let mut out = Vec::new();
    for seg in split_unescaped(raw, ';').into_iter().take(MAX_SEGMENTS) {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        // 敏感字段标记
        let (secret, body) = match seg.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, seg),
        };
        // 第一个未转义的 '=' 分隔名字和值
        let Some((name, value)) = split_first_unescaped_eq(body) else {
            continue;
        };
        let name = unescape(&name);
        if name.trim().is_empty() {
            continue;
        }
        out.push(Field {
            name,
            value: unescape(&value),
            secret,
        });
    }
    out
}

/// 按未转义的分隔符切段（转义符是 `\`）。
fn split_unescaped(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push('\\');
            cur.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == sep {
            out.push(std::mem::take(&mut cur));
            continue;
        }
        cur.push(c);
    }
    if escaped {
        cur.push('\\');
    }
    out.push(cur);
    out
}

fn split_first_unescaped_eq(s: &str) -> Option<(String, String)> {
    let mut name = String::new();
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            name.push('\\');
            name.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '=' {
            return Some((name, s[i + 1..].to_owned()));
        }
        name.push(c);
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        out.push(c);
    }
    if escaped {
        out.push('\\');
    }
    out
}

// ───────────────────────── 时间戳 ─────────────────────────

/// Unix 秒 → `YYYY-MM-DD HH:MM:SS`（UTC）。
///
/// 带秒是必须的：这张表要能被导回来，而 `created_at` / `updated_at`
/// 是「秒」精度。只写到时分会把时间四舍五入掉，往返一次就对不上了。
fn fmt_ts(ts: i64) -> String {
    if ts <= 0 {
        return String::new();
    }
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// `YYYY-MM-DD HH:MM[:SS]` → Unix 秒。解析不了返回 `None`。
fn parse_ts(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (date, time) = match s.split_once([' ', 'T']) {
        Some((d, t)) => (d, t),
        None => (s, ""),
    };
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.trim().parse().ok()?;
    let mo: u32 = dp.next()?.trim().parse().ok()?;
    let da: u32 = dp.next()?.trim().parse().ok()?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) {
        return None;
    }
    let mut tp = time.split(':');
    let hh: i64 = tp.next().map_or(Ok(0), |x| x.trim().parse()).ok()?;
    let mi: i64 = tp.next().map_or(Ok(0), |x| x.trim().parse()).ok()?;
    let ss: i64 = tp.next().map_or(Ok(0), |x| x.trim().parse()).ok()?;
    // 时分秒必须落在合法区间。以前只 parse 不校验，`2026-01-01 99:99:99`
    // 会被算成一个偏移好几天的时间戳 —— 导入是恢复路径，时间算错就是数据错。
    if !(0..=23).contains(&hh) || !(0..=59).contains(&mi) || !(0..=59).contains(&ss) {
        return None;
    }
    let days = days_from_civil(y, mo, da);
    Some(days * 86_400 + hh * 3600 + mi * 60 + ss)
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

/// [`civil_from_days`] 的逆运算。
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mm = u64::from(m);
    let doy = (153 * (if mm > 2 { mm - 3 } else { mm + 9 }) + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

// ───────────────────────── 写出 ─────────────────────────

/// 把若干张表写成一个 xlsx 文件。
///
/// 失败时会把半截文件删掉：留一个内容不完整、但仍然含密码的 `.xlsx`，
/// 比直接失败更糟 —— 用户会以为导出成功了。
pub fn write_xlsx(path: &std::path::Path, sheets: &[Sheet]) -> Result<(), String> {
    let result = (|| -> Result<(), String> {
        let file = std::fs::File::create(path).map_err(|e| format!("建不了文件：{e}"))?;
        write_xlsx_to(std::io::BufWriter::new(file), sheets)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// 把若干张表写进内存，返回完整的 xlsx 字节。
///
/// 给「加密备份」用：先在这里拿到明文表格，再在 `backup::seal` 里整体加密，
/// 磁盘上从头到尾不出现明文。
pub fn write_xlsx_bytes(sheets: &[Sheet]) -> Result<Vec<u8>, String> {
    let mut sink = std::io::Cursor::new(Vec::new());
    write_xlsx_to(&mut sink, sheets)?;
    Ok(sink.into_inner())
}

fn write_xlsx_to<W: std::io::Write + std::io::Seek>(
    sink: W,
    sheets: &[Sheet],
) -> Result<(), String> {
    if sheets.is_empty() {
        return Err("没有可导出的内容".to_owned());
    }

    let mut zip = zip::ZipWriter::new(sink);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let put = |zip: &mut zip::ZipWriter<W>, name: &str, data: &str| -> Result<(), String> {
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

/// Excel 列名（`AB12` 里的 `AB`）→ 列序号。
fn col_index(reference: &str) -> Option<usize> {
    let mut n: usize = 0;
    let mut any = false;
    for c in reference.chars() {
        let u = c.to_ascii_uppercase();
        if u.is_ascii_uppercase() {
            n = n * 26 + (u as usize - 'A' as usize + 1);
            any = true;
        } else {
            break;
        }
    }
    // Excel 的列上限是 16384（XFD）。超过这个值只可能来自畸形文件。
    if any && n <= 16_384 {
        Some(n - 1)
    } else {
        None
    }
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

/// 从 xlsx 读回来的一行条目。
pub struct ImportedRow {
    /// 原始行号（Excel 里的行号，用于报错定位）。
    pub row_number: usize,
    /// 解析好的条目字段。
    pub entry: ParsedRow,
}

/// 从 xlsx 读回来的一张表。
pub struct ImportedSheet {
    /// 工作表名（即专辑名）。
    pub name: String,
    /// 数据行（不含表头）。
    pub rows: Vec<ImportedRow>,
    /// 表里没能解析成条目的行数（名称列为空）。
    ///
    /// 单独计数而不是默默丢掉：导入是恢复路径，用户需要知道
    /// 「有 3 行读不进来」，而不是只看到一个比预期小的数字。
    pub skipped: usize,
}

/// 读取 xlsx 文件。
///
/// 只要有一张表能按表头认出「名称」列就收下；认不出的表整张跳过 ——
/// 不去猜列序，猜错会把密码塞进用户名。
pub fn read_xlsx(path: &std::path::Path) -> Result<Vec<ImportedSheet>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("打不开文件：{e}"))?;
    read_xlsx_from(file)
}

/// 从内存里的 xlsx 字节读取（加密备份解出来之后走这条）。
pub fn read_xlsx_bytes(bytes: &[u8]) -> Result<Vec<ImportedSheet>, String> {
    read_xlsx_from(std::io::Cursor::new(bytes))
}

fn read_xlsx_from<R: std::io::Read + std::io::Seek>(
    reader: R,
) -> Result<Vec<ImportedSheet>, String> {
    let mut zip =
        zip::ZipArchive::new(reader).map_err(|e| format!("这不是有效的 Excel 文件：{e}"))?;

    // Excel 重新保存过的文件会把字符串挪进共享字符串表。
    let shared = read_shared_strings(&mut zip);
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
        let mut rows = parse_sheet_xml(&xml, &shared);
        if rows.is_empty() {
            continue;
        }
        // 首行是表头，按**名字**建列映射
        let head = rows.remove(0);
        let Some(cols) = Columns::from_header(&head) else {
            continue;
        };

        let mut parsed = Vec::new();
        let mut skipped = 0usize;
        for (ri, row) in rows.iter().enumerate() {
            // 整行都是空的（Excel 常见的尾部空行）就跳过，不算「跳过了一条」
            if row.iter().all(|c| c.as_deref().is_none_or(str::is_empty)) {
                continue;
            }
            match cols.to_entry(row, name) {
                Some(p) => parsed.push(ImportedRow {
                    row_number: ri + 2,
                    entry: p,
                }),
                None => skipped += 1,
            }
        }
        if !parsed.is_empty() || skipped > 0 {
            out.push(ImportedSheet {
                name: name.clone(),
                rows: parsed,
                skipped,
            });
        }
    }

    if out.is_empty() {
        return Err(
            "文件里没有可以导入的表。每张工作表的第一行必须包含「名称」列；\
             完整的表头是：名称 / 类型 / 账号 / 密码 / 网址 / 专辑 / 备注 / \
             更新时间 / 自定义字段 / 创建时间 / 过期时间 / 使用次数"
                .to_owned(),
        );
    }
    Ok(out)
}

/// 表头 → 每一列的列序号。
///
/// 用名字对位而不是位置对位：列被拖动过、中间插了一列手写批注、
/// 或者文件是老版本导出的少三列，都能读。
struct Columns {
    name: usize,
    kind: Option<usize>,
    username: Option<usize>,
    secret: Option<usize>,
    url: Option<usize>,
    tags: Option<usize>,
    notes: Option<usize>,
    updated_at: Option<usize>,
    fields: Option<usize>,
    created_at: Option<usize>,
    expires_at: Option<usize>,
    use_count: Option<usize>,
}

/// 表头的归一化：去掉空白和分隔符、转小写。
///
/// 这样「密码 / 密钥」「密码/密钥」「密码」都能对上同一列 —— 用户手改
/// 表头（把单位、斜杠删掉）是很常见的动作。
fn header_key(h: &str) -> String {
    h.chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '/' | '\\' | '／' | '|' | '·'))
        .flat_map(char::to_lowercase)
        .collect()
}

impl Columns {
    fn from_header(head: &[Option<String>]) -> Option<Self> {
        let find = |cands: &[&str]| -> Option<usize> {
            head.iter().position(|h| {
                h.as_deref()
                    .map(|h| cands.iter().any(|c| header_key(h) == header_key(c)))
                    .unwrap_or(false)
            })
        };

        // 「名称」是唯一必需的列。没有它这张表就不是我们导出的东西。
        let name = find(&["名称", "标题", "条目名称", "name"])?;

        let cols = Self {
            name,
            kind: find(&["类型", "kind"]),
            username: find(&["账号", "用户名", "账户", "username"]),
            secret: find(&["密码 / 密钥", "密码密钥", "密码", "密钥", "secret", "password"]),
            url: find(&["网址", "地址", "url"]),
            tags: find(&["专辑", "标签", "分类", "tags"]),
            notes: find(&["备注", "说明", "notes"]),
            updated_at: find(&["更新时间", "修改时间", "updated_at"]),
            fields: find(&["自定义字段", "附加字段", "字段", "fields"]),
            created_at: find(&["创建时间", "created_at"]),
            expires_at: find(&["过期时间", "到期时间", "expires_at"]),
            use_count: find(&["使用次数", "使用计数", "use_count"]),
        };

        // 至少要认出 3 列才认为这是我们的格式。只命中一个「名称」列的话，
        // 任何一张带标题栏的表格都会被当成密钥库。
        let matched = 1
            + [
                cols.kind,
                cols.username,
                cols.secret,
                cols.url,
                cols.tags,
                cols.notes,
                cols.updated_at,
                cols.fields,
            ]
            .iter()
            .filter(|c| c.is_some())
            .count();
        if matched < 3 {
            return None;
        }
        Some(cols)
    }

    fn to_entry(&self, row: &[Option<String>], sheet_name: &str) -> Option<ParsedRow> {
        let get = |i: Option<usize>| -> String {
            i.and_then(|i| row.get(i))
                .and_then(|c| c.clone())
                .unwrap_or_default()
        };
        let get_req = |i: usize| -> String { row.get(i).and_then(|c| c.clone()).unwrap_or_default() };

        let name = get_req(self.name);
        if name.trim().is_empty() {
            return None;
        }

        let kind = match get(self.kind).trim() {
            "登录" => xz_core::entry::EntryKind::Login,
            "密钥" => xz_core::entry::EntryKind::ApiKey,
            "笔记" => xz_core::entry::EntryKind::Note,
            "银行卡" => xz_core::entry::EntryKind::Card,
            "凭据" => xz_core::entry::EntryKind::Credential,
            _ => xz_core::entry::EntryKind::Login,
        };

        // 专辑列和所属工作表都算来源，合并去重。
        //
        // 分隔符认逗号、分号、中文顿号 —— 用户手写表格时这三种都用得上。
        // **不把 `/` 当分隔符**：`CI/CD`、`dev/ops` 这类标签是单个词，
        // 拆开就等于改数据。
        let raw_tags: Vec<String> = get(self.tags)
            .split([',', ';', '、'])
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect();
        let mut seen = std::collections::HashSet::new();
        let mut tags: Vec<String> = raw_tags
            .into_iter()
            .filter(|t| seen.insert(t.clone()))
            .collect();
        if sheet_name != "全部" && !tags.iter().any(|t| t == sheet_name) {
            tags.push(sheet_name.to_owned());
        }

        // 自定义字段里名字非法的（空名、超长）单独剔掉，不让一条脏字段
        // 把整个条目挡在 validate 外面 —— 那等于导入时悄悄少一条记录。
        let mut fields = decode_fields(&get(self.fields));
        fields.retain(|f| !f.name.trim().is_empty() && f.name.len() <= 128);
        fields.truncate(512);

        Some(ParsedRow {
            name: name.trim().to_owned(),
            kind,
            username: get(self.username),
            secret: get(self.secret),
            url: get(self.url),
            tags,
            notes: get(self.notes),
            fields,
            created_at: parse_ts(&get(self.created_at)).unwrap_or(0),
            updated_at: parse_ts(&get(self.updated_at)).unwrap_or(0),
            expires_at: parse_ts(&get(self.expires_at)).unwrap_or(0),
            use_count: get(self.use_count).trim().parse().unwrap_or(0),
        })
    }
}

fn read_entry<R: std::io::Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    name: &str,
) -> Result<String, String> {
    use std::io::Read as _;

    /// 单个 zip 成员解压后的上限。
    ///
    /// xlsx 是个 zip：一个几 KB 的文件完全可以声明「解压后 10 GB」，
    /// 而 `read_to_string` 会老老实实往内存里塞 —— 这是最省事的拒绝服务。
    /// 正常库的每张表远小于这个数（一万条大约几 MB）。
    const MAX_PART_BYTES: u64 = 64 << 20;

    let mut f = zip.by_name(name).map_err(|e| e.to_string())?;
    // zip 头里声明的大小，先看一眼
    if f.size() > MAX_PART_BYTES {
        return Err(format!(
            "「{name}」解压后超过 {} MiB，拒绝读取",
            MAX_PART_BYTES >> 20
        ));
    }
    let mut s = String::new();
    // 声明值也可能撒谎，所以读取时再套一层 take 硬上限。
    f.by_ref()
        .take(MAX_PART_BYTES + 1)
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    if s.len() as u64 > MAX_PART_BYTES {
        return Err(format!("「{name}」超过 {} MiB，拒绝读取", MAX_PART_BYTES >> 20));
    }
    Ok(s)
}

/// 读共享字符串表。文件里没有（我们自己导出的就没有）时返回空。
fn read_shared_strings<R: std::io::Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
) -> Vec<String> {
    let Ok(xml) = read_entry(zip, "xl/sharedStrings.xml") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut rest = xml.as_str();
    while let Some(p) = rest.find("<si") {
        let after = &rest[p..];
        let Some(gt) = after.find('>') else { break };
        // <si/> 空串
        if after[..gt].trim_end().ends_with('/') {
            out.push(String::new());
            rest = &after[gt + 1..];
            continue;
        }
        let body = &after[gt + 1..];
        let Some(cp) = body.find("</si>") else { break };
        // 富文本会被拆成多个 <r><t>…</t></r>，拼起来
        let mut s = String::new();
        let mut inner = &body[..cp];
        while let Some(tp) = inner.find("<t") {
            let ta = &inner[tp..];
            let Some(tgt) = ta.find('>') else { break };
            let tb = &ta[tgt + 1..];
            let Some(tcp) = tb.find("</t>") else { break };
            s.push_str(&xml_unescape(&tb[..tcp]));
            inner = &tb[tcp + 4..];
        }
        out.push(s);
        rest = &body[cp + 5..];
    }
    out
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
    // 属性要么在开头，要么前面有个空格。先试带空格的，避免
    // `data-name="x"` 被当成 `name`。
    let start = match tag.find(&format!(" {pat}")) {
        Some(p) => p + 1 + pat.len(),
        None => {
            let trimmed = tag.trim_start();
            if !trimmed.starts_with(&pat) {
                return None;
            }
            let p = tag.len() - trimmed.len();
            p + pat.len()
        }
    };
    let rest = tag.get(start..)?;
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// 把一张表的 XML 解析成「按列序号定位」的二维格。
///
/// 关键点：**不信出现顺序，只信每个单元格自己的地址**（`<c r="C7">` 里的 `C`）。
/// Excel 省略空单元格是标准行为，按顺序读会让整行左移 —— 表现为
/// 「密码跑到网址列」，而且表头行是完整的，校验根本挡不住。
fn parse_sheet_xml(xml: &str, shared: &[String]) -> Vec<Vec<Option<String>>> {
    let mut rows: Vec<Vec<Option<String>>> = Vec::new();
    let mut rest = xml;

    while let Some(op) = rest.find("<row ") {
        let after = &rest[op + 5..];
        let Some(gt) = after.find('>') else { break };
        let self_closing = after[..gt].trim_end().ends_with('/');
        if self_closing {
            rows.push(Vec::new());
            rest = &after[gt + 1..];
            continue;
        }
        let body = &after[gt + 1..];
        let Some(cp) = body.find("</row>") else { break };
        rows.push(parse_row_cells(&body[..cp], shared));
        rest = &body[cp + 6..];
    }
    rows
}

fn parse_row_cells(inner: &str, shared: &[String]) -> Vec<Option<String>> {
    let mut cells: Vec<Option<String>> = Vec::new();
    let mut rest = inner;
    // 没有 r 属性的单元格（罕见，但 Excel 允许省略）按「上一个 +1」推算
    let mut next_col = 0usize;

    while let Some(p) = rest.find("<c") {
        let after = &rest[p + 2..];
        // 下一个字符必须是空白或 '/' 或 '>'，否则是 <cols> 之类的别的标签
        match after.chars().next() {
            Some(' ') | Some('>') | Some('/') => {}
            _ => {
                rest = after;
                continue;
            }
        }
        let Some(gt) = after.find('>') else { break };
        let tag = &after[..gt];
        let self_closing = tag.trim_end().ends_with('/');

        let col = attr(tag, "r")
            .as_deref()
            .and_then(col_index)
            .unwrap_or(next_col);

        if self_closing {
            rest = &after[gt + 1..];
        } else {
            let body = &after[gt + 1..];
            let Some(cp) = body.find("</c>") else { break };
            let v = cell_value(tag, &body[..cp], shared);
            put_cell(&mut cells, col, v);
            rest = &body[cp + 4..];
        }
        next_col = col.saturating_add(1);
    }
    cells
}

fn put_cell(cells: &mut Vec<Option<String>>, i: usize, v: String) {
    if cells.len() <= i {
        cells.resize(i + 1, None);
    }
    // 空串等价于「这一格没有内容」，省得导出时多写一堆空标签
    cells[i] = if v.is_empty() { None } else { Some(v) };
}

/// 取一个单元格的文本。
///
/// 照顾四种形态：
/// - `t="inlineStr"` —— 我们自己写出的形态，正文在 `<is><t>`
/// - `t="s"` —— Excel 重新保存后的形态，正文是共享字符串表的下标
/// - 无 `t` / `t="n"` —— 数字，正文在 `<v>`
/// - `t="str"` —— 公式结果
fn cell_value(tag: &str, inner: &str, shared: &[String]) -> String {
    let kind = attr(tag, "t");
    let numeric = between(inner, "<v", "</v>");

    match kind.as_deref() {
        Some("s") => numeric
            .and_then(|i| i.trim().parse::<usize>().ok())
            .and_then(|i| shared.get(i).cloned())
            .unwrap_or_default(),
        Some("inlineStr") => text_runs(inner),
        Some("b") => match numeric.as_deref().map(str::trim) {
            Some("1") => "TRUE".to_owned(),
            Some("0") | None => "FALSE".to_owned(),
            Some(other) => other.to_owned(),
        },
        // t="str" / t="e" / 数字 / 无类型：正文都在 <v> 里
        _ => match numeric {
            Some(v) => xml_unescape(&v),
            None => text_runs(inner),
        },
    }
}

/// 把一段 XML 里所有 `<t>…</t>` 的文本拼起来（富文本会被拆成好几段）。
fn text_runs(inner: &str) -> String {
    let mut out = String::new();
    let mut rest = inner;
    while let Some(p) = rest.find("<t") {
        let after = &rest[p..];
        let Some(gt) = after.find('>') else { break };
        let body = &after[gt + 1..];
        let Some(cp) = body.find("</t>") else { break };
        out.push_str(&xml_unescape(&body[..cp]));
        rest = &body[cp + 4..];
    }
    out
}

/// 取 `<open …>内容</close>` 里的内容（open 不含 `>`）。
fn between(src: &str, open: &str, close: &str) -> Option<String> {
    let p = src.find(open)?;
    let after = &src[p..];
    let gt = after.find('>')?;
    let body = &after[gt + 1..];
    let cp = body.find(close)?;
    Some(body[..cp].to_owned())
}

fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < s.len() {
        if s.as_bytes()[i] == b'&' {
            // 实体最长也就 `&#x10FFFF;`（10 字符），限长避免把很远处的
            // 分号误当成实体结尾。
            if let Some(end) = s[i..].find(';').filter(|&e| e <= 12) {
                let body = &s[i + 1..i + end];
                let ch = if let Some(rest) = body.strip_prefix('#') {
                    let code = match rest.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok(),
                        None => rest.parse::<u32>().ok(),
                    };
                    code.and_then(char::from_u32)
                } else {
                    match body {
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        "amp" => Some('&'),
                        _ => None,
                    }
                };
                if let Some(c) = ch {
                    out.push(c);
                    i += end + 1;
                    continue;
                }
            }
        }
        let ch = s[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// 一行数据还原成的完整条目字段。
///
/// 和 [`Entry`] 的区别：这里没有 `id`（导入时重新生成），时间戳缺了用 0 表示
/// 「文件里没写」，由调用方决定补什么默认值。
#[derive(Clone)]
pub struct ParsedRow {
    pub name: String,
    pub kind: xz_core::entry::EntryKind,
    pub username: String,
    pub secret: String,
    pub url: String,
    pub tags: Vec<String>,
    pub notes: String,
    pub fields: Vec<Field>,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
    pub use_count: u32,
}

impl ParsedRow {
    /// 还原成一条可入库的 [`Entry`]。
    ///
    /// `fallback_ts` 用在文件里没写时间的情况下（手工新建的表格）。
    /// 恢复逻辑集中在这里而不是散在命令层：只有一处，才能被单测覆盖。
    #[must_use]
    pub fn into_entry(self, id: String, fallback_ts: i64) -> Entry {
        let created = if self.created_at > 0 {
            self.created_at
        } else {
            fallback_ts
        };
        let updated = if self.updated_at > 0 {
            self.updated_at
        } else {
            created
        };
        Entry {
            id,
            kind: self.kind,
            name: self.name,
            username: self.username,
            secret: self.secret,
            url: self.url,
            fields: self.fields,
            tags: self.tags,
            notes: self.notes,
            created_at: created,
            updated_at: updated,
            expires_at: self.expires_at,
            use_count: self.use_count,
            // 最后使用时间不进表格（它是热榜的次要排序键，重导入后
            // 热度会按 use_count 重新排），这里老实置 0。
            last_used_at: 0,
        }
    }
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
    fn col_index_parses_references() {
        assert_eq!(super::col_index("A1"), Some(0));
        assert_eq!(super::col_index("Z9"), Some(25));
        assert_eq!(super::col_index("AA100"), Some(26));
        assert_eq!(super::col_index("AB"), Some(27));
        assert_eq!(super::col_index("9"), None);
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

    /// 标准 XML 工具会把非 ASCII 写成数字字符引用（`&#21517;`）。
    /// openpyxl / LibreOffice / 部分版本的 Excel 都这么干 —— 不认它，
    /// 那些工具保存过的表格会整张读成乱码，然后「表头认不出来」。
    #[test]
    fn numeric_char_refs_are_decoded() {
        assert_eq!(super::xml_unescape("&#21517;&#31216;"), "名称");
        assert_eq!(super::xml_unescape("&#x540D;&#x79F0;"), "名称");
        assert_eq!(super::xml_unescape("a&amp;b&lt;c&gt;d"), "a&b<c>d");
        // 不是实体的 & 原样保留
        assert_eq!(super::xml_unescape("a & b"), "a & b");
        assert_eq!(super::xml_unescape("&unknown;x"), "&unknown;x");
        // 无分号的裸 & 不能把后面的内容吃掉
        assert_eq!(super::xml_unescape("&abc"), "&abc");
    }

    #[test]
    fn timestamp_roundtrip() {
        for ts in [0i64, 1, 1_700_000_000, 4_102_444_800, 2_000_000_000] {
            let s = super::fmt_ts(ts);
            if ts <= 0 {
                assert_eq!(s, "");
                continue;
            }
            assert_eq!(super::parse_ts(&s), Some(ts), "ts={ts} s={s}");
        }
    }

    #[test]
    fn field_encoding_roundtrip() {
        use xz_core::entry::Field;
        let fields = vec![
            Field::plain("Region", "cn-north-1"),
            Field::secret("刷新令牌", "a=b;c"),
            Field::plain("路径\\带反斜杠", "C:\\x;y"),
        ];
        let enc = super::encode_fields(&fields);
        let back = super::decode_fields(&enc);
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].name, "Region");
        assert_eq!(back[0].value, "cn-north-1");
        assert!(!back[0].secret);
        assert_eq!(back[1].name, "刷新令牌");
        assert_eq!(back[1].value, "a=b;c");
        assert!(back[1].secret, "敏感标记必须还原");
        assert_eq!(back[2].name, "路径\\带反斜杠");
        assert_eq!(back[2].value, "C:\\x;y");
    }

    fn sample_entry() -> xz_core::entry::Entry {
        use xz_core::entry::{Entry, EntryKind, Field};
        Entry {
            id: "abc".into(),
            kind: EntryKind::ApiKey,
            name: "测试条目".into(),
            username: "user@example.com".into(),
            secret: "sk-test-123".into(),
            url: "https://example.com".into(),
            fields: vec![
                Field::secret("刷新令牌", "rt=1;2"),
                Field::plain("Region", "cn-north-1"),
            ],
            tags: vec!["prod".into(), "api".into()],
            notes: "含特殊字符 <>&\"'".into(),
            created_at: 1_600_000_000,
            updated_at: 1_700_000_000,
            expires_at: 1_800_000_000,
            use_count: 7,
            last_used_at: 1_700_000_100,
        }
    }

    /// 给每个测试单独一个临时目录。
    ///
    /// 以前是按 `process::id()` 拼目录名 —— 同一个进程里所有测试拿到的是
    /// **同一个**目录，而 cargo test 默认并行跑。两个同时做导入导出往返的
    /// 测试会互相覆盖 `roundtrip.xlsx`、其中一个还会把目录删掉，
    /// 表现是「偶尔红一次，重跑就过」。加上自增序号把名字拆开。
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "xz-test-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_and_read(e: &xz_core::entry::Entry) -> super::ParsedRow {
        let sheet = super::Sheet {
            name: "prod".into(),
            headers: super::HEADERS.to_vec(),
            rows: vec![super::entry_to_row(e)],
        };
        let dir = temp_dir("roundtrip");
        let path = dir.join("roundtrip.xlsx");
        super::write_xlsx(&path, &[sheet]).unwrap();
        let mut back = super::read_xlsx(&path).unwrap();
        assert_eq!(back.len(), 1, "应该读回一张表");
        assert_eq!(back[0].name, "prod");
        assert_eq!(back[0].rows.len(), 1);
        let row = back.remove(0).rows.remove(0).entry;
        let _ = std::fs::remove_dir_all(&dir);
        row
    }

    /// 写出去再读回来，**每一个字段**都必须一模一样。
    ///
    /// 这是「导出即灾备」这句话的验证点：只要有一列在往返里丢了，
    /// 换机器之后那条数据就是残的。
    #[test]
    fn roundtrip_preserves_every_field() {
        let e = sample_entry();
        let p = write_and_read(&e);

        assert_eq!(p.name, "测试条目");
        assert_eq!(p.username, "user@example.com");
        assert_eq!(p.secret, "sk-test-123");
        assert_eq!(p.url, "https://example.com");
        assert_eq!(p.kind, xz_core::entry::EntryKind::ApiKey);
        // 特殊字符必须原样回来（这是 XML 转义最容易漏的地方）
        assert_eq!(p.notes, "含特殊字符 <>&\"'");
        // 专辑
        assert!(p.tags.contains(&"prod".to_owned()));
        assert!(p.tags.contains(&"api".to_owned()));
        // 自定义字段（含敏感标记）
        assert_eq!(p.fields.len(), 2);
        assert_eq!(p.fields[0].name, "刷新令牌");
        assert_eq!(p.fields[0].value, "rt=1;2");
        assert!(p.fields[0].secret, "敏感标记必须还原");
        assert_eq!(p.fields[1].name, "Region");
        assert_eq!(p.fields[1].value, "cn-north-1");
        assert!(!p.fields[1].secret);
        // 时间与计数
        assert_eq!(p.created_at, 1_600_000_000);
        assert_eq!(p.updated_at, 1_700_000_000);
        assert_eq!(p.expires_at, 1_800_000_000);
        assert_eq!(p.use_count, 7);
    }

    /// 端到端：条目 → 表格 → 条目，`Entry` 层的每个字段都要相等。
    ///
    /// 这一条直接对应「换机器之后导入回来的东西是完整的」。
    #[test]
    fn entry_survives_export_then_import() {
        let before = sample_entry();
        let after = write_and_read(&before).into_entry("new-id".into(), 42);

        assert_eq!(after.name, before.name);
        assert_eq!(after.kind, before.kind);
        assert_eq!(after.username, before.username);
        assert_eq!(after.secret, before.secret);
        assert_eq!(after.url, before.url);
        assert_eq!(after.notes, before.notes);
        assert_eq!(after.created_at, before.created_at);
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.expires_at, before.expires_at);
        assert_eq!(after.use_count, before.use_count);
        assert_eq!(after.fields.len(), before.fields.len());
        for (a, b) in after.fields.iter().zip(before.fields.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.value, b.value);
            assert_eq!(a.secret, b.secret);
        }
        assert_eq!(after.tags, before.tags);
        // 新库里 id 是重新生成的
        assert_eq!(after.id, "new-id");
    }

    /// 表头不对时必须跳过整张表，而不是把数据硬塞进去。
    #[test]
    fn wrong_header_is_rejected() {
        let dir = temp_dir("bad-header");
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

    /// 用户用 Excel 打开、清空一格再保存：那一格会被整个省略。
    /// 按出现顺序读会左移，按 `r` 地址读才对得上。
    #[test]
    fn omitted_empty_cells_do_not_shift_columns() {
        let xml = r#"<?xml version="1.0"?><worksheet><sheetData>
<row r="1">
<c r="A1" t="inlineStr"><is><t>名称</t></is></c>
<c r="B1" t="inlineStr"><is><t>类型</t></is></c>
<c r="C1" t="inlineStr"><is><t>账号</t></is></c>
<c r="D1" t="inlineStr"><is><t>密码 / 密钥</t></is></c>
<c r="E1" t="inlineStr"><is><t>网址</t></is></c>
</row>
<row r="2">
<c r="A2" t="inlineStr"><is><t>GitHub</t></is></c>
<c r="B2" t="inlineStr"><is><t>登录</t></is></c>
<c r="E2" t="inlineStr"><is><t>https://github.com</t></is></c>
</row>
</sheetData></worksheet>"#;

        let rows = super::parse_sheet_xml(xml, &[]);
        assert_eq!(rows.len(), 2);
        let head = &rows[0];
        let cols = super::Columns::from_header(head).expect("表头应该能认出来");
        let p = cols.to_entry(&rows[1], "全部").expect("这条应该能解析");

        assert_eq!(p.name, "GitHub");
        // 账号和密码两格被省略了 —— 必须还落在各自的列里，不能挪位
        assert_eq!(p.username, "");
        assert_eq!(p.secret, "");
        assert_eq!(p.url, "https://github.com", "网址不能跑到密码列里去");
    }

    /// Excel 重新保存后字符串会进 sharedStrings 表，正文变成 <v> 下标。
    #[test]
    fn shared_strings_are_understood() {
        let shared = vec![
            "名称".to_owned(),
            "账号".to_owned(),
            "密码 / 密钥".to_owned(),
            "测试".to_owned(),
            "me".to_owned(),
            "hunter2".to_owned(),
        ];
        let xml = r#"<worksheet><sheetData>
<row r="1">
<c r="A1" t="s"><v>0</v></c>
<c r="B1" t="s"><v>1</v></c>
<c r="C1" t="s"><v>2</v></c>
</row>
<row r="2">
<c r="A2" t="s"><v>3</v></c>
<c r="B2" t="s"><v>4</v></c>
<c r="C2" t="s"><v>5</v></c>
</row>
</sheetData></worksheet>"#;

        let rows = super::parse_sheet_xml(xml, &shared);
        let cols = super::Columns::from_header(&rows[0]).expect("表头应该能认出来");
        let p = cols.to_entry(&rows[1], "全部").unwrap();
        assert_eq!(p.name, "测试");
        assert_eq!(p.username, "me");
        assert_eq!(p.secret, "hunter2");
    }

    /// 只认出「名称」一列的表格不能被当成密钥库。
    #[test]
    fn a_mere_name_column_is_not_enough() {
        let head = vec![Some("名称".to_owned())];
        assert!(super::Columns::from_header(&head).is_none());
    }

    /// 标签按逗号 / 分号 / 顿号拆，但 `/` 是词内字符，不能拆。
    #[test]
    fn tag_separators_keep_slash_words_intact() {
        let head = vec![
            Some("名称".to_owned()),
            Some("账号".to_owned()),
            Some("专辑".to_owned()),
        ];
        let cols = super::Columns::from_header(&head).expect("三列足够认出来");
        let row = vec![
            Some("x".to_owned()),
            Some("u".to_owned()),
            Some("CI/CD, prod; api、infra, prod".to_owned()),
        ];
        let p = cols.to_entry(&row, "全部").unwrap();
        assert_eq!(p.tags, vec!["CI/CD", "prod", "api", "infra"]);
    }

    /// 自定义字段列的内容不受 `Entry::validate` 约束，必须自己设上界。
    #[test]
    fn decode_fields_caps_absurd_input() {
        // 1.2 MB、20 万段
        let huge = "a=1; ".repeat(200_000);
        let out = super::decode_fields(&huge);
        assert!(
            out.len() <= 1024,
            "段数必须有上界，实际 {}",
            out.len()
        );
        assert!(!out.is_empty(), "截断后仍应解出字段");
    }
}

    /// 手写的表格解析器直接吃不可信输入。这里喂各种畸形 XML，
    /// 要求只有一个：**不许 panic**，要么给出结果、要么跳过。
    ///
    /// 为什么值得专门测：`parse_sheet_xml` 是全部外部输入里唯一一个
    /// 「自己解析结构化文本」的地方，其余路径都是 serde 或定长字段。
    /// 它不解析 DTD / 实体声明，所以没有实体扩展面；剩下要守的就是越界。
    #[test]
    fn malformed_sheet_xml_never_panics() {
        let shared: Vec<String> = vec!["甲".into(), "乙".into()];
        let cases: Vec<&str> = vec![
            "",
            "<worksheet>",
            "<worksheet/>",
            "<worksheet></worksheet>",
            "<worksheet><sheetData></sheetData></worksheet>",
            // 缺 r 属性
            "<worksheet><sheetData><row><c><v>1</v></c></row></sheetData></worksheet>",
            // r 属性为空
            "<worksheet><sheetData><row><c r=\"\"><v>1</v></c></row></sheetData></worksheet>",
            // r 只有列字母、没有行号
            "<worksheet><sheetData><row><c r=\"A\"><v>1</v></c></row></sheetData></worksheet>",
            // 行号极大
            "<worksheet><sheetData><row r=\"999999999999999999999\"><c r=\"A1\"><v>1</v></c></row></sheetData></worksheet>",
            // 列字母极长
            "<worksheet><sheetData><row><c r=\"AAAAAAA999999999\"><v>1</v></c></row></sheetData></worksheet>",
            // 共享字符串索引越界
            "<worksheet><sheetData><row><c r=\"A1\" t=\"s\"><v>99999</v></c></row></sheetData></worksheet>",
            // 共享字符串索引是垃圾
            "<worksheet><sheetData><row><c r=\"A1\" t=\"s\"><v>abc</v></c></row></sheetData></worksheet>",
            // 负索引
            "<worksheet><sheetData><row><c r=\"A1\" t=\"s\"><v>-1</v></c></row></sheetData></worksheet>",
            // 未闭合的 c 与 v
            "<worksheet><sheetData><row><c r=\"A1\"><v>1</worksheet>",
            // 嵌套但没闭合
            "<worksheet><sheetData><row><c r=\"A1\"><is><t>x</is></c></row>",
            // 自闭合的 c
            "<worksheet><sheetData><row><c r=\"A1\"/></row></sheetData></worksheet>",
            // 只声明没内容
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            // 数字字符引用残缺
            "<worksheet><sheetData><row><c r=\"A1\" t=\"inlineStr\"><is><t>&#xZZ;</t></is></c></row></sheetData></worksheet>",
            // 双 NUL 与裸标记
            "\u{0}\u{0}<row><c r=\"A1\"><v>1</v></c>",
        ];
        for xml in cases {
            // 崩了就是 bug；返回空表是允许的
            let _ = parse_sheet_xml(xml, &shared);
        }
    }

    /// `xml_unescape` 同样吃不可信输入，必须只返回字符串。
    #[test]
    fn xml_unescape_handles_broken_references() {
        for s in [
            "",
            "&",
            "&;",
            "&#;",
            "&#x;",
            "&#xZZ;",
            "&#99999999;",
            "&#xFFFFFFFF;",
            "&&amp;",
            "&amp",
            "<>&\"'",
        ] {
            let _ = xml_unescape(s);
        }
        // 正常路径仍要正确
        assert_eq!(xml_unescape("&amp;&lt;&gt;&quot;&apos;"), "&<>\"'");
        assert_eq!(xml_unescape("&#65;&#x42;"), "AB");
    }

    /// 自定义字段的转义必须能原样往返，包括分隔符本身出现在值里的情况。
    #[test]
    fn custom_field_escaping_round_trips() {
        let cases = [
            vec![("bucket".to_string(), "my-bucket".to_string(), false)],
            vec![("a".to_string(), "x;y".to_string(), false)],
            vec![("a".to_string(), "x\\y".to_string(), false)],
            vec![("a".to_string(), "x=y".to_string(), false)],
            vec![("a=b".to_string(), "v".to_string(), false)],
            vec![
                ("k1".to_string(), "v1".to_string(), false),
                ("k2".to_string(), ";\\=".to_string(), true),
            ],
        ];
        for fields in cases {
            let fields: Vec<Field> = fields
                .into_iter()
                .map(|(name, value, secret)| Field {
                    name,
                    value,
                    secret,
                })
                .collect();
            let encoded = encode_fields(&fields);
            let decoded = decode_fields(&encoded);
            assert_eq!(decoded.len(), fields.len(), "编码后解码数量不符: {encoded}");
            for (a, b) in fields.iter().zip(decoded.iter()) {
                assert_eq!(a.name, b.name, "字段名往返不一致: {encoded}");
                assert_eq!(a.value, b.value, "字段值往返不一致: {encoded}");
                assert_eq!(a.secret, b.secret, "敏感标记往返不一致: {encoded}");
            }
        }
    }