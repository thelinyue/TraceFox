use crate::{
    extract::{self, Table},
    rules::{Matcher, Rule, RuleSet},
};
use anyhow::{Context, Result, bail};
use flate2::read::MultiGzDecoder;
use regex::Regex;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug, Serialize)]
pub struct LogLine {
    pub number: usize,
    pub text: String,
    pub hit: bool,
    pub ranges: Vec<(usize, usize)>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Fragment {
    pub file: String,
    pub lines: Vec<LogLine>,
    pub time: String,
    pub annotation: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub rule: Rule,
    pub count: usize,
    pub fragments: Vec<Fragment>,
    pub status: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub name: String,
    pub group: String,
    pub time: String,
    pub key: Option<String>,
    pub note: String,
    pub sources: Vec<Fragment>,
}
#[derive(Serialize)]
pub struct Report {
    pub package: String,
    pub generated: String,
    pub layout: crate::rules::Layout,
    pub system: Vec<Table>,
    pub findings: Vec<Finding>,
    pub events: Vec<Event>,
    pub warnings: Vec<String>,
}
/// 报告每条规则只内嵌前 500 个命中（沿用报告排序），扫描和总数保持完整。
/// 截断发生在时间线证据组装之后，不影响时间线；最后一个保留命中的
/// 后文延续到下一个未保留命中之前，避免将被省略的命中伪装成普通上下文。
fn limit_report_evidence(finding: &mut Finding) {
    const LIMIT: usize = 500;
    if finding.count <= LIMIT {
        return;
    }
    let mut hits = std::collections::HashSet::new();
    let mut stopped = false;
    finding.fragments.retain_mut(|fragment| {
        if stopped {
            return false;
        }
        let end = fragment.lines.iter().position(|line| {
            if !line.hit {
                return false;
            }
            let key = (fragment.file.clone(), line.number);
            if hits.contains(&key) {
                return false;
            }
            if hits.len() == LIMIT {
                stopped = true;
                return true;
            }
            hits.insert(key);
            false
        });
        if let Some(end) = end {
            fragment.lines.truncate(end);
        }
        fragment.lines.iter().any(|line| line.hit)
    });
}

/// 显式取消错误供桌面任务状态识别，避免依赖可修改的中文文案。
#[derive(Debug)]
pub struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("任务已取消，已生成文件保留在输出目录")
    }
}
impl std::error::Error for Cancelled {}

fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        return Err(Cancelled.into());
    }
    Ok(())
}
pub fn stamp(path: &Path) -> Result<(u64, std::time::SystemTime)> {
    let m = fs::metadata(path)?;
    Ok((m.len(), m.modified()?))
}
/// 仅允许普通文件和目录；同时检查已有输出路径，拒绝通过 Windows 重解析点逃逸。
fn safe_target(root: &Path, rel: &Path) -> Result<PathBuf> {
    if rel
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        bail!("压缩包包含非法路径");
    }
    let mut p = root.to_path_buf();
    for c in rel.components() {
        if let Component::Normal(s) = c {
            let name = s.to_string_lossy();
            let device = name.split('.').next().unwrap_or("").to_ascii_uppercase();
            if name.contains(':')
                || name.contains('\\')
                || [
                    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                    "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
                    "LPT8", "LPT9",
                ]
                .contains(&device.as_str())
            {
                bail!("压缩包包含不安全文件名：{name}");
            }
            p.push(s);
            if let Ok(m) = fs::symlink_metadata(&p) {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if m.file_attributes() & 0x400 != 0 {
                        bail!("输出路径包含链接或重解析点：{}", p.display());
                    }
                }
                if m.file_type().is_symlink() {
                    bail!("输出路径包含符号链接");
                }
            }
        }
    }
    Ok(p)
}
pub fn validate_archive(path: &Path, cancel: &AtomicBool) -> Result<()> {
    check(cancel)?;
    let mut ar = tar::Archive::new(MultiGzDecoder::new(BufReader::with_capacity(
        128 * 1024,
        File::open(path)?,
    )));
    let mut count = 0;
    for e in ar.entries()? {
        check(cancel)?;
        let mut e = e?;
        let ty = e.header().entry_type();
        if !(ty.is_file() || ty.is_dir()) {
            bail!("压缩包包含链接或不支持的条目类型");
        }
        safe_target(Path::new("."), &e.path()?)?;
        std::io::copy(&mut e, &mut std::io::sink())?;
        count += 1;
    }
    std::io::copy(&mut ar.into_inner(), &mut std::io::sink())?;
    if count == 0 {
        bail!("诊断包为空");
    }
    Ok(())
}
fn unpack(
    path: &Path,
    root: &Path,
    cancel: &AtomicBool,
    progress: &impl Fn(String),
) -> Result<Vec<(String, PathBuf)>> {
    fs::create_dir_all(root)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if fs::symlink_metadata(root)?.file_attributes() & 0x400 != 0 {
            bail!("解压目录不能是链接或重解析点");
        }
    }
    // Windows 规范路径带扩展前缀，保留 Linux 文件名末尾的点和空格。
    let canonical_root = fs::canonicalize(root)?;
    let root = canonical_root.as_path();
    let mut files = vec![];
    let mut ar = tar::Archive::new(MultiGzDecoder::new(BufReader::with_capacity(
        128 * 1024,
        File::open(path)?,
    )));
    let mut buf = vec![0; 128 * 1024];
    for e in ar.entries()? {
        check(cancel)?;
        let mut e = e?;
        let rel = e.path()?.into_owned();
        let dest = safe_target(root, &rel)?;
        let ty = e.header().entry_type();
        if ty.is_dir() {
            fs::create_dir_all(&dest)?;
            continue;
        }
        if !ty.is_file() {
            bail!("拒绝解压链接或特殊文件：{}", rel.display());
        }
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
        }
        let mut out =
            File::create(&dest).with_context(|| format!("无法写入 {}", dest.display()))?;
        loop {
            check(cancel)?;
            let n = e.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }
        let name = rel.to_string_lossy().replace('\\', "/");
        files.push((name, dest));
        if files.len() % 100 == 0 {
            progress(format!("已解压 {} 个文件", files.len()));
        }
    }
    std::io::copy(&mut ar.into_inner(), &mut std::io::sink())?;
    if files.is_empty() {
        bail!("诊断包中没有文件");
    }
    Ok(files)
}
fn reader(p: &Path) -> Result<Box<dyn BufRead>> {
    let f = File::open(p)?;
    if p.extension().is_some_and(|e| e == "gz") {
        Ok(Box::new(BufReader::with_capacity(
            128 * 1024,
            MultiGzDecoder::new(BufReader::with_capacity(128 * 1024, f)),
        )))
    } else {
        Ok(Box::new(BufReader::with_capacity(128 * 1024, f)))
    }
}
/// 不为缺失年份或时区的日志补全日期；完整但无时区的时间可排序，不参与跨来源合并。
pub fn event_time(line: &str, r: &Rule) -> (String, Option<String>) {
    let custom = if r.time_regex.is_empty() {
        None
    } else {
        Regex::new(&r.time_regex).ok()
    };
    event_time_prepared(line, r, custom.as_ref())
}
/// 时间表达式由本次分析预编译；公开入口保留独立调用能力。
fn event_time_prepared(line: &str, r: &Rule, custom: Option<&Regex>) -> (String, Option<String>) {
    static DEFAULT_TIME: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?P<time>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)")
            .unwrap()
    });
    let re = custom.unwrap_or(&DEFAULT_TIME);
    let raw = re.captures(line).map(|c| {
        c.name("time")
            .or_else(|| c.get(1))
            .or_else(|| c.get(0))
            .unwrap()
            .as_str()
            .to_owned()
    });
    if let Some(s) = raw {
        if let Ok(d) = chrono::DateTime::parse_from_rfc3339(&s.replace(' ', "T")) {
            return (
                s,
                Some(
                    d.with_timezone(&chrono::Utc)
                        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                ),
            );
        }
        let fmt = if r.time_format.is_empty() {
            "%Y-%m-%d %H:%M:%S%.f"
        } else {
            &r.time_format
        };
        if let Ok(d) = chrono::NaiveDateTime::parse_from_str(&s, fmt) {
            if !r.timezone.is_empty() {
                let full = format!("{}{}", d.format("%Y-%m-%dT%H:%M:%S%.f"), r.timezone);
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&full) {
                    return (
                        full,
                        Some(
                            dt.with_timezone(&chrono::Utc)
                                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                        ),
                    );
                }
            }
            return (s, None);
        }
        return (s, None);
    }
    static PARTIAL: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d|\[\s*\d+\.\d+\])").unwrap()
    });
    let partial = &*PARTIAL;
    (
        partial
            .find(line)
            .map(|m| format!("{}（时间不完整）", m.as_str()))
            .unwrap_or_else(|| "时间未识别".into()),
        None,
    )
}
fn display_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if !text.contains('\0') {
        return text.trim_end_matches(['\n', '\r']).to_owned();
    }
    let mut out = String::new();
    let mut count = 0;
    for c in text.trim_end_matches(['\n', '\r']).chars() {
        if c == '\0' {
            count += 1;
        } else {
            if count > 0 {
                out.push_str(&format!("[NUL × {count}]"));
                count = 0;
            }
            out.push(c);
        }
    }
    if count > 0 {
        out.push_str(&format!("[NUL × {count}]"));
    }
    out
}
fn compact_json(line: &str) -> Option<String> {
    let line = line.trim_start();
    if !line.starts_with('{') {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| serde_json::to_string(&v).ok())
}

/// 精确来源直接查解压清单的路径索引；前缀和包含规则只筛选条目名称，不读文件。
struct SourceIndex<'a> {
    files: &'a [(String, PathBuf)],
    paths: HashMap<&'a str, Vec<usize>>,
}
impl<'a> SourceIndex<'a> {
    fn new(files: &'a [(String, PathBuf)], exact: &std::collections::HashSet<&str>) -> Self {
        let mut index = Self {
            files,
            paths: HashMap::new(),
        };
        for (i, (path, _)) in files.iter().enumerate() {
            if exact.contains(path.as_str()) {
                index.paths.entry(path).or_default().push(i);
            }
            if let Some((_, relative)) = path.split_once('/') {
                let relative = relative.trim_start_matches('/');
                if exact.contains(relative) {
                    index.paths.entry(relative).or_default().push(i);
                }
            }
        }
        index
    }
    fn candidates(&self, source: &crate::rules::Source) -> Vec<usize> {
        if source.mode == "exact" {
            self.paths
                .get(source.pattern.as_str())
                .cloned()
                .unwrap_or_default()
        } else {
            self.files
                .iter()
                .enumerate()
                .filter_map(|(i, (name, _))| source.matches(name).then_some(i))
                .collect()
        }
    }
}

/// 一个文件只对应一个执行任务，规则编号与预编译列表一致。
struct PlannedFile {
    file_index: usize,
    system: Vec<usize>,
    active: Vec<usize>,
}

/// 分析文件计划：先收集规则来源，再索引精确相对路径，最后按文件合并适用规则。
/// 文件、规则的原始顺序和旧配置的首次分组优先级均在计划阶段确定。
struct AnalysisFilePlan {
    files: Vec<PlannedFile>,
}
impl AnalysisFilePlan {
    fn new(
        files: &[(String, PathBuf)],
        rules: &RuleSet,
        findings: &[Finding],
        cancel: &AtomicBool,
    ) -> Result<Self> {
        // 相同来源范围只筛选一次文件，多个规则复用候选索引。
        let sources: Vec<_> = rules
            .rules
            .iter()
            .flat_map(|r| &r.sources)
            .chain(rules.system.iter().map(|r| &r.source))
            .collect();
        let exact = sources
            .iter()
            .filter(|s| s.mode == "exact")
            .map(|s| s.pattern.as_str())
            .collect();
        let source_index = SourceIndex::new(files, &exact);
        let mut source_files = HashMap::new();
        for source in sources {
            check(cancel)?;
            source_files
                .entry((source.mode.clone(), source.pattern.clone()))
                .or_insert_with(|| source_index.candidates(source));
        }
        let mut first_legacy = vec![None; files.len()];
        for rule in rules.rules.iter().filter(|r| !r.legacy_group.is_empty()) {
            for source in &rule.sources {
                for &i in &source_files[&(source.mode.clone(), source.pattern.clone())] {
                    first_legacy[i].get_or_insert(rule.legacy_group.as_str());
                }
            }
        }
        let mut active_by_file = vec![Vec::new(); files.len()];
        for (i, finding) in findings.iter().enumerate() {
            for source in &finding.rule.sources {
                for &file in &source_files[&(source.mode.clone(), source.pattern.clone())] {
                    if (finding.rule.legacy_group.is_empty()
                        || first_legacy[file] == Some(finding.rule.legacy_group.as_str()))
                        && active_by_file[file].last() != Some(&i)
                    {
                        active_by_file[file].push(i);
                    }
                }
            }
        }
        let mut sys_by_file = vec![Vec::new(); files.len()];
        for (i, rule) in rules.system.iter().filter(|s| s.enabled).enumerate() {
            let source = &rule.source;
            for &file in &source_files[&(source.mode.clone(), source.pattern.clone())] {
                sys_by_file[file].push(i);
            }
        }
        let files = sys_by_file
            .into_iter()
            .zip(active_by_file)
            .enumerate()
            .filter_map(|(file_index, (system, active))| {
                (!system.is_empty() || !active.is_empty()).then_some(PlannedFile {
                    file_index,
                    system,
                    active,
                })
            })
            .collect();
        Ok(Self { files })
    }
}

/// 结构化提取需要完整文本时，保留原始字节供日志扫描复用。
/// UTF-8 失败只影响结构化规则；读取失败在回放末尾仍返回错误，不能伪装成正常 EOF。
struct CapturedSource {
    data: std::io::Cursor<Vec<u8>>,
    error: Option<std::io::Error>,
}
impl CapturedSource {
    fn read(path: &Path, cancel: &AtomicBool) -> Result<Self> {
        let mut input = reader(path)?;
        let mut data = Vec::new();
        let mut buffer = vec![0; 128 * 1024];
        let error = loop {
            check(cancel)?;
            match input.read(&mut buffer) {
                Ok(0) => break None,
                Ok(n) => data.extend_from_slice(&buffer[..n]),
                Err(error) => break Some(error),
            }
        };
        Ok(Self {
            data: std::io::Cursor::new(data),
            error,
        })
    }
    fn text(&self) -> Result<&str> {
        if let Some(error) = &self.error {
            bail!("{error}");
        }
        Ok(std::str::from_utf8(self.data.get_ref()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stream did not contain valid UTF-8",
            )
        })?)
    }
}
impl Read for CapturedSource {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let n = self.data.read(buffer)?;
        if n == 0 && !buffer.is_empty() {
            if let Some(error) = self.error.take() {
                return Err(error);
            }
        }
        Ok(n)
    }
}

/// 单文件任务只写自己的结果；线程间共享预编译规则，不共享报告可变状态。
/// 最多保留一个有界批次的中间结果，合并时保持归档中的文件顺序。
#[derive(Default)]
struct FileAnalysis {
    findings: Vec<Finding>,
    system: Vec<Table>,
    events: Vec<Event>,
    warnings: Vec<String>,
}

fn analyze_file(
    name: &String,
    p: &Path,
    active: &[usize],
    sys: &[&(&crate::rules::SystemRule, extract::PreparedExtractor<'_>)],
    template: &[Finding],
    matchers: &[Matcher],
    time_patterns: &[Option<Regex>],
    cancel: &AtomicBool,
) -> Result<FileAnalysis> {
    check(cancel)?;
    // Regex 的克隆共享编译结果但保留独立搜索缓存，避免多个线程争用同一缓存。
    let matchers = matchers.to_vec();
    let time_patterns = time_patterns.to_vec();
    let mut report = FileAnalysis {
        findings: template.to_vec(),
        ..Default::default()
    };
    let captured = if sys.is_empty() {
        None
    } else {
        Some(CapturedSource::read(p, cancel))
    };
    check(cancel)?;
    if let Some(captured) = &captured {
        let text = captured
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{e}"))
            .and_then(CapturedSource::text);
        let json = text
            .as_ref()
            .ok()
            .filter(|_| sys.iter().any(|(s, _)| s.kind == "json"))
            .map(|text| serde_json::from_str::<serde_json::Value>(text));
        for (s, extractor) in sys {
            check(cancel)?;
            let parsed = (|| -> Result<Table> {
                let text = text.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
                let root = if s.kind == "json" {
                    Some(
                        json.as_ref()
                            .expect("已读取 JSON 来源")
                            .as_ref()
                            .map_err(|_| anyhow::anyhow!("JSON 内容无法解析"))?,
                    )
                } else {
                    None
                };
                extractor.extract(text, name, root)
            })();
            match parsed {
                Ok(t) => report.system.push(t),
                Err(e) => report.warnings.push(format!("{} / {}：{e}", s.name, name)),
            }
        }
    }
    if active.is_empty() {
        return Ok(report);
    }
    let max_before = active
        .iter()
        .map(|&i| report.findings[i].rule.before)
        .max()
        .unwrap_or(0);
    let mut previous: VecDeque<(usize, String)> = VecDeque::new();
    // 规则编号连续，直接索引片段状态，避免每行每条规则反复计算哈希。
    let mut pending: Vec<Option<(Fragment, usize)>> = vec![None; template.len()];
    let mut rd: Box<dyn BufRead> = match captured {
        Some(captured) => Box::new(BufReader::with_capacity(128 * 1024, captured?)),
        None => reader(p)?,
    };
    let mut bytes = vec![];
    let mut line_number = 0;
    let mut noted_nul = false;
    for &i in active {
        report.findings[i].status = "未找到符合规则的日志".into();
    }
    loop {
        check(cancel)?;
        bytes.clear();
        match rd.read_until(b'\n', &mut bytes) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                report.warnings.push(format!("日志读取失败 {name}：{e}"));
                for &i in active {
                    report.findings[i].status = "日志读取不完整".into();
                }
                break;
            }
        }
        line_number += 1;
        if !noted_nul && bytes.contains(&0) {
            report.warnings.push(format!(
                "{name} 含不可见 NUL 字节；报告用 [NUL × 数量] 表示连续字节，原文件保持不变。"
            ));
            noted_nul = true;
        }
        let line = display_line(&bytes);
        let compact = std::cell::OnceCell::new();
        for &i in active {
            let r = &report.findings[i].rule;
            let hit = matchers[i].matches(&line)
                || compact
                    .get_or_init(|| compact_json(&line))
                    .as_ref()
                    .is_some_and(|s| matchers[i].matches(s));
            let ranges = if hit {
                matchers[i].ranges(&line)
            } else {
                vec![]
            };
            // 若下一次命中与前一片段的前后文相接，则直接合并，避免重复存储。
            if pending[i]
                .as_ref()
                .is_some_and(|(_, end)| line_number > end.saturating_add(r.before))
            {
                let (f, _) = pending[i].take().unwrap();
                report.findings[i].fragments.push(f);
            }
            let r = &report.findings[i].rule;
            if hit {
                let (time, key) = event_time_prepared(&line, r, time_patterns[i].as_ref());
                if r.target != "keywords" {
                    report.events.push(Event {
                        name: r.name.clone(),
                        group: r.group.clone(),
                        time: time.clone(),
                        key,
                        note: r.note.clone(),
                        sources: vec![Fragment {
                            file: name.clone(),
                            lines: vec![LogLine {
                                number: line_number,
                                text: line.clone(),
                                hit: true,
                                ranges: ranges.clone(),
                            }],
                            time: time.clone(),
                            annotation: String::new(),
                        }],
                    });
                }
                if let Some((fragment, end)) = pending[i].as_mut() {
                    let last = fragment.lines.last().map(|l| l.number).unwrap_or(0);
                    for (n, t) in previous
                        .iter()
                        .filter(|(n, _)| *n > last && *n >= line_number.saturating_sub(r.before))
                    {
                        fragment.lines.push(LogLine {
                            number: *n,
                            text: t.clone(),
                            hit: false,
                            ranges: vec![],
                        });
                    }
                    *end = line_number.saturating_add(r.after);
                } else {
                    let lines = previous
                        .iter()
                        .filter(|(n, _)| *n >= line_number.saturating_sub(r.before))
                        .map(|(n, t)| LogLine {
                            number: *n,
                            text: t.clone(),
                            hit: false,
                            ranges: vec![],
                        })
                        .collect();
                    pending[i] = Some((
                        Fragment {
                            file: name.clone(),
                            lines,
                            time,
                            annotation: String::new(),
                        },
                        line_number.saturating_add(r.after),
                    ));
                }
                report.findings[i].count += 1;
            }
            if let Some((f, end)) = pending[i].as_mut() {
                if line_number <= *end {
                    f.lines.push(LogLine {
                        number: line_number,
                        text: line.clone(),
                        hit,
                        ranges,
                    });
                }
            }
        }
        previous.push_back((line_number, line));
        while previous.len() > max_before {
            previous.pop_front();
        }
    }
    for (i, (f, _)) in pending
        .into_iter()
        .enumerate()
        .filter_map(|(i, p)| p.map(|p| (i, p)))
    {
        report.findings[i].fragments.push(f);
    }
    Ok(report)
}

pub fn analyze(
    path: &Path,
    rules: &RuleSet,
    cancel: &AtomicBool,
    progress: impl Fn(String),
) -> Result<PathBuf> {
    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(4);
    analyze_with_workers(path, rules, cancel, workers, progress, |_, _| {})
}

/// 性能诊断入口：允许显式选择串行扫描，并收集单文件耗时，不写入报告或用户配置。
pub fn analyze_with_workers(
    path: &Path,
    rules: &RuleSet,
    cancel: &AtomicBool,
    workers: usize,
    progress: impl Fn(String),
    timing: impl Fn(&str, std::time::Duration),
) -> Result<PathBuf> {
    // 通过进度回调报告各阶段累计耗时，帮助桌面端区分实际分析与等待时间。
    let started = std::time::Instant::now();
    rules.validate()?;
    let original = stamp(path)?;
    progress(format!(
        "归档校验完成（{:.2} 秒）",
        started.elapsed().as_secs_f64()
    ));
    let root = path.with_extension("");
    progress("正在解压诊断包…".into());
    let files = unpack(path, &root, cancel, &progress)
        .context("解压失败，文件可能未下载完成、损坏或磁盘空间不足")?;
    progress(format!(
        "解压与准备完成（{:.2} 秒）",
        started.elapsed().as_secs_f64()
    ));
    let mut report = Report {
        package: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into(),
        generated: chrono::Local::now().to_rfc3339(),
        layout: rules.layout.clone(),
        system: vec![],
        findings: rules
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| Finding {
                rule: r.clone(),
                count: 0,
                fragments: vec![],
                status: "来源文件缺失".into(),
            })
            .collect(),
        events: vec![],
        warnings: vec![],
    };
    let matchers: Vec<_> = report
        .findings
        .iter()
        .map(|f| Matcher::new(&f.rule))
        .collect::<Result<_>>()?;
    let time_patterns: Vec<_> = report
        .findings
        .iter()
        .map(|f| {
            if f.rule.time_regex.is_empty() {
                None
            } else {
                Regex::new(&f.rule.time_regex).ok()
            }
        })
        .collect();
    let extractors: Vec<_> = rules
        .system
        .iter()
        .filter(|s| s.enabled)
        .map(|s| extract::PreparedExtractor::new(s).map(|e| (s, e)))
        .collect::<Result<_>>()?;
    let plan = AnalysisFilePlan::new(&files, rules, &report.findings, cancel)?;
    let jobs = &plan.files;
    let template = report.findings.clone();
    let workers = workers.clamp(1, 4);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .context("无法启动分析工作线程")?;
    let mut completed = 0;
    let mut last_progress = std::time::Instant::now();
    progress(format!("分析文件 0/{}", jobs.len()));
    for batch in jobs.chunks(workers) {
        check(cancel)?;
        let results = pool.in_place_scope(|scope| {
            let (sender, receiver) = std::sync::mpsc::channel();
            for (slot, job) in batch.iter().enumerate() {
                let (name, p) = &files[job.file_index];
                let sys: Vec<_> = job.system.iter().map(|&i| &extractors[i]).collect();
                let active = &job.active;
                let sender = sender.clone();
                let template = &template;
                let matchers = &matchers;
                let time_patterns = &time_patterns;
                scope.spawn(move |_| {
                    let start = std::time::Instant::now();
                    let result = analyze_file(
                        name,
                        p,
                        active,
                        &sys,
                        template,
                        matchers,
                        time_patterns,
                        cancel,
                    );
                    let _ = sender.send((slot, start.elapsed(), result));
                });
            }
            drop(sender);
            let mut results = Vec::with_capacity(batch.len());
            loop {
                match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(message) => {
                        completed += 1;
                        results.push(message);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if last_progress.elapsed() >= std::time::Duration::from_millis(100)
                    || completed == jobs.len()
                {
                    progress(format!("分析文件 {}/{}", completed, jobs.len()));
                    last_progress = std::time::Instant::now();
                }
            }
            results
        });
        check(cancel)?;
        let mut results = results;
        results.sort_by_key(|(slot, _, _)| *slot);
        for (slot, elapsed, result) in results {
            let local = result?;
            timing(&files[batch[slot].file_index].0, elapsed);
            for &i in &batch[slot].active {
                report.findings[i].count += local.findings[i].count;
                report.findings[i].status = local.findings[i].status.clone();
            }
            for (target, source) in report.findings.iter_mut().zip(local.findings) {
                target.fragments.extend(source.fragments);
            }
            report.system.extend(local.system);
            report.events.extend(local.events);
            report.warnings.extend(local.warnings);
        }
    }
    for s in rules.system.iter().filter(|s| s.enabled) {
        if !report.system.iter().any(|t| t.id == s.id) {
            report.system.push(Table {
                storage: vec![],
                id: s.id.clone(),
                name: s.name.clone(),
                group: s.group.clone(),
                view: s.view.clone(),
                fields: s.fields.clone(),
                rows: vec![],
                source: s.source.pattern.clone(),
                warning: if s.missing.is_empty() {
                    String::new()
                } else {
                    format!("{}：来源缺失或提取失败", s.missing)
                },
            });
        }
    }
    // 分组顺序来自完整配置，停用规则和仅时间线规则不会改变组的首次出现位置。
    report.findings.sort_by_key(|f| {
        rules
            .rules
            .iter()
            .position(|r| r.group == f.rule.group)
            .unwrap_or(usize::MAX)
    });
    report.system.sort_by_key(|t| {
        rules
            .system
            .iter()
            .position(|s| s.id == t.id)
            .unwrap_or(usize::MAX)
    });
    extract::join_tables(&mut report.system, &rules.system);
    // 将 lsblk 的 md RAID 类型按 poolN 回填到 sysinfo.json 的 used_for 存储池。
    let mut raid_by_pool = std::collections::HashMap::new();
    if let Some(block) = report.system.iter().find(|t| t.id == "block") {
        let mut raid = None;
        for row in &block.rows {
            let text = row.values().cloned().collect::<Vec<_>>().join(" ");
            if let Some(c) = regex::Regex::new(r"\braid(\d+)\b")
                .ok()
                .and_then(|r| r.captures(&text))
            {
                raid = Some(format!("RAID{}", &c[1]));
            }
            if let Some(c) = regex::Regex::new(r"pool(\d+)-")
                .ok()
                .and_then(|r| r.captures(&text))
            {
                if let Some(value) = &raid {
                    raid_by_pool.insert(format!("Storage Pool {}", &c[1]), value.clone());
                }
            }
        }
    }
    progress(format!(
        "扫描与结果合并完成（{:.2} 秒）",
        started.elapsed().as_secs_f64()
    ));
    for table in report.system.iter_mut().filter(|t| t.view == "storage") {
        for storage in &mut table.storage {
            storage.raid = raid_by_pool.get(&storage.pool).cloned().unwrap_or_default();
        }
    }
    for f in &mut report.findings {
        if f.count > 0 && f.status != "日志读取不完整" {
            f.status = "已提取".into();
        }
        if f.rule.reverse {
            let mut start = 0;
            while start < f.fragments.len() {
                let mut end = start + 1;
                while end < f.fragments.len() && f.fragments[end].file == f.fragments[start].file {
                    end += 1;
                }
                f.fragments[start..end].reverse();
                start = end;
            }
        }
        if f.rule.sort != "source" {
            f.fragments.sort_by(|a, b| a.time.cmp(&b.time));
            if f.rule.sort == "desc" {
                f.fragments.reverse();
            }
        }
    }
    for f in &mut report.findings {
        if f.rule.fmt == "volume_info" && f.rule.regex {
            if let Some(re) = f.rule.terms.first().and_then(|t| Regex::new(t).ok()) {
                for p in &mut f.fragments {
                    if let Some(c) = p
                        .lines
                        .iter()
                        .filter(|l| l.hit)
                        .find_map(|l| re.captures(&l.text))
                    {
                        let values: Vec<_> = (1..=3)
                            .filter_map(|i| c.get(i).and_then(|m| m.as_str().parse::<f64>().ok()))
                            .collect();
                        if values.len() == 3 {
                            p.annotation = format!(
                                "总容量：{:.1} GiB | 已使用：{:.1} GiB | 可用：{:.1} GiB",
                                values[0] / 1073741824.0,
                                values[1] / 1073741824.0,
                                values[2] / 1073741824.0
                            );
                        }
                    }
                }
            }
        }
    }
    // 按来源行索引证据，避免大量时间线命中时反复遍历所有片段。
    let mut evidence = HashMap::new();
    for f in report
        .findings
        .iter()
        .filter(|f| f.rule.target != "keywords")
    {
        for fragment in &f.fragments {
            for line in fragment.lines.iter().filter(|l| l.hit) {
                evidence.insert(
                    (
                        f.rule.name.as_str(),
                        f.rule.group.as_str(),
                        fragment.file.as_str(),
                        line.number,
                    ),
                    fragment,
                );
            }
        }
    }
    for event in &mut report.events {
        for source in &mut event.sources {
            let n = source.lines[0].number;
            if let Some(fragment) = evidence.get(&(
                event.name.as_str(),
                event.group.as_str(),
                source.file.as_str(),
                n,
            )) {
                *source = (*fragment).clone();
            }
        }
    }
    let mut merged: Vec<Event> = vec![];
    let mut event_indices = HashMap::new();
    for event in report.events {
        if let Some(time) = &event.key {
            let key = (event.name.clone(), event.group.clone(), time.clone());
            if let Some(&i) = event_indices.get(&key) {
                let previous: &mut Event = &mut merged[i];
                previous.sources.extend(event.sources);
                continue;
            }
            event_indices.insert(key, merged.len());
        }
        merged.push(event);
    }
    merged.sort_by(|a, b| match (&a.key, &b.key) {
        (Some(a), Some(b)) => {
            if rules.layout.timeline_sort == "desc" {
                b.cmp(a)
            } else {
                a.cmp(b)
            }
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        _ => a.time.cmp(&b.time),
    });
    report.events = merged;
    for finding in &mut report.findings {
        limit_report_evidence(finding);
    }
    check(cancel)?;
    if stamp(path)? != original {
        bail!("分析期间诊断包发生变化，请等待下载完成后重试");
    }
    progress("正在生成离线 HTML…".into());
    let tmp = root.join("report.html.tmp");
    safe_target(&root, Path::new("report.html.tmp"))?;
    safe_target(&root, Path::new("report.html"))?;
    let (prefix, suffix) = include_str!("../assets/report.html")
        .split_once("/*REPORT_DATA*/null")
        .expect("报告模板包含数据插入位置");
    {
        let mut out = BufWriter::with_capacity(128 * 1024, File::create(&tmp)?);
        out.write_all(prefix.as_bytes())?;
        serde_json::to_writer(HtmlJsonWriter(&mut out), &report)?;
        out.write_all(suffix.as_bytes())?;
        out.flush()?;
    }
    check(cancel)?;
    if stamp(path)? != original {
        bail!("生成期间诊断包发生变化，未替换报告");
    }
    let dest = root.join("report.html");
    replace_file(&tmp, &dest)?;
    progress(format!(
        "报告写入完成（{:.2} 秒）",
        started.elapsed().as_secs_f64()
    ));
    progress(format!("分析完成：{}", dest.display()));
    Ok(dest)
}
/// 流式转义内嵌 JSON，避免脚本标签注入，同时不构造完整 JSON 和 HTML 副本。
struct HtmlJsonWriter<W>(W);
impl<W: Write> Write for HtmlJsonWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut start = 0;
        for (index, byte) in bytes.iter().enumerate() {
            let escaped: &[u8] = match byte {
                b'&' => br"\u0026",
                b'<' => br"\u003c",
                b'>' => br"\u003e",
                _ => continue,
            };
            self.0.write_all(&bytes[start..index])?;
            self.0.write_all(escaped)?;
            start = index + 1;
        }
        self.0.write_all(&bytes[start..])?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

pub fn replace_file(from: &Path, to: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let a: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let b: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::MoveFileExW(
                a.as_ptr(),
                b.as_ptr(),
                windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING
                    | windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to)?;
        Ok(())
    }
}
/// 规则编辑器使用同一份离线模板预览，确保预览与正式报告一致。
pub fn preview(rules: &RuleSet, index: usize, system: bool, text: &str) -> Result<String> {
    let mut report = Report {
        package: "规则预览".into(),
        generated: chrono::Local::now().to_rfc3339(),
        layout: rules.layout.clone(),
        system: vec![],
        findings: vec![],
        events: vec![],
        warnings: vec![],
    };
    if system {
        let selected = &rules.system[index];
        report
            .system
            .push(extract::extract(selected, text, "样例日志")?);
        // 存储预览加载同来源的配套规则，使用与正式报告相同的磁盘身份关联。
        if selected.view == "storage" || selected.view == "storage-smart" {
            for r in &rules.system {
                if r.id != selected.id
                    && r.enabled
                    && r.source.pattern == selected.source.pattern
                    && r.source.mode == selected.source.mode
                    && (r.view == "storage" || r.view == "storage-smart")
                {
                    report.system.push(extract::extract(r, text, "样例日志")?);
                }
            }
        }
    } else {
        let r = &rules.rules[index];
        let m = Matcher::new(r)?;
        let lines: Vec<_> = text.lines().collect();
        let mut finding = Finding {
            rule: r.clone(),
            count: 0,
            fragments: vec![],
            status: "未匹配".into(),
        };
        for (i, line) in lines.iter().enumerate() {
            if !m.matches(line) {
                continue;
            }
            let (time, key) = event_time(line, r);
            let f = Fragment {
                file: "样例日志".into(),
                time: time.clone(),
                annotation: String::new(),
                lines: lines
                    .iter()
                    .enumerate()
                    .skip(i.saturating_sub(r.before))
                    .take(
                        i.saturating_add(r.after).saturating_add(1).min(lines.len())
                            - i.saturating_sub(r.before),
                    )
                    .map(|(n, l)| LogLine {
                        number: n + 1,
                        text: l.to_string(),
                        hit: m.matches(l),
                        ranges: m.ranges(l),
                    })
                    .collect(),
            };
            finding.count += 1;
            finding.fragments.push(f.clone());
            if r.target != "keywords" {
                report.events.push(Event {
                    name: r.name.clone(),
                    group: r.group.clone(),
                    time,
                    key,
                    note: r.note.clone(),
                    sources: vec![f],
                });
            }
        }
        if finding.count > 0 {
            finding.status = "已匹配".into();
        }
        report.findings.push(finding);
    }
    let json = serde_json::to_string(&report)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e");
    Ok(include_str!("../assets/report.html").replace("/*REPORT_DATA*/null", &json))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streamed_json_matches_existing_escaping_and_propagates_write_errors() {
        let value = serde_json::json!({"文本": "</script>&>中文\\u003c\n\"", "rows": [1, 2]});
        let expected = serde_json::to_string(&value)
            .unwrap()
            .replace('&', "\\u0026")
            .replace('<', "\\u003c")
            .replace('>', "\\u003e");
        let mut actual = Vec::new();
        serde_json::to_writer(HtmlJsonWriter(&mut actual), &value).unwrap();
        assert_eq!(actual, expected.as_bytes());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&actual).unwrap(),
            value
        );
        // 固定容量输出模拟磁盘写入失败，错误必须返回，不能伪报成功。
        let mut short = [0; 5];
        assert!(serde_json::to_writer(HtmlJsonWriter(&mut short[..]), &value).is_err());
    }
    #[test]
    fn rejects_escape() {
        assert!(safe_target(Path::new("."), Path::new("../oops")).is_err());
        assert!(safe_target(Path::new("."), Path::new("x:stream")).is_err());
    }
    #[test]
    fn incomplete_time_not_invented() {
        let r = Rule::default();
        let (t, k) = event_time("Sep 09 08:01:46 kernel: Linux version", &r);
        assert!(k.is_none());
        assert!(t.contains("不完整"));
    }
    #[test]
    fn timezone_required_for_merge() {
        let r = Rule::default();
        assert!(event_time("2026-09-09 08:00:00", &r).1.is_none());
        let r = Rule {
            timezone: "+08:00".into(),
            ..r
        };
        assert!(event_time("2026-09-09 08:00:00", &r).1.is_some());
    }
}
