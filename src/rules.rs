use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

fn yes() -> bool {
    true
}
fn ten() -> usize {
    10
}
fn default_mode() -> String {
    "any".into()
}
fn default_target() -> String {
    "keywords".into()
}
fn default_source_mode() -> String {
    "prefix".into()
}
fn default_sort() -> String {
    "source".into()
}
fn default_view() -> String {
    "table".into()
}

/// 规则包是报告内容的唯一配置来源；程序只解释提取和展示方式，不内置故障结论。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleSet {
    pub version: u32,
    /// 日志文件目录：名称与路径的唯一维护来源。
    pub log_files: Vec<LogFile>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub system: Vec<SystemRule>,
    #[serde(default)]
    pub layout: Layout,
    /// 时间线专用配置。缺失时使用空配置，旧规则仍由 rules.target 兼容执行。
    #[serde(default)]
    pub timeline: TimelineConfig,
}

/// 时间线事实识别、会话判定和阈值配置；采用数据驱动结构，便于高级 JSON 维护。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TimelineConfig {
    #[serde(default)]
    pub events: Vec<TimelineEventRule>,
    #[serde(default)]
    pub judgements: Vec<TimelineJudgementRule>,
    #[serde(default)]
    pub thresholds: TimelineThresholds,
    #[serde(default)]
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineEventRule {
    pub id: String,
    pub event_type: String,
    #[serde(default)]
    pub source_file_ids: Vec<String>,
    #[serde(default)]
    pub terms: Vec<String>,
    #[serde(default)]
    pub regex: bool,
    #[serde(default = "default_evidence_strength")]
    pub evidence_strength: String,
    #[serde(default)]
    pub time_regex: String,
    #[serde(default)]
    pub time_format: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineJudgementRule {
    pub id: String,
    #[serde(default)]
    pub start_event: String,
    #[serde(default)]
    pub end_event: String,
    #[serde(default)]
    pub must_have: Vec<String>,
    #[serde(default)]
    pub must_not_have: Vec<String>,
    #[serde(default)]
    pub any_of: Vec<String>,
    #[serde(default)]
    pub output: String,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    #[serde(default)]
    pub limitation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineThresholds {
    #[serde(default = "default_match_window_seconds")]
    pub match_window_seconds: u64,
    #[serde(default = "default_gap_seconds")]
    pub gap_seconds: u64,
}

impl Default for TimelineThresholds {
    fn default() -> Self {
        Self {
            match_window_seconds: default_match_window_seconds(),
            gap_seconds: default_gap_seconds(),
        }
    }
}

fn default_evidence_strength() -> String {
    "medium".into()
}
fn default_confidence() -> String {
    "medium".into()
}
fn default_match_window_seconds() -> u64 {
    300
}
fn default_gap_seconds() -> u64 {
    120
}

/// 日志文件目录项，规则和报告通过此目录统一解析显示名称与来源。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogFile {
    pub id: String,
    pub name: String,
    pub path: String,
    #[serde(default = "default_source_mode")]
    pub mode: String,
    /// 预留归档容器类型；当前仅支持 diagnostic_archive。
    #[serde(default = "default_container")]
    pub container: String,
}

impl LogFile {
    /// 列表只显示中文名与文件名；完整路径只在配置表单中展示。
    pub fn file_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
    pub fn label(&self) -> String {
        format!("{} · {}", self.name, self.file_name())
    }

    /// path 是归档内相对路径（也是匹配文本）；不再重复保存 entry_path。
    /// ZIP 在入口统一拒绝，未来读取器接入时不需要改变规则的目录引用。
    pub fn source(&self) -> Result<Source> {
        match self.container.as_str() {
            "diagnostic_archive" => {}
            "zip" => bail!("日志文件「{}」暂不支持 ZIP 容器", self.name),
            _ => bail!(
                "日志文件「{}」的归档容器不受支持：{}",
                self.name,
                self.container
            ),
        }
        let source = Source {
            pattern: self.path.clone(),
            mode: self.mode.clone(),
        };
        validate_source(&source)?;
        if self.path.contains('\\')
            || self.path.starts_with('/')
            || self.path.contains(':')
            || self.path.split('/').any(|p| p == "..")
        {
            bail!(
                "日志文件路径须为归档内的相对路径，使用 / 分隔：{}",
                self.path
            );
        }
        Ok(source)
    }
}
fn default_container() -> String {
    "diagnostic_archive".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Layout {
    pub title: String,
    pub system_title: String,
    pub keyword_title: String,
    pub timeline_title: String,
    pub sections: Vec<String>,
    pub accent: String,
    pub font_size: u32,
    pub density: String,
    pub timeline_sort: String,
    pub first_open: bool,
    /// 日志视图每批渲染的行数；仅影响报告浏览器的 DOM 数量，不截断报告数据。
    pub log_lines_per_batch: u32,
    /// 规则编辑器中的日志文件导航顺序，不参与规则命中或报告排序。
    pub file_order: Vec<String>,
    /// 规则编辑器日志文件栏宽度。
    pub file_panel_width: u32,
}
impl Default for Layout {
    fn default() -> Self {
        Self {
            title: "诊断信息汇总".into(),
            system_title: "系统信息".into(),
            keyword_title: "关键词线索".into(),
            timeline_title: "开关机记录".into(),
            sections: vec!["keywords".into(), "timeline".into()],
            accent: "#2468d8".into(),
            font_size: 14,
            density: "comfortable".into(),
            timeline_sort: "desc".into(),
            first_open: true,
            log_lines_per_batch: 200,
            file_order: Vec::new(),
            file_panel_width: 240,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Source {
    pub pattern: String,
    #[serde(default = "default_source_mode")]
    pub mode: String,
}
impl Source {
    pub fn matches(&self, path: &str) -> bool {
        // 归档路径通常已经使用 `/`；避免无意义的字符串分配，降低逐文件规则筛选成本。
        let normalized;
        let p = if path.contains('\\') {
            normalized = path.replace('\\', "/");
            normalized.as_str()
        } else {
            path
        };
        let base = p.rsplit('/').next().unwrap_or(&p);
        match self.mode.as_str() {
            "exact" => {
                p == self.pattern
                    || p.strip_prefix(p.split('/').next().unwrap_or(""))
                        .is_some_and(|s| s.trim_start_matches('/') == self.pattern)
            }
            "path" => p.contains(&self.pattern),
            // 带目录的前缀限定相对路径，保留同目录轮转日志和服务子日志覆盖；
            // 不带目录的配置按文件名匹配。
            _ if self.pattern.contains('/') => {
                let (directory, prefix) = self.pattern.rsplit_once('/').unwrap();
                let matches = |path: &str| {
                    path.rsplit_once('/').is_some_and(|(parent, name)| {
                        parent == directory && name.starts_with(prefix)
                    })
                };
                matches(p)
                    || p.split_once('/')
                        .is_some_and(|(_, relative)| matches(relative.trim_start_matches('/')))
            }
            _ => base.starts_with(&self.pattern),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub group: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// 持久化只保存目录 ID；允许一条规则匹配多个已维护日志文件。
    pub source_file_ids: Vec<String>,
    /// 仅供分析使用的解析结果，不写入规则 JSON。每次分析和目录编辑后重新解析。
    #[serde(skip)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub terms: Vec<String>,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default = "yes")]
    pub case_sensitive: bool,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default = "ten")]
    pub before: usize,
    #[serde(default = "ten")]
    pub after: usize,
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default = "default_sort")]
    pub sort: String,
    #[serde(default)]
    pub reverse: bool,
    #[serde(default)]
    pub fmt: String,
    #[serde(default)]
    pub time_regex: String,
    #[serde(default)]
    pub time_format: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub legacy_group: String,
    #[serde(default)]
    pub open: bool,
}
impl Default for Rule {
    fn default() -> Self {
        Self {
            id: format!(
                "rule-{}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
            name: "新规则".into(),
            group: "自定义".into(),
            enabled: true,
            source_file_ids: vec![],
            sources: vec![Source {
                pattern: "syslog".into(),
                mode: "prefix".into(),
            }],
            terms: vec![],
            mode: "any".into(),
            regex: false,
            case_sensitive: true,
            exclude: vec![],
            note: String::new(),
            before: 10,
            after: 10,
            target: "keywords".into(),
            sort: "source".into(),
            reverse: false,
            fmt: String::new(),
            time_regex: String::new(),
            time_format: String::new(),
            timezone: String::new(),
            legacy_group: String::new(),
            open: false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub unit: String,
    #[serde(default)]
    pub missing: String,
    #[serde(default)]
    pub wide: bool,
    #[serde(default)]
    pub view: String,
    #[serde(default)]
    pub capture: String,
}
/// 结构化提取描述。数组、段落和表格都生成行；关联必须显式声明键，禁止按位置猜测。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemRule {
    pub id: String,
    pub name: String,
    pub group: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub source_file_id: String,
    /// 从日志目录解析的运行时来源，不作为第二份配置保存。
    #[serde(skip)]
    pub source: Source,
    pub kind: String,
    #[serde(default)]
    pub selector: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default = "default_view")]
    pub view: String,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub missing: String,
    #[serde(default)]
    pub join_rule: String,
    #[serde(default)]
    pub join_key: String,
    #[serde(default)]
    pub join_foreign_key: String,
}
impl Default for SystemRule {
    fn default() -> Self {
        Self {
            id: format!(
                "system-{}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
            name: "新信息组".into(),
            group: "基本信息".into(),
            enabled: true,
            source_file_id: String::new(),
            source: Source {
                pattern: "sysinfo.json".into(),
                mode: "prefix".into(),
            },
            kind: "json".into(),
            selector: String::new(),
            pattern: String::new(),
            view: "cards".into(),
            fields: vec![],
            missing: "未获取".into(),
            join_rule: String::new(),
            join_key: String::new(),
            join_foreign_key: String::new(),
        }
    }
}
#[derive(Clone)]
pub struct Matcher {
    patterns: Vec<Regex>,
    exclude: Vec<String>,
    all: bool,
    sensitive: bool,
}
impl Matcher {
    pub fn new(r: &Rule) -> Result<Self> {
        let patterns = r
            .terms
            .iter()
            .map(|t| {
                regex::RegexBuilder::new(&if r.regex { t.clone() } else { regex::escape(t) })
                    .case_insensitive(!r.case_sensitive)
                    .build()
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self {
            patterns,
            exclude: r
                .exclude
                .iter()
                .map(|s| {
                    if r.case_sensitive {
                        s.clone()
                    } else {
                        s.to_lowercase()
                    }
                })
                .collect(),
            all: r.mode == "all",
            sensitive: r.case_sensitive,
        })
    }
    pub fn matches(&self, s: &str) -> bool {
        if !self.exclude.is_empty() {
            let test = if self.sensitive {
                std::borrow::Cow::Borrowed(s)
            } else {
                std::borrow::Cow::Owned(s.to_lowercase())
            };
            if self.exclude.iter().any(|x| test.contains(x)) {
                return false;
            }
        }
        if self.all {
            !self.patterns.is_empty() && self.patterns.iter().all(|p| p.is_match(s))
        } else {
            self.patterns.iter().any(|p| p.is_match(s))
        }
    }
    pub fn ranges(&self, s: &str) -> Vec<(usize, usize)> {
        self.patterns
            .iter()
            .flat_map(|p| p.find_iter(s).map(|m| (m.start(), m.end())))
            .collect()
    }
}
/// 按首次出现顺序交换整组，稳定排序保留组内顺序，不引入额外排序配置。
pub fn swap_groups<T>(items: &mut [T], a: &str, b: &str, group: impl Fn(&T) -> &str) {
    let mut order = Vec::<String>::new();
    for item in items.iter() {
        let g = group(item);
        if !order.iter().any(|x| x == g) {
            order.push(g.into());
        }
    }
    if let (Some(i), Some(j)) = (
        order.iter().position(|x| x == a),
        order.iter().position(|x| x == b),
    ) {
        order.swap(i, j);
        items.sort_by_key(|x| order.iter().position(|g| g == group(x)).unwrap());
    }
}
/// 编辑器按身份移动规则，插入而非交换；其他规则的相对顺序保持稳定。
fn insert_rule<T>(
    items: &mut Vec<T>,
    id: &str,
    destination: &str,
    anchor: Option<&str>,
    after: bool,
    identity: impl Fn(&T) -> &str,
    group: impl Fn(&T) -> &str,
    set_group: impl Fn(&mut T, String),
) -> bool {
    let Some(from) = items.iter().position(|r| identity(r) == id) else {
        return false;
    };
    if anchor == Some(id) {
        return false;
    }
    if let Some(anchor) = anchor {
        if !items
            .iter()
            .any(|r| identity(r) == anchor && group(r) == destination)
        {
            return false;
        }
    }
    let mut order = Vec::<String>::new();
    for r in items.iter() {
        if !order.iter().any(|g| g == group(r)) {
            order.push(group(r).to_owned());
        }
    }
    if !order.iter().any(|g| g == destination) {
        order.push(destination.to_owned());
    }
    let mut rule = items.remove(from);
    set_group(&mut rule, destination.to_owned());
    let index = anchor
        .and_then(|id| items.iter().position(|r| identity(r) == id))
        .map(|i| i + usize::from(after))
        .unwrap_or_else(|| {
            items
                .iter()
                .rposition(|r| group(r) == destination)
                .map_or(items.len(), |i| i + 1)
        });
    items.insert(index, rule);
    // 移动第一条成员不能改变分组顺序；稳定归组兼容旧配置中交错存储的成员。
    items.sort_by_key(|r| order.iter().position(|g| g == group(r)).unwrap());
    true
}

/// 整组按目标位置插入，保持组内顺序，包含当前页面没有展示的共享规则。
fn insert_group<T>(
    items: &mut [T],
    source: &str,
    target: &str,
    after: bool,
    group: impl Fn(&T) -> &str,
) -> bool {
    let mut order = Vec::<String>::new();
    for r in items.iter() {
        if !order.iter().any(|g| g == group(r)) {
            order.push(group(r).to_owned());
        }
    }
    if source == target || !order.iter().any(|g| g == target) {
        return false;
    }
    let Some(index) = order.iter().position(|g| g == source) else {
        return false;
    };
    let name = order.remove(index);
    let index = order.iter().position(|g| g == target).unwrap() + usize::from(after);
    order.insert(index, name);
    items.sort_by_key(|r| order.iter().position(|g| g == group(r)).unwrap());
    true
}

impl RuleSet {
    pub fn move_rule(
        &mut self,
        system: bool,
        id: &str,
        group: &str,
        anchor: Option<&str>,
        after: bool,
    ) -> bool {
        if system {
            insert_rule(
                &mut self.system,
                id,
                group,
                anchor,
                after,
                |r| &r.id,
                |r| &r.group,
                |r, g| r.group = g,
            )
        } else {
            insert_rule(
                &mut self.rules,
                id,
                group,
                anchor,
                after,
                |r| &r.id,
                |r| &r.group,
                |r, g| r.group = g,
            )
        }
    }
    pub fn move_group(&mut self, system: bool, group: &str, target: &str, after: bool) -> bool {
        if system {
            insert_group(&mut self.system, group, target, after, |r| &r.group)
        } else {
            insert_group(&mut self.rules, group, target, after, |r| &r.group)
        }
    }

    /// 参考配置只按内置 ID 替换系统规则，自定义规则追加保留，不使用名称匹配。
    pub fn with_reference_system(&self) -> Result<Self> {
        let mut out = self.clone();
        let mut defaults = Self::defaults();
        out.merge_catalog(&mut defaults, false);
        out.system = defaults.system.clone();
        out.system.extend(
            self.system
                .iter()
                .filter(|r| !defaults.system.iter().any(|x| x.id == r.id))
                .cloned(),
        );
        out.validate()?;
        out.resolve_sources()?;
        Ok(out)
    }

    /// 新格式只按稳定标识合并规则；不同日志下的同名规则不能互相覆盖。
    pub fn merge(&self, incoming: &Self, replace: bool) -> Result<Self> {
        let mut out = self.clone();
        let mut incoming = incoming.clone();
        // 导入旧规则时先保留原文并在预览中提示；用户确认合并后再生成基础事实事件。
        incoming.migrate_legacy_timeline_rules();
        out.merge_catalog(&mut incoming, replace);
        for r in &incoming.rules {
            let found = out.rules.iter().position(|x| x.id == r.id);
            if let Some(i) = found {
                if replace {
                    out.rules[i] = r.clone();
                }
            } else {
                out.rules.push(r.clone());
            }
        }
        for rule in &incoming.system {
            if let Some(index) = out
                .system
                .iter()
                .position(|existing| existing.id == rule.id)
            {
                if replace {
                    out.system[index] = rule.clone();
                }
            } else {
                out.system.push(rule.clone());
            }
        }
        if replace {
            out.layout = incoming.layout.clone();
        }
        out.validate()?;
        out.resolve_sources()?;
        Ok(out)
    }
    /// 导入同时合并引用的目录；相同路径和匹配方式复用已有身份。
    fn merge_catalog(&mut self, incoming: &mut Self, replace: bool) {
        let mut mapping = std::collections::HashMap::new();
        for file in &incoming.log_files {
            if let Some(existing) = self.log_files.iter_mut().find(|x| {
                x.id == file.id
                    || (x.path == file.path && x.mode == file.mode && x.container == file.container)
            }) {
                mapping.insert(file.id.clone(), existing.id.clone());
                if replace {
                    let id = existing.id.clone();
                    *existing = file.clone();
                    existing.id = id;
                }
            } else {
                self.log_files.push(file.clone());
                mapping.insert(file.id.clone(), file.id.clone());
            }
        }
        for rule in &mut incoming.rules {
            for id in &mut rule.source_file_ids {
                if let Some(mapped) = mapping.get(id) {
                    *id = mapped.clone();
                }
            }
        }
        for rule in &mut incoming.system {
            if let Some(mapped) = mapping.get(&rule.source_file_id) {
                rule.source_file_id = mapped.clone();
            }
        }
        incoming.layout.file_order = incoming
            .layout
            .file_order
            .iter()
            .filter_map(|id| mapping.get(id).cloned())
            .collect();
    }
    pub fn defaults() -> Self {
        let mut rules: Self = serde_json::from_str(include_str!("../assets/default-rules.json"))
            .expect("内置规则无效");
        rules.resolve_sources().expect("内置日志引用无效");
        rules
    }
    pub fn log_file(&self, id: &str) -> Result<&LogFile> {
        self.log_files
            .iter()
            .find(|file| file.id == id)
            .with_context(|| format!("日志文件引用不存在：{id}"))
    }
    /// 展示名称只读取目录，改名不会改变规则身份、路径或报告关联键。
    pub fn source_label(&self, ids: &[String]) -> String {
        ids.iter()
            .filter_map(|id| self.log_file(id).ok())
            .map(LogFile::label)
            .collect::<Vec<_>>()
            .join("；")
    }
    /// 先完整解析后提交，缺失引用不会留下半更新的运行时来源。
    pub fn resolve_sources(&mut self) -> Result<()> {
        let keyword_sources = self
            .rules
            .iter()
            .map(|rule| {
                if rule.source_file_ids.is_empty() {
                    bail!("规则「{}」：请选择已维护的日志文件", rule.name);
                }
                let mut seen = std::collections::HashSet::new();
                rule.source_file_ids
                    .iter()
                    .map(|id| {
                        if !seen.insert(id) {
                            bail!("规则「{}」重复引用日志文件：{id}", rule.name);
                        }
                        self.log_file(id)?.source()
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let system_sources = self
            .system
            .iter()
            .map(|r| self.log_file(&r.source_file_id)?.source())
            .collect::<Result<Vec<_>>>()?;
        for (rule, sources) in self.rules.iter_mut().zip(keyword_sources) {
            rule.sources = sources;
        }
        for (rule, source) in self.system.iter_mut().zip(system_sources) {
            rule.source = source;
        }
        Ok(())
    }
    /// 目录编辑只提交有效候选项；调用方负责在整个编辑窗口保存时落盘。
    pub fn save_log_file(&mut self, file: LogFile) -> Result<()> {
        let mut next = self.clone();
        if let Some(existing) = next.log_files.iter_mut().find(|f| f.id == file.id) {
            *existing = file;
        } else {
            next.log_files.push(file);
        }
        next.validate_catalog()?;
        next.resolve_sources()?;
        *self = next;
        Ok(())
    }
    pub fn delete_log_file(&mut self, id: &str) -> Result<()> {
        self.log_file(id)?;
        let references = self
            .rules
            .iter()
            .filter(|r| r.source_file_ids.iter().any(|x| x == id))
            .map(|r| r.name.as_str())
            .chain(
                self.system
                    .iter()
                    .filter(|r| r.source_file_id == id)
                    .map(|r| r.name.as_str()),
            )
            .collect::<Vec<_>>();
        if !references.is_empty() {
            bail!(
                "日志文件仍被以下规则引用，请先调整或删除规则：{}",
                references.join("、")
            );
        }
        self.log_files.retain(|f| f.id != id);
        self.layout.file_order.retain(|x| x != id);
        Ok(())
    }
    pub fn validate_catalog(&self) -> Result<()> {
        let mut ids = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        let mut paths = std::collections::HashSet::new();
        for file in &self.log_files {
            if file.id.trim().is_empty() || !ids.insert(&file.id) {
                bail!("日志文件标识重复或为空：{}", file.name);
            }
            if file.name.trim().is_empty() || !names.insert(&file.name) {
                bail!("日志文件名称重复或为空：{}", file.name);
            }
            file.source()?;
            // 同一归档容器内的路径是唯一来源；匹配方式属于目录项属性，不能制造重复路径。
            if !paths.insert((&file.container, &file.path)) {
                bail!("日志文件路径重复：{}", file.path);
            }
        }
        if !(180..=360).contains(&self.layout.file_panel_width) {
            bail!("日志文件栏宽度须为 180～360");
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<Vec<String>> {
        self.validate_catalog()?;
        let mut resolved = self.clone();
        resolved.resolve_sources()?;
        resolved.validate_resolved()
    }
    fn validate_resolved(&self) -> Result<Vec<String>> {
        if self.version != 3 {
            bail!("不支持的规则格式版本：{}，请使用新版规则文件", self.version);
        }
        let mut ids = std::collections::HashSet::new();
        let mut warnings = vec![];
        for r in &self.rules {
            if !ids.insert(&r.id) {
                bail!("规则标识重复：{}", r.name);
            }
            if r.name.trim().is_empty()
                || r.terms.is_empty()
                || r.terms.iter().any(|s| s.is_empty())
            {
                bail!("规则「{}」：请填写名称和至少一个非空关键词", r.name);
            }
            if r.sources.is_empty() || r.sources.iter().any(|s| s.pattern.is_empty()) {
                bail!("规则「{}」：请选择日志范围", r.name);
            }
            Matcher::new(r).with_context(|| format!("规则「{}」正则无效", r.name))?;
            if !["any", "all"].contains(&r.mode.as_str())
                || !["keywords", "timeline", "both"].contains(&r.target.as_str())
                || !["source", "asc", "desc"].contains(&r.sort.as_str())
            {
                bail!("规则「{}」包含不支持的匹配或展示选项", r.name);
            }
            for source in &r.sources {
                validate_source(source)?;
            }
            if !r.timezone.is_empty()
                && !Regex::new(r"^[+-](?:0\d|1[0-4]):[0-5]\d$")?.is_match(&r.timezone)
            {
                bail!("规则「{}」时区格式应为 +08:00 或 -05:00", r.name);
            }
            if !r.time_format.is_empty()
                && chrono::format::StrftimeItems::new(&r.time_format)
                    .any(|x| matches!(x, chrono::format::Item::Error))
            {
                bail!("规则「{}」时间格式无效", r.name);
            }
            if !r.time_regex.is_empty() {
                Regex::new(&r.time_regex)
                    .with_context(|| format!("规则「{}」时间表达式无效", r.name))?;
            }
            if !r.regex && r.terms.iter().any(|s| s.contains(".*")) {
                warnings.push(format!("「{}」包含 .*，但使用普通关键词匹配", r.name));
            }
            if r.target == "timeline"
                && self
                    .timeline
                    .events
                    .iter()
                    .all(|event| event.id != format!("legacy-{}", r.id))
            {
                warnings.push(format!(
                    "旧时间线规则「{}」将在导入时迁移为基础事实事件",
                    r.name
                ));
            }
        }
        for (i, r) in self.rules.iter().enumerate() {
            if self.rules[..i].iter().any(|x| {
                x.terms == r.terms
                    && serde_json::to_string(&x.sources).ok()
                        == serde_json::to_string(&r.sources).ok()
                    && x.regex == r.regex
                    && x.mode == r.mode
                    && x.exclude == r.exclude
                    && x.before == r.before
                    && x.after == r.after
            }) {
                warnings.push(format!("「{}」与前面的规则匹配条件重复", r.name));
            }
        }
        for s in &self.system {
            validate_source(&s.source)?;
            if !["json", "kv", "sections", "columns", "regex"].contains(&s.kind.as_str())
                || !["cards", "table", "storage", "storage-smart"].contains(&s.view.as_str())
            {
                bail!("「{}」提取或展示方式不支持", s.name);
            }
            if (s.view == "storage" || s.view == "storage-smart")
                && (s.kind != "json"
                    || s.selector
                        != if s.view == "storage" {
                            "disk.devices[]"
                        } else {
                            "disk.devices[].smart_info.report[]"
                        })
            {
                bail!("「{}」存储展示需要 JSON 提取及对应的磁盘数组路径", s.name);
            }
            if s.kind == "regex" && s.pattern.is_empty() {
                bail!("「{}」请填写提取表达式", s.name);
            }
            if !ids.insert(&s.id) {
                bail!("信息组标识重复：{}", s.name);
            }
            if s.fields.is_empty()
                || s.fields
                    .iter()
                    .any(|f| f.name.is_empty() || f.path.is_empty())
            {
                bail!("「{}」需要至少一个有名称和来源的字段", s.name);
            }
            let mut names = std::collections::HashSet::new();
            for f in &s.fields {
                if !names.insert(&f.name) {
                    bail!("「{}」字段名称重复：{}", s.name, f.name);
                }
                if !f.capture.is_empty() {
                    Regex::new(&f.capture).with_context(|| {
                        format!("「{} / {}」字段提取表达式无效", s.name, f.name)
                    })?;
                }
                if !["", "bytes", "unix", "kib"].contains(&f.format.as_str())
                    || !["", "cards", "table"].contains(&f.view.as_str())
                {
                    bail!("「{} / {}」格式或展示方式无效", s.name, f.name);
                }
            }
            if !s.pattern.is_empty() {
                Regex::new(&s.pattern).with_context(|| format!("「{}」提取表达式无效", s.name))?;
            }
            if !s.join_rule.is_empty()
                && (!self.system.iter().any(|x| x.id == s.join_rule)
                    || s.join_rule == s.id
                    || s.join_key.is_empty()
                    || s.join_foreign_key.is_empty())
            {
                bail!("「{}」关联配置不完整", s.name);
            }
        }
        let mut timeline_ids = std::collections::HashSet::new();
        let event_types = [
            "boot",
            "systemd_ready",
            "shutdown_request",
            "shutdown_complete",
            "reboot_request",
            "reboot_complete",
            "kernel_panic",
            "watchdog_reset",
            "hardware_reset",
            "power_loss_hint",
            "filesystem_recovery",
            "device_reenumeration",
            "log_gap",
            "reset_reason",
            "evidence",
        ];
        for event in &self.timeline.events {
            if event.id.trim().is_empty() || !timeline_ids.insert(&event.id) {
                bail!("时间线事实事件标识重复或为空：{}", event.id);
            }
            if !event_types.contains(&event.event_type.as_str()) {
                bail!(
                    "时间线事实事件「{}」类型不支持：{}",
                    event.id,
                    event.event_type
                );
            }
            if event.terms.is_empty() {
                bail!("时间线事实事件「{}」至少需要一个关键词", event.id);
            }
            if !["strong", "medium", "weak"].contains(&event.evidence_strength.as_str()) {
                bail!(
                    "时间线事实事件「{}」证据等级不支持：{}",
                    event.id,
                    event.evidence_strength
                );
            }
            for id in &event.source_file_ids {
                self.log_file(id).with_context(|| {
                    format!("时间线事实事件「{}」引用的日志不存在：{}", event.id, id)
                })?;
            }
            if event.regex {
                for term in &event.terms {
                    Regex::new(term)
                        .with_context(|| format!("时间线事实事件「{}」正则无效", event.id))?;
                }
            }
        }
        for judgement in &self.timeline.judgements {
            if judgement.id.trim().is_empty() || !timeline_ids.insert(&judgement.id) {
                bail!("时间线判定规则标识重复或为空：{}", judgement.id);
            }
            if judgement.output.trim().is_empty() {
                bail!("时间线判定规则「{}」必须填写输出结论", judgement.id);
            }
            if !["high", "medium", "low"].contains(&judgement.confidence.as_str()) {
                bail!(
                    "时间线判定规则「{}」置信度不支持：{}",
                    judgement.id,
                    judgement.confidence
                );
            }
        }
        if self.timeline.thresholds.match_window_seconds == 0
            || self.timeline.thresholds.gap_seconds == 0
        {
            bail!("时间线匹配窗口和日志断档阈值必须大于 0 秒");
        }
        if !Regex::new(r"^#[0-9a-fA-F]{6}$")?.is_match(&self.layout.accent)
            || !(10..=24).contains(&self.layout.font_size)
        {
            bail!("报告样式：颜色需为 #RRGGBB，字号需为 10 至 24");
        }
        if !(10..=5000).contains(&self.layout.log_lines_per_batch) {
            bail!("报告样式：每批显示行数需为 10 至 5000");
        }
        Ok(warnings)
    }
    pub fn import(text: &str) -> Result<Self> {
        let mut rules: Self = serde_json::from_str(text)
            .context("规则 JSON 无效，请使用包含日志文件目录的新版规则")?;
        rules.validate()?;
        rules.resolve_sources()?;
        Ok(rules)
    }

    /// 将旧 target=timeline 规则转换为基础事实规则，只迁移识别条件，不猜测会话语义。
    fn migrate_legacy_timeline_rules(&mut self) {
        for rule in self.rules.iter().filter(|r| r.target == "timeline") {
            let id = format!("legacy-{}", rule.id);
            if self.timeline.events.iter().any(|event| event.id == id) {
                continue;
            }
            self.timeline.events.push(TimelineEventRule {
                id,
                event_type: "evidence".into(),
                source_file_ids: rule.source_file_ids.clone(),
                terms: rule.terms.clone(),
                regex: rule.regex,
                evidence_strength: "medium".into(),
                time_regex: rule.time_regex.clone(),
                time_format: rule.time_format.clone(),
                note: rule.note.clone(),
            });
        }
    }
}
fn validate_source(s: &Source) -> Result<()> {
    if s.pattern.trim().is_empty() || !["prefix", "path", "exact"].contains(&s.mode.as_str()) {
        bail!("日志来源不能为空，匹配方式需为前缀、路径片段或精确路径");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn combination_exclusion_and_case() {
        let r = Rule {
            terms: vec!["ATA".into(), "reset".into()],
            mode: "all".into(),
            exclude: vec!["success".into()],
            case_sensitive: false,
            ..Rule::default()
        };
        let m = Matcher::new(&r).unwrap();
        assert!(m.matches("ata reset"));
        assert!(!m.matches("ata reset success"));
        assert!(!m.matches("ata"));
    }
}
