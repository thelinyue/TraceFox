use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub system: Vec<SystemRule>,
    #[serde(default)]
    pub layout: Layout,
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
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
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
            // 不带目录的旧配置继续按文件名匹配。
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
        let defaults = Self::defaults();
        out.system = defaults.system.clone();
        out.system.extend(
            self.system
                .iter()
                .filter(|r| !defaults.system.iter().any(|x| x.id == r.id))
                .cloned(),
        );
        out.validate()?;
        Ok(out)
    }

    /// 合并以标识优先，名称仅作为兼容回退；保留现有标识，避免关联字段因替换失效。
    pub fn merge(&self, incoming: &Self, replace: bool) -> Result<Self> {
        let mut out = self.clone();
        for r in &incoming.rules {
            let found = out.rules.iter().position(|x| x.id == r.id).or_else(|| {
                out.rules
                    .iter()
                    .position(|x| x.name == r.name && x.group == r.group)
            });
            if let Some(i) = found {
                if replace {
                    let mut new = r.clone();
                    new.id = out.rules[i].id.clone();
                    out.rules[i] = new;
                }
            } else {
                out.rules.push(r.clone());
            }
        }
        let mut map = std::collections::HashMap::new();
        for r in &incoming.system {
            let existing = out.system.iter().find(|x| x.id == r.id).or_else(|| {
                out.system
                    .iter()
                    .find(|x| x.name == r.name && x.group == r.group)
            });
            map.insert(
                r.id.clone(),
                existing
                    .map(|x| x.id.clone())
                    .unwrap_or_else(|| r.id.clone()),
            );
        }
        for r in &incoming.system {
            let mut new = r.clone();
            new.id = map[&r.id].clone();
            if let Some(id) = map.get(&r.join_rule) {
                new.join_rule = id.clone();
            }
            if let Some(i) = out.system.iter().position(|x| x.id == new.id) {
                if replace {
                    out.system[i] = new;
                }
            } else {
                out.system.push(new);
            }
        }
        if replace {
            out.layout = incoming.layout.clone();
        }
        out.validate()?;
        Ok(out)
    }
    pub fn defaults() -> Self {
        serde_json::from_str(include_str!("../assets/default-rules.json")).expect("内置规则无效")
    }
    pub fn validate(&self) -> Result<Vec<String>> {
        if self.version != 2 {
            bail!("不支持的规则格式版本：{}", self.version);
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
        let v: Value = serde_json::from_str(text).context("文件不是有效的 JSON")?;
        if v.get("version").is_some() {
            let r: Self = serde_json::from_value(v)?;
            r.validate()?;
            return Ok(r);
        }
        let files = v["files"]
            .as_array()
            .context("缺少 files 或 version 字段")?;
        let mut out = Self {
            version: 2,
            rules: vec![],
            system: vec![],
            layout: Layout::default(),
        };
        for (fi, f) in files.iter().enumerate() {
            let name = f["name"].as_str().context("文件范围缺少 name")?;
            for (ki, k) in f["keywords"]
                .as_array()
                .context("缺少 keywords")?
                .iter()
                .enumerate()
            {
                let n = k["context_lines"].as_u64().unwrap_or(0) as usize;
                let up = k["context_direction"] == "up";
                out.rules.push(Rule {
                    id: format!("legacy-{fi}-{ki}"),
                    name: k["result"].as_str().unwrap_or("日志线索").into(),
                    group: f["category"].as_str().unwrap_or(name).into(),
                    sources: vec![Source {
                        pattern: name.into(),
                        mode: if name.contains('/') { "path" } else { "prefix" }.into(),
                    }],
                    terms: vec![k["term"].as_str().context("关键词缺少 term")?.into()],
                    regex: k["regex"].as_bool().unwrap_or(false),
                    note: k["result"].as_str().unwrap_or("").into(),
                    before: if up { n } else { 0 },
                    after: if up { 0 } else { n },
                    reverse: k["search_direction"] == "up",
                    fmt: k["fmt"].as_str().unwrap_or("").into(),
                    legacy_group: fi.to_string(),
                    ..Rule::default()
                });
            }
        }
        out.validate()?;
        Ok(out)
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
    #[test]
    fn legacy_context() {
        let r=RuleSet::import(r#"{"files":[{"name":"kern","keywords":[{"term":"abc","context_lines":2,"context_direction":"up"}]}]}"#).unwrap();
        assert_eq!(r.rules[0].before, 2);
        assert_eq!(r.rules[0].after, 0);
    }
}
