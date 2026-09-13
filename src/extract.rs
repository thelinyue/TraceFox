use crate::rules::{Field, SystemRule};
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// 专用存储视图的来源身份；磁盘数组位置只在同一个来源文件内有效。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageContext {
    pub device: usize,
    pub pool: String,
    pub label: String,
    #[serde(default)]
    pub raid: String,
    /// 磁盘原始 disk_info 字段，供报告详情展示未知及嵌套字段。
    #[serde(default)]
    pub details: Vec<(String, String)>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Table {
    pub id: String,
    pub name: String,
    pub group: String,
    pub view: String,
    pub fields: Vec<Field>,
    pub rows: Vec<BTreeMap<String, String>>,
    #[serde(default)]
    pub storage: Vec<StorageContext>,
    /// lsblk 原始日志文本；仅为块设备规则保留，供报告底部的证据面板展示。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw_text: String,
    pub source: String,
    pub warning: String,
}
/// 支持点路径和 [] 数组展开；$parent 可引用上一级数组对象，用于保留 SMART 所属磁盘。
fn select<'a>(v: &'a Value, path: &str) -> Vec<&'a Value> {
    if path.is_empty() || path == "$" {
        return vec![v];
    }
    let mut values = vec![v];
    for part in path.trim_start_matches("$.").split('.') {
        let array = part.ends_with("[]");
        let key = part.trim_end_matches("[]");
        let mut next = vec![];
        for v in values {
            let item = if key.is_empty() { Some(v) } else { v.get(key) };
            if let Some(x) = item {
                if array {
                    if let Some(a) = x.as_array() {
                        next.extend(a);
                    }
                } else {
                    next.push(x);
                }
            }
        }
        values = next;
    }
    values
}
fn val(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(val).collect::<Vec<_>>().join("\n"),
        _ => v.to_string(),
    }
}
fn formatted(raw: String, f: &Field, captures: &HashMap<String, Regex>) -> String {
    let raw = if f.capture.is_empty() {
        raw
    } else {
        captures
            .get(&f.capture)
            .and_then(|r| {
                r.captures(&raw)
                    .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
            })
            .unwrap_or_default()
    };
    if raw.is_empty() {
        return f.missing.clone();
    }
    let mut value = raw.clone();
    if f.format == "bytes" || f.format == "kib" {
        if let Ok(n) = raw.parse::<f64>() {
            let mut n = if f.format == "kib" { n * 1024.0 } else { n };
            let u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
            let mut i = 0;
            while n >= 1024.0 && i < u.len() - 1 {
                n /= 1024.0;
                i += 1;
            }
            value = format!("{n:.2} {}", u[i]);
        }
    }
    if f.format == "unix" {
        if let Ok(n) = raw.parse::<i64>() {
            if let Some(d) = chrono::DateTime::from_timestamp(n, 0) {
                value = d.to_rfc3339();
            }
        }
    }
    if !f.unit.is_empty() {
        value.push(' ');
        value.push_str(&f.unit);
    }
    value
}

/// 判断系统规则是否描述 lsblk，兼容默认规则和用户自定义的规则标识。
fn is_lsblk_rule(rule: &SystemRule) -> bool {
    rule.id.eq_ignore_ascii_case("block")
        || rule.id.to_ascii_lowercase().contains("lsblk")
        || rule.name.to_ascii_lowercase().contains("lsblk")
        || rule.source.pattern.to_ascii_lowercase().contains("lsblk")
}
pub fn json_paths(v: &Value, prefix: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                json_paths(
                    v,
                    &if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    },
                    out,
                )
            }
        }
        Value::Array(a) => {
            if let Some(v) = a.first() {
                json_paths(v, &format!("{prefix}[]"), out)
            }
        }
        _ => out.push(prefix.into()),
    }
}
/// 单次分析内复用字段捕获和整段提取正则；不缓存来源文本，避免跨文件占用内存。
pub(crate) struct PreparedExtractor<'a> {
    rule: &'a SystemRule,
    captures: HashMap<String, Regex>,
    pattern: Option<Regex>,
}
impl<'a> PreparedExtractor<'a> {
    pub(crate) fn new(rule: &'a SystemRule) -> Result<Self> {
        let mut captures = HashMap::new();
        for field in &rule.fields {
            if !field.capture.is_empty() && !captures.contains_key(&field.capture) {
                if let Ok(regex) = Regex::new(&field.capture) {
                    captures.insert(field.capture.clone(), regex);
                }
            }
        }
        let pattern = if rule.kind == "regex" {
            Some(Regex::new(&rule.pattern)?)
        } else {
            None
        };
        Ok(Self {
            rule,
            captures,
            pattern,
        })
    }
    /// 调用者可提供当前文件已解析的 JSON；独立预览仍在本方法中解析。
    pub(crate) fn extract(&self, text: &str, source: &str, json: Option<&Value>) -> Result<Table> {
        extract_prepared(self, text, source, json)
    }
}
fn extract_prepared(
    prepared: &PreparedExtractor<'_>,
    text: &str,
    source: &str,
    json: Option<&Value>,
) -> Result<Table> {
    let rule = prepared.rule;
    let formatted = |raw, field| formatted(raw, field, &prepared.captures);
    let mut table = Table {
        id: rule.id.clone(),
        name: rule.name.clone(),
        group: rule.group.clone(),
        view: rule.view.clone(),
        fields: rule.fields.clone(),
        rows: vec![],
        storage: vec![],
        raw_text: is_lsblk_rule(rule)
            .then(|| text.to_owned())
            .unwrap_or_default(),
        source: source.into(),
        warning: String::new(),
    };
    match rule.kind.as_str() {
        "json" => {
            let parsed;
            let root = if let Some(json) = json {
                json
            } else {
                parsed = serde_json::from_str(text).context("JSON 内容无法解析")?;
                &parsed
            };
            // 一次展开当前选择路径；字段可通过 $root 显式回到根，避免混淆不同设备。
            let (parent_path, child_path) = rule
                .selector
                .rsplit_once("[].")
                .map(|(a, b)| (format!("{a}[]"), b.to_owned()))
                .unwrap_or((String::new(), rule.selector.clone()));
            for (parent_index, parent) in select(root, &parent_path).into_iter().enumerate() {
                for (item_index, item) in select(parent, &child_path).into_iter().enumerate() {
                    let mut row = BTreeMap::new();
                    for f in &rule.fields {
                        let (v, p) = if let Some(p) = f.path.strip_prefix("$root.") {
                            (root, p)
                        } else if let Some(p) = f.path.strip_prefix("$parent.") {
                            (parent, p)
                        } else {
                            (item, f.path.as_str())
                        };
                        row.insert(
                            f.name.clone(),
                            formatted(select(v, p).first().map(|v| val(v)).unwrap_or_default(), f),
                        );
                    }
                    if rule.view == "storage" || rule.view == "storage-smart" {
                        let disk = if rule.view == "storage" { item } else { parent };
                        let info = &disk["disk_info"];
                        let details = info
                            .as_object()
                            .map(|o| o.iter().map(|(k, v)| (k.clone(), val(v))).collect())
                            .unwrap_or_default();
                        table.storage.push(StorageContext {
                            device: if rule.view == "storage" {
                                item_index
                            } else {
                                parent_index
                            },
                            pool: info["used_for"].as_str().unwrap_or("").into(),
                            label: info["label"]
                                .as_str()
                                .or(info["name"].as_str())
                                .unwrap_or("未命名硬盘")
                                .into(),
                            raid: String::new(),
                            details,
                        });
                    }
                    table.rows.push(row);
                }
            }
        }
        "regex" => {
            let re = prepared.pattern.as_ref().expect("正则规则已预编译");
            for caps in re.captures_iter(text) {
                let mut row = BTreeMap::new();
                for f in &rule.fields {
                    let m = if let Ok(i) = f.path.parse::<usize>() {
                        caps.get(i)
                    } else {
                        caps.name(&f.path)
                    };
                    row.insert(
                        f.name.clone(),
                        formatted(m.map(|m| m.as_str().to_owned()).unwrap_or_default(), f),
                    );
                }
                table.rows.push(row);
            }
        }
        "kv" | "sections" => {
            let chunks: Vec<&str> = if rule.kind == "sections" {
                text.split("\n\n").collect()
            } else {
                vec![text]
            };
            for chunk in chunks {
                if !rule.selector.is_empty() && !chunk.lines().any(|l| l.trim() == rule.selector) {
                    continue;
                }
                let mut values = BTreeMap::new();
                for line in chunk.lines() {
                    if let Some((k, v)) = line.trim().split_once(':') {
                        values.insert(k.trim(), v.trim());
                    }
                }
                let mut row = BTreeMap::new();
                let mut found = false;
                for f in &rule.fields {
                    let raw = values.get(f.path.as_str()).copied().unwrap_or("");
                    found |= !raw.is_empty();
                    row.insert(f.name.clone(), formatted(raw.into(), f));
                }
                if found {
                    table.rows.push(row);
                }
            }
        }
        "columns" => {
            let mut lines = text.lines();
            let header = lines.next().unwrap_or("");
            let re = Regex::new(r"\S+")?;
            let names: Vec<_> = re.find_iter(header).collect();
            let mut last: Option<BTreeMap<String, String>> = None;
            for line in lines {
                if line.trim().is_empty() {
                    continue;
                }
                // 按字符列取值，保持树形前缀和多挂载点续行，不按空格拆散路径。
                let chars: Vec<char> = line.chars().collect();
                let mut vals = BTreeMap::new();
                for (i, h) in names.iter().enumerate() {
                    let start = header[..h.start()].chars().count();
                    let end = names
                        .get(i + 1)
                        .map(|n| header[..n.start()].chars().count())
                        .unwrap_or(chars.len())
                        .min(chars.len());
                    let s = if start < end {
                        chars[start..end]
                            .iter()
                            .collect::<String>()
                            .trim()
                            .to_owned()
                    } else {
                        String::new()
                    };
                    vals.insert(h.as_str(), s);
                }
                if vals
                    .get(names.first().map(|x| x.as_str()).unwrap_or(""))
                    .is_none_or(|s| s.is_empty())
                {
                    if let Some(row) = last.as_mut() {
                        for f in &rule.fields {
                            if let Some(v) = vals.get(f.path.as_str()).filter(|v| !v.is_empty()) {
                                let cell = row.entry(f.name.clone()).or_default();
                                cell.push('\n');
                                cell.push_str(v);
                            }
                        }
                    }
                    continue;
                }
                if let Some(r) = last.take() {
                    table.rows.push(r);
                }
                let mut row = BTreeMap::new();
                for f in &rule.fields {
                    row.insert(
                        f.name.clone(),
                        formatted(vals.get(f.path.as_str()).cloned().unwrap_or_default(), f),
                    );
                }
                last = Some(row);
            }
            if let Some(r) = last {
                table.rows.push(r);
            }
        }
        other => anyhow::bail!("不支持的提取方式：{other}"),
    }
    if table.storage.is_empty() {
        table
            .rows
            .retain(|row| row.values().any(|value| !value.is_empty()));
    }
    if table.rows.is_empty() {
        table.warning = rule.missing.clone();
    }
    Ok(table)
}

pub fn extract(rule: &SystemRule, text: &str, source: &str) -> Result<Table> {
    PreparedExtractor::new(rule)?.extract(text, source, None)
}
pub fn join_tables(tables: &mut Vec<Table>, rules: &[SystemRule]) {
    let originals = tables.clone();
    for rule in rules.iter().filter(|r| !r.join_rule.is_empty()) {
        let donors: Vec<_> = originals
            .iter()
            .filter(|t| t.id == rule.join_rule)
            .collect();
        for target in tables.iter_mut().filter(|t| t.id == rule.id) {
            let mut ambiguous = false;
            for row in &mut target.rows {
                let key = row.get(&rule.join_key).cloned().unwrap_or_default();
                if key.is_empty() {
                    continue;
                }
                let matches: Vec<_> = donors
                    .iter()
                    .flat_map(|t| &t.rows)
                    .filter(|r| r.get(&rule.join_foreign_key) == Some(&key))
                    .collect();
                if matches.len() == 1 {
                    for (k, v) in matches[0] {
                        row.entry(k.clone()).or_insert(v.clone());
                    }
                } else {
                    ambiguous = true;
                }
            }
            for donor in &donors {
                for f in &donor.fields {
                    if !target.fields.iter().any(|x| x.name == f.name) {
                        target.fields.push(f.clone());
                    }
                }
            }
            if ambiguous {
                target.warning = "部分关联键缺失或不唯一，未合并的来源保留独立展示".into();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arrays_keep_disk_parent() {
        let r = SystemRule {
            selector: "disk.devices[].smart.report[]".into(),
            fields: vec![
                Field {
                    name: "盘".into(),
                    path: "$parent.name".into(),
                    format: String::new(),
                    unit: String::new(),
                    missing: String::new(),
                    wide: false,
                    view: String::new(),
                    capture: String::new(),
                },
                Field {
                    name: "值".into(),
                    path: "raw".into(),
                    format: String::new(),
                    unit: String::new(),
                    missing: String::new(),
                    wide: false,
                    view: String::new(),
                    capture: String::new(),
                },
            ],
            ..SystemRule::default()
        };
        let t=extract(&r,r#"{"disk":{"devices":[{"name":"a","smart":{"report":[{"raw":1}]}},{"name":"b","smart":{"report":[{"raw":2}]}}]}}"#,"x").unwrap();
        assert_eq!(t.rows[1]["盘"], "b");
        assert_eq!(t.rows.len(), 2);
    }
    #[test]
    fn lsblk_rule_keeps_complete_source_text() {
        let rule = SystemRule {
            id: "block".into(),
            source: crate::rules::Source {
                pattern: "cmd/lsblk.log".into(),
                mode: "exact".into(),
            },
            kind: "columns".into(),
            ..SystemRule::default()
        };
        let text = "NAME TYPE\npool1-md0 linear\n";
        let table = extract(&rule, text, "cmd/lsblk.log").unwrap();
        assert_eq!(table.raw_text, text);
    }
}
