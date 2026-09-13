use crate::{
    extract::{self, Table},
    rules::{Matcher, Rule, RuleSet},
};
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{Datelike, FixedOffset, TimeZone, Timelike, Utc};
use flate2::{Compression, read::MultiGzDecoder, write::GzEncoder};
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
    /// 结构化事实类型；旧时间线规则未声明时由名称和内容推断。
    pub event_type: String,
    pub evidence_strength: String,
    pub time_precision: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct TimelineSession {
    pub session_id: String,
    pub boot_time: String,
    pub boot_time_precision: String,
    /// 面向报告展示的异常或结束时间；范围用于表达只能从恢复记录和下次启动之间定位的情况。
    pub incident_time_start: String,
    pub incident_time_end: Option<String>,
    pub incident_time_precision: String,
    pub boot_id: Option<String>,
    pub facts: Vec<Event>,
    pub end_classification: String,
    pub confidence: String,
    pub supporting_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

/// 将旧版自由文本时间线规则映射为稳定的事实事件类型。
/// 这里只做保守识别，无法确认原因时保留 unknown，避免把关键词误当成故障结论。
fn classify_timeline_event(name: &str, text: &str) -> String {
    let s = format!("{} {}", name, text).to_ascii_lowercase();
    if s.contains("kernel panic")
        || s.contains("panic - not syncing")
        || s.contains(" oops:")
        || s.starts_with("oops:")
        || s.contains(" call trace:")
        || s.starts_with("call trace:")
    {
        "kernel_panic"
    } else if s.contains("watchdog") {
        "watchdog_reset"
    } else if s.contains("do poweroff proc info")
        || s.contains("reached target shutdown")
        || s.contains("systemd-shutdown")
        || s.contains("powering off")
        || s.contains("关机流程")
    {
        "shutdown_request"
    } else if s.contains("do reboot proc info")
        || s.contains("reached target reboot")
        || s.contains("reboot: restarting system")
        || s.contains("重启流程")
    {
        "reboot_request"
    } else if s.contains("linux version") {
        "boot"
    } else if s.contains("recovery complete") {
        "filesystem_recovery"
    } else if s.contains("sata link up") || s.contains("attached scsi") {
        "device_reenumeration"
    } else if s.contains("unknown") {
        "reset_reason"
    } else {
        "evidence"
    }
    .into()
}

/// 不依赖用户规则识别少量稳定的 Linux 生命周期事实。这里输出事实，不直接输出故障结论。
fn automatic_timeline_event(file: &str, line: &str, number: usize) -> Option<Event> {
    let lower = line.to_ascii_lowercase();
    let (event_type, name, strength) = if lower.contains("linux version") {
        ("boot", "系统启动", "strong")
    } else if lower.contains("kernel panic - not syncing")
        || lower.contains("panic - not syncing")
        || lower.contains(" oops:")
        || lower.starts_with("oops:")
        || lower.contains(" call trace:")
        || lower.starts_with("call trace:")
    {
        ("kernel_panic", "Kernel Panic / Oops", "strong")
    } else if (lower.contains("watchdog") && (lower.contains("reset") || lower.contains("reboot")))
        || lower.contains("hard lockup")
        || lower.contains("soft lockup")
    {
        ("watchdog_reset", "Watchdog 复位", "strong")
    } else if lower.contains("reached target shutdown")
        || lower.contains("systemd-shutdown")
        || lower.contains("powering off")
        || lower.contains("do poweroff proc info")
    {
        ("shutdown_request", "系统关机流程", "strong")
    } else if lower.contains("reached target reboot")
        || lower.contains("reboot: restarting system")
        || lower.contains("systemd reboot")
    {
        ("reboot_request", "系统重启流程", "strong")
    } else if lower.contains("recovery complete")
        || lower.contains("recovering journal")
        || lower.contains("ext4-fs") && lower.contains("recovery")
    {
        ("filesystem_recovery", "文件系统恢复", "medium")
    } else if lower.contains("sata link up")
        || lower.contains("attached scsi disk")
        || lower.contains("ata[0-9].*link up")
    {
        ("device_reenumeration", "存储设备重新枚举", "medium")
    } else if (lower.contains(" md") || lower.contains("raid"))
        && (lower.contains("assemble") || lower.contains("started") || lower.contains("recovery"))
    {
        ("device_reenumeration", "RAID 阵列重新组装", "medium")
    } else {
        return None;
    };
    let (time, key) = event_time_prepared(line, &Rule::default(), None);
    let time_precision = if key.is_some() { "exact" } else { "partial" };
    Some(Event {
        name: name.into(),
        group: "系统时间线事实".into(),
        time,
        key,
        note: "由通用 Linux 日志结构识别，需结合其他事实推断会话结束原因".into(),
        sources: vec![Fragment {
            file: file.into(),
            lines: vec![LogLine {
                number,
                text: line.into(),
                hit: true,
                ranges: vec![],
            }],
            time: String::new(),
            annotation: "自动识别的日志事实".into(),
        }],
        event_type: event_type.into(),
        evidence_strength: strength.into(),
        time_precision: time_precision.into(),
    })
}

/// 解析 UGOS 的 pstore 复位原因块。该文件不是普通逐行关键词日志，必须按块保留 boot_id 与原因字段。
fn parse_reset_reason_blocks(name: &str, text: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let mut block = Vec::new();
    let flush = |block: &mut Vec<(usize, String)>, events: &mut Vec<Event>| {
        if block.is_empty() {
            return;
        }
        let joined = block
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let boot_id = block
            .iter()
            .find_map(|(_, line)| line.strip_prefix("# boot_id:").map(str::trim));
        let boot_time = block.iter().find_map(|(_, line)| {
            line.strip_prefix("  Boot Time")
                .and_then(|v| v.split_once(' ').map(|(_, value)| value.trim()))
        });
        let cause = block
            .iter()
            .find_map(|(_, line)| line.strip_prefix("│ REBOOT CAUSE:").map(str::trim));
        let reason = block.iter().find_map(|(_, line)| {
            line.strip_prefix("  Reason")
                .and_then(|v| v.split_once(' ').map(|(_, value)| value.trim()))
        });
        let source = block.iter().find_map(|(_, line)| {
            line.strip_prefix("  Source")
                .and_then(|v| v.split_once(' ').map(|(_, value)| value.trim()))
        });
        let sw = block.iter().find_map(|(_, line)| {
            line.strip_prefix("  SW")
                .and_then(|v| v.split_once(' ').map(|(_, value)| value.trim()))
        });
        let hw = block.iter().find_map(|(_, line)| {
            line.strip_prefix("  HW")
                .and_then(|v| v.split_once(' ').map(|(_, value)| value.trim()))
        });
        let Some(cause) = cause.or(reason) else {
            block.clear();
            return;
        };
        let time = boot_time.unwrap_or("时间未识别").to_string();
        let key = parse_vendor_boot_key(boot_time);
        let event_type = if cause.contains("Kernel Panic")
            || reason.is_some_and(|r| r.eq_ignore_ascii_case("kernel_panic"))
        {
            "kernel_panic"
        } else if cause.contains("NORMAL — Shutdown")
            || reason.is_some_and(|r| r.eq_ignore_ascii_case("poweroff"))
        {
            "shutdown_complete"
        } else if cause.contains("NORMAL — Reboot")
            || reason.is_some_and(|r| r.eq_ignore_ascii_case("normal_reboot"))
        {
            "reboot_complete"
        } else if cause.contains("POWER")
            || cause.contains("Power")
            || reason.is_some_and(|r| r.eq_ignore_ascii_case("power_loss"))
        {
            "power_loss_hint"
        } else if cause.to_ascii_lowercase().contains("watchdog")
            || reason.is_some_and(|r| r.eq_ignore_ascii_case("watchdog"))
        {
            "watchdog_reset"
        } else if cause.to_ascii_lowercase().contains("hardware")
            || reason.is_some_and(|r| r.eq_ignore_ascii_case("hardware_reset"))
        {
            "hardware_reset"
        } else {
            "reset_reason"
        };
        let strength = if event_type == "reset_reason" {
            "high"
        } else {
            "strong"
        };
        let source_line = block.first().map(|(line, _)| *line).unwrap_or(1);
        events.push(Event {
            name: format!("厂商复位原因：{}", cause),
            group: "系统事件".into(),
            time,
            key,
            note: format!(
                "boot_id：{}；原始复位原因：{}；Source：{}；SW：{}；HW：{}",
                boot_id.unwrap_or("未提供"),
                cause,
                source.unwrap_or("未提供"),
                sw.unwrap_or("未提供"),
                hw.unwrap_or("未提供")
            ),
            sources: vec![Fragment {
                file: name.to_string(),
                lines: vec![LogLine {
                    number: source_line,
                    text: joined,
                    hit: true,
                    ranges: vec![],
                }],
                time: boot_time.unwrap_or("时间未识别").to_string(),
                annotation: "pstore 结构化复位原因块".into(),
            }],
            event_type: event_type.into(),
            evidence_strength: strength.into(),
            time_precision: if boot_time.is_some() {
                "exact"
            } else {
                "unknown"
            }
            .into(),
        });
        block.clear();
    };
    for (index, line) in text.lines().enumerate() {
        if line.contains("# BEGIN ug_reset_reason") {
            block.clear();
        }
        if !block.is_empty() || line.contains("# BEGIN ug_reset_reason") {
            block.push((index + 1, line.to_string()));
        }
        if line.contains("# END ug_reset_reason") {
            flush(&mut block, &mut events);
        }
    }
    flush(&mut block, &mut events);
    events
}

/// 按启动事实建立可审计的启动会话；结论只使用明确事实，未知原因不会升级为断电。
fn build_timeline_sessions(events: &[Event], match_window_seconds: i64) -> Vec<TimelineSession> {
    let mut ordered = events.to_vec();
    ordered.sort_by(|a, b| a.key.cmp(&b.key).then_with(|| a.time.cmp(&b.time)));
    let mut sessions = Vec::new();
    let boot_candidates = ordered
        .iter()
        .enumerate()
        .filter_map(|(i, e)| (e.event_type == "boot").then_some(i))
        .collect::<Vec<_>>();
    let exact_boot_candidates = boot_candidates
        .iter()
        .copied()
        .filter(|&i| ordered[i].key.is_some())
        .collect::<Vec<_>>();
    let mut boot_positions = if boot_candidates.is_empty() {
        ordered
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                e.sources
                    .iter()
                    .any(|s| s.annotation == "pstore 结构化复位原因块")
                    .then_some(i)
            })
            .collect::<Vec<_>>()
    } else if exact_boot_candidates.is_empty() {
        boot_candidates
    } else {
        exact_boot_candidates
    };
    // 同一启动可能同时命中“Linux version”和“NUL 前 Linux version”规则，只保留一个启动锚点。
    let mut unique_boots: Vec<usize> = Vec::new();
    for position in boot_positions.drain(..) {
        let duplicate = unique_boots.iter().any(|&prior| {
            ordered[prior].key.is_some() && ordered[prior].key == ordered[position].key
        });
        if !duplicate {
            unique_boots.push(position);
        }
    }
    let boot_positions = unique_boots;
    for (idx, &position) in boot_positions.iter().enumerate() {
        let event = &ordered[position];
        let next_boot = boot_positions.get(idx + 1).map(|&next| &ordered[next]);
        let mut facts = ordered
            .iter()
            .filter(|candidate| event_belongs_to_session(candidate, event, next_boot))
            .take(128)
            .cloned()
            .collect::<Vec<_>>();
        // pstore 原因通常与 Linux version 同一启动时间，但文件行序可能排在启动事实之前；
        // 按五分钟窗口补入同一会话，避免重复会话或丢失厂商原因。
        let extra_vendor_facts = ordered
            .iter()
            .filter(|candidate| {
                candidate
                    .sources
                    .iter()
                    .any(|s| s.annotation == "pstore 结构化复位原因块")
                    && !facts
                        .iter()
                        .any(|fact| fact.name == candidate.name && fact.time == candidate.time)
                    && candidate.key.as_deref() >= event.key.as_deref()
                    && same_time_window(&event.key, &candidate.key, match_window_seconds)
            })
            .cloned()
            .collect::<Vec<_>>();
        facts.extend(extra_vendor_facts);
        facts.sort_by(|a, b| a.key.cmp(&b.key).then_with(|| a.time.cmp(&b.time)));
        let has_panic = facts.iter().any(|e| e.event_type == "kernel_panic");
        let has_watchdog = facts.iter().any(|e| e.event_type == "watchdog_reset");
        let has_hardware_reset = facts.iter().any(|e| e.event_type == "hardware_reset");
        let has_shutdown = facts.iter().any(|e| e.event_type == "shutdown_request");
        let has_reboot = facts.iter().any(|e| e.event_type == "reboot_request");
        let vendor_shutdown = facts.iter().any(|e| e.event_type == "shutdown_complete");
        let vendor_reboot = facts.iter().any(|e| e.event_type == "reboot_complete");
        let (classification, confidence, evidence) = if has_panic {
            (
                "Kernel Panic 重启",
                "高",
                vec!["发现系统内核崩溃记录".into()],
            )
        } else if has_watchdog {
            (
                "Watchdog 重启",
                "高",
                vec!["系统在无响应后触发了自动复位".into()],
            )
        } else if has_hardware_reset {
            ("硬件复位", "高", vec!["设备记录到硬件复位".into()])
        } else if has_reboot || vendor_reboot {
            ("正常重启", "高", vec!["找到完整的正常重启记录".into()])
        } else if has_shutdown || vendor_shutdown {
            ("正常关机", "高", vec!["找到正常关机流程记录".into()])
        } else if facts.iter().any(|e| {
            e.event_type == "filesystem_recovery" || e.event_type == "device_reenumeration"
        }) {
            let mut evidence = Vec::new();
            if facts.iter().any(|e| e.event_type == "device_reenumeration") {
                evidence.push("硬盘在启动过程中被重新识别".into());
            }
            if facts.iter().any(|e| e.event_type == "filesystem_recovery") {
                evidence.push("文件系统执行过异常中断恢复".into());
            }
            if !has_shutdown && !has_reboot && !vendor_shutdown && !vendor_reboot {
                evidence.push("没有找到正常关机或重启记录".into());
            }
            ("疑似断电", "中", evidence)
        } else {
            (
                "未知复位",
                "低",
                vec!["没有足够记录判断上次关机原因".into()],
            )
        };
        let (incident_time_start, incident_time_end, incident_time_precision) =
            session_incident_time(
                classification,
                &facts,
                event,
                next_boot,
                match_window_seconds,
            );
        let boot_id = facts.iter().find_map(extract_boot_id);
        let mut limitations = Vec::new();
        if facts.iter().any(|fact| fact.event_type == "reset_reason") {
            limitations.push("设备自身没有记录明确原因".into());
        }
        if classification == "疑似断电" {
            limitations.push("没有直接的电源状态记录".into());
        }
        if event.key.is_none() || facts.iter().any(|fact| fact.time_precision == "partial") {
            limitations.push("部分日志时间可能存在少量偏差".into());
        }
        sessions.push(TimelineSession {
            session_id: format!("session-{}", idx + 1),
            boot_time: event.time.clone(),
            boot_time_precision: event.time_precision.clone(),
            incident_time_start,
            incident_time_end,
            incident_time_precision,
            boot_id,
            facts,
            end_classification: classification.into(),
            confidence: confidence.into(),
            supporting_evidence: evidence,
            limitations,
        });
    }
    sessions
}

/// 将内部会话边界转换为报告使用的异常时间。疑似断电没有直接时刻，显示恢复证据到下次启动的范围。
fn session_incident_time(
    classification: &str,
    facts: &[Event],
    current_boot: &Event,
    next_boot: Option<&Event>,
    match_window_seconds: i64,
) -> (String, Option<String>, String) {
    if classification == "疑似断电" {
        if let Some(next) = next_boot {
            let mut candidates = facts
                .iter()
                .filter(|fact| {
                    matches!(
                        fact.event_type.as_str(),
                        "filesystem_recovery" | "device_reenumeration" | "power_loss_hint"
                    ) && seconds_before(fact, next)
                        .is_some_and(|seconds| seconds <= match_window_seconds)
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|fact| local_clock_value(&fact.time));
            let start = candidates
                .first()
                .map(|fact| fact.time.clone())
                .unwrap_or_else(|| next.time.clone());
            return (start, Some(next.time.clone()), "range".into());
        }
    }
    let decisive_types: &[&str] = match classification {
        "正常关机" => &["shutdown_complete", "shutdown_request"],
        "正常重启" => &["reboot_complete", "reboot_request"],
        "Kernel Panic 重启" => &["kernel_panic"],
        "Watchdog 重启" => &["watchdog_reset"],
        "硬件复位" => &["hardware_reset"],
        _ => &[],
    };
    if let Some(fact) = facts
        .iter()
        .filter(|fact| decisive_types.contains(&fact.event_type.as_str()))
        .max_by_key(|fact| local_clock_value(&fact.time))
    {
        return (
            fact.time.clone(),
            None,
            if fact.key.is_some() {
                "exact"
            } else {
                "approximate"
            }
            .into(),
        );
    }
    let time = next_boot.unwrap_or(current_boot).time.clone();
    (time, None, "unknown".into())
}

fn seconds_before(event: &Event, next_boot: &Event) -> Option<i64> {
    if let (Some(event), Some(next)) = (event.key.as_deref(), next_boot.key.as_deref()) {
        let event = chrono::DateTime::parse_from_rfc3339(event).ok()?;
        let next = chrono::DateTime::parse_from_rfc3339(next).ok()?;
        let seconds = next.timestamp() - event.timestamp();
        return (seconds >= 0).then_some(seconds);
    }
    let (event_month, event_day, event_seconds) = local_clock_value(&event.time)?;
    let (next_month, next_day, next_seconds) = local_clock_value(&next_boot.time)?;
    if (event_month, event_day) != (next_month, next_day) || event_seconds > next_seconds {
        return None;
    }
    Some((next_seconds - event_seconds) as i64)
}

fn local_clock_value(value: &str) -> Option<(u32, u32, u32)> {
    if let Ok(time) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some((
            time.month(),
            time.day(),
            time.time().num_seconds_from_midnight(),
        ));
    }
    let raw = value.get(..19).unwrap_or(value);
    if let Ok(time) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S") {
        return Some((
            time.month(),
            time.day(),
            time.time().num_seconds_from_midnight(),
        ));
    }
    partial_clock(value)
}

fn parse_vendor_boot_key(boot_time: Option<&str>) -> Option<String> {
    let value = boot_time?.get(..19)?;
    let naive = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok()?;
    if boot_time.is_some_and(|time| time.contains("CST")) {
        FixedOffset::east_opt(8 * 60 * 60)
            .and_then(|offset| offset.from_local_datetime(&naive).single())
            .map(|time| {
                time.with_timezone(&Utc)
                    .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
            })
    } else {
        Some(
            naive
                .and_utc()
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        )
    }
}

fn event_belongs_to_session(event: &Event, current: &Event, next: Option<&Event>) -> bool {
    let Some(current_key) = current.key.as_deref() else {
        return true;
    };
    if let Some(key) = event.key.as_deref() {
        return key >= current_key
            && next
                .and_then(|end| end.key.as_deref())
                .map_or(true, |end| key < end);
    }
    let Some(next) = next else {
        return false;
    };
    let (Ok(current), Ok(next)) = (
        chrono::DateTime::parse_from_rfc3339(&current.time),
        chrono::DateTime::parse_from_rfc3339(&next.time),
    ) else {
        return false;
    };
    let Some((month, day, seconds)) = partial_clock(&event.time) else {
        return false;
    };
    if month != current.month() || day != current.day() || current.date_naive() != next.date_naive()
    {
        return false;
    }
    let start = current.time().num_seconds_from_midnight();
    let end = next.time().num_seconds_from_midnight();
    seconds >= start && seconds < end
}

fn partial_clock(value: &str) -> Option<(u32, u32, u32)> {
    let raw = value.split('（').next()?.trim();
    let mut parts = raw.split_whitespace();
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let mut clock = time.split(':');
    let hour: u32 = clock.next()?.parse().ok()?;
    let minute: u32 = clock.next()?.parse().ok()?;
    let second: u32 = clock.next()?.parse().ok()?;
    Some((month, day, hour * 3600 + minute * 60 + second))
}

fn same_time_window(a: &Option<String>, b: &Option<String>, seconds: i64) -> bool {
    let (Some(a), Some(b)) = (a, b) else {
        return false;
    };
    let (Ok(a), Ok(b)) = (
        chrono::DateTime::parse_from_rfc3339(a),
        chrono::DateTime::parse_from_rfc3339(b),
    ) else {
        return a == b;
    };
    (a.timestamp() - b.timestamp()).abs() <= seconds
}

fn extract_boot_id(event: &Event) -> Option<String> {
    event
        .note
        .split_once("boot_id：")
        .and_then(|(_, value)| value.split('；').next())
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "未提供")
        .map(ToOwned::to_owned)
}
#[derive(Serialize)]
pub struct Report {
    pub package: String,
    pub generated: String,
    pub layout: crate::rules::Layout,
    pub log_files: Vec<crate::rules::LogFile>,
    /// 实际解压路径与目录中文名的展示映射，不替换证据中的路径。
    pub source_labels: HashMap<String, String>,
    pub source_catalog: HashMap<String, Vec<String>>,
    pub system_file_ids: HashMap<String, String>,
    pub system: Vec<Table>,
    pub findings: Vec<Finding>,
    pub events: Vec<Event>,
    /// 事实事件的稳定输出名称；events 保留旧报告兼容，两个字段内容一致。
    pub timeline_facts: Vec<Event>,
    pub timeline_sessions: Vec<TimelineSession>,
    pub timeline_warnings: Vec<String>,
    pub warnings: Vec<String>,
}

const REPORT_PAYLOAD_PREFIX: &str = "gzip-base64-v1:";

/// 将完整报告 JSON 流式压缩后编码为脚本安全的 Base64 字符串。
///
/// 报告仍保留原始 JSON 数据模型，压缩只改变 HTML 内的传输形式。Base64 字符集不含
/// `<`、`>` 和 `&`，因此诊断日志无法闭合 script 标签或注入页面代码。
fn encode_report_payload<T: Serialize>(value: &T) -> Result<String> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
    serde_json::to_writer(&mut gzip, value).context("序列化报告数据失败")?;
    let compressed = gzip.finish().context("压缩报告数据失败")?;
    Ok(format!(
        "{REPORT_PAYLOAD_PREFIX}{}",
        BASE64.encode(compressed)
    ))
}

/// 写入单文件离线报告；模板和压缩数据分段输出，避免构造完整 HTML 副本。
fn write_report_document<W: Write, T: Serialize>(out: &mut W, value: &T) -> Result<()> {
    let (prefix, suffix) = include_str!("../assets/report.html")
        .split_once("/*REPORT_DATA*/null")
        .expect("报告模板包含数据插入位置");
    let payload = encode_report_payload(value)?;
    out.write_all(prefix.as_bytes())?;
    serde_json::to_writer(&mut *out, &payload)?;
    out.write_all(suffix.as_bytes())?;
    Ok(())
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
/// 统一归档读取入口：调用方显式传入容器类型，格式读取器只产出相对路径和字节流。
/// 新增 ZIP 时只扩展此处分派；日志目录和规则引用不依赖 TAR 数据结构。
fn visit_archive(
    path: &Path,
    container: &str,
    cancel: &AtomicBool,
    mut visit: impl FnMut(&Path, bool, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    check(cancel)?;
    let mut file = File::open(path)?;
    let mut signature = [0u8; 4];
    let n = file.read(&mut signature)?;
    match container {
        "zip" => bail!("暂不支持 ZIP 诊断包，请使用 TGZ 格式"),
        "diagnostic_archive" => {}
        other => bail!("归档容器不受支持：{other}"),
    }
    if n >= 2 && signature[..2] == *b"PK" {
        bail!("归档容器标记为诊断包，但实际文件是 ZIP；请检查日志文件配置");
    }
    if n < 2 || signature[..2] != [0x1f, 0x8b] {
        bail!("诊断包格式不受支持，请使用 TGZ 格式");
    }
    file.seek(SeekFrom::Start(0))?;
    let mut archive = tar::Archive::new(MultiGzDecoder::new(BufReader::with_capacity(
        128 * 1024,
        file,
    )));
    let mut count = 0;
    for entry in archive.entries()? {
        check(cancel)?;
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            bail!("压缩包包含链接或不支持的条目类型");
        }
        let relative = entry.path()?.into_owned();
        visit(&relative, kind.is_dir(), &mut entry)?;
        count += 1;
    }
    // 必须读取至 gzip 结束，确保尾部 CRC 错误也能被检测。
    let mut tail = archive.into_inner();
    let mut buffer = [0u8; 8192];
    loop {
        check(cancel)?;
        if tail.read(&mut buffer)? == 0 {
            break;
        }
    }
    if count == 0 {
        bail!("诊断包为空");
    }
    Ok(())
}
pub fn validate_archive(path: &Path, cancel: &AtomicBool) -> Result<()> {
    visit_archive(path, "diagnostic_archive", cancel, |relative, _, reader| {
        safe_target(Path::new("."), relative)?;
        let mut buffer = [0u8; 8192];
        loop {
            check(cancel)?;
            if reader.read(&mut buffer)? == 0 {
                break;
            }
        }
        Ok(())
    })
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
    let mut buf = vec![0; 128 * 1024];
    visit_archive(path, "diagnostic_archive", cancel, |rel, directory, e| {
        let dest = safe_target(root, rel)?;
        if directory {
            fs::create_dir_all(&dest)?;
            return Ok(());
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
        Ok(())
    })?;
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
        let archive_files = files;
        let files: Vec<PlannedFile> = sys_by_file
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
        let mut plans = files;
        // pstore 复位原因是结构化事实来源，即使用户没有创建对应关键词规则也必须进入分析计划。
        for (file_index, (name, _)) in archive_files.iter().enumerate() {
            if (name
                .replace('\\', "/")
                .ends_with("/pstore/ug_reset_reason.log")
                || is_likely_timeline_source(name))
                && !plans.iter().any(|p| p.file_index == file_index)
            {
                plans.push(PlannedFile {
                    file_index,
                    system: vec![],
                    active: vec![],
                });
            }
        }
        Ok(Self { files: plans })
    }
}

fn is_likely_timeline_source(name: &str) -> bool {
    let path = name.replace('\\', "/").to_ascii_lowercase();
    let base = path.rsplit('/').next().unwrap_or(&path);
    base.starts_with("dmesg")
        || (base.starts_with("kern") && (base.ends_with(".log") || !base.contains('.')))
        || base.starts_with("syslog")
        || base.starts_with("journal")
        || base.starts_with("messages")
        || path.contains("/pstore/")
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
    // 已配置的时间线规则负责该日志时，保留旧规则的事件数量和合并语义；
    // 没有时间线规则覆盖的日志才启用通用事实识别，避免重复展示。
    let has_configured_timeline = template.iter().any(|finding| {
        finding.rule.target != "keywords"
            && finding
                .rule
                .sources
                .iter()
                .any(|source| source.matches(name))
    });
    if name
        .replace('\\', "/")
        .ends_with("/pstore/ug_reset_reason.log")
    {
        match CapturedSource::read(p, cancel)
            .and_then(|captured| captured.text().map(str::to_owned))
        {
            Ok(text) => report.events.extend(parse_reset_reason_blocks(name, &text)),
            Err(error) => report
                .warnings
                .push(format!("无法解析 pstore 复位原因 {name}：{error}")),
        }
    }
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
        if !has_configured_timeline {
            if let Some(event) = automatic_timeline_event(name, &line, line_number) {
                report.events.push(event);
            }
        }
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
                        key: key.clone(),
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
                        event_type: classify_timeline_event(&r.name, &line),
                        evidence_strength: "medium".into(),
                        time_precision: if key.is_some() { "exact" } else { "partial" }.into(),
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
    let mut resolved = rules.clone();
    resolved.resolve_sources()?;
    let rules = &resolved;
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
        log_files: rules.log_files.clone(),
        source_labels: HashMap::new(),
        source_catalog: HashMap::new(),
        system_file_ids: rules
            .system
            .iter()
            .map(|r| (r.id.clone(), r.source_file_id.clone()))
            .collect(),
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
        timeline_facts: vec![],
        timeline_sessions: vec![],
        timeline_warnings: vec![],
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
                raw_text: String::new(),
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
    let raid_by_pool = report
        .system
        .iter()
        .find(|t| t.id == "block")
        .map(infer_raid_by_pool)
        .unwrap_or_default();
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
    report.timeline_facts = report.events.clone();
    report.timeline_sessions = build_timeline_sessions(
        &report.events,
        rules.timeline.thresholds.match_window_seconds as i64,
    );
    if rules.layout.timeline_sort == "desc" {
        report.timeline_sessions.reverse();
    }
    if !report.events.iter().any(|event| {
        event.sources.iter().any(|source| {
            source
                .file
                .replace('\\', "/")
                .ends_with("/pstore/ug_reset_reason.log")
        })
    }) {
        report.timeline_warnings.push(
            "未发现 ug_reset_reason.log；厂商复位原因不可用，未知复位不会被自动判定为断电。".into(),
        );
    }
    if report.events.iter().any(|e| e.time_precision == "partial") {
        report
            .timeline_warnings
            .push("部分时间只有局部时间或无法统一到绝对时间，跨日志来源未强行合并。".into());
    }
    for finding in &mut report.findings {
        limit_report_evidence(finding);
    }
    check(cancel)?;
    if stamp(path)? != original {
        bail!("分析期间诊断包发生变化，请等待下载完成后重试");
    }
    for (path, _) in &files {
        let ids = rules
            .log_files
            .iter()
            .filter(|file| file.source().is_ok_and(|source| source.matches(path)))
            .map(|file| file.id.clone())
            .collect::<Vec<_>>();
        report.source_catalog.insert(path.clone(), ids);
        let names = rules
            .log_files
            .iter()
            .filter(|file| file.source().is_ok_and(|source| source.matches(path)))
            .map(|file| file.name.as_str())
            .collect::<Vec<_>>();
        if !names.is_empty() {
            report.source_labels.insert(
                path.clone(),
                format!(
                    "{} · {}",
                    names.join("、"),
                    path.rsplit('/').next().unwrap_or(path)
                ),
            );
        }
    }
    progress("正在生成离线 HTML…".into());
    let tmp = root.join("report.html.tmp");
    safe_target(&root, Path::new("report.html.tmp"))?;
    safe_target(&root, Path::new("report.html"))?;
    {
        let mut out = BufWriter::with_capacity(128 * 1024, File::create(&tmp)?);
        write_report_document(&mut out, &report)?;
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

/// 从 lsblk 行中提取存储池 RAID 标签；linear 在摘要中按 JBOD 展示，原始行不改写。
fn infer_raid_by_pool(block: &Table) -> std::collections::HashMap<String, String> {
    let raid_re = Regex::new(r"(?i)\braid(\d+)\b").expect("RAID 类型正则有效");
    let linear_re = Regex::new(r"(?i)\blinear\b").expect("linear 类型正则有效");
    let pool_re = Regex::new(r"pool(\d+)-").expect("存储池编号正则有效");
    let mut raid_by_pool = std::collections::HashMap::new();
    let mut raid = None;
    for row in &block.rows {
        let text = row.values().cloned().collect::<Vec<_>>().join(" ");
        if linear_re.is_match(&text) {
            raid = Some("JBOD".to_owned());
        } else if let Some(c) = raid_re.captures(&text) {
            raid = Some(format!("RAID{}", &c[1]));
        }
        if let Some(c) = pool_re.captures(&text) {
            if let Some(value) = &raid {
                raid_by_pool.insert(format!("Storage Pool {}", &c[1]), value.clone());
            }
        }
    }
    raid_by_pool
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
    rules.validate()?;
    let mut resolved = rules.clone();
    resolved.resolve_sources()?;
    let rules = &resolved;
    let mut report = Report {
        package: "规则预览".into(),
        generated: chrono::Local::now().to_rfc3339(),
        layout: rules.layout.clone(),
        log_files: rules.log_files.clone(),
        source_labels: HashMap::new(),
        source_catalog: HashMap::new(),
        system_file_ids: rules
            .system
            .iter()
            .map(|r| (r.id.clone(), r.source_file_id.clone()))
            .collect(),
        system: vec![],
        findings: vec![],
        events: vec![],
        timeline_facts: vec![],
        timeline_sessions: vec![],
        timeline_warnings: vec![],
        warnings: vec![],
    };
    let preview_ids = if system {
        vec![rules.system[index].source_file_id.clone()]
    } else {
        rules.rules[index].source_file_ids.clone()
    };
    report
        .source_labels
        .insert("样例日志".into(), rules.source_label(&preview_ids));
    report.source_catalog.insert("样例日志".into(), preview_ids);
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
                    key: key.clone(),
                    note: r.note.clone(),
                    sources: vec![f],
                    event_type: classify_timeline_event(&r.name, &line),
                    evidence_strength: "medium".into(),
                    time_precision: if key.is_some() { "exact" } else { "partial" }.into(),
                });
            }
        }
        if finding.count > 0 {
            finding.status = "已匹配".into();
        }
        report.findings.push(finding);
    }
    report.timeline_facts = report.events.clone();
    report.timeline_sessions = build_timeline_sessions(
        &report.events,
        rules.timeline.thresholds.match_window_seconds as i64,
    );
    if rules.layout.timeline_sort == "desc" {
        report.timeline_sessions.reverse();
    }
    let mut html = Vec::new();
    write_report_document(&mut html, &report)?;
    String::from_utf8(html).context("报告模板不是有效的 UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compressed_payload_round_trips_and_is_script_safe() {
        let value = serde_json::json!({"文本": "</script>&>中文\\u003c\n\"", "rows": [1, 2]});
        let payload = encode_report_payload(&value).unwrap();
        assert!(payload.starts_with(REPORT_PAYLOAD_PREFIX));
        assert!(
            !payload
                .bytes()
                .any(|byte| matches!(byte, b'<' | b'>' | b'&'))
        );
        let compressed = BASE64
            .decode(payload.strip_prefix(REPORT_PAYLOAD_PREFIX).unwrap())
            .unwrap();
        let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut actual = Vec::new();
        decoder.read_to_end(&mut actual).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&actual).unwrap(),
            value
        );
    }

    #[test]
    fn compressed_report_propagates_write_errors() {
        let value = serde_json::json!({"rows": [1, 2]});
        // 固定容量输出模拟磁盘写入失败，错误必须返回，不能伪报成功。
        let mut short = [0; 5];
        assert!(write_report_document(&mut short.as_mut_slice(), &value).is_err());
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
    #[test]
    fn parses_vendor_reset_reason_blocks_without_overclaiming_unknown() {
        let text = "# BEGIN ug_reset_reason\n# boot_id: abc\n  Boot Time  2026-09-08 08:53:26 CST\n│ REBOOT CAUSE: UNKNOWN — Insufficient Data                  │\n  Reason     unknown\n# END ug_reset_reason\n# BEGIN ug_reset_reason\n# boot_id: def\n  Boot Time  2026-09-08 08:23:08 CST\n│ REBOOT CAUSE: NORMAL — Shutdown                            │\n  Reason     poweroff\n# END ug_reset_reason";
        let events = parse_reset_reason_blocks("pstore/ug_reset_reason.log", text);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "reset_reason");
        assert_eq!(events[1].event_type, "shutdown_complete");
        assert_eq!(events[0].evidence_strength, "high");
        assert!(events[0].key.is_some());
    }
    #[test]
    fn automatic_facts_cover_boot_recovery_and_do_not_call_unknown_power_loss() {
        let boot = automatic_timeline_event(
            "var/log/kern.log",
            "2026-09-08T08:50:00+08:00 Linux version 6.1.0",
            1,
        )
        .unwrap();
        let recovery = automatic_timeline_event(
            "var/log/kern.log",
            "2026-09-08T08:51:13+08:00 EXT4-fs: recovery complete",
            2,
        )
        .unwrap();
        let next_boot = automatic_timeline_event(
            "var/log/kern.log",
            "2026-09-08T08:53:26+08:00 Linux version 6.1.0",
            3,
        )
        .unwrap();
        assert_eq!(boot.event_type, "boot");
        assert_eq!(recovery.event_type, "filesystem_recovery");
        let sessions = build_timeline_sessions(&[boot, recovery, next_boot], 300);
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].end_classification, "疑似断电");
        assert_ne!(sessions[0].end_classification, "断电");
        assert_eq!(sessions[0].incident_time_start, "2026-09-08T08:51:13+08:00");
        assert_eq!(
            sessions[0].incident_time_end.as_deref(),
            Some("2026-09-08T08:53:26+08:00")
        );
        assert_eq!(sessions[0].incident_time_precision, "range");
        assert!(
            sessions[0]
                .supporting_evidence
                .contains(&"文件系统执行过异常中断恢复".to_string())
        );
    }
    #[test]
    fn vendor_boot_id_is_kept_on_session_when_time_matches_boot() {
        let mut boot = automatic_timeline_event(
            "var/log/kern.log",
            "2026-09-08T08:53:26+08:00 Linux version 6.1.0",
            1,
        )
        .unwrap();
        let vendor = parse_reset_reason_blocks(
            "pstore/ug_reset_reason.log",
            "# BEGIN ug_reset_reason\n# boot_id: abc\n  Boot Time  2026-09-08 08:53:26 CST\n│ REBOOT CAUSE: UNKNOWN — Insufficient Data │\n  Reason unknown\n# END ug_reset_reason",
        )
        .pop()
        .unwrap();
        boot.key = Some("2026-09-08T00:53:26Z".into());
        let sessions = build_timeline_sessions(&[boot, vendor], 300);
        assert_eq!(sessions[0].boot_id.as_deref(), Some("abc"));
        assert_eq!(sessions[0].end_classification, "未知复位");
    }
    #[test]
    fn linear_lsblk_is_reported_as_jbod_without_rewriting_rows() {
        let row = |name: &str, kind: &str| {
            let mut row = std::collections::BTreeMap::new();
            row.insert("设备树".into(), name.into());
            row.insert("类型".into(), kind.into());
            row
        };
        let block = Table {
            id: "block".into(),
            name: "块设备与挂载".into(),
            group: "补充信息".into(),
            view: "table".into(),
            fields: vec![],
            rows: vec![row("pool1-md0", "linear"), row("pool2-md1", "raid1")],
            storage: vec![],
            raw_text: "NAME TYPE\npool1-md0 linear\n".into(),
            source: "cmd/lsblk.log".into(),
            warning: String::new(),
        };
        let raid = infer_raid_by_pool(&block);
        assert_eq!(raid.get("Storage Pool 1"), Some(&"JBOD".to_owned()));
        assert_eq!(raid.get("Storage Pool 2"), Some(&"RAID1".to_owned()));
        assert_eq!(block.rows[0]["类型"], "linear");
    }
}
