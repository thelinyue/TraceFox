mod common;
use common::engine;
use std::{fs, io::Write, sync::atomic::AtomicBool};
use tracefox::rules::{Rule, RuleSet, Source};
fn package(path: &std::path::Path, entries: &[(&str, &str)]) {
    let f = fs::File::create(path).unwrap();
    let gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
    let mut t = tar::Builder::new(gz);
    for (name, text) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(text.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, name, text.as_bytes()).unwrap();
    }
    t.into_inner().unwrap().finish().unwrap();
}
fn rules() -> RuleSet {
    common::catalog(&RuleSet {
        log_files: vec![],
        version: 2,
        rules: vec![Rule {
            terms: vec!["error".into()],
            sources: vec![Source {
                pattern: "syslog".into(),
                mode: "prefix".into(),
            }],
            before: 1,
            after: 1,
            ..Rule::default()
        }],
        system: vec![],
        layout: Default::default(),
        timeline: Default::default(),
    })
}
fn data(p: &std::path::Path) -> serde_json::Value {
    common::report_data(p)
}

#[test]
fn lazy_compact_json_and_custom_time_keep_evidence() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("compact.tgz");
    let line = r#"{"event": "error", "at": "10/09/2026 09:08:07"}"#;
    package(&p, &[("syslog", &format!("{line}\n{line}\n"))]);
    let mut r = rules();
    let mut compact = r.rules[0].clone();
    compact.id = "compact".into();
    compact.name = "紧凑匹配".into();
    compact.terms = vec![r#""event":"error""#.into()];
    compact.target = "both".into();
    compact.time_regex = r"(?P<time>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})".into();
    compact.time_format = "%d/%m/%Y %H:%M:%S".into();
    compact.timezone = "+08:00".into();
    r.rules.push(compact);
    let v = data(&engine::analyze(&p, &r, &AtomicBool::new(false), |_| {}).unwrap());
    assert_eq!(v["findings"][0]["count"], 2);
    assert_eq!(v["findings"][1]["count"], 2);
    // 紧凑文本仅用于匹配，原始文本及其高亮坐标不被改写。
    assert_eq!(v["findings"][1]["fragments"][0]["lines"][0]["text"], line);
    assert_eq!(
        v["findings"][1]["fragments"][0]["lines"][0]["ranges"],
        serde_json::json!([])
    );
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
    assert_eq!(v["events"][0]["key"], "2026-09-10T01:08:07.000000000Z");
    assert_eq!(v["events"][0]["sources"].as_array().unwrap().len(), 2);
}

#[test]
fn shared_source_keeps_json_failures_independent_of_text_rules() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("shared.tgz");
    package(&p, &[("sysinfo.json", "value: disk-42")]);
    let mut r = rules();
    r.rules.clear();
    let field = serde_json::from_value(serde_json::json!({
        "name": "值", "path": "value", "capture": "disk-(\\d+)"
    }))
    .unwrap();
    let json = tracefox::rules::SystemRule {
        id: "json-one".into(),
        name: "JSON 一".into(),
        source: Source {
            pattern: "sysinfo.json".into(),
            mode: "exact".into(),
        },
        fields: vec![field],
        ..Default::default()
    };
    let mut second = json.clone();
    second.id = "json-two".into();
    second.name = "JSON 二".into();
    let mut text = json.clone();
    text.id = "text".into();
    text.kind = "kv".into();
    r.system = vec![json, second, text];
    let v = data(&engine::analyze(&p, &r, &AtomicBool::new(false), |_| {}).unwrap());
    assert_eq!(
        v["warnings"],
        serde_json::json!([
            "JSON 一 / sysinfo.json：JSON 内容无法解析",
            "JSON 二 / sysinfo.json：JSON 内容无法解析"
        ])
    );
    assert_eq!(v["system"][2]["rows"][0]["值"], "42");
    package(&p, &[("sysinfo.json", r#"{"value":"disk-73"}"#)]);
    let v = data(&engine::analyze(&p, &r, &AtomicBool::new(false), |_| {}).unwrap());
    assert_eq!(v["system"][0]["rows"][0]["值"], "73");
    assert_eq!(v["system"][1]["rows"][0]["值"], "73");
}
#[test]
fn overlap_overwrite_and_html_safety() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("case.tgz");
    package(
        &p,
        &[(
            "diag/syslog",
            "before\nerror one\nerror two </script><script>alert(1)</script>\nafter\n",
        )],
    );
    let root = d.path().join("case");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("syslog-old"), "error stale").unwrap();
    fs::write(root.join("mine.txt"), "keep").unwrap();
    let report = engine::analyze(&p, &rules(), &AtomicBool::new(false), |_| {}).unwrap();
    let v = data(&report);
    assert_eq!(v["findings"][0]["count"], 2);
    assert_eq!(v["findings"][0]["fragments"].as_array().unwrap().len(), 1);
    assert_eq!(
        v["findings"][0]["fragments"][0]["lines"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert!(
        !fs::read_to_string(&report)
            .unwrap()
            .contains("</script><script>alert")
    );
    package(&p, &[("diag/syslog", "clean\n")]);
    engine::analyze(&p, &rules(), &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(data(&report)["findings"][0]["count"], 0);
    assert_eq!(fs::read_to_string(root.join("mine.txt")).unwrap(), "keep");
}
#[test]
fn cancelled_keeps_previous_report() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("a.tgz");
    package(&p, &[("syslog", "error")]);
    let r = engine::analyze(&p, &rules(), &AtomicBool::new(false), |_| {}).unwrap();
    let old = fs::read(&r).unwrap();
    assert!(engine::analyze(&p, &rules(), &AtomicBool::new(true), |_| {}).is_err());
    assert_eq!(fs::read(r).unwrap(), old);
}

#[test]
fn cancel_or_source_change_during_report_preserves_previous_report() {
    use std::sync::atomic::Ordering;
    for cancel_run in [true, false] {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("case.tgz");
        package(&p, &[("syslog", "error\n")]);
        let root = p.with_extension("");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("report.html"), "previous").unwrap();
        let cancel = AtomicBool::new(false);
        let result = engine::analyze(&p, &rules(), &cancel, |message| {
            if message == "正在生成离线 HTML…" {
                if cancel_run {
                    cancel.store(true, Ordering::Relaxed);
                } else {
                    fs::OpenOptions::new()
                        .append(true)
                        .open(&p)
                        .unwrap()
                        .write_all(b"changed")
                        .unwrap();
                }
            }
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(root.join("report.html")).unwrap(),
            "previous"
        );
    }
}

#[test]
fn gzip_trailer_corruption_is_rejected_by_validation_and_analysis() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("crc.tgz");
    package(&p, &[("syslog", "error\n")]);
    let mut bytes = fs::read(&p).unwrap();
    let crc = bytes.len() - 8;
    bytes[crc] ^= 1;
    fs::write(&p, bytes).unwrap();
    let cancel = AtomicBool::new(false);
    assert!(engine::validate_archive(&p, &cancel).is_err());
    assert!(engine::analyze(&p, &rules(), &cancel, |_| {}).is_err());
    assert!(!p.with_extension("").join("report.html").exists());
}
#[test]
fn corrupted_gzip_rejected() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("x.tgz");
    fs::File::create(&p).unwrap().write_all(b"not tgz").unwrap();
    assert!(engine::validate_archive(&p, &AtomicBool::new(false)).is_err());
}
#[test]
fn defaults_roundtrip() {
    let r = RuleSet::defaults();
    r.validate().unwrap();
    let s = serde_json::to_string(&r).unwrap();
    let imported = RuleSet::import(&s).unwrap();
    assert_eq!(serde_json::to_string(&imported).unwrap(), s);
    assert!(!r.rules.is_empty());
    assert_eq!(r.layout.log_lines_per_batch, 200);
}

#[test]
fn old_layout_defaults_log_batch_size() {
    let mut value = serde_json::to_value(RuleSet::defaults()).unwrap();
    value["layout"]
        .as_object_mut()
        .unwrap()
        .remove("log_lines_per_batch");
    let imported = RuleSet::import(&value.to_string()).unwrap();
    assert_eq!(imported.layout.log_lines_per_batch, 200);
}

#[test]
fn invalid_log_batch_size_is_rejected() {
    for value in [0, 9, 5001] {
        let mut rules = RuleSet::defaults();
        rules.layout.log_lines_per_batch = value;
        let error = rules.validate().unwrap_err().to_string();
        assert!(error.contains("每批显示行数需为 10 至 5000"), "{error}");
    }
}

#[test]
fn adjacent_zero_context_stays_separate() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("case.tgz");
    package(&p, &[("syslog", "error error\nerror\n")]);
    let mut r = rules();
    r.rules[0].before = 0;
    r.rules[0].after = 0;
    let html = engine::analyze(&p, &r, &AtomicBool::new(false), |_| {}).unwrap();
    let v = data(&html);
    assert_eq!(v["findings"][0]["count"], 2);
    assert_eq!(v["findings"][0]["fragments"].as_array().unwrap().len(), 2);
}

#[test]
fn event_merge_preserves_sources() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("events.tgz");
    let line = "2026-09-09T10:00:00+08:00 kernel: Linux version 6.18\n";
    package(&p, &[("syslog", line), ("kern.log", line)]);
    let mut r = rules();
    r.rules[0].terms = vec!["Linux version".into()];
    r.rules[0].sources.push(Source {
        pattern: "kern".into(),
        mode: "prefix".into(),
    });
    r.rules[0].target = "timeline".into();
    let h = engine::analyze(&p, &r, &AtomicBool::new(false), |_| {}).unwrap();
    let v = data(&h);
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
    assert_eq!(v["events"][0]["sources"].as_array().unwrap().len(), 2);
}

#[test]
fn boot_nul_rule_marks_possible_power_instability() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("boot-nul.tgz");
    package(
        &p,
        &[(
            "log/syslog",
            "2026-09-09T10:00:00+08:00 kernel: \0\0Linux version 6.18\n2026-09-09T10:01:00+08:00 kernel: Linux version 6.18\n",
        )],
    );
    let mut r = RuleSet::defaults();
    r.rules.retain(|rule| rule.id == "boot-nul-before-kernel");
    let v = data(&engine::analyze(&p, &r, &AtomicBool::new(false), |_| {}).unwrap());
    assert_eq!(v["findings"][0]["count"], 1);
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
    assert_eq!(v["events"][0]["name"], "开机前存在 NUL 字节");
}

#[test]
fn btrfs_snapshot_delete_rule_reports_keyword_and_timeline() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("btrfs-snapshot-delete.tgz");
    package(
        &p,
        &[(
            "log/kern.log",
            "2026-09-08T17:35:12+08:00 kernel: btrfs_commit_transaction: deleting scheduled snapshot\n",
        )],
    );
    let mut rules = RuleSet::defaults();
    rules
        .rules
        .retain(|rule| rule.id == "btrfs-snapshot-delete");

    let report = data(&engine::analyze(&p, &rules, &AtomicBool::new(false), |_| {}).unwrap());
    let finding = &report["findings"][0];
    assert_eq!(finding["count"], 1);
    assert_eq!(finding["fragments"][0]["file"], "log/kern.log");
    assert_eq!(
        finding["rule"]["note"],
        "可能是 Btrfs 快照定期删除导致 NAS 系统无法访问"
    );
    assert_eq!(report["events"].as_array().unwrap().len(), 1);
    assert_eq!(report["events"][0]["name"], "Btrfs 快照定期删除");
    assert_eq!(report["events"][0]["group"], "内核服务");
    assert_eq!(
        report["events"][0]["note"],
        "可能是 Btrfs 快照定期删除导致 NAS 系统无法访问"
    );

    let clean = d.path().join("btrfs-clean.tgz");
    package(
        &clean,
        &[(
            "log/kern.log",
            "2026-09-08T17:35:12+08:00 kernel: btrfs read ok\n",
        )],
    );
    let clean_report =
        data(&engine::analyze(&clean, &rules, &AtomicBool::new(false), |_| {}).unwrap());
    assert_eq!(clean_report["findings"][0]["count"], 0);
    assert!(clean_report["events"].as_array().unwrap().is_empty());
}

#[test]
fn gzip_rotated_log_and_legacy_volume() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("rotated.tgz");
    let file = fs::File::create(&p).unwrap();
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
        file,
        flate2::Compression::fast(),
    ));
    let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::fast());
    gz.write_all(b"allVolumes 2147483648 1073741824 1073741824\n")
        .unwrap();
    let bytes = gz.finish().unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_size(bytes.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    tar.append_data(&mut h, "syslog.1.gz", &bytes[..]).unwrap();
    tar.into_inner().unwrap().finish().unwrap();
    let mut r = rules();
    r.rules[0].terms = vec![r"allVolumes (\d+) (\d+) (\d+)".into()];
    r.rules[0].regex = true;
    r.rules[0].fmt = "volume_info".into();
    let html = engine::analyze(&p, &r, &AtomicBool::new(false), |_| {}).unwrap();
    let v = data(&html);
    assert_eq!(v["findings"][0]["count"], 1);
    assert!(
        v["findings"][0]["fragments"][0]["annotation"]
            .as_str()
            .unwrap()
            .contains("2.0 GiB")
    );
}

#[test]
fn reject_link_archive_and_invalid_regex() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("link.tgz");
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
        fs::File::create(&p).unwrap(),
        flate2::Compression::fast(),
    ));
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Symlink);
    h.set_size(0);
    h.set_mode(0o777);
    h.set_link_name("../outside").unwrap();
    h.set_cksum();
    tar.append_data(&mut h, "link", &b""[..]).unwrap();
    tar.into_inner().unwrap().finish().unwrap();
    assert!(engine::validate_archive(&p, &AtomicBool::new(false)).is_err());
    let mut r = rules();
    r.rules[0].regex = true;
    r.rules[0].terms = vec!["[".into()];
    assert!(r.validate().is_err());
}

#[test]
fn merge_prefers_id_over_duplicate_name() {
    let mut r = rules();
    let mut second = r.rules[0].clone();
    second.id = "second".into();
    second.terms = vec!["different".into()];
    r.rules.push(second);
    let mut incoming = r.clone();
    incoming.rules[1].note = "updated second".into();
    let merged = r.merge(&incoming, true).unwrap();
    assert_eq!(merged.rules[0].terms, vec!["error"]);
    assert_eq!(merged.rules[1].note, "updated second");
    let kept = r.merge(&incoming, false).unwrap();
    assert_eq!(kept.rules[1].note, "");
}

#[test]
fn linux_trailing_dot_filename_is_preserved() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("linux.tgz");
    package(&p, &[("samba/log.", "linux log"), ("syslog", "error")]);
    engine::validate_archive(&p, &AtomicBool::new(false)).unwrap();
    engine::analyze(&p, &rules(), &AtomicBool::new(false), |_| {}).unwrap();
    let root = fs::canonicalize(d.path().join("linux")).unwrap();
    assert_eq!(
        fs::read_to_string(root.join("samba").join("log.")).unwrap(),
        "linux log"
    );
}

/// 交错分组整组移动后仍保留规则身份和组内顺序，不依赖显示名称唯一。
#[test]
fn group_move_preserves_members_and_identity() {
    let mut items = vec![("A", 1), ("B", 2), ("A", 3), ("C", 4), ("B", 5)];
    tracefox::rules::swap_groups(&mut items, "A", "B", |r| r.0);
    assert_eq!(
        items,
        vec![("B", 2), ("B", 5), ("A", 1), ("A", 3), ("C", 4)]
    );
    let before = items.clone();
    tracefox::rules::swap_groups(&mut items, "missing", "A", |r| r.0);
    assert_eq!(items, before);
}

#[test]
fn reference_configuration_only_replaces_builtin_system_ids() {
    let mut original = RuleSet::defaults();
    original.layout.title = "保留标题".into();
    original.rules[0].name = "保留关键词".into();
    original.system[0].name = "修改过的内置规则".into();
    let mut custom = original.system[0].clone();
    custom.id = "custom-base".into();
    custom.name = "设备概览".into(); // 同名也不得覆盖自定义规则。
    original.system.push(custom.clone());
    let updated = original.with_reference_system().unwrap();
    assert_eq!(updated.layout.title, "保留标题");
    assert_eq!(updated.rules[0].name, "保留关键词");
    assert_eq!(updated.system.last().unwrap().id, custom.id);
    assert_eq!(updated.system[0].name, "设备概览");
    assert_eq!(original.system[0].name, "修改过的内置规则");
    assert_eq!(
        updated.with_reference_system().unwrap().system.len(),
        updated.system.len()
    );
    RuleSet::import(&serde_json::to_string(&updated).unwrap()).unwrap();
}

#[test]
fn storage_context_and_preview_keep_smart_with_its_disk() {
    let rules = RuleSet::defaults();
    let disks = rules.system.iter().find(|r| r.id == "disks").unwrap();
    let smart = rules.system.iter().find(|r| r.id == "smart").unwrap();
    let sample = r#"{"disk":{"devices":[
      {"disk_info":{"model":"same","used_for":"Storage Pool 1","vendor_extra":{"lane":2},"media":["ssd","nvme"]},"smart_info":{"report":[{"id":5,"name":"Reallocated_Sector_Ct","raw_string":"0","status":1}]}},
      {"disk_info":{"model":"same","used_for":"Unused"},"smart_info":{"report":[{"id":5,"name":"data_units_read","value":99}]}},
      {"disk_info":{},"smart_info":{"report":[]}}
    ]}}"#;
    let d = tracefox::extract::extract(disks, sample, "source-a").unwrap();
    let s = tracefox::extract::extract(smart, sample, "source-a").unwrap();
    assert_eq!(d.rows.len(), 3);
    assert_eq!(
        d.storage.iter().map(|c| c.device).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        s.storage.iter().map(|c| c.device).collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(d.storage[1].pool, "Unused");
    assert_eq!(d.storage[2].pool, "");
    assert!(
        d.storage[0]
            .details
            .iter()
            .any(|(k, v)| k == "vendor_extra" && v.contains("lane"))
    );
    assert!(
        d.storage[0]
            .details
            .iter()
            .any(|(k, v)| k == "media" && v.contains("nvme"))
    );
    assert_eq!(s.rows[0]["Raw"], "0");
    assert_eq!(s.rows[1]["Current"], "99");
    assert_eq!(s.rows[1]["源状态"], "");
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("storage.tgz");
    package(
        &archive,
        &[("sysinfo.json", sample), ("other/sysinfo.json", sample)],
    );
    let report = engine::analyze(&archive, &rules, &AtomicBool::new(false), |_| {}).unwrap();
    let result = data(&report);
    let tables = result["system"].as_array().unwrap();
    let disk_tables: Vec<_> = tables.iter().filter(|t| t["id"] == "disks").collect();
    assert_eq!(disk_tables.len(), 2);
    assert_ne!(disk_tables[0]["source"], disk_tables[1]["source"]);
    let html = engine::preview(
        &rules,
        rules.system.iter().position(|r| r.id == "disks").unwrap(),
        true,
        sample,
    )
    .unwrap();
    let preview_path = temp.path().join("preview.html");
    fs::write(&preview_path, html).unwrap();
    let preview = data(&preview_path);
    assert_eq!(preview["system"].as_array().unwrap().len(), 2);
    let mut invalid = rules.clone();
    invalid
        .system
        .iter_mut()
        .find(|r| r.id == "disks")
        .unwrap()
        .selector = "other[]".into();
    assert!(invalid.validate().is_err());
}

#[test]
fn report_group_order_uses_disabled_first_occurrence() {
    let mut r = rules();
    let base = r.rules[0].clone();
    r.rules = vec![
        Rule {
            id: "disabled-b".into(),
            group: "B".into(),
            enabled: false,
            ..base.clone()
        },
        Rule {
            id: "a".into(),
            group: "A".into(),
            ..base.clone()
        },
        Rule {
            id: "b".into(),
            group: "B".into(),
            ..base
        },
    ];
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("groups.tgz");
    package(&archive, &[("syslog", "error\n")]);
    let report = engine::analyze(&archive, &r, &AtomicBool::new(false), |_| {}).unwrap();
    let result = data(&report);
    assert_eq!(result["findings"][0]["rule"]["group"], "B");
    assert_eq!(result["findings"][1]["rule"]["group"], "A");
}

/// 真实旧配置可能交错保存分组成员，拖动规则不应顺便改变组顺序。
#[test]
fn editor_insert_and_cross_group_roundtrip() {
    let mut set = tracefox::rules::RuleSet::defaults();
    let base = set.rules[0].clone();
    set.rules = [("a1", "A"), ("b1", "B"), ("a2", "A"), ("a3", "A")]
        .into_iter()
        .map(|(id, group)| tracefox::rules::Rule {
            id: id.into(),
            group: group.into(),
            name: id.into(),
            ..base.clone()
        })
        .collect();
    assert!(set.move_rule(false, "a1", "A", Some("a3"), true));
    assert_eq!(
        set.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["a2", "a3", "a1", "b1"]
    );
    assert!(set.move_rule(false, "a3", "B", Some("b1"), false));
    assert_eq!(
        set.rules
            .iter()
            .map(|r| (r.id.as_str(), r.group.as_str()))
            .collect::<Vec<_>>(),
        [("a2", "A"), ("a1", "A"), ("a3", "B"), ("b1", "B")]
    );
    let reopened: tracefox::rules::RuleSet =
        serde_json::from_str(&serde_json::to_string(&set).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(&set).unwrap(),
        serde_json::to_value(reopened).unwrap()
    );
}

#[test]
fn editor_group_insertion_keeps_hidden_and_shared_members() {
    let mut set = tracefox::rules::RuleSet::defaults();
    let base = set.rules[0].clone();
    set.rules = [
        ("a", "A", "keywords"),
        ("b", "B", "both"),
        ("c", "C", "timeline"),
        ("d", "D", "keywords"),
    ]
    .into_iter()
    .map(|(id, group, target)| tracefox::rules::Rule {
        id: id.into(),
        group: group.into(),
        target: target.into(),
        ..base.clone()
    })
    .collect();
    assert!(set.move_group(false, "A", "D", true));
    assert_eq!(
        set.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["b", "c", "d", "a"]
    );
    assert!(set.move_rule(false, "b", "D", None, true));
    assert_eq!(
        set.rules.iter().find(|r| r.id == "b").unwrap().target,
        "both"
    );
    assert!(!set.rules.iter().any(|r| r.group == "B"));
    assert_eq!(
        set.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["c", "d", "b", "a"]
    );
    let before = serde_json::to_value(&set).unwrap();
    assert!(!set.move_rule(false, "b", "C", Some("missing"), false));
    assert!(!set.move_rule(false, "b", "C", Some("b"), true));
    assert!(!set.move_group(false, "C", "missing", false));
    assert_eq!(serde_json::to_value(&set).unwrap(), before);
}

#[test]
fn editor_system_move_preserves_fields_and_links() {
    let mut set = tracefox::rules::RuleSet::defaults();
    let mut first = set.system[0].clone();
    first.id = "first".into();
    first.group = "A".into();
    let mut second = first.clone();
    second.id = "second".into();
    second.group = "B".into();
    second.join_rule = "first".into();
    set.system = vec![first.clone(), second.clone()];
    assert!(set.move_rule(true, "first", "B", None, true));
    assert_eq!(set.system[0].id, "second");
    assert_eq!(set.system[0].join_rule, "first");
    assert_eq!(
        serde_json::to_value(&set.system[1].fields).unwrap(),
        serde_json::to_value(first.fields).unwrap()
    );
    assert!(set.system.iter().all(|r| r.group == "B"));
}

/// 上限作用于整条规则而非单个文件，保留总数、行号和邻近上下文。
#[test]
fn report_limits_each_rule_to_500_hits_across_files() {
    for total in [499, 500, 501, 1001] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limited.tgz");
        let first = (0..250)
            .map(|_| "before\nerror\nafter\n")
            .collect::<String>();
        let second = (250..total)
            .map(|_| "before\nerror\nafter\n")
            .collect::<String>();
        package(&path, &[("syslog", &first), ("syslog.1", &second)]);
        let report =
            data(&engine::analyze(&path, &rules(), &AtomicBool::new(false), |_| {}).unwrap());
        let finding = &report["findings"][0];
        assert_eq!(finding["count"], total);
        let mut hits = std::collections::HashSet::new();
        for fragment in finding["fragments"].as_array().unwrap() {
            for line in fragment["lines"].as_array().unwrap() {
                if line["hit"] == true {
                    hits.insert((
                        fragment["file"].as_str().unwrap(),
                        line["number"].as_u64().unwrap(),
                    ));
                    assert_eq!(line["text"], "error");
                    assert!(!line["ranges"].as_array().unwrap().is_empty());
                }
            }
        }
        assert_eq!(hits.len(), total.min(500));
    }
}
