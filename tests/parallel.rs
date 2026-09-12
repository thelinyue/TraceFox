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
    })
}
fn data(p: &std::path::Path) -> serde_json::Value {
    let s = fs::read_to_string(p).unwrap();
    let json = s
        .split("const report=")
        .nth(1)
        .unwrap()
        .split(";\nconst $")
        .next()
        .unwrap();
    serde_json::Deserializer::from_str(json)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap()
        .unwrap()
}

// 比较完整报告数据（只排除生成时间），涵盖索引重叠、顺序、上下文和跨文件事件合并。
#[test]
fn bounded_parallel_scan_preserves_results_and_source_order() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("parallel.tgz");
    package(
        &p,
        &[
            (
                "root/syslog.9",
                "before\n2026-09-09T08:00:00Z error first\nafter\n",
            ),
            ("root/unrelated", "error must not appear\n"),
            (
                "root/syslog.1",
                "2026-09-09T08:00:00Z error second\n\0error\n",
            ),
            ("root/syslog", "error third\n"),
            ("root/syslog.3", "before\nerror fourth\nafter\n"),
            ("root/syslog.2", "error fifth\n"),
        ],
    );
    let mut r = rules();
    r.rules[0].target = "both".into();
    r.rules[0].sources.push(Source {
        pattern: "syslog.9".into(),
        mode: "exact".into(),
    });
    let mut exact = r.rules[0].clone();
    exact.id = "exact".into();
    exact.name = "固定路径".into();
    exact.sources = vec![Source {
        pattern: "syslog.1".into(),
        mode: "exact".into(),
    }];
    exact.reverse = true;
    r.rules.push(exact);
    let mut contains = r.rules[0].clone();
    contains.id = "contains".into();
    contains.name = "包含路径".into();
    contains.sources = vec![Source {
        pattern: "syslog.3".into(),
        mode: "path".into(),
    }];
    r.rules.push(contains);
    let baseline = data(
        &engine::analyze_with_workers(&p, &r, &AtomicBool::new(false), 1, |_| {}, |_, _| {})
            .unwrap(),
    );
    assert_eq!(baseline["findings"][0]["count"], 6);
    assert_eq!(
        baseline["findings"][0]["fragments"][0]["file"],
        "root/syslog.9"
    );
    assert_eq!(baseline["findings"][1]["count"], 2);
    assert_eq!(baseline["findings"][2]["count"], 1);
    let mut baseline = baseline;
    baseline.as_object_mut().unwrap().remove("generated");
    for workers in [2, 4] {
        let mut actual = data(
            &engine::analyze_with_workers(
                &p,
                &r,
                &AtomicBool::new(false),
                workers,
                |_| {},
                |_, _| {},
            )
            .unwrap(),
        );
        actual.as_object_mut().unwrap().remove("generated");
        assert_eq!(actual, baseline);
    }
}

#[test]
fn cancellation_during_parallel_scan_keeps_previous_report() {
    use std::sync::atomic::Ordering;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("cancel.tgz");
    package(&p, &[("syslog", "error\n")]);
    let r = rules();
    let report = engine::analyze(&p, &r, &AtomicBool::new(false), |_| {}).unwrap();
    let previous = fs::read(&report).unwrap();
    let cancel = AtomicBool::new(false);
    let result = engine::analyze_with_workers(
        &p,
        &r,
        &cancel,
        4,
        |message| {
            if message.starts_with("分析文件") {
                cancel.store(true, Ordering::Relaxed);
            }
        },
        |_, _| {},
    );
    assert!(result.unwrap_err().is::<engine::Cancelled>());
    assert_eq!(fs::read(report).unwrap(), previous);
}

#[test]
fn shared_binary_and_corrupt_gzip_preserve_independent_failures() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("shared.tgz");
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    let mut compressed = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    compressed
        .write_all(b"error valid line\nerror unterminated")
        .unwrap();
    let mut compressed = compressed.finish().unwrap();
    let n = compressed.len();
    compressed[n - 8] ^= 0xff;
    for (name, content) in [
        ("syslog.1", b"error \xff\n".as_slice()),
        ("syslog.2.gz", compressed.as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, content).unwrap();
    }
    fs::write(&p, tar.into_inner().unwrap().finish().unwrap()).unwrap();
    let mut r = rules();
    r.system.push(tracefox::rules::SystemRule {
        id: "shared".into(),
        name: "共享 JSON".into(),
        kind: "json".into(),
        fields: vec![
            serde_json::from_value(serde_json::json!({"name": "值", "path": "value"})).unwrap(),
        ],
        source: Source {
            pattern: "syslog".into(),
            mode: "prefix".into(),
        },
        ..Default::default()
    });
    let mut baseline = None;
    for workers in [1, 4] {
        let mut actual = data(
            &engine::analyze_with_workers(
                &p,
                &r,
                &AtomicBool::new(false),
                workers,
                |_| {},
                |_, _| {},
            )
            .unwrap(),
        );
        assert!(actual["findings"][0]["count"].as_u64().unwrap() >= 1);
        assert_eq!(actual["findings"][0]["status"], "日志读取不完整");
        assert!(
            actual["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w.as_str().unwrap().contains("日志读取失败"))
        );
        actual.as_object_mut().unwrap().remove("generated");
        if let Some(baseline) = &baseline {
            assert_eq!(&actual, baseline);
        } else {
            baseline = Some(actual);
        }
    }
}

#[test]
fn relative_defaults_exclude_same_named_files_in_other_directories() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("relative.tgz");
    let line = "2026-09-08T17:35:12+08:00 btrfs_commit_transaction: deleting scheduled snapshot\n";
    package(
        &p,
        &[
            ("diag/log/kern.log.1", line),
            ("diag/appLog/Config/kernel.cfg", line),
        ],
    );
    let mut r = RuleSet::defaults();
    r.rules.retain(|r| r.id == "btrfs-snapshot-delete");
    r.system.clear();
    let visited = std::cell::RefCell::new(Vec::new());
    let report = data(
        &engine::analyze_with_workers(
            &p,
            &r,
            &AtomicBool::new(false),
            4,
            |_| {},
            |name, _| {
                visited.borrow_mut().push(name.to_owned());
            },
        )
        .unwrap(),
    );
    assert_eq!(report["findings"][0]["count"], 1);
    assert_eq!(*visited.borrow(), ["diag/log/kern.log.1"]);
}

#[test]
fn exact_relative_path_groups_system_and_log_rules_into_one_file_task() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("exact.tgz");
    package(
        &p,
        &[
            ("diag/cmd/info.json", "{\"value\":\"error\"}\n"),
            ("diag/other/info.json", "{\"value\":\"error\"}\n"),
        ],
    );
    let mut r = rules();
    r.rules[0].sources = vec![Source {
        pattern: "cmd/info.json".into(),
        mode: "exact".into(),
    }];
    let mut second = r.rules[0].clone();
    second.id = "second".into();
    second.name = "另一条规则".into();
    r.rules.push(second);
    r.system.push(tracefox::rules::SystemRule {
        id: "json".into(),
        name: "JSON".into(),
        kind: "json".into(),
        source: Source {
            pattern: "cmd/info.json".into(),
            mode: "exact".into(),
        },
        fields: vec![
            serde_json::from_value(serde_json::json!({"name":"值","path":"value"})).unwrap(),
        ],
        ..Default::default()
    });
    let visited = std::cell::Cell::new(0);
    let report = data(
        &engine::analyze_with_workers(
            &p,
            &r,
            &AtomicBool::new(false),
            4,
            |_| {},
            |_, _| visited.set(visited.get() + 1),
        )
        .unwrap(),
    );
    assert_eq!(visited.get(), 1);
    assert_eq!(report["findings"][0]["count"], 1);
    assert_eq!(report["findings"][1]["count"], 1);
    assert_eq!(report["system"][0]["source"], "diag/cmd/info.json");
    assert!(report["warnings"].as_array().unwrap().is_empty());
}

#[test]
fn disabled_legacy_owner_still_determines_first_matching_group() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("legacy.tgz");
    package(&p, &[("syslog", "error\n")]);
    let mut r = rules();
    r.rules[0].id = "owner".into();
    r.rules[0].legacy_group = "first".into();
    r.rules[0].enabled = false;
    let mut skipped = r.rules[0].clone();
    skipped.id = "skipped".into();
    skipped.name = "后续组".into();
    skipped.legacy_group = "second".into();
    skipped.enabled = true;
    let mut selected = r.rules[0].clone();
    selected.id = "selected".into();
    selected.name = "首组".into();
    selected.enabled = true;
    r.rules.extend([skipped, selected]);
    let report = data(&engine::analyze(&p, &r, &AtomicBool::new(false), |_| {}).unwrap());
    assert_eq!(report["findings"][0]["count"], 0);
    assert_eq!(report["findings"][0]["status"], "来源文件缺失");
    assert_eq!(report["findings"][1]["count"], 1);
}

#[test]
fn relative_prefix_does_not_enter_similarly_named_service_directories() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("service.tgz");
    package(
        &p,
        &[
            ("diag/appLog/cloud_serv.slog.1", "error\n"),
            ("diag/appLog/cloud_serv_log/data.gz", "not a gzip archive"),
        ],
    );
    let mut r = rules();
    r.rules[0].sources = vec![Source {
        pattern: "appLog/cloud_serv".into(),
        mode: "prefix".into(),
    }];
    let visited = std::cell::RefCell::new(Vec::new());
    let report = data(
        &engine::analyze_with_workers(
            &p,
            &r,
            &AtomicBool::new(false),
            4,
            |_| {},
            |name, _| visited.borrow_mut().push(name.to_owned()),
        )
        .unwrap(),
    );
    assert_eq!(*visited.borrow(), ["diag/appLog/cloud_serv.slog.1"]);
    assert_eq!(report["findings"][0]["count"], 1);
    assert!(report["warnings"].as_array().unwrap().is_empty());
}
