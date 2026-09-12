use std::{fs, sync::atomic::AtomicBool};
use tracefox::{
    engine,
    rules::{LogFile, Rule, RuleSet, Source},
};

fn file(id: &str, name: &str, path: &str) -> LogFile {
    LogFile {
        id: id.into(),
        name: name.into(),
        path: path.into(),
        mode: "exact".into(),
        container: "diagnostic_archive".into(),
    }
}
fn rules() -> RuleSet {
    RuleSet {
        version: 3,
        log_files: vec![file("one", "系统日志", "log/a.log")],
        rules: vec![Rule {
            id: "rule".into(),
            group: "internal-group".into(),
            source_file_ids: vec!["one".into()],
            sources: vec![],
            terms: vec!["error".into()],
            ..Rule::default()
        }],
        system: vec![],
        layout: Default::default(),
    }
}
fn package(path: &std::path::Path) {
    let writer =
        flate2::write::GzEncoder::new(fs::File::create(path).unwrap(), flate2::Compression::fast());
    let mut archive = tar::Builder::new(writer);
    for name in ["log/a.log", "log/b.log"] {
        let text = b"error\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(text.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, text.as_slice())
            .unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap();
}
#[test]
fn directory_edits_are_atomic_and_protect_references() {
    let mut r = rules();
    r.resolve_sources().unwrap();
    assert!(
        r.delete_log_file("one")
            .unwrap_err()
            .to_string()
            .contains("引用")
    );
    r.save_log_file(file("two", "其他日志", "log/b.log"))
        .unwrap();
    r.delete_log_file("two").unwrap();
    let before = serde_json::to_value(&r).unwrap();
    assert!(
        r.save_log_file(file("two", "系统日志", "log/b.log"))
            .is_err()
    );
    assert_eq!(before, serde_json::to_value(&r).unwrap());
    assert!(
        r.save_log_file(file("two", "其他日志", "log/a.log"))
            .is_err()
    );
    r.save_log_file(file("one", "更名后的日志", "log/b.log"))
        .unwrap();
    assert_eq!(r.rules[0].source_file_ids, ["one"]);
    assert_eq!(r.rules[0].group, "internal-group");
    assert_eq!(r.rules[0].sources[0].pattern, "log/b.log");
    assert!(
        r.source_label(&r.rules[0].source_file_ids)
            .contains("更名后的日志")
    );
    assert_eq!(
        r.source_label(&r.rules[0].source_file_ids),
        "更名后的日志 · b.log"
    );
}
#[test]
fn persisted_rules_only_contain_references_and_reload_from_directory() {
    let mut r = rules();
    r.layout.file_panel_width = 310;
    r.resolve_sources().unwrap();
    let value = serde_json::to_value(&r).unwrap();
    assert!(value["rules"][0].get("sources").is_none());
    assert!(value["log_files"][0].get("entry_path").is_none());
    let loaded = RuleSet::import(&value.to_string()).unwrap();
    assert_eq!(loaded.rules[0].sources[0].pattern, "log/a.log");
    assert_eq!(loaded.layout.file_panel_width, 310);
    let mut invalid = value.clone();
    invalid["rules"][0]["source_file_ids"] = serde_json::json!(["missing"]);
    assert!(RuleSet::import(&invalid.to_string()).is_err());
    invalid["rules"][0]["source_file_ids"] = serde_json::json!([]);
    assert!(RuleSet::import(&invalid.to_string()).is_err());
    assert!(RuleSet::import(r#"{"version":2,"rules":[]}"#).is_err());
}
#[test]
fn invalid_catalog_options_and_zip_are_rejected() {
    for (property, value) in [
        ("mode", "unknown"),
        ("container", "unknown"),
        ("path", "../escape"),
        ("path", "/root/log"),
        ("name", ""),
    ] {
        let mut r = serde_json::to_value(rules()).unwrap();
        r["log_files"][0][property] = value.into();
        assert!(RuleSet::import(&r.to_string()).is_err());
    }
    let mut r = rules();
    let mut duplicate_path = r.clone();
    duplicate_path.log_files.push(LogFile {
        id: "two".into(),
        name: "第二日志".into(),
        path: duplicate_path.log_files[0].path.clone(),
        mode: "exact".into(),
        container: "diagnostic_archive".into(),
    });
    assert!(duplicate_path.validate().is_err());
    r.log_files[0].container = "zip".into();
    assert!(
        r.validate()
            .unwrap_err()
            .to_string()
            .contains("暂不支持 ZIP")
    );
    r.log_files[0].container = "diagnostic_archive".into();
    r.layout.file_panel_width = 999;
    assert!(r.validate().is_err());
    let d = tempfile::tempdir().unwrap();
    let zip = d.path().join("input.zip");
    fs::write(&zip, b"PK\x03\x04").unwrap();
    assert!(
        engine::validate_archive(&zip, &AtomicBool::new(false))
            .unwrap_err()
            .to_string()
            .contains("ZIP")
    );
}
#[test]
fn analysis_and_preview_resolve_directory_and_keep_internal_groups() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("input.tgz");
    package(&path);
    let mut r = rules();
    r.log_files[0].path = "log/b.log".into();
    r.log_files[0].name = "自定义中文名".into();
    // 故意留下旧运行时缓存，分析必须重新读取目录。
    r.rules[0].sources = vec![Source {
        pattern: "wrong.log".into(),
        mode: "exact".into(),
    }];
    let report = engine::analyze(&path, &r, &AtomicBool::new(false), |_| {}).unwrap();
    let html = fs::read_to_string(report).unwrap();
    let data = html.split("const report=").nth(1).unwrap();
    let json: serde_json::Value = serde_json::Deserializer::from_str(data)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(json["findings"][0]["count"], 1);
    assert_eq!(json["findings"][0]["rule"]["group"], "internal-group");
    assert_eq!(json["findings"][0]["fragments"][0]["file"], "log/b.log");
    assert_eq!(json["log_files"][0]["name"], "自定义中文名");
    assert_eq!(
        json["source_catalog"]["log/b.log"],
        serde_json::json!(["one"])
    );
    assert!(
        json["source_labels"]["log/b.log"]
            .as_str()
            .unwrap()
            .contains("自定义中文名")
    );
    let preview = engine::preview(&r, 0, false, "error").unwrap();
    assert!(preview.contains("自定义中文名"));
}
#[test]
fn imports_remap_directory_ids_without_losing_multi_file_references() {
    let r = rules();
    let mut incoming = rules();
    incoming.log_files[0].id = "remote".into();
    incoming.rules[0].id = "remote-rule".into();
    // 同名规则来自不同日志，导入时仍以 ID 区分。
    incoming.rules[0].name = r.rules[0].name.clone();
    incoming.rules[0].source_file_ids = vec!["remote".into()];
    incoming
        .log_files
        .push(file("two", "第二日志", "log/b.log"));
    incoming.rules[0].source_file_ids.push("two".into());
    let merged = r.merge(&incoming, false).unwrap();
    assert_eq!(merged.log_files.len(), 2);
    let rule = merged.rules.iter().find(|x| x.id == "remote-rule").unwrap();
    assert_eq!(rule.source_file_ids, ["one", "two"]);
    assert_eq!(rule.sources.len(), 2);
    let again = RuleSet::import(&serde_json::to_string(&merged).unwrap()).unwrap();
    assert_eq!(again.rules[1].source_file_ids, ["one", "two"]);
}

#[test]
fn system_references_and_reference_import_preserve_directory_edits() {
    let mut r = RuleSet::defaults();
    let id = r.system[0].source_file_id.clone();
    let mut edited = r.log_file(&id).unwrap().clone();
    edited.name = "自定义设备信息".into();
    edited.path = "custom/device.json".into();
    r.save_log_file(edited).unwrap();
    assert!(r.delete_log_file(&id).is_err());
    let updated = r.with_reference_system().unwrap();
    assert_eq!(updated.log_file(&id).unwrap().name, "自定义设备信息");
    for rule in updated
        .system
        .iter()
        .filter(|rule| rule.source_file_id == id)
    {
        assert_eq!(rule.source.pattern, "custom/device.json");
    }
    let json = serde_json::to_value(&updated).unwrap();
    assert!(json["system"][0].get("source").is_none());
    assert_eq!(r.rules[0].source_file_ids, updated.rules[0].source_file_ids);
}
