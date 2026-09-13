//! 为既有分析算法测试构建目录。Source 在这些测试中只是测试数据，生产代码不会自动重建目录。
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::io::Read;
use tracefox::rules::{LogFile, RuleSet, Source};

/// 解码生成报告，供集成测试继续按完整业务 JSON 断言新旧两种格式。
pub fn report_data_html(html: &str) -> serde_json::Value {
    if let Some(data) = html.split("const reportPayload=").nth(1) {
        let payload = serde_json::Deserializer::from_str(data)
            .into_iter::<serde_json::Value>()
            .next()
            .unwrap()
            .unwrap();
        if payload.is_object() {
            return payload;
        }
        let encoded = payload
            .as_str()
            .unwrap()
            .strip_prefix("gzip-base64-v1:")
            .unwrap();
        let compressed = BASE64.decode(encoded).unwrap();
        let mut gzip = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut json = Vec::new();
        gzip.read_to_end(&mut json).unwrap();
        return serde_json::from_slice(&json).unwrap();
    }
    let data = html.split("const report=").nth(1).unwrap();
    serde_json::Deserializer::from_str(data)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap()
        .unwrap()
}

pub fn report_data(path: &std::path::Path) -> serde_json::Value {
    report_data_html(&std::fs::read_to_string(path).unwrap())
}

pub fn catalog(input: &RuleSet) -> RuleSet {
    let mut rules = input.clone();
    let mut files = Vec::<LogFile>::new();
    let mut register = |source: &Source| {
        if let Some(file) = files
            .iter()
            .find(|f| f.path == source.pattern && f.mode == source.mode)
        {
            return file.id.clone();
        }
        let prior = input
            .log_files
            .iter()
            .find(|f| f.path == source.pattern && f.mode == source.mode);
        let id = prior
            .map(|f| f.id.clone())
            .unwrap_or_else(|| format!("fixture-{}", files.len()));
        files.push(LogFile {
            id: id.clone(),
            name: prior
                .map(|f| f.name.clone())
                .unwrap_or_else(|| format!("测试日志 {}", files.len())),
            path: source.pattern.clone(),
            mode: source.mode.clone(),
            container: "diagnostic_archive".into(),
        });
        id
    };
    for rule in &mut rules.rules {
        rule.source_file_ids = rule.sources.iter().map(&mut register).collect();
    }
    for rule in &mut rules.system {
        rule.source_file_id = register(&rule.source);
    }
    rules.log_files = files;
    rules.version = 3;
    rules
}
#[allow(dead_code, unused_imports)]
pub mod engine {
    use std::{
        path::{Path, PathBuf},
        sync::atomic::AtomicBool,
        time::Duration,
    };
    pub use tracefox::engine::{Cancelled, validate_archive};
    use tracefox::rules::RuleSet;
    pub fn analyze(
        path: &Path,
        rules: &RuleSet,
        cancel: &AtomicBool,
        progress: impl Fn(String),
    ) -> anyhow::Result<PathBuf> {
        tracefox::engine::analyze(path, &super::catalog(rules), cancel, progress)
    }
    pub fn analyze_with_workers(
        path: &Path,
        rules: &RuleSet,
        cancel: &AtomicBool,
        workers: usize,
        progress: impl Fn(String),
        timing: impl Fn(&str, Duration),
    ) -> anyhow::Result<PathBuf> {
        tracefox::engine::analyze_with_workers(
            path,
            &super::catalog(rules),
            cancel,
            workers,
            progress,
            timing,
        )
    }
    pub fn preview(
        rules: &RuleSet,
        index: usize,
        system: bool,
        text: &str,
    ) -> anyhow::Result<String> {
        tracefox::engine::preview(&super::catalog(rules), index, system, text)
    }
}
