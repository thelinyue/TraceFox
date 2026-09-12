//! 手动性能测量入口：仅处理调用者放在隔离目录中的样本，不设置耗时门禁。
use std::{
    cell::{Cell, RefCell},
    path::Path,
    sync::atomic::AtomicBool,
    time::Instant,
};

#[test]
#[ignore = "需指定 TRACEFOX_PERF_PACKAGE，输出目录必须为隔离的样本副本"]
fn measure_pipeline() {
    let package = std::env::var("TRACEFOX_PERF_PACKAGE").unwrap();
    let path = Path::new(&package);
    let rules = tracefox::rules::RuleSet::defaults();
    let cancel = AtomicBool::new(false);
    let start = Instant::now();
    tracefox::engine::validate_archive(path, &cancel).unwrap();
    let validated = start.elapsed().as_secs_f64();
    let scan = Cell::new(None);
    let write = Cell::new(None);
    let workers = std::env::var("TRACEFOX_PERF_WORKERS")
        .ok()
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(4)
        });
    let files = RefCell::new(Vec::new());
    tracefox::engine::analyze_with_workers(
        path,
        &rules,
        &cancel,
        workers,
        |message| {
            if message.starts_with("分析文件") && scan.get().is_none() {
                scan.set(Some(start.elapsed().as_secs_f64()));
            }
            if message == "正在生成离线 HTML…" {
                write.set(Some(start.elapsed().as_secs_f64()));
            }
        },
        |name, elapsed| {
            files
                .borrow_mut()
                .push(serde_json::json!({"file": name, "seconds": elapsed.as_secs_f64()}));
        },
    )
    .unwrap();
    let total = start.elapsed().as_secs_f64();
    let scan = scan.get().unwrap();
    let write = write.get().unwrap();
    println!(
        "PERF {}",
        serde_json::json!({
            "package": path.file_name().unwrap().to_string_lossy(), "workers": workers.clamp(1, 4),
            "files": files.into_inner(), "validate": validated, "unpack_prepare": scan-validated,
            "analyze": write-scan, "report": total-write, "total": total
        })
    );
}
