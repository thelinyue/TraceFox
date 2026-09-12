//! 本次运行的诊断任务及清理边界。路径标识文件，递增 ID 标识行；后台消息不依赖行索引。
use crate::engine;
use anyhow::{Context, Result, bail};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    time::SystemTime,
};
pub type Stamp = (u64, SystemTime);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Waiting,
    Queued,
    Running,
    Cancelling,
    Cancelled,
    Failed,
    Damaged,
    Completed,
}
impl Phase {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Waiting | Self::Queued | Self::Running | Self::Cancelling
        )
    }
}
#[derive(Clone, Debug)]
pub struct Task {
    pub id: i32,
    pub package: PathBuf,
    pub phase: Phase,
    pub status: String,
    pub report: Option<PathBuf>,
    pub source_stamp: Option<Stamp>,
    pub output_stamp: Option<Stamp>,
    pub finished: u64,
}
/// 只有终态记录参与 20 条上限；重试保持原行位置，完成时间单独用于淘汰。
#[derive(Default)]
pub struct Tasks {
    pub rows: VecDeque<Task>,
    pub queue: VecDeque<i32>,
    pub running: Option<i32>,
    next_id: i32,
    clock: u64,
}
pub fn absolute(path: &Path) -> PathBuf {
    if let Ok(full) = path.canonicalize() {
        return full;
    }
    let full = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    full.parent()
        .and_then(|p| p.canonicalize().ok())
        .and_then(|p| full.file_name().map(|n| p.join(n)))
        .unwrap_or(full)
}
impl Tasks {
    pub fn get(&self, id: i32) -> Option<&Task> {
        self.rows.iter().find(|r| r.id == id)
    }
    pub fn get_mut(&mut self, id: i32) -> Option<&mut Task> {
        self.rows.iter_mut().find(|r| r.id == id)
    }
    pub fn register(&mut self, path: PathBuf, phase: Phase) -> i32 {
        let path = absolute(&path);
        if let Some(r) = self.rows.iter_mut().find(|r| r.package == path) {
            if !r.phase.active() {
                r.phase = phase;
                r.status = if phase == Phase::Waiting {
                    "等待文件稳定"
                } else {
                    "排队中"
                }
                .into();
            }
            return r.id;
        }
        self.next_id += 1;
        self.rows.push_front(Task {
            id: self.next_id,
            package: path,
            phase,
            status: if phase == Phase::Waiting {
                "等待文件稳定"
            } else {
                "排队中"
            }
            .into(),
            report: None,
            source_stamp: None,
            output_stamp: None,
            finished: 0,
        });
        self.next_id
    }
    pub fn enqueue(&mut self, path: PathBuf) {
        if !crate::monitor::is_package(&path) {
            return;
        }
        let id = self.register(path, Phase::Queued);
        let r = self.get_mut(id).unwrap();
        if matches!(r.phase, Phase::Running | Phase::Cancelling) {
            return;
        }
        r.phase = Phase::Queued;
        r.status = "排队中".into();
        if !self.queue.contains(&id) {
            self.queue.push_back(id);
        }
    }
    pub fn start(&mut self, paused: Option<&Path>) -> Option<(i32, PathBuf)> {
        if self.running.is_some() {
            return None;
        }
        let pos = self.queue.iter().position(|id| {
            self.get(*id)
                .is_some_and(|r| paused.is_none_or(|p| r.package.parent() != Some(p)))
        })?;
        let id = self.queue.remove(pos)?;
        self.running = Some(id);
        let r = self.get_mut(id)?;
        r.phase = Phase::Running;
        r.status = "准备解压诊断包…".into();
        Some((id, r.package.clone()))
    }
    /// 已经成功提交的报告优先于晚到的取消请求，避免把成功结果误报为取消。
    pub fn finish(
        &mut self,
        id: i32,
        phase: Phase,
        status: String,
        report: Option<PathBuf>,
        stamp: Option<Stamp>,
    ) {
        if self.running == Some(id) {
            self.running = None;
        }
        self.clock += 1;
        let clock = self.clock;
        if let Some(r) = self.get_mut(id) {
            r.phase = phase;
            r.status = status;
            r.finished = clock;
            if phase == Phase::Damaged {
                r.source_stamp = stamp;
            }
            if let Some(report) = report {
                r.output_stamp = report.parent().and_then(|p| engine::stamp(p).ok());
                r.report = Some(report);
                r.source_stamp = stamp;
            }
        }
        let mut finished = self
            .rows
            .iter()
            .filter(|r| !r.phase.active())
            .map(|r| (r.finished, r.id))
            .collect::<Vec<_>>();
        finished.sort_unstable_by(|a, b| b.cmp(a));
        let remove = finished
            .into_iter()
            .skip(20)
            .map(|(_, id)| id)
            .collect::<Vec<_>>();
        self.rows.retain(|r| !remove.contains(&r.id));
    }
    pub fn cancel(&mut self, id: i32) -> bool {
        let Some(r) = self.get_mut(id) else {
            return false;
        };
        if r.phase == Phase::Running {
            r.phase = Phase::Cancelling;
            r.status = "正在取消…".into();
            return true;
        }
        if matches!(r.phase, Phase::Waiting | Phase::Queued) {
            self.queue.retain(|queued| *queued != id);
            self.finish(id, Phase::Cancelled, "已取消".into(), None, None);
        }
        false
    }
    pub fn has_active_in(&self, dir: &Path) -> bool {
        self.rows
            .iter()
            .any(|r| r.package.parent() == Some(dir) && r.phase.active())
    }
    pub fn candidates(&self, dir: &Path) -> Vec<Task> {
        if self.has_active_in(dir) {
            return vec![];
        }
        self.rows
            .iter()
            .filter(|r| r.phase == Phase::Completed && r.package.parent() == Some(dir))
            .cloned()
            .collect()
    }
}

/// 损坏包只删除源文件，已有报告目录保持原样。确认后必须仍是同一版本。
pub fn delete_damaged(task: &Task) -> Result<()> {
    if task.phase != Phase::Damaged {
        bail!("任务状态已变化，未删除");
    }
    match std::fs::symlink_metadata(&task.package) {
        Ok(meta) => {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & 0x400 != 0 {
                    bail!("拒绝删除重解析点");
                }
            }
            if !meta.is_file()
                || meta.file_type().is_symlink()
                || Some(engine::stamp(&task.package)?) != task.source_stamp
            {
                bail!("文件已变化，请重新检查后再删除");
            }
            std::fs::remove_file(&task.package).context("无法删除损坏的压缩包")?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// 删除前校验已分析版本及输出关系；只接受同目录同名输出，拒绝链接或重解析点。
pub fn validate_cleanup(task: &Task) -> Result<PathBuf> {
    if task.phase != Phase::Completed {
        bail!("任务尚未成功完成");
    }
    let output = task.package.with_extension("");
    if task.report.as_deref() != Some(output.join("report.html").as_path()) {
        bail!("输出目录与诊断包不对应");
    }
    for path in [&task.package, &output] {
        for ancestor in path.ancestors() {
            if let Ok(m) = std::fs::symlink_metadata(ancestor) {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if m.file_attributes() & 0x400 != 0 {
                        bail!("路径包含重解析点：{}", ancestor.display());
                    }
                }
                if m.file_type().is_symlink() {
                    bail!("路径包含链接：{}", ancestor.display());
                }
            }
        }
    }
    // 部分清理失败后允许重试：缺失文件无需再删，存在文件必须仍为原分析版本。
    match std::fs::symlink_metadata(&task.package) {
        Ok(m) => {
            if !m.is_file() || Some(engine::stamp(&task.package)?) != task.source_stamp {
                bail!("诊断包已发生变化，已跳过");
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    match std::fs::symlink_metadata(&output) {
        Ok(m) => {
            if !m.is_dir() {
                bail!("输出路径不是目录");
            }
            if Some(engine::stamp(&output)?) != task.output_stamp {
                bail!("输出目录已发生变化，已跳过");
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(output)
}
/// 每项独立返回错误。先删源包，目录失败仍保留任务以便重试，并刷新目录元信息。
pub fn cleanup(task: &Task) -> Result<()> {
    let output = validate_cleanup(task)?;
    match std::fs::remove_file(&task.package) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("无法删除诊断包"),
    }
    match std::fs::remove_dir_all(&output) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("无法删除输出目录"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn completed(root: &Path, name: &str) -> Task {
        let package = absolute(root).join(format!("{name}.tgz"));
        let output = package.with_extension("");
        std::fs::write(&package, b"package").unwrap();
        std::fs::create_dir(&output).unwrap();
        let report = output.join("report.html");
        std::fs::write(&report, b"report").unwrap();
        Task {
            id: 1,
            package: package.clone(),
            phase: Phase::Completed,
            status: "分析完成".into(),
            report: Some(report),
            source_stamp: Some(engine::stamp(&package).unwrap()),
            output_stamp: Some(engine::stamp(&output).unwrap()),
            finished: 1,
        }
    }
    #[test]
    fn damaged_delete_keeps_report_and_refuses_changed_package() {
        let d = tempfile::tempdir().unwrap();
        let mut r = completed(d.path(), "bad");
        r.phase = Phase::Damaged;
        std::fs::write(&r.package, b"new version").unwrap();
        assert!(delete_damaged(&r).is_err());
        r.source_stamp = engine::stamp(&r.package).ok();
        delete_damaged(&r).unwrap();
        assert!(!r.package.exists());
        assert!(r.report.unwrap().exists());
    }
    #[test]
    fn cancellation_error_is_typed_and_does_not_replace_report() {
        use std::sync::atomic::AtomicBool;
        let d = tempfile::tempdir().unwrap();
        let r = completed(d.path(), "cancel");
        let error = engine::validate_archive(&r.package, &AtomicBool::new(true)).unwrap_err();
        assert!(error.downcast_ref::<engine::Cancelled>().is_some());
        assert_eq!(std::fs::read(r.report.unwrap()).unwrap(), b"report");
    }
    #[test]
    fn stable_identity_retry_cancel_and_same_name() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a/x.tgz");
        let b = d.path().join("b/x.tgz");
        let mut t = Tasks::default();
        t.enqueue(a.clone());
        t.enqueue(a.clone());
        t.enqueue(b.clone());
        assert_eq!(t.rows.len(), 2);
        assert_eq!(t.queue.len(), 2);
        let (id, _) = t.start(None).unwrap();
        t.enqueue(a.clone());
        assert_eq!(t.queue.len(), 1);
        assert!(t.cancel(id));
        assert_eq!(t.get(id).unwrap().phase, Phase::Cancelling);
        t.finish(id, Phase::Cancelled, "已取消".into(), None, None);
        t.enqueue(a);
        assert_eq!(t.rows.len(), 2);
        assert_eq!(t.get(id).unwrap().phase, Phase::Queued);
        let other = t.rows[0].id;
        t.cancel(other);
        assert_eq!(t.get(other).unwrap().phase, Phase::Cancelled);
        assert_eq!(t.start(None).unwrap().0, id);
    }
    #[test]
    fn terminal_retention_uses_completion_time_and_keeps_active() {
        let mut t = Tasks::default();
        let waiting = t.register("waiting.tgz".into(), Phase::Waiting);
        for n in 0..25 {
            let id = t.register(format!("{n}.tgz").into(), Phase::Queued);
            t.finish(id, Phase::Completed, "ok".into(), None, None);
        }
        assert_eq!(t.rows.len(), 21);
        assert!(t.get(waiting).is_some());
        assert!(!t.rows.iter().any(|r| r.package.ends_with("0.tgz")));
    }
    #[test]
    fn cleanup_scope_and_paused_scheduler() {
        let d = tempfile::tempdir().unwrap();
        let mut t = Tasks::default();
        let mut done = completed(d.path(), "done");
        done.id = 100;
        t.rows.push_back(done);
        assert_eq!(t.candidates(&absolute(d.path())).len(), 1);
        let wait = t.register(d.path().join("wait.tgz"), Phase::Waiting);
        assert!(t.candidates(&absolute(d.path())).is_empty());
        t.cancel(wait);
        t.enqueue(d.path().join("queued.tgz"));
        t.enqueue(d.path().join("elsewhere/out.tgz"));
        assert!(
            t.start(Some(&absolute(d.path())))
                .unwrap()
                .1
                .ends_with("elsewhere/out.tgz")
        );
    }
    #[test]
    fn cleanup_removes_only_matching_package_and_output() {
        let d = tempfile::tempdir().unwrap();
        let r = completed(d.path(), "done");
        std::fs::write(d.path().join("keep.txt"), b"keep").unwrap();
        cleanup(&r).unwrap();
        assert!(!r.package.exists());
        assert!(!r.package.with_extension("").exists());
        assert!(d.path().join("keep.txt").exists());
        cleanup(&r).unwrap();
    }
    #[test]
    fn changed_source_or_wrong_output_is_never_deleted() {
        let d = tempfile::tempdir().unwrap();
        let mut r = completed(d.path(), "done");
        std::fs::write(&r.package, b"changed package").unwrap();
        assert!(cleanup(&r).is_err());
        assert!(r.report.as_ref().unwrap().exists());
        r.source_stamp = Some(engine::stamp(&r.package).unwrap());
        r.report = Some(d.path().join("report.html"));
        assert!(cleanup(&r).is_err());
        assert!(r.package.exists());
    }
    #[test]
    fn retry_failure_keeps_old_report() {
        let d = tempfile::tempdir().unwrap();
        let r = completed(d.path(), "old");
        let mut t = Tasks::default();
        t.next_id = 1;
        t.rows.push_back(r.clone());
        t.enqueue(r.package.clone());
        let (id, _) = t.start(None).unwrap();
        t.finish(id, Phase::Failed, "失败".into(), None, None);
        assert_eq!(t.get(id).unwrap().report, r.report);
        assert!(t.candidates(&absolute(d.path())).is_empty());
    }
    #[cfg(windows)]
    #[test]
    fn partial_delete_failure_keeps_output_for_retry() {
        use std::os::windows::fs::OpenOptionsExt;
        let d = tempfile::tempdir().unwrap();
        let mut r = completed(d.path(), "locked");
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(r.report.as_ref().unwrap())
            .unwrap();
        assert!(cleanup(&r).is_err());
        assert!(!r.package.exists());
        assert!(r.report.as_ref().unwrap().exists());
        drop(lock);
        r.output_stamp = engine::stamp(&r.package.with_extension("")).ok();
        cleanup(&r).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn output_reparse_point_is_rejected() {
        use std::os::windows::fs::symlink_dir;
        let d = tempfile::tempdir().unwrap();
        let r = completed(d.path(), "link");
        let output = r.package.with_extension("");
        std::fs::remove_dir_all(&output).unwrap();
        let elsewhere = d.path().join("keep");
        std::fs::create_dir(&elsewhere).unwrap();
        // 无创建符号链接权限的 Windows 环境仍由正常路径测试覆盖；不提升权限。
        if symlink_dir(&elsewhere, &output).is_ok() {
            assert!(cleanup(&r).is_err());
            assert!(r.package.exists());
            assert!(elsewhere.exists());
        }
    }
}
