use crate::engine::stamp;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};
/// 只保存文件元信息；稳定窗口用于防抖，真正完整性由归档解析验证。
pub struct DirectoryState {
    known: HashMap<PathBuf, (u64, SystemTime)>,
    pending: HashMap<PathBuf, Instant>,
}
impl DirectoryState {
    pub fn start(dir: &Path) -> Self {
        Self {
            known: snapshot(dir),
            pending: HashMap::new(),
        }
    }
    pub fn changed(&mut self, path: &Path, now: Instant) {
        if is_package(path)
            && stamp(path)
                .is_ok_and(|s| self.known.get(path) != Some(&s) || self.pending.contains_key(path))
        {
            self.pending.insert(path.to_path_buf(), now);
        }
    }
    /// 取消只消费当前文件版本；未来大小或修改时间发生变化仍会重新发现。
    pub fn dismiss(&mut self, path: &Path) {
        self.pending.remove(path);
        if let Ok(value) = stamp(path) {
            self.known.insert(path.to_path_buf(), value);
        }
    }
    pub fn pending_paths(&self) -> Vec<PathBuf> {
        self.pending.keys().cloned().collect()
    }
    pub fn poll(&mut self, dir: &Path, now: Instant) -> Vec<PathBuf> {
        let current = snapshot(dir);
        for (p, s) in &current {
            if self.known.get(p) != Some(s) {
                self.pending.insert(p.clone(), now);
            }
        }
        self.pending.retain(|p, _| current.contains_key(p));
        self.known = current;
        let mut ready: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, t)| now.duration_since(**t) >= Duration::from_secs(10))
            .map(|(p, _)| p.clone())
            .collect();
        ready.sort_by(|a, b| self.pending[a].cmp(&self.pending[b]).then(a.cmp(b)));
        for p in &ready {
            self.pending.remove(p);
        }
        ready
    }
}
fn snapshot(dir: &Path) -> HashMap<PathBuf, (u64, SystemTime)> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| is_package(p))
        .filter_map(|p| stamp(&p).ok().map(|s| (p, s)))
        .collect()
}
pub fn is_package(p: &Path) -> bool {
    p.extension().is_some_and(|e| e.eq_ignore_ascii_case("tgz"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_version_stays_dismissed_until_changed() {
        let d = tempfile::tempdir().unwrap();
        let mut monitor = DirectoryState::start(d.path());
        let path = d.path().join("new.tgz");
        std::fs::write(&path, b"a").unwrap();
        let now = Instant::now();
        monitor.poll(d.path(), now);
        assert_eq!(monitor.pending_paths(), vec![path.clone()]);
        monitor.dismiss(&path);
        monitor.changed(&path, now);
        assert!(
            monitor
                .poll(d.path(), now + Duration::from_secs(20))
                .is_empty()
        );
        std::fs::write(&path, b"new version").unwrap();
        monitor.poll(d.path(), now + Duration::from_secs(21));
        assert_eq!(
            monitor.poll(d.path(), now + Duration::from_secs(32)),
            vec![path]
        );
    }
    #[test]
    fn ignores_existing_and_coalesces() {
        let d = tempfile::tempdir().unwrap();
        let old = d.path().join("old.tgz");
        std::fs::write(&old, b"a").unwrap();
        let mut s = DirectoryState::start(d.path());
        let n = Instant::now();
        assert!(s.poll(d.path(), n + Duration::from_secs(20)).is_empty());
        let p = d.path().join("new.tgz");
        std::fs::write(&p, b"a").unwrap();
        assert!(s.poll(d.path(), n + Duration::from_secs(21)).is_empty());
        std::fs::write(&p, b"abc").unwrap();
        assert!(s.poll(d.path(), n + Duration::from_secs(25)).is_empty());
        assert!(s.poll(d.path(), n + Duration::from_secs(34)).is_empty());
        assert_eq!(s.poll(d.path(), n + Duration::from_secs(35)), vec![p]);
        assert!(s.poll(d.path(), n + Duration::from_secs(50)).is_empty());
    }
}
