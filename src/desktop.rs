use anyhow::{Context, Result};
use notify::Watcher;
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use tracefox::{
    engine, extract, monitor,
    rules::{Field, LogFile, Rule, RuleSet, SystemRule},
    tasks::{self, Phase, Tasks},
};
slint::include_modules!();

/// 桌面偏好与监控配置共用本地设置文件；新增启动选项对旧配置默认为关闭。
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct Settings {
    directory: String,
    watching: bool,
    /// WebDAV 配置；密码通过系统凭据库保存，不写入此文件。
    #[serde(default)]
    webdav: Option<tracefox::webdav::WebDavSettings>,
    #[serde(default)]
    autostart: bool,
    #[serde(default)]
    start_minimized: bool,
}

/// 设置保存以系统启动项和 JSON 均成功为准；JSON 落盘失败时恢复原启动命令。
fn persist_startup(settings: &Settings) -> Result<()> {
    use crate::windows_integration::{startup_command, startup_value, write_startup};
    let previous = startup_value().context("无法读取 Windows 启动项")?;
    let command = settings
        .autostart
        .then(|| std::env::current_exe().map(|p| startup_command(&p)))
        .transpose()?;
    if let Err(e) = write_startup(command.as_deref()).context("无法保存 Windows 启动项") {
        if let Err(rollback) = write_startup(previous.as_deref()) {
            anyhow::bail!("{e:#}；恢复原启动项也失败：{rollback:#}");
        }
        return Err(e);
    }
    if let Err(e) = save_json("settings.json", settings) {
        if let Err(rollback) = write_startup(previous.as_deref()) {
            anyhow::bail!("保存设置失败：{e:#}；恢复原启动项也失败：{rollback:#}");
        }
        anyhow::bail!("保存设置失败，启动项已恢复：{e:#}");
    }
    Ok(())
}

/// 托盘和失败通知共用恢复入口，同时处理隐藏、最小化与前台焦点。
fn show_main(ui: &AppWindow) {
    show_and_focus(ui);
}

/// 将已存在的窗口恢复并置前，避免入口点击后窗口仍被其他窗口遮挡。
fn show_and_focus<C: ComponentHandle>(ui: &C) {
    let _ = ui.show();
    ui.window().set_minimized(false);
    use slint::winit_030::WinitWindowAccessor;
    ui.window()
        .with_winit_window(|window| window.focus_window());
}

/// 跨显示器时 Windows 会先改变窗口 DPI，再异步调整软件渲染缓冲区。
/// 这里把关键窗口事件转换成一次显式重绘；DPI 切换额外重新提交当前物理尺寸，
/// 让 Slint 的 software renderer 丢弃旧缓冲区，避免拖动后只剩背景或出现空白。
fn recover_window_rendering(
    window: &slint::Window,
    event: &slint::winit_030::winit::event::WindowEvent,
) {
    use slint::winit_030::WinitWindowAccessor;
    use slint::winit_030::winit::event::WindowEvent;

    let scale_changed = matches!(event, WindowEvent::ScaleFactorChanged { .. });
    let should_redraw = scale_changed
        || matches!(
            event,
            WindowEvent::Resized(_) | WindowEvent::Focused(true) | WindowEvent::Occluded(false)
        );
    if !should_redraw {
        return;
    }

    if scale_changed {
        if let Some(size) = window.with_winit_window(|winit_window| winit_window.inner_size()) {
            // 物理尺寸不变，只是重新走一遍后端的尺寸同步，避免旧 DPI 的绘制缓冲区残留。
            window.set_size(slint::PhysicalSize::new(size.width, size.height));
        } else {
            eprintln!("TraceFox：窗口渲染恢复失败，未找到对应的 Windows 窗口句柄");
        }
    }
    window.request_redraw();
}

/// 为没有其他 Winit 事件处理需求的窗口安装统一的跨屏重绘恢复器。
fn install_window_rendering_recovery(window: &slint::Window) {
    use slint::winit_030::{EventResult, WinitWindowAccessor};
    window.on_winit_window_event(|window, event| {
        recover_window_rendering(window, event);
        EventResult::Propagate
    });
}

fn open_report_path(path: &std::path::Path) -> Result<()> {
    anyhow::ensure!(
        path.is_file(),
        "报告文件不存在，可能已被移动或清理：{}",
        path.display()
    );
    open::that(path).context("无法打开 HTML 报告，请检查默认浏览器设置")
}

fn data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("TraceFox")
}
/// 桌面端规则唯一落盘位置：程序目录中的默认规则文件。
fn default_rules_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|d| d.join("assets").join("default-rules.json"))
        })
        .unwrap_or_else(|| PathBuf::from("assets/default-rules.json"))
}
fn save_default_rules(rules: &RuleSet) -> Result<()> {
    save_rules_at(&default_rules_path(), rules)
}
/// 先写同目录临时文件再替换，保存失败时保留上一份规则。
fn save_rules_at(path: &std::path::Path, rules: &RuleSet) -> Result<()> {
    rules.validate()?;
    std::fs::create_dir_all(path.parent().context("规则目录不存在")?)
        .context("无法创建规则目录，请检查安装目录写入权限")?;
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(rules)?)
        .context("无法写入规则，请检查安装目录写入权限")?;
    engine::replace_file(&temp, path).context("无法替换规则文件")
}
fn save_json<T: serde::Serialize>(name: &str, value: &T) -> Result<()> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    let temp = dir.join(format!("{name}.tmp"));
    std::fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    engine::replace_file(&temp, &dir.join(name))
}
fn save_sync_metadata(m: &tracefox::webdav::SyncMetadata) -> Result<()> {
    save_json("webdav-sync.json", m)
}
fn load_sync_metadata() -> tracefox::webdav::SyncMetadata {
    std::fs::read_to_string(data_dir().join("webdav-sync.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}
fn rules_hash(r: &RuleSet) -> Result<String> {
    Ok(tracefox::webdav::content_hash(&serde_json::to_vec(r)?))
}
enum Message {
    Progress(i32, String),
    Done(
        i32,
        std::result::Result<PathBuf, (bool, bool, String)>,
        Option<tasks::Stamp>,
        Duration,
    ),
    Cleaned(
        Vec<(
            i32,
            std::result::Result<(), String>,
            Option<tasks::Stamp>,
            bool,
        )>,
        usize,
    ),
}
/// 状态仅由界面线程修改；分析和删除在后台执行，以稳定任务 ID 回传结果。
struct State {
    rules: RuleSet,
    settings: Settings,
    tasks: Tasks,
    deferred: std::collections::HashMap<PathBuf, (Option<tasks::Stamp>, Instant)>,
    cancel: Arc<AtomicBool>,
    directory: Option<monitor::DirectoryState>,
    watcher: Option<notify::RecommendedWatcher>,
    events: Option<mpsc::Receiver<notify::Result<notify::Event>>>,
    last_poll: Instant,
    editor: Option<EditorWindow>,
    monitor_status: String,
    cleaning: Vec<i32>,
    cleanup_directory: Option<PathBuf>,
}
fn enqueue(state: &mut State, path: PathBuf) {
    let path = tasks::absolute(&path);
    if !state
        .tasks
        .rows
        .iter()
        .any(|r| r.package == path && state.cleaning.contains(&r.id))
    {
        state.tasks.enqueue(path);
    }
}
/// 先建立新监控并保存，全部成功后再替换旧对象；失败不会丢失原目录监控。
fn configure_monitor(state: &mut State, mut settings: Settings) -> Result<()> {
    let mut watcher = None;
    let mut events = None;
    let mut directory = None;
    if !settings.directory.is_empty() {
        let path = tasks::absolute(std::path::Path::new(&settings.directory));
        if !path.is_dir() && (settings.watching || settings.directory != state.settings.directory) {
            anyhow::bail!("请选择可访问的监控目录");
        }
        settings.directory = path.to_string_lossy().into();
    }
    if settings.watching {
        if settings.directory.is_empty() {
            anyhow::bail!("请先选择监控目录");
        }
        let path = PathBuf::from(&settings.directory);
        directory = Some(monitor::DirectoryState::start(&path));
        let (tx, rx) = mpsc::channel();
        let mut w = notify::recommended_watcher(move |e: notify::Result<notify::Event>| {
            let _ = tx.send(e);
        })?;
        w.watch(&path, notify::RecursiveMode::NonRecursive)?;
        watcher = Some(w);
        events = Some(rx);
    }
    save_json("settings.json", &settings)?;
    // 关闭或切换监控时结束旧目录中尚未稳定的等待，已入队任务照常执行。
    let waiting = state
        .tasks
        .rows
        .iter()
        .filter(|r| r.phase == Phase::Waiting && !state.deferred.contains_key(&r.package))
        .map(|r| r.id)
        .collect::<Vec<_>>();
    for id in waiting {
        state.tasks.cancel(id);
    }
    state.settings = settings;
    state.directory = directory;
    state.watcher = watcher;
    state.events = events;
    state.monitor_status.clear();
    Ok(())
}
/// 界面隐藏 Windows 扩展路径前缀，内部路径仍用于稳定身份与安全检查。
fn directory_label(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()
    }
}
fn choose_monitor(ui: &AppWindow, state: &Rc<RefCell<State>>, choose: bool) {
    let mut settings = state.borrow().settings.clone();
    if state.borrow().cleanup_directory.is_some() {
        return;
    }
    if !choose {
        settings.watching = ui.get_watching();
    }
    if choose || (settings.watching && settings.directory.is_empty()) {
        let Some(path) = rfd::FileDialog::new().pick_folder() else {
            ui.set_watching(state.borrow().settings.watching);
            return;
        };
        settings.directory = path.to_string_lossy().into();
    }
    let mut st = state.borrow_mut();
    if let Err(e) = configure_monitor(&mut st, settings) {
        st.monitor_status = format!("监控配置未更改：{e}");
    }
    ui.set_directory(directory_label(&st.settings.directory).into());
    ui.set_watching(st.settings.watching);
}
fn cancel_task(state: &mut State, id: i32) {
    let Some(path) = state.tasks.get(id).map(|r| r.package.clone()) else {
        return;
    };
    if state.cleaning.contains(&id) {
        return;
    }
    if state.tasks.cancel(id) {
        state.cancel.store(true, Ordering::Relaxed);
    }
    state.deferred.remove(&path);
    if let Some(ds) = state.directory.as_mut() {
        ds.dismiss(&path);
    }
}
/// 确认中不持有 RefCell 借用；确认后重新检查活动任务与文件，再启动异步清理。
fn confirm_cleanup(state: &Rc<RefCell<State>>, tx: &mpsc::Sender<Message>, single: Option<i32>) {
    let (dir, candidates) = {
        let st = state.borrow();
        if st.cleanup_directory.is_some() {
            return;
        }
        let dir = single
            .and_then(|id| st.tasks.get(id))
            .and_then(|r| r.package.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from(&st.settings.directory));
        let candidates = if let Some(id) = single {
            st.tasks
                .get(id)
                .filter(|r| r.phase == Phase::Completed)
                .cloned()
                .into_iter()
                .collect()
        } else {
            st.tasks.candidates(&dir)
        };
        (dir, candidates)
    };
    if candidates.is_empty() {
        return;
    }
    let listing = candidates
        .iter()
        .map(|r| {
            format!(
                "诊断包：{}\n输出目录：{}",
                r.package.display(),
                r.package.with_extension("").display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    let confirmed = rfd::MessageDialog::new()
        .set_title("确认清理已完成诊断包")
        .set_description(format!(
            "将永久删除以下 {} 个诊断包及输出目录，无法恢复。\n监控目录：{}\n\n{}",
            candidates.len(),
            dir.display(),
            listing
        ))
        .set_buttons(rfd::MessageButtons::YesNo)
        .show()
        == rfd::MessageDialogResult::Yes;
    if !confirmed {
        return;
    }
    let mut st = state.borrow_mut();
    if st.tasks.has_active_in(&dir) {
        st.monitor_status = "目录中有活动任务，未执行清理".into();
        return;
    }
    let mut skipped = 0;
    let mut valid = Vec::new();
    for item in candidates {
        if !st
            .tasks
            .get(item.id)
            .is_some_and(|r| r.phase == Phase::Completed && r.finished == item.finished)
        {
            skipped += 1;
            continue;
        }
        match tasks::validate_cleanup(&item) {
            Ok(_) => valid.push(item),
            Err(e) => {
                skipped += 1;
                if let Some(r) = st.tasks.get_mut(item.id) {
                    r.status = format!("清理已跳过：{e}");
                }
            }
        }
    }
    st.cleanup_directory = Some(dir);
    st.cleaning = valid.iter().map(|r| r.id).collect();
    st.monitor_status = "正在清理已完成诊断包…".into();
    let tx = tx.clone();
    std::thread::spawn(move || {
        let results = valid
            .into_iter()
            .map(|r| {
                if let Err(e) = tasks::validate_cleanup(&r) {
                    return (r.id, Err(e.to_string()), None, true);
                }
                let result = tasks::cleanup(&r).map_err(|e| format!("{e:#}"));
                let stamp = if !r.package.exists() {
                    engine::stamp(&r.package.with_extension("")).ok()
                } else {
                    r.output_stamp
                };
                (r.id, result, stamp, false)
            })
            .collect();
        let _ = tx.send(Message::Cleaned(results, skipped));
    });
}
fn error(e: impl std::fmt::Display) {
    rfd::MessageDialog::new()
        .set_title("TraceFox")
        .set_description(e.to_string())
        .set_level(rfd::MessageLevel::Error)
        .show();
}

/// 托盘使用独立的 32 像素透明图标，避免将大尺寸插画直接缩小后丢失轮廓。
fn load_tray_icon() -> Result<tray_icon::Icon> {
    let image = image::load_from_memory(include_bytes!("../assets/branding/tracefox-tray.png"))
        .context("内置托盘图标无法解码")?
        .into_rgba8();
    let (width, height) = image.dimensions();
    if (width, height) != (32, 32) {
        anyhow::bail!("内置托盘图标尺寸应为 32×32，实际为 {width}×{height}");
    }
    tray_icon::Icon::from_rgba(image.into_raw(), width, height).context("内置托盘图标数据无效")
}

pub fn run(startup: bool) -> Result<()> {
    let dir = data_dir();
    let rules = if default_rules_path().exists() {
        RuleSet::import(&std::fs::read_to_string(default_rules_path())?)?
    } else {
        RuleSet::defaults()
    };
    let settings: Settings = std::fs::read_to_string(dir.join("settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let start_hidden = startup && settings.start_minimized;
    let ui = AppWindow::new()?;
    {
        use slint::winit_030::WinitWindowAccessor;
        let weak = ui.as_weak();
        ui.on_drag_window(move || {
            weak.unwrap().window().with_winit_window(|w| {
                let _ = w.drag_window();
            });
        });
        let weak = ui.as_weak();
        ui.on_minimize_window(move || weak.unwrap().window().set_minimized(true));
        let weak = ui.as_weak();
        ui.on_maximize_window(move || {
            weak.unwrap()
                .window()
                .with_winit_window(|w| w.set_maximized(!w.is_maximized()));
        });
        let weak = ui.as_weak();
        ui.on_hide_window(move || {
            let _ = weak.unwrap().hide();
        });
        let weak = ui.as_weak();
        ui.on_resize_window(move |edge| {
            use slint::winit_030::winit::window::ResizeDirection::*;
            if let Some(&direction) = [
                North, NorthEast, East, SouthEast, South, SouthWest, West, NorthWest,
            ]
            .get(edge as usize)
            {
                weak.unwrap().window().with_winit_window(|w| {
                    let _ = w.drag_resize_window(direction);
                });
            }
        });
    }
    ui.set_tasks(ModelRc::new(VecModel::<TaskRow>::default()));
    ui.set_directory(directory_label(&settings.directory).into());
    ui.set_watching(settings.watching);
    let state = Rc::new(RefCell::new(State {
        rules,
        settings,
        tasks: Tasks::default(),
        deferred: Default::default(),
        monitor_status: String::new(),
        cleaning: Vec::new(),
        cleanup_directory: None,
        cancel: Arc::new(AtomicBool::new(false)),
        directory: None,
        watcher: None,
        events: None,
        last_poll: Instant::now(),
        editor: None,
    }));
    let initial = state.borrow().settings.clone();
    let initialized = configure_monitor(&mut state.borrow_mut(), initial);
    if let Err(e) = initialized {
        state.borrow_mut().settings.watching = false;
        ui.set_watching(false);
        state.borrow_mut().monitor_status = e.to_string();
    }
    let (tx, rx) = mpsc::channel::<Message>();
    {
        let w = ui.as_weak();
        let st = state.clone();
        ui.on_choose_directory(move || choose_monitor(&w.unwrap(), &st, true));
    }
    {
        let w = ui.as_weak();
        let st = state.clone();
        ui.on_toggle_watch(move || choose_monitor(&w.unwrap(), &st, false));
    }
    {
        let state = state.clone();
        ui.on_import_package(move || {
            if let Some(paths) = rfd::FileDialog::new()
                .add_filter("TGZ 诊断包", &["tgz"])
                .pick_files()
            {
                let mut st = state.borrow_mut();
                for p in paths {
                    enqueue(&mut st, p);
                }
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_open_settings(move || {
            let ui = weak.unwrap();
            let settings = &state.borrow().settings;
            ui.set_draft_minimized(settings.start_minimized);
            match crate::windows_integration::startup_value() {
                Ok(value) => {
                    ui.set_draft_autostart(value.is_some());
                    ui.set_settings_feedback(
                        if value.is_some() {
                            "已保存：开机自启已开启"
                        } else {
                            "已保存：开机自启未开启"
                        }
                        .into(),
                    );
                }
                Err(e) => {
                    ui.set_draft_autostart(settings.autostart);
                    ui.set_settings_feedback(format!("无法读取启动项：{e:#}").into());
                }
            }
            ui.set_settings_open(true);
            ui.invoke_focus_settings();
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_save_settings(move || {
            let ui = weak.unwrap();
            let mut settings = state.borrow().settings.clone();
            settings.autostart = ui.get_draft_autostart();
            settings.start_minimized = ui.get_draft_minimized();
            match persist_startup(&settings) {
                Ok(()) => {
                    state.borrow_mut().settings = settings;
                    ui.set_settings_open(false);
                }
                Err(e) => {
                    eprintln!("TraceFox：{e:#}");
                    ui.set_settings_feedback(format!("{e:#}").into());
                }
            }
        });
    }
    {
        let st = state.clone();
        ui.on_cancel(move |id| cancel_task(&mut st.borrow_mut(), id));
    }
    {
        let st = state.clone();
        ui.on_retry(move |id| {
            let path = st
                .borrow()
                .tasks
                .get(id)
                .filter(|r| !r.phase.active())
                .map(|r| r.package.clone());
            if let Some(path) = path {
                enqueue(&mut st.borrow_mut(), path);
            }
        });
    }
    {
        let st = state.clone();
        ui.on_open_report(move |id| {
            let report = st.borrow().tasks.get(id).and_then(|r| r.report.clone());
            if let Some(path) = report {
                if let Err(e) = open_report_path(&path) {
                    error(format!("无法打开 HTML：{e}"));
                }
            }
        });
    }
    {
        let st = state.clone();
        ui.on_open_folder(move |id| {
            let folder = st
                .borrow()
                .tasks
                .get(id)
                .and_then(|r| r.report.as_ref())
                .and_then(|p| p.parent().map(|p| p.to_path_buf()));
            if let Some(path) = folder {
                if let Err(e) = open::that(path) {
                    error(format!("无法打开输出目录：{e}"));
                }
            }
        });
    }
    {
        let st = state.clone();
        ui.on_delete_damaged(move |id| {
            let Some(task) = st
                .borrow()
                .tasks
                .get(id)
                .filter(|r| r.phase == Phase::Damaged)
                .cloned()
            else {
                return;
            };
            let yes = rfd::MessageDialog::new()
                .set_title("删除损坏的压缩包")
                .set_description(format!(
                    "将永久删除以下压缩包，无法恢复：\n{}\n\n已有报告目录将保留。",
                    task.package.display()
                ))
                .set_buttons(rfd::MessageButtons::YesNo)
                .show()
                == rfd::MessageDialogResult::Yes;
            if !yes {
                return;
            }
            let mut state = st.borrow_mut();
            if !state
                .tasks
                .get(id)
                .is_some_and(|r| r.phase == Phase::Damaged && r.finished == task.finished)
            {
                return;
            }
            match tasks::delete_damaged(&task) {
                Ok(()) => {
                    state.tasks.rows.retain(|r| r.id != id);
                    if let Some(ds) = state.directory.as_mut() {
                        ds.dismiss(&task.package);
                    }
                }
                Err(e) => {
                    if let Some(r) = state.tasks.get_mut(id) {
                        r.status = format!("删除失败：{e}");
                    }
                }
            }
        });
    }
    {
        let st = state.clone();
        ui.on_details(move |id| {
            let task = st.borrow().tasks.get(id).cloned();
            if let Some(r) = task {
                let old = r.report.as_ref().filter(|p| p.is_file());
                let answer = rfd::MessageDialog::new()
                    .set_title("诊断包详情")
                    .set_description(format!(
                        "{}\n\n{}{}",
                        r.package.display(),
                        r.status,
                        if old.is_some() {
                            "\n\n打开已生成的报告？"
                        } else {
                            ""
                        }
                    ))
                    .set_buttons(if old.is_some() {
                        rfd::MessageButtons::YesNo
                    } else {
                        rfd::MessageButtons::Ok
                    })
                    .show();
                if answer == rfd::MessageDialogResult::Yes {
                    if let Some(path) = old {
                        if let Err(e) = open::that(path) {
                            error(e);
                        }
                    }
                }
            }
        });
    }
    {
        let st = state.clone();
        let tx = tx.clone();
        ui.on_cleanup_report(move |id| confirm_cleanup(&st, &tx, Some(id)));
    }
    {
        let st = state.clone();
        let tx = tx.clone();
        ui.on_cleanup_completed(move || confirm_cleanup(&st, &tx, None));
    }
    {
        let state = state.clone();
        ui.on_edit_rules(move || {
            if let Some(e) = &state.borrow().editor {
                show_and_focus(e);
                return;
            }
            match make_editor(state.clone()) {
                Ok(e) => {
                    show_and_focus(&e);
                    state.borrow_mut().editor = Some(e);
                }
                Err(e) => error(e),
            }
        });
    }
    {
        use slint::winit_030::{EventResult, WinitWindowAccessor, winit};
        let state = state.clone();
        ui.window().on_winit_window_event(move |window, event| {
            recover_window_rendering(window, event);
            if let winit::event::WindowEvent::DroppedFile(path) = event {
                enqueue(&mut state.borrow_mut(), path.clone());
            }
            EventResult::Propagate
        });
    }
    {
        let weak = ui.as_weak();
        ui.window().on_close_requested(move || {
            let ui = weak.unwrap();
            if ui.get_settings_open() {
                ui.set_settings_open(false);
                slint::CloseRequestResponse::KeepWindowShown
            } else {
                slint::CloseRequestResponse::HideWindow
            }
        });
    }
    let menu = tray_icon::menu::Menu::new();
    let show = tray_icon::menu::MenuItem::new("打开 TraceFox", true, None);
    let pause = tray_icon::menu::MenuItem::new("暂停 / 恢复监控", true, None);
    let quit = tray_icon::menu::MenuItem::new("退出", true, None);
    menu.append_items(&[&show, &pause, &quit])?;
    let _tray = tray_icon::TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("TraceFox · NAS 诊断信息提取")
        .with_icon(load_tray_icon()?)
        .build()?;
    let (activation_tx, activation_rx) = mpsc::channel();
    let mut notifications = match crate::windows_integration::Notifications::new(activation_tx) {
        Ok(notifications) => Some(notifications),
        Err(e) => {
            eprintln!("TraceFox：Windows 通知初始化失败：{e:#}");
            None
        }
    };
    let timer = slint::Timer::default();
    let weak = ui.as_weak();
    let st = state.clone();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(200),
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            while let Ok(e) = tray_icon::menu::MenuEvent::receiver().try_recv() {
                if e.id == *show.id() {
                    show_main(&ui);
                } else if e.id == *pause.id() {
                    ui.set_watching(!st.borrow().settings.watching);
                    choose_monitor(&ui, &st, false);
                } else if e.id == *quit.id() {
                    st.borrow().cancel.store(true, Ordering::Relaxed);
                    let _ = slint::quit_event_loop();
                }
            }
            while let Ok(action) = activation_rx.try_recv() {
                use crate::windows_integration::Activation;
                match action {
                    Activation::Report(path) => {
                        if let Err(e) = open_report_path(&path) {
                            show_main(&ui);
                            rfd::MessageDialog::new()
                                .set_title("无法打开 HTML 报告")
                                .set_description(format!("{e:#}"))
                                .show();
                        }
                    }
                    Activation::Failed { id, package, error } => {
                        show_main(&ui);
                        let state = st.borrow();
                        if let Some(index) = state
                            .tasks
                            .rows
                            .iter()
                            .position(|r| r.id == id && r.package == package)
                        {
                            ui.set_selected_task(id);
                            ui.set_task_scroll_y(-54.0 * index as f32);
                        } else {
                            rfd::MessageDialog::new()
                                .set_title("诊断包分析失败")
                                .set_description(format!(
                                    "{}\n{error}\n该任务已不在本次分析列表中。",
                                    package.display()
                                ))
                                .show();
                        }
                    }
                }
            }
            let mut s = st.borrow_mut();
            while let Ok(message) = rx.try_recv() {
                match message {
                    Message::Progress(id, text) => {
                        if let Some(r) = s.tasks.get_mut(id) {
                            if r.phase == Phase::Running {
                                r.status = text;
                            }
                        }
                    }
                    Message::Done(id, result, stamp, elapsed) => {
                        let Some(path) = s.tasks.get(id).map(|r| r.package.clone()) else {
                            continue;
                        };
                        match result {
                            Ok(report) => s.tasks.finish(
                                id,
                                Phase::Completed,
                                format!("分析完成（耗时 {:.2} 秒）", elapsed.as_secs_f64()),
                                Some(report),
                                stamp,
                            ),
                            Err((cancelled, damaged, text)) => {
                                let changed = !cancelled && text.contains("发生变化");
                                s.tasks.finish(
                                    id,
                                    if cancelled {
                                        Phase::Cancelled
                                    } else if damaged {
                                        Phase::Damaged
                                    } else if changed {
                                        Phase::Waiting
                                    } else {
                                        Phase::Failed
                                    },
                                    if changed {
                                        "文件发生变化，等待稳定后重新分析".into()
                                    } else if damaged {
                                        format!("压缩包损坏：{text}")
                                    } else {
                                        text
                                    },
                                    None,
                                    stamp,
                                );
                                if changed {
                                    s.deferred.insert(
                                        path.clone(),
                                        (engine::stamp(&path).ok(), Instant::now()),
                                    );
                                }
                            }
                        }
                        if let (Some(notifications), Some(task)) =
                            (notifications.as_mut(), s.tasks.get(id))
                        {
                            use crate::windows_integration::Activation;
                            let action = match task.phase {
                                Phase::Completed => task.report.clone().map(Activation::Report),
                                Phase::Failed | Phase::Damaged => Some(Activation::Failed {
                                    id,
                                    package: task.package.clone(),
                                    error: task.status.clone(),
                                }),
                                _ => None,
                            };
                            if let Some(action) = action {
                                if let Err(e) =
                                    notifications.show(&task.package, &task.status, action)
                                {
                                    eprintln!("TraceFox：通知发送失败：{e:#}");
                                }
                            }
                        }
                    }
                    Message::Cleaned(results, mut skipped) => {
                        let mut success = 0;
                        let mut failed = 0;
                        for (id, result, stamp, was_skipped) in results {
                            match result {
                                Ok(()) => {
                                    success += 1;
                                    s.tasks.rows.retain(|r| r.id != id);
                                }
                                Err(e) => {
                                    if was_skipped {
                                        skipped += 1;
                                    } else {
                                        failed += 1;
                                    }
                                    if let Some(r) = s.tasks.get_mut(id) {
                                        r.status = format!(
                                            "清理{}：{e}",
                                            if was_skipped {
                                                "已跳过"
                                            } else {
                                                "未完成"
                                            }
                                        );
                                        if !was_skipped {
                                            r.output_stamp = stamp;
                                        }
                                    }
                                }
                            }
                        }
                        s.cleaning.clear();
                        s.cleanup_directory = None;
                        s.monitor_status =
                            format!("清理完成：成功 {success}，跳过 {skipped}，失败 {failed}");
                    }
                }
            }
            let mut changes = vec![];
            let mut monitor_error = None;
            if let Some(events) = &s.events {
                while let Ok(event) = events.try_recv() {
                    match event {
                        Ok(e)
                            if matches!(
                                e.kind,
                                notify::EventKind::Create(_) | notify::EventKind::Modify(_)
                            ) =>
                        {
                            changes.extend(e.paths)
                        }
                        Err(e) => monitor_error = Some(format!("目录通知异常，正在核对目录：{e}")),
                        _ => {}
                    }
                }
            }
            if let Some(e) = monitor_error {
                s.monitor_status = e;
            }
            let watch_path = PathBuf::from(&s.settings.directory);
            if let Some(ds) = s.directory.as_mut() {
                for path in changes {
                    let path = tasks::absolute(&path);
                    if path.parent() == Some(watch_path.as_path()) {
                        ds.changed(&path, Instant::now());
                    }
                }
            }
            if s.last_poll.elapsed() >= Duration::from_secs(2) {
                s.last_poll = Instant::now();
                if s.settings.watching {
                    if watch_path.is_dir() {
                        if s.monitor_status == "监控目录不可访问，等待目录恢复" {
                            s.monitor_status.clear();
                        }
                        if let Some(ds) = s.directory.as_mut() {
                            let ready = ds.poll(&watch_path, Instant::now());
                            for path in ready {
                                enqueue(&mut s, path);
                            }
                        }
                    } else {
                        s.monitor_status = "监控目录不可访问，等待目录恢复".into();
                    }
                }
            }
            let pending = s
                .directory
                .as_ref()
                .map(|d| d.pending_paths())
                .unwrap_or_default();
            for path in &pending {
                if !s
                    .tasks
                    .rows
                    .iter()
                    .any(|r| r.package == *path && s.cleaning.contains(&r.id))
                {
                    s.tasks.register(path.clone(), Phase::Waiting);
                }
            }
            let gone = s
                .tasks
                .rows
                .iter()
                .filter(|r| {
                    r.phase == Phase::Waiting
                        && !pending.contains(&r.package)
                        && !s.deferred.contains_key(&r.package)
                })
                .map(|r| r.id)
                .collect::<Vec<_>>();
            for id in gone {
                s.tasks.finish(
                    id,
                    Phase::Cancelled,
                    "文件已移除，等待已结束".into(),
                    None,
                    None,
                );
            }
            let mut settled = vec![];
            let mut missing = vec![];
            for (path, (last, changed)) in &mut s.deferred {
                let current = engine::stamp(path).ok();
                if current.is_none() {
                    missing.push(path.clone());
                } else if current != *last {
                    *last = current;
                    *changed = Instant::now();
                } else if changed.elapsed() >= Duration::from_secs(10) {
                    settled.push(path.clone());
                }
            }
            for path in missing {
                s.deferred.remove(&path);
                if let Some(id) = s
                    .tasks
                    .rows
                    .iter()
                    .find(|r| r.package == path)
                    .map(|r| r.id)
                {
                    s.tasks
                        .finish(id, Phase::Failed, "诊断包已不存在".into(), None, None);
                }
            }
            for path in settled {
                s.deferred.remove(&path);
                enqueue(&mut s, path);
            }
            let paused = s.cleanup_directory.clone();
            if let Some((id, path)) = s.tasks.start(paused.as_deref()) {
                s.cancel = Arc::new(AtomicBool::new(false));
                let cancel = s.cancel.clone();
                let rules = s.rules.clone();
                let tx = tx.clone();
                std::thread::spawn(move || {
                    // 记录从实际分析开始到报告替换完成的墙钟时间，不包含文件稳定等待。
                    let started = Instant::now();
                    let stamp = engine::stamp(&path).ok();
                    let mut damaged = false;
                    let result = (|| -> Result<PathBuf> {
                        engine::analyze(&path, &rules, &cancel, |text| {
                            let _ = tx.send(Message::Progress(id, text));
                        })
                        .map_err(|e| {
                            damaged = e.downcast_ref::<engine::Cancelled>().is_none()
                                && !e.downcast_ref::<std::io::Error>().is_some_and(|io| {
                                    matches!(
                                        io.kind(),
                                        std::io::ErrorKind::NotFound
                                            | std::io::ErrorKind::PermissionDenied
                                    )
                                });
                            e.context("诊断包解压或分析失败，可能是包内容损坏或磁盘空间不足")
                        })
                    })();
                    let result = result.map_err(|e| {
                        (
                            e.downcast_ref::<engine::Cancelled>().is_some(),
                            damaged,
                            format!("{e:#}"),
                        )
                    });
                    let _ = tx.send(Message::Done(id, result, stamp, started.elapsed()));
                });
            }
            ui.set_cleaning(s.cleanup_directory.is_some());
            ui.set_can_cleanup(
                s.cleanup_directory.is_none() && !s.tasks.candidates(&watch_path).is_empty(),
            );
            ui.set_monitor_status(if s.monitor_status.is_empty() {
                if s.settings.watching {
                    "正在监控 · 托盘运行时继续处理"
                } else {
                    "仅处理开启后新增或发生变化的 TGZ"
                }
                .into()
            } else {
                s.monitor_status.clone().into()
            });
            ui.set_queue_text(
                format!(
                    "处理中 {} · 等待 {}",
                    usize::from(s.tasks.running.is_some()),
                    s.tasks
                        .rows
                        .iter()
                        .filter(|r| matches!(r.phase, Phase::Waiting | Phase::Queued))
                        .count()
                )
                .into(),
            );
            let rows = s
                .tasks
                .rows
                .iter()
                .map(|r| TaskRow {
                    id: r.id,
                    package: r
                        .package
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                        .into(),
                    status: r.status.clone().into(),
                    active: r.phase.active(),
                    cancellable: matches!(r.phase, Phase::Waiting | Phase::Queued | Phase::Running),
                    completed: r.phase == Phase::Completed,
                    damaged: r.phase == Phase::Damaged,
                    cleaning: s.cleaning.contains(&r.id),
                })
                .collect::<Vec<_>>();
            // 原位更新行，避免每 200ms 重建列表使菜单关闭、焦点和滚动位置丢失。
            let model = ui.get_tasks();
            if let Some(model) = model.as_any().downcast_ref::<VecModel<TaskRow>>() {
                for i in (0..model.row_count()).rev() {
                    if !rows
                        .iter()
                        .any(|r| Some(r.id) == model.row_data(i).map(|r| r.id))
                    {
                        model.remove(i);
                    }
                }
                for (i, row) in rows.into_iter().enumerate() {
                    if model.row_data(i).map(|r| r.id) != Some(row.id) {
                        model.insert(i, row);
                    } else if model.row_data(i).as_ref() != Some(&row) {
                        model.set_row_data(i, row);
                    }
                }
            }
        },
    );
    if !start_hidden {
        ui.show()?;
    }
    slint::run_event_loop_until_quit()?;
    Ok(())
}

/// 文件视图通过索引引用唯一规则；抽屉持有独立副本，行内文本在导航前提交。
struct Draft {
    import_window: Option<ImportWindow>,
    rules: RuleSet,
    indices: Vec<usize>,
    selected: Option<usize>,
    section: i32,
    /// 弹窗拥有独立副本；只有完成校验才提交，预览与取消不触碰主草稿。
    editing: Option<Box<Draft>>,
    expanded_rules: std::collections::HashSet<String>,
    pending_terms: std::collections::HashMap<(String, i32), String>,
}
/// 下载成功落盘后才替换运行状态与草稿；同步记录失败需明确提示已保存的规则状态。
fn accept_download(
    e: &EditorWindow,
    state: &mut State,
    draft: &mut Draft,
    rules: RuleSet,
    etag: Option<String>,
) -> Result<()> {
    let hash = rules_hash(&rules)?;
    save_default_rules(&rules)?;
    state.rules = rules.clone();
    draft.rules = rules;
    draft.selected = None;
    draft.pending_terms.clear();
    load_layout(e, &draft.rules.layout);
    refresh(e, draft);
    e.set_dirty(false);
    save_sync_metadata(&tracefox::webdav::SyncMetadata {
        local_hash: hash.clone(),
        remote_hash: hash,
        etag,
    })
    .context("规则已保存，但同步记录保存失败")?;
    e.set_feedback("规则已下载并保存".into());
    Ok(())
}

impl Draft {
    fn fork(&self) -> Self {
        Self {
            import_window: None,
            rules: self.rules.clone(),
            indices: self.indices.clone(),
            selected: self.selected,
            section: self.section,
            editing: None,
            expanded_rules: self.expanded_rules.clone(),
            pending_terms: Default::default(),
        }
    }
    fn selected_id(&self) -> Option<String> {
        self.selected.map(|i| {
            if self.section == 1 {
                self.rules.system[i].id.clone()
            } else {
                self.rules.rules[i].id.clone()
            }
        })
    }
    fn select_id(&mut self, id: Option<&str>) {
        self.selected = id.and_then(|id| {
            if self.section == 1 {
                self.rules.system.iter().position(|r| r.id == id)
            } else {
                self.rules.rules.iter().position(|r| r.id == id)
            }
        });
    }
}

fn open_rule(e: &EditorWindow, d: &mut Draft, mut edit: Draft, new: bool) {
    edit.editing = None;
    load(e, &edit);
    e.set_feedback("".into());
    e.set_new_term("".into());
    e.set_sample("".into());
    e.set_sample_paths(ModelRc::new(VecModel::from(Vec::<SharedString>::new())));
    e.set_advanced(false);
    e.set_match_options(false);
    e.set_field_options(false);
    e.set_show_errors(false);
    e.set_display_options(!new);
    e.set_test_options(false);
    e.set_wizard(new);
    e.set_step(0);
    e.set_dialog_open(true);
    e.set_menu_row(-1);
    d.editing = Some(Box::new(edit));
    e.invoke_focus_dialog();
    e.set_rule_name_focus_generation(e.get_rule_name_focus_generation() + 1);
}

/// 从表单构造候选草稿，验证/预览都使用它，失败不会留下半条规则。
fn candidate(e: &EditorWindow, d: &Draft) -> Result<Draft> {
    let mut edit = d.editing.as_ref().context("请先打开规则")?.fork();
    if !e.get_new_term().trim().is_empty() {
        e.invoke_add_term();
    }
    apply(e, &mut edit)?;
    if e.get_rule_name().trim().is_empty() {
        anyhow::bail!("请填写规则名称");
    }
    Ok(edit)
}

fn strings(lines: &str) -> Vec<String> {
    lines
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
fn source_mode(i: i32) -> String {
    ["prefix", "path", "exact"]
        .get(i as usize)
        .unwrap_or(&"prefix")
        .to_string()
}
/// 行内输入先暂存；在切换文件、打开抽屉、保存或排序前统一提交，避免依赖焦点事件顺序。
fn flush_inline(e: &EditorWindow, d: &mut Draft) {
    for ((id, index), value) in std::mem::take(&mut d.pending_terms) {
        if let Some(term) = d
            .rules
            .rules
            .iter_mut()
            .find(|r| r.id == id)
            .and_then(|r| r.terms.get_mut(index as usize))
        {
            if *term != value {
                *term = value;
                e.set_dirty(true);
            }
        }
    }
}
/// 文件导航只投影来源，不复制规则；报告分组与列表分类独立。
fn refresh(e: &EditorWindow, d: &mut Draft) {
    flush_inline(e, d);
    let query = e.get_search().to_lowercase();
    let entries: Vec<(usize, String, String, Vec<String>, bool, Vec<String>)> = if d.section == 1 {
        d.rules
            .system
            .iter()
            .enumerate()
            .map(|(i, r)| {
                (
                    i,
                    r.name.clone(),
                    r.group.clone(),
                    vec![r.source_file_id.clone()],
                    r.enabled,
                    vec![],
                )
            })
            .collect()
    } else {
        d.rules
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                (d.section == 2 && r.target != "keywords")
                    || (d.section == 0 && r.target != "timeline")
            })
            .map(|(i, r)| {
                (
                    i,
                    r.name.clone(),
                    r.group.clone(),
                    r.source_file_ids.clone(),
                    r.enabled,
                    r.terms.clone(),
                )
            })
            .collect()
    };
    let mut files: Vec<String> = d.rules.log_files.iter().map(|f| f.id.clone()).collect();
    for (_, _, _, sources, _, _) in &entries {
        for source in sources {
            if !files.contains(source) {
                files.push(source.clone());
            }
        }
    }
    let mut active = e.get_active_file().to_string();
    let mut ordered_files = d
        .rules
        .layout
        .file_order
        .iter()
        .filter(|f| files.contains(f))
        .cloned()
        .collect::<Vec<_>>();
    let remaining = files
        .into_iter()
        .filter(|f| !ordered_files.contains(f))
        .collect::<Vec<_>>();
    ordered_files.extend(remaining);
    let files = ordered_files;
    if !files.contains(&active) {
        active = files.first().cloned().unwrap_or_default();
    }
    e.set_active_file(active.clone().into());
    e.set_file_names(ModelRc::new(VecModel::from(
        files
            .iter()
            .map(|f| SharedString::from(f.as_str()))
            .collect::<Vec<_>>(),
    )));
    e.set_file_index(
        files
            .iter()
            .position(|f| f == &active)
            .map(|i| i as i32)
            .unwrap_or(-1),
    );
    e.set_file_labels(ModelRc::new(VecModel::from(
        files
            .iter()
            .map(|id| {
                let label = d.rules.source_label(std::slice::from_ref(id));
                SharedString::from(format!(
                    "{} · {} 条规则",
                    label,
                    entries.iter().filter(|r| r.3.contains(id)).count()
                ))
            })
            .collect::<Vec<_>>(),
    )));
    e.set_file_titles(ModelRc::new(VecModel::from(
        files
            .iter()
            .map(|id| {
                let file = d.rules.log_file(id).expect("导航引用有效目录");
                SharedString::from(format!(
                    "{}\n{} · {} 条规则",
                    file.name,
                    file.file_name(),
                    entries.iter().filter(|r| r.3.contains(id)).count()
                ))
            })
            .collect::<Vec<_>>(),
    )));
    e.set_active_file_label(d.rules.source_label(std::slice::from_ref(&active)).into());
    d.indices.clear();
    let mut rows = Vec::new();
    let mut offset = 0.0;
    for (i, name, group, sources, enabled, terms) in entries {
        if !sources.contains(&active) {
            continue;
        }
        if ![
            name.clone(),
            group.clone(),
            d.rules.source_label(&sources),
            terms.join(" "),
        ]
        .iter()
        .any(|v| v.to_lowercase().contains(&query))
        {
            continue;
        }
        let id = if d.section == 1 {
            d.rules.system[i].id.clone()
        } else {
            d.rules.rules[i].id.clone()
        };
        let expanded = d.expanded_rules.contains(&id);
        let height = if !expanded {
            62.0
        } else if d.section == 1 {
            86.0
        } else {
            94.0 + 36.0 * terms.len() as f32
        };
        rows.push(RuleListRow {
            expanded,
            name: name.into(),
            identity: id.into(),
            summary: if d.section == 1 {
                format!("{} 个展示字段", d.rules.system[i].fields.len()).into()
            } else {
                "".into()
            },
            source: d.rules.source_label(&sources).into(),
            enabled,
            offset,
            height,
            terms: ModelRc::new(VecModel::from(
                terms
                    .iter()
                    .map(|t| SharedString::from(t.as_str()))
                    .collect::<Vec<_>>(),
            )),
        });
        offset += height;
        d.indices.push(i);
    }
    e.set_content_height(offset);
    // 同一文件下原位更新，避免确认输入时销毁控件、丢失焦点。
    let current = e.get_rows();
    if let Some(model) = current.as_any().downcast_ref::<VecModel<RuleListRow>>() {
        if model.row_count() == rows.len()
            && rows.iter().enumerate().all(|(i, r)| {
                model
                    .row_data(i)
                    .is_some_and(|old| old.identity == r.identity)
            })
        {
            for (i, mut row) in rows.into_iter().enumerate() {
                let old = model.row_data(i).unwrap();
                if let Some(terms) = old.terms.as_any().downcast_ref::<VecModel<SharedString>>() {
                    let values = (0..row.terms.row_count())
                        .filter_map(|i| row.terms.row_data(i))
                        .collect::<Vec<_>>();
                    while terms.row_count() > values.len() {
                        terms.remove(terms.row_count() - 1);
                    }
                    for (n, value) in values.into_iter().enumerate() {
                        if n < terms.row_count() {
                            if terms.row_data(n).as_ref() != Some(&value) {
                                terms.set_row_data(n, value);
                            }
                        } else {
                            terms.push(value);
                        }
                    }
                    row.terms = old.terms;
                }
                model.set_row_data(i, row);
            }
        } else {
            e.set_rows(ModelRc::new(VecModel::from(rows)));
        }
    } else {
        e.set_rows(ModelRc::new(VecModel::from(rows)));
    }
    e.set_selected(
        d.selected
            .and_then(|i| d.indices.iter().position(|x| *x == i))
            .map(|i| i as i32)
            .unwrap_or(-1),
    );
}

/// 排序仅移动同一实体，绝不因为文件视图中的落点改写报告分组或日志来源。
fn reorder_file_rule(rules: &mut RuleSet, system: bool, id: &str, anchor: &str, after: bool) {
    fn reorder<T>(
        rows: &mut Vec<T>,
        id: &str,
        anchor: &str,
        after: bool,
        key: impl Fn(&T) -> &str,
    ) {
        if id == anchor {
            return;
        }
        if let Some(from) = rows.iter().position(|r| key(r) == id) {
            if !rows.iter().any(|r| key(r) == anchor) {
                return;
            }
            let row = rows.remove(from);
            let to = rows.iter().position(|r| key(r) == anchor).unwrap() + usize::from(after);
            rows.insert(to, row);
        }
    }
    if system {
        reorder(&mut rules.system, id, anchor, after, |r| &r.id)
    } else {
        reorder(&mut rules.rules, id, anchor, after, |r| &r.id)
    }
}

/// 按日志侧栏的完整可见顺序移动文件；关联规则只在存在目标规则时同步移动。
fn reorder_log_files(
    rules: &mut RuleSet,
    visible: &[String],
    from: usize,
    to: usize,
    system: bool,
) -> bool {
    if from >= visible.len() || to >= visible.len() || from == to {
        return false;
    }
    let source = visible[from].clone();
    let target = visible[to].clone();
    let mut files = visible.to_vec();
    let moving = files.remove(from);
    files.insert(to, moving);
    rules.layout.file_order = files;

    let moving_down = from < to;
    if system {
        let related = |r: &SystemRule, id: &str| r.source_file_id == id;
        let moving_rules = rules
            .system
            .iter()
            .filter(|r| related(r, &source) && !related(r, &target))
            .cloned()
            .collect::<Vec<_>>();
        let has_anchor = rules
            .system
            .iter()
            .any(|r| related(r, &target) && !related(r, &source));
        if !moving_rules.is_empty() && has_anchor {
            rules
                .system
                .retain(|r| !(related(r, &source) && !related(r, &target)));
            let anchor = if moving_down {
                rules
                    .system
                    .iter()
                    .rposition(|r| related(r, &target) && !related(r, &source))
                    .map(|i| i + 1)
            } else {
                rules
                    .system
                    .iter()
                    .position(|r| related(r, &target) && !related(r, &source))
            };
            if let Some(at) = anchor {
                rules.system.splice(at..at, moving_rules);
            }
        }
    } else {
        let related = |r: &Rule, id: &str| r.source_file_ids.iter().any(|x| x == id);
        let moving_rules = rules
            .rules
            .iter()
            .filter(|r| related(r, &source) && !related(r, &target))
            .cloned()
            .collect::<Vec<_>>();
        let has_anchor = rules
            .rules
            .iter()
            .any(|r| related(r, &target) && !related(r, &source));
        if !moving_rules.is_empty() && has_anchor {
            rules
                .rules
                .retain(|r| !(related(r, &source) && !related(r, &target)));
            let anchor = if moving_down {
                rules
                    .rules
                    .iter()
                    .rposition(|r| related(r, &target) && !related(r, &source))
                    .map(|i| i + 1)
            } else {
                rules
                    .rules
                    .iter()
                    .position(|r| related(r, &target) && !related(r, &source))
            };
            if let Some(at) = anchor {
                rules.rules.splice(at..at, moving_rules);
            }
        }
    }
    true
}

fn pos(s: &str, a: &[&str]) -> i32 {
    a.iter().position(|x| *x == s).unwrap_or(0) as i32
}
fn source_form_ids(e: &EditorWindow) -> Vec<String> {
    e.get_source_selected_options()
        .iter()
        .map(|option| option.id.to_string())
        .collect()
}
/// 候选过滤只生成界面投影；已选来源由独立模型保存，搜索不会清空选择。
/// 搜索同时覆盖日志名称、目录 ID、完整归档路径和路径末尾的文件名。
fn source_choices(rules: &RuleSet, ids: &[String], query: &str) -> Vec<LogFileChoice> {
    let query = query.trim().to_lowercase();
    rules
        .log_files
        .iter()
        .filter(|file| {
            query.is_empty()
                || file.id.to_lowercase().contains(&query)
                || file.name.to_lowercase().contains(&query)
                || file.path.to_lowercase().contains(&query)
                || file.file_name().to_lowercase().contains(&query)
        })
        .map(|file| LogFileChoice {
            id: file.id.clone().into(),
            label: file.label().into(),
            chosen: ids.contains(&file.id),
            matching: true,
        })
        .collect()
}
fn load_source_form(e: &EditorWindow, rules: &RuleSet, ids: &[String]) {
    let options = source_choices(rules, ids, "");
    let selected = options
        .iter()
        .filter(|option| option.chosen)
        .cloned()
        .collect::<Vec<_>>();
    e.set_source_options(ModelRc::new(VecModel::from(options)));
    e.set_source_selected_options(ModelRc::new(VecModel::from(selected)));
    let source = rules.source_label(ids);
    e.set_source(source.clone().into());
    e.set_source_query("".into());
    e.set_source_picker_open(false);
}
fn load(e: &EditorWindow, d: &Draft) {
    if let Some(i) = d.selected {
        if d.section == 1 {
            let r = &d.rules.system[i];
            e.set_rule_name(r.name.clone().into());
            e.set_enabled_rule(r.enabled);
            load_source_form(e, &d.rules, std::slice::from_ref(&r.source_file_id));
            e.set_extract_mode(pos(
                &r.kind,
                &["json", "kv", "sections", "columns", "regex"],
            ));
            e.set_selector(r.selector.clone().into());
            e.set_extract_pattern(r.pattern.clone().into());
            e.set_view_mode(pos(
                &r.view,
                &["cards", "table", "storage", "storage-smart"],
            ));
            e.set_missing(r.missing.clone().into());
            e.set_join_rule(r.join_rule.clone().into());
            e.set_join_key(r.join_key.clone().into());
            e.set_foreign_key(r.join_foreign_key.clone().into());
            e.set_fields(serde_json::to_string(&r.fields).unwrap().into());
            load_fields(e, 0);
            e.set_feedback("".into());
        } else {
            let r = &d.rules.rules[i];
            e.set_rule_name(r.name.clone().into());
            e.set_enabled_rule(r.enabled);
            load_source_form(e, &d.rules, &r.source_file_ids);
            e.set_terms(r.terms.join("\n").into());
            e.set_term_tags(ModelRc::new(VecModel::from(
                r.terms
                    .iter()
                    .map(|s| SharedString::from(s.as_str()))
                    .collect::<Vec<_>>(),
            )));
            e.set_excludes(r.exclude.join("\n").into());
            e.set_note(r.note.clone().into());
            e.set_match_mode(pos(&r.mode, &["any", "all"]));
            e.set_regex_mode(r.regex);
            e.set_case_sensitive(r.case_sensitive);
            e.set_before(r.before as i32);
            e.set_after(r.after as i32);
            e.set_target(pos(&r.target, &["keywords", "timeline", "both"]));
            e.set_reverse(r.reverse);
            e.set_rule_open(r.open);
            e.set_formatter(r.fmt.clone().into());
            e.set_time_pattern(r.time_regex.clone().into());
            e.set_time_format(r.time_format.clone().into());
            e.set_timezone(r.timezone.clone().into());
            e.set_sort_mode(pos(&r.sort, &["source", "asc", "desc"]));
            e.set_feedback("".into());
        }
    }
}
fn apply(e: &EditorWindow, d: &mut Draft) -> Result<()> {
    if d.section != 3 && (!e.get_dialog_open() || d.editing.is_some()) {
        return Ok(());
    }
    if d.section == 1 {
        save_field_form(e);
    }
    if d.section == 3 {
        let l = &mut d.rules.layout;
        l.title = e.get_title_text().into();
        l.system_title = e.get_system_title().into();
        l.keyword_title = e.get_keyword_title().into();
        l.timeline_title = e.get_timeline_title().into();
        l.accent = e.get_accent().into();
        l.font_size = e.get_font_size() as u32;
        l.density = if e.get_density() == 1 {
            "compact"
        } else {
            "comfortable"
        }
        .into();
        l.sections = match e.get_section_order() {
            1 => vec!["timeline".into(), "keywords".into()],
            2 => vec!["keywords".into()],
            3 => vec!["timeline".into()],
            _ => vec!["keywords".into(), "timeline".into()],
        };
        l.timeline_sort = if e.get_timeline_sort() == 1 {
            "asc"
        } else {
            "desc"
        }
        .into();
        l.first_open = e.get_first_open();
        l.log_lines_per_batch = e.get_log_lines_per_batch().max(10) as u32;
        return Ok(());
    }
    let Some(i) = d.selected else {
        return Ok(());
    };
    if d.section == 1 {
        let r = &mut d.rules.system[i];
        r.name = e.get_rule_name().into();
        r.enabled = e.get_enabled_rule();
        r.source_file_id = source_form_ids(e)
            .first()
            .cloned()
            .context("请选择日志文件")?;
        r.kind =
            ["json", "kv", "sections", "columns", "regex"][e.get_extract_mode() as usize].into();
        r.selector = e.get_selector().into();
        r.pattern = e.get_extract_pattern().into();
        r.view = ["cards", "table", "storage", "storage-smart"][e.get_view_mode() as usize].into();
        r.missing = e.get_missing().into();
        r.join_rule = e.get_join_rule().into();
        r.join_key = e.get_join_key().into();
        r.join_foreign_key = e.get_foreign_key().into();
        r.fields = field_values(e);
    } else {
        let r = &mut d.rules.rules[i];
        r.name = e.get_rule_name().into();
        r.enabled = e.get_enabled_rule();
        r.source_file_ids = source_form_ids(e);
        r.terms = strings(&e.get_terms());
        r.exclude = strings(&e.get_excludes());
        r.note = e.get_note().into();
        r.mode = if e.get_match_mode() == 1 {
            "all"
        } else {
            "any"
        }
        .into();
        r.regex = e.get_regex_mode();
        r.case_sensitive = e.get_case_sensitive();
        r.before = e.get_before().max(0) as usize;
        r.after = e.get_after().max(0) as usize;
        r.target = ["keywords", "timeline", "both"][e.get_target() as usize].into();
        r.reverse = e.get_reverse();
        r.open = e.get_rule_open();
        r.fmt = e.get_formatter().into();
        r.time_regex = e.get_time_pattern().into();
        r.time_format = e.get_time_format().into();
        r.timezone = e.get_timezone().into();
        r.sort = ["source", "asc", "desc"][e.get_sort_mode() as usize].into();
    }
    d.rules.resolve_sources()?;
    Ok(())
}

fn load_layout(e: &EditorWindow, l: &tracefox::rules::Layout) {
    e.set_title_text(l.title.clone().into());
    e.set_system_title(l.system_title.clone().into());
    e.set_keyword_title(l.keyword_title.clone().into());
    e.set_timeline_title(l.timeline_title.clone().into());
    e.set_accent(l.accent.clone().into());
    e.set_font_size(l.font_size as i32);
    e.set_density(i32::from(l.density == "compact"));
    e.set_timeline_sort(i32::from(l.timeline_sort == "asc"));
    e.set_first_open(l.first_open);
    e.set_log_lines_per_batch(l.log_lines_per_batch as i32);
    e.set_file_panel_width(l.file_panel_width.clamp(180, 360) as f32);
    e.set_section_order(if l.sections == ["timeline"] {
        3
    } else if l.sections == ["keywords"] {
        2
    } else if l.sections.first().is_some_and(|s| s == "timeline") {
        1
    } else {
        0
    });
}
fn field_values(e: &EditorWindow) -> Vec<Field> {
    serde_json::from_str(&e.get_fields()).unwrap_or_default()
}
fn store_fields(e: &EditorWindow, fields: &[Field]) {
    e.set_fields(serde_json::to_string(fields).unwrap().into());
    let rows: Vec<_> = fields
        .iter()
        .map(|f| FieldListRow {
            name: f.name.clone().into(),
            path: f.path.clone().into(),
            format: pos(&f.format, &["", "bytes", "unix", "kib"]),
        })
        .collect();
    let model = e.get_field_rows();
    if let Some(model) = model.as_any().downcast_ref::<VecModel<FieldListRow>>() {
        if model.row_count() == rows.len() {
            for (i, row) in rows.into_iter().enumerate() {
                model.set_row_data(i, row);
            }
            return;
        }
    }
    e.set_field_rows(ModelRc::new(VecModel::from(rows)));
}
fn save_field_form(e: &EditorWindow) {
    let i = e.get_loaded_field();
    let mut fields = field_values(e);
    if i < 0 || i as usize >= fields.len() {
        return;
    }
    fields[i as usize] = Field {
        name: e.get_field_name().into(),
        path: e.get_field_path().into(),
        format: ["", "bytes", "unix", "kib"][e.get_field_format() as usize].into(),
        unit: e.get_field_unit().into(),
        missing: e.get_field_missing().into(),
        wide: e.get_field_wide(),
        view: ["", "cards", "table"][e.get_field_view() as usize].into(),
        capture: e.get_field_capture().into(),
    };
    // 此处仅保存详细选项，避免在内联输入事件中用旧文本覆盖正在编辑的行。
    e.set_fields(serde_json::to_string(&fields).unwrap().into());
}
fn load_fields(e: &EditorWindow, index: i32) {
    let fields = field_values(e);
    store_fields(e, &fields);
    e.set_field_names(ModelRc::new(VecModel::from(
        fields
            .iter()
            .map(|f| SharedString::from(f.name.as_str()))
            .collect::<Vec<_>>(),
    )));
    let index = if fields.is_empty() {
        -1
    } else {
        index.max(0).min(fields.len() as i32 - 1)
    };
    e.set_field_index(index);
    e.set_loaded_field(index);
    let f = fields.get(index as usize);
    e.set_field_name(f.map(|f| f.name.as_str()).unwrap_or("").into());
    e.set_field_path(f.map(|f| f.path.as_str()).unwrap_or("").into());
    e.set_field_format(pos(
        f.map(|f| f.format.as_str()).unwrap_or(""),
        &["", "bytes", "unix", "kib"],
    ));
    e.set_field_unit(f.map(|f| f.unit.as_str()).unwrap_or("").into());
    e.set_field_missing(f.map(|f| f.missing.as_str()).unwrap_or("").into());
    e.set_field_wide(f.is_some_and(|f| f.wide));
    e.set_field_view(pos(
        f.map(|f| f.view.as_str()).unwrap_or(""),
        &["", "cards", "table"],
    ));
    e.set_field_capture(f.map(|f| f.capture.as_str()).unwrap_or("").into());
}

/// 弹窗表单与已保存配置分离；留空密码始终从原服务器凭据中读取。
fn webdav_form(
    e: &EditorWindow,
    settings: &Settings,
) -> Result<(tracefox::webdav::WebDavSettings, String)> {
    let config = tracefox::webdav::WebDavSettings {
        enabled: true,
        url: e.get_webdav_url().trim().to_owned(),
        remote_path: e.get_webdav_path().trim().to_owned(),
        username: e.get_webdav_user().trim().to_owned(),
    };
    config.validate()?;
    let password = resolve_webdav_password(
        &e.get_webdav_password(),
        settings.webdav.as_ref(),
        tracefox::load_webdav_password,
    )?;
    Ok((config, password))
}

fn resolve_webdav_password(
    input: &str,
    original: Option<&tracefox::webdav::WebDavSettings>,
    read: impl FnOnce(&str) -> Result<String>,
) -> Result<String> {
    if !input.is_empty() {
        return Ok(input.to_owned());
    }
    match original {
        Some(c) => read(&format!("{}#{}", c.url, c.remote_path)),
        None => Ok(String::new()),
    }
}

/// 配置文件和系统凭据无法共用事务：文件保存失败时恢复旧凭据，成功后才更新内存。
fn persist_webdav_config(
    settings: &mut Settings,
    config: tracefox::webdav::WebDavSettings,
    password: &str,
    save: impl FnOnce(&Settings) -> Result<()>,
) -> Result<()> {
    config.validate()?;
    let target = format!("{}#{}", config.url, config.remote_path);
    let previous = tracefox::read_webdav_password(&target)?;
    tracefox::save_webdav_password(&target, password).context("密码保存失败")?;
    let mut updated = settings.clone();
    updated.webdav = Some(config);
    if let Err(error) = save(&updated) {
        let restored = match previous {
            Some(ref old) => tracefox::save_webdav_password(&target, old),
            None => tracefox::delete_webdav_password(&target),
        };
        if let Err(rollback) = restored {
            anyhow::bail!("配置文件保存失败：{error}；原凭据恢复失败：{rollback}，请重新保存密码");
        }
        return Err(error.context("配置文件保存失败，已撤销本次凭据修改"));
    }
    *settings = updated;
    Ok(())
}

fn reset_webdav_form(e: &EditorWindow, settings: &Settings) {
    e.set_webdav_url(
        settings
            .webdav
            .as_ref()
            .map(|c| c.url.as_str())
            .unwrap_or("")
            .into(),
    );
    e.set_webdav_path(
        settings
            .webdav
            .as_ref()
            .map(|c| c.remote_path.as_str())
            .unwrap_or("rules.json")
            .into(),
    );
    e.set_webdav_user(
        settings
            .webdav
            .as_ref()
            .map(|c| c.username.as_str())
            .unwrap_or("")
            .into(),
    );
    e.set_webdav_password("".into());
    e.set_webdav_feedback("".into());
}

fn make_editor(state: Rc<RefCell<State>>) -> Result<EditorWindow> {
    let e = EditorWindow::new()?;
    install_window_rendering_recovery(&e.window());
    // 跟随 Windows 动画偏好；原生 Slint 不使用浏览器媒体查询。
    let mut animations: i32 = 1;
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::SystemParametersInfoW(
            windows_sys::Win32::UI::WindowsAndMessaging::SPI_GETCLIENTAREAANIMATION,
            0,
            (&mut animations as *mut i32).cast(),
            0,
        );
    }
    e.set_reduced_motion(animations == 0);
    e.set_webdav_dialog_open(false);
    let d = Rc::new(RefCell::new(Draft {
        import_window: None,
        rules: state.borrow().rules.clone(),
        indices: vec![],
        selected: None,
        section: 0,
        editing: None,
        expanded_rules: Default::default(),
        pending_terms: Default::default(),
    }));
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_choose_source(move |id, chosen| {
            let e = w.unwrap();
            let draft = d.borrow();
            let mut ids = source_form_ids(&e);
            if draft.section == 1 {
                ids.clear();
            }
            ids.retain(|x| x != id.as_str());
            if chosen {
                ids.push(id.to_string());
            }
            let options = source_choices(&draft.rules, &ids, "");
            let selected = options
                .iter()
                .filter(|option| option.chosen)
                .cloned()
                .collect::<Vec<_>>();
            e.set_source_options(ModelRc::new(VecModel::from(options)));
            e.set_source_selected_options(ModelRc::new(VecModel::from(selected)));
            let source = draft.rules.source_label(&ids);
            e.set_source(source.clone().into());
            e.set_source_query("".into());
            e.set_source_picker_open(false);
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_search_source(move || {
            let Some(e) = w.upgrade() else { return };
            let query = e.get_source_query();
            let draft = d.borrow();
            // 名称、ID 和归档路径统一做大小写不敏感的包含匹配。
            let ids = source_form_ids(&e);
            let options = source_choices(&draft.rules, &ids, query.as_str());
            e.set_source_options(ModelRc::new(VecModel::from(options)));
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_remove_last_source(move || {
            let Some(e) = w.upgrade() else { return };
            let mut ids = source_form_ids(&e);
            if ids.pop().is_none() {
                return;
            }
            let draft = d.borrow();
            let options = source_choices(&draft.rules, &ids, "");
            let selected = options
                .iter()
                .filter(|option| option.chosen)
                .cloned()
                .collect::<Vec<_>>();
            e.set_source_options(ModelRc::new(VecModel::from(options)));
            e.set_source_selected_options(ModelRc::new(VecModel::from(selected)));
            e.set_source(draft.rules.source_label(&ids).into());
            e.set_source_query("".into());
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_open_file_form(move |new| {
            let e = w.unwrap();
            let mut draft = d.borrow_mut();
            flush_inline(&e, &mut draft);
            let file = if new {
                None
            } else {
                draft.rules.log_file(e.get_active_file().as_str()).ok()
            };
            e.set_catalog_id(file.map(|f| f.id.clone()).unwrap_or_default().into());
            e.set_catalog_name(file.map(|f| f.name.clone()).unwrap_or_default().into());
            e.set_catalog_path(file.map(|f| f.path.clone()).unwrap_or_default().into());
            e.set_catalog_mode(
                file.map(|f| pos(&f.mode, &["prefix", "path", "exact"]))
                    .unwrap_or(0),
            );
            e.set_catalog_container(file.map(|f| i32::from(f.container == "zip")).unwrap_or(0));
            e.set_catalog_error("".into());
            e.set_catalog_open(true);
            e.set_dialog_open(true);
            e.invoke_focus_file_form();
        });
    }
    {
        let w = e.as_weak();
        e.on_close_file_form(move || {
            let e = w.unwrap();
            e.set_catalog_open(false);
            e.set_dialog_open(false);
            e.invoke_focus_list();
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_save_file_form(move || {
            let e = w.unwrap();
            let mut draft = d.borrow_mut();
            let id = if e.get_catalog_id().is_empty() {
                format!(
                    "log-file-{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
            } else {
                e.get_catalog_id().to_string()
            };
            let file = LogFile {
                id: id.clone(),
                name: e.get_catalog_name().trim().into(),
                path: e.get_catalog_path().trim().replace('\\', "/"),
                mode: source_mode(e.get_catalog_mode()),
                container: if e.get_catalog_container() == 0 {
                    "diagnostic_archive"
                } else {
                    "zip"
                }
                .into(),
            };
            match draft.rules.save_log_file(file) {
                Ok(()) => {
                    e.set_active_file(id.into());
                    e.set_dirty(true);
                    e.set_catalog_open(false);
                    e.set_dialog_open(false);
                    refresh(&e, &mut draft);
                    e.set_feedback("日志文件已添加，现在可以添加规则".into());
                    e.invoke_focus_list();
                }
                Err(err) => e.set_catalog_error(err.to_string().into()),
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_delete_file(move || {
            let e = w.unwrap();
            let mut draft = d.borrow_mut();
            flush_inline(&e, &mut draft);
            match draft.rules.delete_log_file(e.get_active_file().as_str()) {
                Ok(()) => {
                    e.set_dirty(true);
                    draft.selected = None;
                    refresh(&e, &mut draft);
                    e.set_feedback("日志文件已从草稿删除，保存全部后生效".into());
                }
                Err(err) => e.set_feedback(err.to_string().into()),
            }
        });
    }
    e.set_webdav_configured(state.borrow().settings.webdav.is_some());
    {
        let w = e.as_weak();
        let state = state.clone();
        e.on_open_webdav_dialog(move || {
            let e = w.unwrap();
            reset_webdav_form(&e, &state.borrow().settings);
            e.set_webdav_generation(e.get_webdav_generation().wrapping_add(1));
            e.set_webdav_testing(false);
            e.set_menu_row(-1);
            e.set_export_menu(false);
            e.set_webdav_dialog_open(true);
            e.set_dialog_open(true);
            e.invoke_focus_webdav();
        });
    }
    {
        let w = e.as_weak();
        let state = state.clone();
        e.on_webdav_cancel(move || {
            let e = w.unwrap();
            e.set_webdav_generation(e.get_webdav_generation().wrapping_add(1));
            reset_webdav_form(&e, &state.borrow().settings);
            e.set_webdav_testing(false);
            e.set_webdav_dialog_open(false);
            e.set_dialog_open(false);
            e.invoke_focus_webdav_entry();
        });
    }
    {
        let w = e.as_weak();
        let state = state.clone();
        e.on_webdav_save(move || {
            let e = w.unwrap();
            if e.get_webdav_testing() {
                return;
            }
            let form = webdav_form(&e, &state.borrow().settings);
            let result = form.and_then(|(config, password)| {
                persist_webdav_config(
                    &mut state.borrow_mut().settings,
                    config,
                    &password,
                    |updated| save_json("settings.json", updated),
                )
            });
            match result {
                Ok(()) => {
                    e.set_webdav_configured(true);
                    e.invoke_webdav_cancel();
                    e.set_feedback("WebDAV 配置已保存".into());
                }
                Err(error) => e.set_webdav_feedback(format!("保存失败：{error:#}").into()),
            }
        });
    }
    {
        let w = e.as_weak();
        let state = state.clone();
        e.on_webdav_test_dialog(move || {
            let e = w.unwrap();
            if e.get_webdav_testing() {
                return;
            }
            let (config, password) = match webdav_form(&e, &state.borrow().settings) {
                Ok(form) => form,
                Err(error) => {
                    e.set_webdav_feedback(format!("无法测试：{error:#}").into());
                    return;
                }
            };
            e.set_webdav_testing(true);
            e.set_webdav_feedback("正在连接服务器…".into());
            let generation = e.get_webdav_generation();
            let weak = e.as_weak();
            // 工作线程只接收表单副本，不接触配置写入；关闭后返回的结果不能污染新弹窗。
            std::thread::spawn(move || {
                let result = tracefox::webdav::WebDavClient::new(&config, password)
                    .and_then(|client| client.test_connection());
                let message = match result {
                    Ok(()) => "连接成功，配置尚未保存".to_owned(),
                    Err(error) => format!("连接失败：{error:#}"),
                };
                let _ = weak.upgrade_in_event_loop(move |e| {
                    if e.get_webdav_dialog_open() && e.get_webdav_generation() == generation {
                        e.set_webdav_testing(false);
                        e.set_webdav_feedback(message.into());
                    }
                });
            });
        });
    }
    {
        let w = e.as_weak();
        let state = state.clone();
        let d = d.clone();
        e.on_webdav_sync(move || {
            let e = w.unwrap();
            let result = (|| -> Result<()> {
                let config = state.borrow().settings.webdav.clone().context("请先配置 WebDAV")?;
                let password = tracefox::load_webdav_password(&format!("{}#{}", config.url, config.remote_path))?;
                let (remote, etag) = tracefox::webdav::WebDavClient::new(&config, password)?.download()?;
                let local_hash = rules_hash(&d.borrow().rules)?;
                let remote_hash = rules_hash(&remote)?;
                match tracefox::webdav::detect_conflict(&load_sync_metadata(), &local_hash, &remote_hash) {
                    tracefox::webdav::Conflict::LocalOnly => {
                        e.set_feedback("本地规则有更新，请使用上传规则".into());
                        return Ok(());
                    }
                    tracefox::webdav::Conflict::UpToDate => {
                        e.set_feedback("规则已是最新".into());
                        return Ok(());
                    }
                    tracefox::webdav::Conflict::BothChanged => {
                        let choice = rfd::MessageDialog::new().set_title("规则同步冲突")
                            .set_description("本地和远端规则均有更新。是=保留本地并上传，否=保留远端并下载，取消=不改变。")
                            .set_buttons(rfd::MessageButtons::YesNoCancel).show();
                        match choice {
                            rfd::MessageDialogResult::No => {}
                            rfd::MessageDialogResult::Yes => {
                                e.set_feedback("请使用上传规则完成本地覆盖".into());
                                return Ok(());
                            }
                            _ => {
                                e.set_feedback("已取消同步".into());
                                return Ok(());
                            }
                        }
                    }
                    tracefox::webdav::Conflict::RemoteOnly => {}
                }
                accept_download(&e, &mut state.borrow_mut(), &mut d.borrow_mut(), remote, etag)
            })();
            if let Err(err) = result {
                e.set_feedback(format!("双向同步失败：{err:#}").into());
            }
        });
    }
    {
        let w = e.as_weak();
        let state = state.clone();
        let d = d.clone();
        e.on_webdav_upload(move || {
            let e = w.unwrap();
            let st = state.borrow();
            let result = st
                .settings
                .webdav
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("请先配置 WebDAV"))
                .and_then(|c| {
                    tracefox::load_webdav_password(&format!("{}#{}", c.url, c.remote_path))
                        .and_then(|p| tracefox::webdav::WebDavClient::new(c, p))
                })
                .and_then(|c| {
                    let r = d.borrow().rules.clone();
                    c.upload(&r).and_then(|etag| Ok((r, etag)))
                })
                .and_then(|(r, etag)| {
                    rules_hash(&r).and_then(|h| {
                        save_sync_metadata(&tracefox::webdav::SyncMetadata {
                            local_hash: h.clone(),
                            remote_hash: h,
                            etag,
                        })
                    })
                });
            match result {
                Ok(_) => e.set_feedback("规则已上传到 WebDAV".into()),
                Err(err) => e.set_feedback(format!("上传失败：{err}").into()),
            }
        });
    }
    {
        let w = e.as_weak();
        let state = state.clone();
        let d = d.clone();
        e.on_webdav_download(move || {
            let e = w.unwrap();
            let result = (|| -> Result<()> {
                let config = state
                    .borrow()
                    .settings
                    .webdav
                    .clone()
                    .context("请先配置 WebDAV")?;
                let password = tracefox::load_webdav_password(&format!(
                    "{}#{}",
                    config.url, config.remote_path
                ))?;
                let (rules, etag) =
                    tracefox::webdav::WebDavClient::new(&config, password)?.download()?;
                accept_download(
                    &e,
                    &mut state.borrow_mut(),
                    &mut d.borrow_mut(),
                    rules,
                    etag,
                )
            })();
            if let Err(err) = result {
                e.set_feedback(format!("下载失败：{err:#}").into());
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_select_file(move |i| {
            let e = w.unwrap();
            if let Some(file) = e.get_file_names().row_data(i as usize) {
                e.set_active_file(file);
                e.set_menu_row(-1);
                e.set_dragging(false);
                e.set_drag_from(-1);
                e.set_file_drop_target(-1);
                let mut d = d.borrow_mut();
                flush_inline(&e, &mut d);
                d.selected = None;
                refresh(&e, &mut d);
            }
        });
    }
    {
        let d = d.clone();
        e.on_stage_term(move |id, index, value| {
            let mut draft = d.borrow_mut();
            if draft.editing.is_none() {
                draft
                    .pending_terms
                    .insert((id.to_string(), index), value.to_string());
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_inline_term(move |id, index, value, remove| {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            if let Some(r) = d.rules.rules.iter_mut().find(|r| r.id == id.as_str()) {
                let value = value.trim().to_string();
                if remove {
                    if index >= 0 && (index as usize) < r.terms.len() {
                        r.terms.remove(index as usize);
                    }
                } else if index < 0 {
                    if !value.is_empty() {
                        r.terms.push(value);
                    }
                } else if let Some(t) = r.terms.get_mut(index as usize) {
                    *t = value;
                }
                e.set_dirty(true);
                refresh(&e, &mut d);
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_inline_enabled(move |id, enabled| {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            if d.section == 1 {
                if let Some(r) = d.rules.system.iter_mut().find(|r| r.id == id.as_str()) {
                    r.enabled = enabled;
                }
            } else if let Some(r) = d.rules.rules.iter_mut().find(|r| r.id == id.as_str()) {
                r.enabled = enabled;
            }
            e.set_dirty(true);
            refresh(&e, &mut d);
        });
    }
    {
        let w = e.as_weak();
        e.on_edit_term(move |i, value| {
            let e = w.unwrap();
            if let Some(model) = e
                .get_term_tags()
                .as_any()
                .downcast_ref::<VecModel<SharedString>>()
            {
                model.set_row_data(i as usize, value);
                e.set_terms(
                    (0..model.row_count())
                        .filter_map(|i| model.row_data(i))
                        .map(|t| t.to_string())
                        .collect::<Vec<_>>()
                        .join("\n")
                        .into(),
                );
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_cancel_dialog(move || {
            let e = w.unwrap();
            if e.get_catalog_open() {
                e.invoke_close_file_form();
                return;
            }
            if e.get_webdav_dialog_open() {
                e.invoke_webdav_cancel();
                return;
            }
            d.borrow_mut().editing = None;
            e.set_source_picker_open(false);
            e.set_dialog_open(false);
            e.set_feedback("".into());
            e.invoke_focus_list();
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_next_step(move || {
            let e = w.unwrap();
            e.set_show_errors(true);
            if e.get_step() == 0 {
                if e.get_rule_name().trim().is_empty() || e.get_source().trim().is_empty() {
                    e.set_feedback("请填写规则名称和日志来源。".into());
                    return;
                }
            } else if let Err(err) =
                candidate(&e, &d.borrow()).and_then(|edit| edit.rules.validate())
            {
                e.set_feedback(format!("请检查配置：{err:#}").into());
                return;
            }
            e.set_feedback("".into());
            e.set_show_errors(false);
            e.set_step(e.get_step() + 1);
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_choose_row(move |row| {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            d.selected = d
                .indices
                .get(row as usize)
                .copied()
                .filter(|i| *i != usize::MAX);
            refresh(&e, &mut d);
        });
    }

    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_drop_row(move |moving, to, after| {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            if !e.get_search().is_empty() || to < 0 {
                return;
            }
            let Some(&target) = d.indices.get(to as usize) else {
                return;
            };
            if target == usize::MAX {
                return;
            }
            let system = d.section == 1;
            let anchor = if system {
                d.rules.system[target].id.clone()
            } else {
                d.rules.rules[target].id.clone()
            };
            let selected = d.selected_id();
            reorder_file_rule(&mut d.rules, system, &moving, &anchor, after);
            d.select_id(selected.as_deref());
            e.set_dirty(true);
            refresh(&e, &mut d);
        });
    }
    {
        let w = e.as_weak();
        e.on_drag_hover(move |y| {
            let e = w.unwrap();
            let rows = e.get_rows();
            e.set_drop_target(-1);
            for i in 0..rows.row_count() {
                let row = rows.row_data(i).unwrap();
                if y >= row.offset && y < row.offset + row.height {
                    let after = y > row.offset + row.height / 2.0;
                    e.set_drop_target(i as i32);
                    e.set_drop_after(after);
                    e.set_drop_line_y(row.offset + if after { row.height } else { 0.0 });
                    break;
                }
            }
        });
    }
    {
        let w = e.as_weak();
        e.on_edit_field(move |index, column, value| {
            let e = w.unwrap();
            save_field_form(&e);
            let mut fields = field_values(&e);
            let Some(field) = fields.get_mut(index as usize) else {
                return;
            };
            match column {
                0 => field.name = value.to_string(),
                1 => {
                    let selector = e.get_selector();
                    field.path = value
                        .strip_prefix(&format!("{selector}."))
                        .unwrap_or(&value)
                        .to_string();
                }
                2 => {
                    field.format = ["", "bytes", "unix", "kib"]
                        .get(value.parse::<usize>().unwrap_or(0))
                        .unwrap_or(&"")
                        .to_string()
                }
                _ => return,
            }
            if index == e.get_loaded_field() {
                e.set_field_name(field.name.clone().into());
                e.set_field_path(field.path.clone().into());
                e.set_field_format(pos(&field.format, &["", "bytes", "unix", "kib"]));
            }
            store_fields(&e, &fields);
            e.set_field_names(ModelRc::new(VecModel::from(
                fields
                    .iter()
                    .map(|f| SharedString::from(f.name.as_str()))
                    .collect::<Vec<_>>(),
            )));
        });
    }
    load_layout(&e, &d.borrow().rules.layout);

    {
        let w = e.as_weak();
        e.on_add_term(move || {
            let e = w.unwrap();
            let term = e.get_new_term().trim().to_owned();
            if !term.is_empty() {
                let mut terms = strings(&e.get_terms());
                if !terms.contains(&term) {
                    terms.push(term);
                }
                e.set_terms(terms.join("\n").into());
                e.set_term_tags(ModelRc::new(VecModel::from(
                    terms
                        .iter()
                        .map(|s| SharedString::from(s.as_str()))
                        .collect::<Vec<_>>(),
                )));
                e.set_new_term("".into());
            }
        });
    }
    {
        let w = e.as_weak();
        e.on_remove_term(move |i| {
            let e = w.unwrap();
            let model = e.get_term_tags();
            let mut terms = (0..model.row_count())
                .filter_map(|i| model.row_data(i))
                .map(|t| t.to_string())
                .collect::<Vec<_>>();
            if (i as usize) < terms.len() {
                terms.remove(i as usize);
            }
            e.set_terms(terms.join("\n").into());
            e.set_term_tags(ModelRc::new(VecModel::from(
                terms
                    .iter()
                    .map(|s| SharedString::from(s.as_str()))
                    .collect::<Vec<_>>(),
            )));
        });
    }
    {
        let w = e.as_weak();
        e.on_select_field(move |i| {
            let e = w.unwrap();
            save_field_form(&e);
            load_fields(&e, i);
        });
    }

    {
        let w = e.as_weak();
        e.on_new_field(move || {
            let e = w.unwrap();
            save_field_form(&e);
            let mut fs = field_values(&e);
            fs.push(Field {
                name: "".into(),
                path: "".into(),
                format: String::new(),
                unit: String::new(),
                missing: String::new(),
                wide: false,
                view: String::new(),
                capture: String::new(),
            });
            store_fields(&e, &fs);
            load_fields(&e, fs.len() as i32 - 1);
        });
    }
    {
        let w = e.as_weak();
        e.on_delete_field(move |index| {
            let e = w.unwrap();
            // 删除以列表行索引为准，避免详细设置面板的旧选中项误删其他字段。
            save_field_form(&e);
            let mut fs = field_values(&e);
            if index < 0 || index as usize >= fs.len() {
                return;
            }
            fs.remove(index as usize);
            store_fields(&e, &fs);
            // 保持当前位置：删除中间项时选中后续字段，删除末项时回退到前一项。
            load_fields(&e, index);
        });
    }
    {
        let w = e.as_weak();
        e.on_move_field(move |delta| {
            let e = w.unwrap();
            save_field_form(&e);
            let mut fs = field_values(&e);
            let i = e.get_loaded_field();
            let j = i + delta;
            if i >= 0 && j >= 0 && (j as usize) < fs.len() {
                fs.swap(i as usize, j as usize);
                store_fields(&e, &fs);
                load_fields(&e, j);
            }
        });
    }

    refresh(&e, &mut d.borrow_mut());
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_section_change(move || {
            let e = w.unwrap();
            e.set_drag_from(-1);
            e.set_dragging(false);
            e.set_file_drop_target(-1);
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            if let Err(err) = apply(&e, &mut d) {
                e.set_feedback(err.to_string().into());
            }
            d.section = e.get_section();
            d.selected = None;
            e.set_search("".into());
            refresh(&e, &mut d);
            if let Some(&i) = d.indices.iter().find(|&&i| i != usize::MAX) {
                d.selected = Some(i);
                load(&e, &d);
                refresh(&e, &mut d);
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_toggle_rule(move |id| {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            if !d.expanded_rules.remove(id.as_str()) {
                d.expanded_rules.insert(id.to_string());
            }
            refresh(&e, &mut d);
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_select_rule(move |i| {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            d.selected = d
                .indices
                .get(i as usize)
                .copied()
                .filter(|i| *i != usize::MAX);
            if d.selected.is_some() {
                let edit = d.fork();
                open_rule(&e, &mut d, edit, false);
            }
            refresh(&e, &mut d);
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_search_change(move || {
            let e = w.unwrap();
            e.set_drag_from(-1);
            e.set_dragging(false);
            e.set_file_drop_target(-1);
            refresh(&e, &mut d.borrow_mut());
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_apply_rule(move || {
            let e = w.unwrap();
            e.set_show_errors(true);
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            let result = candidate(&e, &d).and_then(|edit| {
                edit.rules.validate()?;
                Ok(edit)
            });
            match result {
                Ok(edit) => {
                    let id = edit.selected_id();
                    if let Some(id) = &id {
                        d.expanded_rules.insert(id.clone());
                    }
                    d.rules = edit.rules;
                    d.select_id(id.as_deref());
                    d.editing = None;
                    e.set_source_picker_open(false);
                    e.set_dialog_open(false);
                    e.set_dirty(true);
                    e.set_feedback("修改已加入草稿，保存全部后生效。".into());
                    refresh(&e, &mut d);
                    e.invoke_focus_list();
                }
                Err(err) => e.set_feedback(format!("请检查配置：{err:#}").into()),
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_add_rule(move || {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            let mut edit = d.fork();
            let file = e.get_active_file().to_string();
            if d.rules.log_file(&file).is_err() {
                e.set_feedback("请先添加日志文件，再添加规则".into());
                return;
            }
            if edit.section == 1 {
                let mut r = SystemRule::default();
                r.name.clear();
                r.source_file_id = file.clone();
                edit.rules.system.push(r);
                edit.selected = Some(edit.rules.system.len() - 1);
            } else {
                let mut r = Rule {
                    target: if edit.section == 2 {
                        "timeline"
                    } else {
                        "keywords"
                    }
                    .into(),
                    ..Rule::default()
                };
                r.name.clear();
                r.source_file_ids = vec![file];
                edit.rules.rules.push(r);
                edit.selected = Some(edit.rules.rules.len() - 1);
            }
            if let Err(err) = edit.rules.resolve_sources() {
                e.set_feedback(err.to_string().into());
                return;
            }
            open_rule(&e, &mut d, edit, true);
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_copy_rule(move || {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            let mut edit = d.fork();
            if let Some(i) = edit.selected {
                if edit.section == 1 {
                    let mut r = edit.rules.system[i].clone();
                    r.id = SystemRule::default().id;
                    r.name.push_str(" 副本");
                    edit.rules.system.push(r);
                    edit.selected = Some(edit.rules.system.len() - 1);
                } else {
                    let mut r = edit.rules.rules[i].clone();
                    r.id = Rule::default().id;
                    r.name.push_str(" 副本");
                    edit.rules.rules.push(r);
                    edit.selected = Some(edit.rules.rules.len() - 1);
                }
                open_rule(&e, &mut d, edit, false);
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_delete_rule(move || {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            if let Some(i) = d.selected {
                if d.section == 1 {
                    d.rules.system.remove(i);
                } else {
                    d.rules.rules.remove(i);
                }
                d.selected = None;
                e.set_dirty(true);
                refresh(&e, &mut d);
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_move_rule(move |delta| {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            if !e.get_search().is_empty() {
                return;
            }
            if let Some(id) = d.selected_id() {
                if let Some(row) = d.indices.iter().position(|i| Some(*i) == d.selected) {
                    let position = row as i32 + delta;
                    if position >= 0 && (position as usize) < d.indices.len() {
                        let i = d.indices[position as usize];
                        let anchor = if d.section == 1 {
                            d.rules.system[i].id.clone()
                        } else {
                            d.rules.rules[i].id.clone()
                        };
                        let system = d.section == 1;
                        reorder_file_rule(&mut d.rules, system, &id, &anchor, delta > 0);
                        d.select_id(Some(&id));
                        e.set_dirty(true);
                        refresh(&e, &mut d);
                    }
                }
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        let state = state.clone();
        e.on_save_all(move || {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            let result = apply(&e, &mut d)
                .and_then(|_| d.rules.validate())
                .and_then(|_| save_default_rules(&d.rules));
            match result {
                Ok(()) => {
                    state.borrow_mut().rules = d.rules.clone();
                    e.set_dirty(false);
                    e.set_feedback("规则已保存，编辑窗口保持打开。".into());
                }
                Err(err) => e.set_feedback(format!("无法保存：{err:#}").into()),
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_restore_defaults(move || {
            let e = w.unwrap();
            // 还原与导入一样只修改草稿，取消编辑不能覆盖已保存规则。
            let mut d = d.borrow_mut();
            d.rules = RuleSet::defaults();
            d.selected = None;
            d.pending_terms.clear();
            load_layout(&e, &d.rules.layout);
            refresh(&e, &mut d);
            e.set_dirty(true);
            e.set_feedback("默认规则已还原到草稿，保存全部后生效".into());
        });
    }
    {
        let w = e.as_weak();
        let state = state.clone();
        e.on_cancel_edit(move || {
            let _ = w.unwrap().hide();
            state.borrow_mut().editor = None;
        });
    }
    {
        let state = state.clone();
        let w = e.as_weak();
        e.window().on_close_requested(move || {
            if let Some(e) = w.upgrade() {
                if e.get_dialog_open() {
                    e.invoke_cancel_dialog();
                    return slint::CloseRequestResponse::KeepWindowShown;
                }
            }
            state.borrow_mut().editor = None;
            slint::CloseRequestResponse::HideWindow
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_test_rule(move || {
            let e = w.unwrap();
            let d = d.borrow();
            let result = (|| -> Result<String> {
                let edit = candidate(&e, &d)?;
                edit.rules.validate()?;
                let i = edit.selected.context("请先选择规则")?;
                let html = engine::preview(&edit.rules, i, edit.section == 1, &e.get_sample())?;
                let dir = data_dir();
                std::fs::create_dir_all(&dir)?;
                let path = dir.join("rule-preview.html");
                std::fs::write(&path, html)?;
                open::that(&path)?;
                Ok("已在浏览器打开预览，可查看字段表格、关键词高亮及上下文。".into())
            })();
            e.set_feedback(result.unwrap_or_else(|e| format!("测试失败：{e:#}")).into());
        });
    }
    {
        let w = e.as_weak();
        e.on_load_sample(move || {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                let e = w.unwrap();
                match std::fs::read(&p) {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        e.set_sample(text.as_ref().into());
                        e.set_sample_paths(ModelRc::new(VecModel::from(
                            text.lines()
                                .filter_map(|l| {
                                    l.trim()
                                        .split_once(':')
                                        .map(|(k, _)| SharedString::from(k.trim()))
                                })
                                .collect::<Vec<_>>(),
                        )));
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                            let mut paths = vec![];
                            extract::json_paths(&v, "", &mut paths);
                            e.set_sample_paths(ModelRc::new(VecModel::from(
                                paths
                                    .iter()
                                    .map(|s| SharedString::from(s.as_str()))
                                    .collect::<Vec<_>>(),
                            )));
                            e.set_feedback("样例已加载，可从来源字段下拉列表选择字段。".into());
                        }
                    }
                    Err(err) => error(err),
                }
            }
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        let import = Rc::new(move |reference: bool| {
            let incoming = if reference {
                Ok(RuleSet::defaults())
            } else {
                let Some(path) = rfd::FileDialog::new()
                    .add_filter("规则 JSON", &["json"])
                    .pick_file()
                else {
                    return;
                };
                std::fs::read_to_string(path)
                    .map_err(anyhow::Error::from)
                    .and_then(|s| RuleSet::import(&s))
            };
            let e = w.unwrap();
            let incoming = match incoming {
                Ok(r) => r,
                Err(err) => {
                    e.set_feedback(format!("导入失败：{err:#}").into());
                    return;
                }
            };
            let mut draft = d.borrow_mut();
            let _ = apply(&e, &mut draft);
            let preview = match ImportWindow::new() {
                Ok(p) => p,
                Err(err) => {
                    e.set_feedback(err.to_string().into());
                    return;
                }
            };
            install_window_rendering_recovery(&preview.window());
            preview.set_reference_only(reference);
            let warnings = incoming.validate().unwrap_or_default();
            preview.set_summary(
                format!(
                    "关键词/时间线 {} 条，系统信息 {} 组。\n\n{}\n\n{}",
                    incoming.rules.len(),
                    incoming.system.len(),
                    incoming
                        .rules
                        .iter()
                        .map(|r| format!("{} / {}", r.group, r.name))
                        .chain(
                            incoming
                                .system
                                .iter()
                                .map(|r| format!("{} / {}", r.group, r.name))
                        )
                        .collect::<Vec<_>>()
                        .join("\n"),
                    warnings.join("\n")
                )
                .into(),
            );
            if reference {
                preview.set_summary(format!("将按内置 ID 更新以下系统规则到草稿；自定义规则、关键词和时间线保持不变。保存全部后生效。\n\n{}",incoming.system.iter().map(|r|format!("{}：{} / {}",if draft.rules.system.iter().any(|x|x.id==r.id){"更新"}else{"新增"},r.group,r.name)).collect::<Vec<_>>().join("\n")).into());
            }
            let dw = Rc::downgrade(&d);
            let ew = e.as_weak();
            let pw = preview.as_weak();
            preview.on_confirm(move |replace| {
                if let (Some(d), Some(e), Some(p)) = (dw.upgrade(), ew.upgrade(), pw.upgrade()) {
                    let mut draft = d.borrow_mut();
                    match if reference {
                        draft.rules.with_reference_system()
                    } else {
                        draft.rules.merge(&incoming, replace)
                    } {
                        Ok(r) => {
                            draft.rules = r;
                            e.set_dirty(true);
                            load_layout(&e, &draft.rules.layout);
                            draft.selected = None;
                            refresh(&e, &mut draft);
                            e.set_feedback("规则已导入草稿，保存全部后生效".into());
                            let _ = p.hide();
                            draft.import_window = None;
                        }
                        Err(err) => e.set_feedback(format!("导入未应用：{err:#}").into()),
                    }
                }
            });
            let pw = preview.as_weak();
            let dw = Rc::downgrade(&d);
            preview.on_cancel_import(move || {
                if let Some(p) = pw.upgrade() {
                    let _ = p.hide();
                }
                if let Some(d) = dw.upgrade() {
                    d.borrow_mut().import_window = None;
                }
            });
            let _ = preview.show();
            draft.import_window = Some(preview);
        });
        let action = import.clone();
        e.on_import_rules(move || action(false));
        e.on_reference_rules(move || import(true));
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_export_rules(move |selected| {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            flush_inline(&e, &mut d);
            let _ = apply(&e, &mut d);
            let mut out = d.rules.clone();
            if selected {
                if let Some(i) = d.selected {
                    if d.section == 1 {
                        let r = out.system[i].clone();
                        let mut keep = vec![r.id.clone()];
                        let mut next = r.join_rule.clone();
                        while !next.is_empty() && !keep.contains(&next) {
                            keep.push(next.clone());
                            next = out
                                .system
                                .iter()
                                .find(|x| x.id == next)
                                .map(|x| x.join_rule.clone())
                                .unwrap_or_default();
                        }
                        out.system.retain(|x| keep.contains(&x.id));
                        out.rules.clear();
                    } else {
                        out.rules = vec![out.rules[i].clone()];
                        out.system.clear();
                    }
                } else {
                    e.set_feedback("请先选择规则".into());
                    return;
                }
            }
            if selected {
                let ids = out
                    .rules
                    .iter()
                    .flat_map(|r| r.source_file_ids.iter())
                    .chain(out.system.iter().map(|r| &r.source_file_id))
                    .cloned()
                    .collect::<std::collections::HashSet<_>>();
                out.log_files.retain(|file| ids.contains(&file.id));
                out.layout.file_order.retain(|id| ids.contains(id));
            }
            if let Err(err) = out.validate() {
                e.set_feedback(err.to_string().into());
                return;
            }
            if let Some(p) = rfd::FileDialog::new()
                .add_filter("规则 JSON", &["json"])
                .set_file_name("tracefox-rules.json")
                .save_file()
            {
                if let Err(err) = std::fs::write(p, serde_json::to_vec_pretty(&out).unwrap()) {
                    error(err);
                }
            }
        });
    }
    {
        let mut draft = d.borrow_mut();
        draft.selected = None;
        refresh(&e, &mut draft);
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_drop_file(move |from, to| {
            let e = w.unwrap();
            let mut d = d.borrow_mut();
            let visible = e.get_file_names();
            let visible = (0..visible.row_count())
                .filter_map(|i| visible.row_data(i).map(|s| s.to_string()))
                .collect::<Vec<_>>();
            let system = d.section == 1;
            if reorder_log_files(&mut d.rules, &visible, from as usize, to as usize, system) {
                e.set_dirty(true);
                refresh(&e, &mut d);
            }
        });
    }
    {
        let w = e.as_weak();
        e.on_file_drag_hover(move |y| {
            let e = w.unwrap();
            let count = e.get_file_names().row_count();
            if count == 0 {
                e.set_file_drop_target(-1);
                return;
            }
            let target = ((y.max(0.0) / 62.0).floor() as usize).min(count - 1);
            e.set_file_drop_target(target as i32);
        });
    }
    {
        let w = e.as_weak();
        let d = d.clone();
        e.on_file_panel_width_changed(move || {
            let e = w.unwrap();
            let width = e.get_file_panel_width().round().clamp(180.0, 360.0) as u32;
            let mut draft = d.borrow_mut();
            if draft.rules.layout.file_panel_width != width {
                draft.rules.layout.file_panel_width = width;
                e.set_dirty(true);
            }
        });
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_settings_keep_startup_disabled_and_preserve_monitor() {
        let settings: Settings =
            serde_json::from_str(r#"{"directory":"downloads","watching":true}"#).unwrap();
        assert!(!settings.autostart);
        assert!(!settings.start_minimized);
        assert!(settings.watching);
        assert_eq!(settings.directory, "downloads");
        let enabled = Settings {
            autostart: true,
            start_minimized: true,
            ..settings
        };
        let restored: Settings =
            serde_json::from_slice(&serde_json::to_vec(&enabled).unwrap()).unwrap();
        assert!(restored.autostart && restored.start_minimized && restored.watching);
    }

    #[test]
    fn portable_rules_save_creates_directory_and_preserves_previous_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("assets/default-rules.json");
        let rules = RuleSet::defaults();
        save_rules_at(&path, &rules).unwrap();
        let original = std::fs::read(&path).unwrap();
        assert!(RuleSet::import(std::str::from_utf8(&original).unwrap()).is_ok());
        // 临时路径不可写时，不允许损坏或覆盖上一份规则。
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        assert!(save_rules_at(&path, &rules).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
    #[test]
    fn log_file_sort_uses_visible_order_and_preserves_related_rule_data() {
        let mut rules = RuleSet::defaults();
        rules.log_files = ["a", "b", "c"]
            .into_iter()
            .map(|id| LogFile {
                id: id.into(),
                name: id.into(),
                path: format!("{id}.log"),
                mode: "prefix".into(),
                container: "diagnostic_archive".into(),
            })
            .collect();
        rules.layout.file_order = vec!["a".into(), "c".into()];
        let template = rules.rules[0].clone();
        rules.rules = [
            ("rule-a", vec!["a"]),
            ("rule-b", vec!["b"]),
            ("rule-c", vec!["c"]),
            ("rule-shared", vec!["a", "c"]),
        ]
        .into_iter()
        .map(|(id, source_file_ids)| Rule {
            id: id.into(),
            source_file_ids: source_file_ids.into_iter().map(String::from).collect(),
            group: format!("group-{id}"),
            ..template.clone()
        })
        .collect();
        let original = rules.rules.clone();
        let visible = ["a", "b", "c"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();

        assert!(reorder_log_files(&mut rules, &visible, 0, 2, false));
        assert_eq!(
            rules.layout.file_order,
            ["b", "c", "a"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            rules
                .rules
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            ["rule-b", "rule-c", "rule-a", "rule-shared"]
        );
        for row in &rules.rules {
            let before = original.iter().find(|r| r.id == row.id).unwrap();
            assert_eq!(
                serde_json::to_value(row).unwrap(),
                serde_json::to_value(before).unwrap()
            );
        }

        let visible_after_down = rules.layout.file_order.clone();
        assert!(reorder_log_files(
            &mut rules,
            &visible_after_down,
            2,
            0,
            false
        ));
        assert_eq!(
            rules.layout.file_order,
            ["a", "b", "c"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        let before_noop = serde_json::to_value(&rules).unwrap();
        let visible_for_noop = rules.layout.file_order.clone();
        assert!(!reorder_log_files(
            &mut rules,
            &visible_for_noop,
            1,
            1,
            false
        ));
        assert_eq!(serde_json::to_value(&rules).unwrap(), before_noop);

        let mut without_target_rules = rules.clone();
        without_target_rules
            .rules
            .retain(|r| !r.source_file_ids.iter().any(|id| id == "b"));
        let rules_before_empty_target = serde_json::to_value(&without_target_rules.rules).unwrap();
        let visible_for_empty_target = without_target_rules.layout.file_order.clone();
        assert!(reorder_log_files(
            &mut without_target_rules,
            &visible_for_empty_target,
            0,
            1,
            false
        ));
        assert_eq!(
            serde_json::to_value(&without_target_rules.rules).unwrap(),
            rules_before_empty_target
        );

        let mut system_rules = RuleSet::defaults();
        let system_template = system_rules.system[0].clone();
        system_rules.system = ["a", "b", "c"]
            .into_iter()
            .map(|source_file_id| SystemRule {
                id: format!("system-{source_file_id}"),
                source_file_id: source_file_id.into(),
                ..system_template.clone()
            })
            .collect();
        system_rules.layout.file_order = visible.clone();
        assert!(reorder_log_files(&mut system_rules, &visible, 0, 2, true));
        assert_eq!(
            system_rules
                .system
                .iter()
                .map(|r| r.source_file_id.as_str())
                .collect::<Vec<_>>(),
            ["b", "c", "a"]
        );
    }

    #[test]
    fn file_sort_keeps_report_groups_sources_and_hidden_rules() {
        let mut rules = RuleSet::defaults();
        let first = rules.rules[0].clone();
        rules.rules = (0..4)
            .map(|i| Rule {
                id: format!("file-{i}"),
                group: format!("report-{i}"),
                target: if i == 1 {
                    "timeline".into()
                } else {
                    "both".into()
                },
                ..first.clone()
            })
            .collect();
        let original = rules.rules.clone();
        reorder_file_rule(&mut rules, false, "file-0", "file-2", true);
        assert_eq!(
            rules
                .rules
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            ["file-1", "file-2", "file-0", "file-3"]
        );
        for r in &rules.rules {
            let before = original.iter().find(|o| o.id == r.id).unwrap();
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::to_value(before).unwrap()
            );
        }
        let before = serde_json::to_value(&rules).unwrap();
        reorder_file_rule(&mut rules, false, "file-0", "missing", false);
        reorder_file_rule(&mut rules, false, "file-0", "file-0", true);
        assert_eq!(serde_json::to_value(&rules).unwrap(), before);
    }

    #[test]
    fn webdav_empty_password_uses_original_server_credential() {
        let original = tracefox::webdav::WebDavSettings {
            enabled: true,
            url: "https://old.example/dav/".into(),
            remote_path: "rules.json".into(),
            username: "user".into(),
        };
        let password = resolve_webdav_password("", Some(&original), |key| {
            assert_eq!(key, "https://old.example/dav/#rules.json");
            Ok("stored-password".into())
        })
        .unwrap();
        assert_eq!(password, "stored-password");
        assert!(
            resolve_webdav_password("", Some(&original), |_| anyhow::bail!("凭据读取失败"))
                .is_err()
        );
        assert_eq!(
            resolve_webdav_password("new", Some(&original), |_| panic!("不应读取旧凭据")).unwrap(),
            "new"
        );
        assert_eq!(
            resolve_webdav_password("", None, |_| panic!("新增匿名配置不应读取凭据")).unwrap(),
            ""
        );
    }

    #[test]
    fn webdav_invalid_form_never_reaches_persistence() {
        let mut settings = Settings::default();
        let config = tracefox::webdav::WebDavSettings {
            url: "not a server".into(),
            remote_path: "rules.json".into(),
            ..Default::default()
        };
        assert!(
            persist_webdav_config(&mut settings, config, "", |_| panic!("无效配置不应保存"))
                .is_err()
        );
        assert!(settings.webdav.is_none());
    }
}
