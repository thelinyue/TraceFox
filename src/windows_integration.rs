//! Windows 桌面集成：启动项只修改当前用户；通知回调只传消息，不跨线程操作界面。
use anyhow::{Context, Result};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::Sender,
};
use windows::{
    Data::Xml::Dom::XmlDocument,
    Foundation::TypedEventHandler,
    UI::Notifications::{ToastNotification, ToastNotificationManager, ToastNotifier},
    core::HSTRING,
};
use winreg::{RegKey, enums::*};

const APP_ID: &str = "TraceFox.Desktop";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

pub fn startup_command(exe: &Path) -> String {
    format!("\"{}\" --startup", exe.display())
}

pub fn startup_value() -> Result<Option<String>> {
    match RegKey::predef(HKEY_CURRENT_USER).open_subkey(RUN_KEY) {
        Ok(key) => read_startup(&key),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("无法读取 Windows 启动项"),
    }
}
fn read_startup(key: &RegKey) -> Result<Option<String>> {
    match key.get_value("TraceFox") {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("无法读取 Windows 启动项"),
    }
}
/// 写后读回确认；用于保存失败时恢复原有命令，不覆盖其他应用的启动配置。
pub fn write_startup(value: Option<&str>) -> Result<()> {
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN_KEY)?;
    write_startup_at(&key, value)
}
fn write_startup_at(key: &RegKey, value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        key.set_value("TraceFox", &value)?;
    } else if let Err(e) = key.delete_value("TraceFox") {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e.into());
        }
    }
    anyhow::ensure!(
        read_startup(key)?.as_deref() == value,
        "Windows 启动项写入后校验失败"
    );
    Ok(())
}

/// 点击动作保存当次结果，不从可能已重试或淘汰的列表反查报告路径。
#[derive(Clone, Debug)]
pub enum Activation {
    Report(PathBuf),
    Failed {
        id: i32,
        package: PathBuf,
        error: String,
    },
}

fn escape_xml(text: &str) -> String {
    text.chars()
        .filter(|&c| c >= ' ' || matches!(c, '\n' | '\r' | '\t'))
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn toast_xml(package: &Path, summary: &str, success: bool) -> String {
    let title = if success {
        "诊断包分析完成"
    } else {
        "诊断包分析失败"
    };
    let hint = if success {
        "点击打开 HTML 报告"
    } else {
        "点击查看失败任务"
    };
    let package = package.file_name().unwrap_or_default().to_string_lossy();
    format!(
        r#"<toast><visual><binding template="ToastGeneric"><text>{title}</text><text>{}</text><text>{} · {hint}</text></binding></visual></toast>"#,
        escape_xml(&package),
        escape_xml(summary)
    )
}

/// Toast 对象保留到退出，以支持通知中心中的延后点击；退出时清理本次通知。
/// 回调携带报告绝对路径或任务身份，任务被列表淘汰后仍可解释通知的含义。
pub struct Notifications {
    notifier: ToastNotifier,
    toasts: Vec<ToastNotification>,
    group: String,
    sender: Sender<Activation>,
    _apartment: Apartment,
}

/// 只平衡本模块成功取得的 WinRT 初始化计数，不撤销 Slint 的 COM 初始化。
struct Apartment(bool);
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe {
                windows::Win32::System::WinRT::RoUninitialize();
            }
        }
    }
}
impl Notifications {
    pub fn new(sender: Sender<Activation>) -> Result<Self> {
        // Slint 可能已初始化 COM；只在当前线程尚未初始化时由 WinRT 初始化。
        let result = unsafe {
            windows::Win32::System::WinRT::RoInitialize(
                windows::Win32::System::WinRT::RO_INIT_SINGLETHREADED,
            )
        };
        let apartment = Apartment(result.is_ok());
        if let Err(e) = result {
            if e.code().0 != 0x80010106u32 as i32 {
                return Err(e.into());
            }
        }
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(r"Software\Classes\AppUserModelId\{APP_ID}"))?;
        key.set_value("DisplayName", &"TraceFox")?;
        let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_ID))?;
        Ok(Self {
            notifier,
            toasts: Vec::new(),
            sender,
            group: std::process::id().to_string(),
            _apartment: apartment,
        })
    }
    pub fn show(&mut self, package: &Path, summary: &str, action: Activation) -> Result<()> {
        let xml = XmlDocument::new()?;
        xml.LoadXml(&HSTRING::from(toast_xml(
            package,
            summary,
            matches!(action, Activation::Report(_)),
        )))?;
        let toast = ToastNotification::CreateToastNotification(&xml)?;
        toast.SetGroup(&HSTRING::from(&self.group))?;
        toast.SetTag(&HSTRING::from(self.toasts.len().to_string()))?;
        let sender = self.sender.clone();
        toast.Activated(&TypedEventHandler::new(move |_, _| {
            let _ = sender.send(action.clone());
            Ok(())
        }))?;
        toast.Failed(&TypedEventHandler::new(|_, _| {
            eprintln!("TraceFox：Windows 无法显示系统通知，请检查系统通知设置");
            Ok(())
        }))?;
        self.notifier
            .Show(&toast)
            .context("发送 Windows 系统通知失败")?;
        self.toasts.push(toast);
        Ok(())
    }
}
impl Drop for Notifications {
    fn drop(&mut self) {
        if let Ok(history) = ToastNotificationManager::History() {
            let _ = history.RemoveGroupWithId(&HSTRING::from(&self.group), &HSTRING::from(APP_ID));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_roundtrip_and_quoted_path() {
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let path = format!(r"Software\TraceFoxTests\{}", std::process::id());
        let (key, _) = root.create_subkey(&path).unwrap();
        let command = startup_command(Path::new(r"C:\中文 空格\TraceFox.exe"));
        assert_eq!(command, "\"C:\\中文 空格\\TraceFox.exe\" --startup");
        write_startup_at(&key, Some(&command)).unwrap();
        assert_eq!(read_startup(&key).unwrap(), Some(command));
        write_startup_at(&key, Some("updated")).unwrap();
        assert_eq!(read_startup(&key).unwrap().as_deref(), Some("updated"));
        write_startup_at(&key, None).unwrap();
        write_startup_at(&key, None).unwrap();
        assert!(read_startup(&key).unwrap().is_none());
        drop(key);
        root.delete_subkey_all(path).unwrap();
    }
    #[test]
    fn toast_escapes_package_and_error() {
        for success in [true, false] {
            let xml = toast_xml(Path::new("中文 & <test>.tgz"), "错误 <&>\"'\u{1}", success);
            assert!(xml.contains("中文 &amp; &lt;test&gt;.tgz"));
            assert!(!xml.contains('\u{1}'));
            assert!(xml.contains(if success {
                "点击打开 HTML 报告"
            } else {
                "点击查看失败任务"
            }));
            let doc = XmlDocument::new().unwrap();
            doc.LoadXml(&HSTRING::from(xml)).unwrap();
        }
    }
}
