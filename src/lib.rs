pub mod engine;
pub mod extract;
pub mod monitor;
pub mod rules;
pub mod tasks;
pub mod webdav;

#[cfg(windows)]
pub fn save_webdav_password(target: &str, password: &str) -> anyhow::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::*;
    let t: Vec<u16> = OsStr::new(target).encode_wide().chain(Some(0)).collect();
    let b = password.as_bytes().to_vec();
    let mut c: CREDENTIALW = unsafe { std::mem::zeroed() };
    c.Flags = 0;
    c.Type = CRED_TYPE_GENERIC;
    c.TargetName = t.as_ptr() as _;
    c.CredentialBlobSize = b.len() as u32;
    c.CredentialBlob = b.as_ptr() as _;
    c.Persist = CRED_PERSIST_LOCAL_MACHINE;
    unsafe {
        if CredWriteW(&mut c, 0) == 0 {
            anyhow::bail!("无法保存 Windows 凭据")
        }
    }
    Ok(())
}

/// 区分凭据不存在与系统读取失败，保存回滚时不能把读取失败当成空密码。
#[cfg(windows)]
pub fn read_webdav_password(target: &str) -> anyhow::Result<Option<String>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::*;
    let target: Vec<u16> = std::ffi::OsStr::new(target)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut pointer = std::ptr::null_mut();
    unsafe {
        if CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pointer) == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(1168) {
                return Ok(None);
            }
            anyhow::bail!("读取 Windows 凭据失败：{error}");
        }
        let credential = &*pointer;
        let password = if credential.CredentialBlobSize == 0 {
            String::new()
        } else {
            String::from_utf8_lossy(std::slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            ))
            .into_owned()
        };
        CredFree(pointer as _);
        Ok(Some(password))
    }
}

#[cfg(windows)]
pub fn load_webdav_password(target: &str) -> anyhow::Result<String> {
    read_webdav_password(target)?
        .ok_or_else(|| anyhow::anyhow!("未找到 WebDAV 凭据，请重新填写密码"))
}

/// 仅用于配置保存失败时撤销本次新建的凭据，不清理用户已有服务器凭据。
#[cfg(windows)]
pub fn delete_webdav_password(target: &str) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::*;
    let target: Vec<u16> = std::ffi::OsStr::new(target)
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        if CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(1168) {
                anyhow::bail!("撤销 Windows 凭据失败：{error}");
            }
        }
    }
    Ok(())
}
