//! WebDAV 规则同步核心。网络访问与冲突判定集中于此，界面层只负责展示结果。
use crate::rules::RuleSet;
use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

/// 单服务器配置仅包含非敏感字段；校验不连接网络，可用于离线保存。
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WebDavSettings {
    pub enabled: bool,
    pub url: String,
    pub remote_path: String,
    pub username: String,
}

impl WebDavSettings {
    pub fn validate(&self) -> Result<()> {
        let base = Url::parse(&self.url).context("WebDAV 地址格式无效")?;
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
            bail!("WebDAV 地址必须使用 HTTP 或 HTTPS，并包含服务器地址")
        }
        if self.remote_path.trim().trim_matches('/').is_empty() {
            bail!("远端文件路径不能为空")
        }
        let endpoint = base
            .join(self.remote_path.trim_start_matches('/'))
            .context("WebDAV 远端路径无效")?;
        if endpoint.origin() != base.origin() {
            bail!("远端文件路径必须位于当前 WebDAV 服务器")
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SyncMetadata {
    pub local_hash: String,
    pub remote_hash: String,
    pub etag: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conflict {
    UpToDate,
    LocalOnly,
    RemoteOnly,
    BothChanged,
}

pub fn content_hash(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

pub fn detect_conflict(meta: &SyncMetadata, local: &str, remote: &str) -> Conflict {
    let l = local != meta.local_hash;
    let r = remote != meta.remote_hash;
    match (l, r) {
        (false, false) => Conflict::UpToDate,
        (true, false) => Conflict::LocalOnly,
        (false, true) => Conflict::RemoteOnly,
        (true, true) => Conflict::BothChanged,
    }
}

/// 网络客户端只负责远端访问；连接测试设置独立超时，不承担配置保存。
pub struct WebDavClient {
    client: Client,
    base: Url,
    username: String,
    password: String,
    path: String,
}
impl WebDavClient {
    pub fn new(settings: &WebDavSettings, password: impl Into<String>) -> Result<Self> {
        settings.validate()?;
        let base = Url::parse(&settings.url).context("WebDAV 地址格式无效")?;
        if !matches!(base.scheme(), "http" | "https") {
            bail!("WebDAV 地址必须使用 HTTP 或 HTTPS")
        }
        if settings.remote_path.trim().is_empty() {
            bail!("远端文件路径不能为空")
        }
        Ok(Self {
            client: Client::new(),
            base,
            username: settings.username.clone(),
            password: password.into(),
            path: settings.remote_path.trim_start_matches('/').into(),
        })
    }
    fn endpoint(&self) -> Result<Url> {
        self.base.join(&self.path).context("WebDAV 远端路径无效")
    }
    fn req(&self, b: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        if self.username.is_empty() {
            b
        } else {
            b.basic_auth(&self.username, Some(&self.password))
        }
    }
    pub fn test_connection(&self) -> Result<()> {
        let r = self
            .req(
                self.client
                    .head(self.endpoint()?)
                    .timeout(std::time::Duration::from_secs(15)),
            )
            .send()
            .context("连接 WebDAV 失败")?;
        if !r.status().is_success() {
            bail!("WebDAV 服务器返回错误状态：{}", r.status())
        }
        Ok(())
    }
    pub fn download(&self) -> Result<(RuleSet, Option<String>)> {
        let r = self
            .req(self.client.get(self.endpoint()?))
            .send()
            .context("下载规则失败")?;
        if !r.status().is_success() {
            bail!("下载规则失败，服务器状态：{}", r.status())
        }
        let etag = r
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = r.bytes().context("读取远端规则失败")?;
        let rules =
            RuleSet::import(std::str::from_utf8(&bytes).context("远端规则必须为 UTF-8 文本")?)
                .context("远端规则 JSON 格式无效")?;
        Ok((rules, etag))
    }
    pub fn upload(&self, rules: &RuleSet) -> Result<Option<String>> {
        rules.validate()?;
        let bytes = serde_json::to_vec_pretty(rules).context("序列化规则失败")?;
        let r = self
            .req(
                self.client
                    .put(self.endpoint()?)
                    .header("content-type", "application/json")
                    .body(bytes),
            )
            .send()
            .context("上传规则失败")?;
        if !r.status().is_success() {
            bail!("上传规则失败，服务器状态：{}", r.status())
        }
        Ok(r.headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned))
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;

    #[test]
    fn offline_validation_rejects_invalid_server_and_file_paths() {
        let mut config = WebDavSettings {
            url: "https://example.com/dav/".into(),
            remote_path: "rules.json".into(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
        for url in ["", "server", "ftp://example.com/"] {
            config.url = url.into();
            assert!(config.validate().is_err());
        }
        config.url = "https://example.com/dav/".into();
        for path in ["", " ", "/", "https://elsewhere.example/rules.json"] {
            config.remote_path = path.into();
            assert!(config.validate().is_err());
        }
    }
}
