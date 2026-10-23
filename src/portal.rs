//! Opt-in SCUT wireless ePortal provider, separate from Ethernet EAP/DrCOM.
//!
//! Requests are bounded, redirects never receive credentials, and a login reply
//! is not considered connected until the portal lists this client's session.
//! Behavioral references and protocol limitations are documented in docs/portal.md.
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use reqwest::{Client, Response, Url, redirect::Policy};
use serde_json::Value;
use tokio::sync::watch;

const CALLBACK: &str = "drcom4scut";
const MAX_RESPONSE: usize = 64 * 1024;

/// Configuration contains no credentials. Passwords are provided only to login.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PortalConfig {
    pub base_url: String,
    pub api_url: Option<String>,
    pub ac_ip: Option<Ipv4Addr>,
    pub client_ip: Option<Ipv4Addr>,
    /// Actual local transport source, separate from the portal-observed identity.
    pub local_ip: Option<IpAddr>,
    pub client_mac: Option<String>,
    /// Required for campus deployments that expose an unencrypted HTTP portal.
    pub allow_http: bool,
    pub timeout: Duration,
    pub confirm_attempts: u8,
    pub confirm_interval: Duration,
}

impl Default for PortalConfig {
    fn default() -> Self {
        Self {
            base_url: "https://s.scut.edu.cn".into(),
            api_url: None,
            ac_ip: None,
            client_ip: None,
            local_ip: None,
            client_mac: None,
            allow_http: false,
            timeout: Duration::from_secs(5),
            confirm_attempts: 5,
            confirm_interval: Duration::from_secs(2),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortalStatus {
    pub online: bool,
    pub client_ip: Ipv4Addr,
    /// Account reported for this IP/MAC session, when supplied by the portal.
    /// This private metadata must not be persisted in connection status or logs.
    pub user_account: Option<String>,
}

impl PortalStatus {
    /// Missing account metadata preserves the portal's network-ready semantics;
    /// it is not evidence that the supplied credentials were authenticated.
    pub fn account_matches(&self, username: &str) -> bool {
        self.user_account.as_deref().is_none_or(|account| {
            account.strip_suffix("@wifi").unwrap_or(account)
                == username.strip_suffix("@wifi").unwrap_or(username)
        })
    }

    fn require_account(self, username: &str) -> Result<Self, PortalError> {
        if self.online && !self.account_matches(username) {
            return Err(PortalError::AccountMismatch);
        }
        Ok(self)
    }
}

/// Errors deliberately retain neither request URLs nor remote response text:
/// portal login URLs contain credentials and server error fields may echo them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortalError {
    InvalidConfig,
    HttpRequiresOptIn,
    TlsNotAvailable,
    InvalidCredentials,
    RequestFailed,
    HttpStatus,
    RedirectRejected,
    ResponseTooLarge,
    InvalidResponse,
    MissingClientIp,
    MissingAcIp,
    AccountMismatch,
    LoginRejected,
    OnlineNotConfirmed,
    LogoutNotConfirmed,
    Cancelled,
}

impl fmt::Display for PortalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "Invalid portal configuration or untrusted API origin",
            Self::HttpRequiresOptIn => "HTTP portal requires explicit portal.allow_http=true; HTTP exposes credentials on the network",
            Self::TlsNotAvailable => "HTTPS portal requires a binary built with the portal-tls feature",
            Self::InvalidCredentials => "Portal credentials must be nonempty single-line strings",
            Self::RequestFailed => "Portal request failed or timed out",
            Self::HttpStatus => "Portal returned an unsuccessful HTTP status",
            Self::RedirectRejected => "Portal redirect was rejected; configure the trusted portal origin explicitly",
            Self::ResponseTooLarge => "Portal response exceeded the size limit",
            Self::InvalidResponse => "Portal returned malformed or unsupported JSON/JSONP",
            Self::MissingClientIp => "Portal did not report a usable client IPv4 address; set portal.client_ip explicitly",
            Self::MissingAcIp => "Portal AC address was not discovered; set portal.ac_ip or use the trusted portal entry URL",
            Self::AccountMismatch => "Portal session belongs to a different account; disconnect it explicitly before signing in",
            Self::LoginRejected => "Portal rejected the login request",
            Self::OnlineNotConfirmed => "Portal accepted login but did not confirm this client's online session",
            Self::LogoutNotConfirmed => "Portal did not confirm this client's logout",
            Self::Cancelled => "Portal operation was cancelled",
        })
    }
}

impl std::error::Error for PortalError {}

pub struct PortalClient {
    config: PortalConfig,
    client: Client,
    base: Url,
    api: Url,
}

impl PortalClient {
    pub fn new(config: PortalConfig) -> Result<Self, PortalError> {
        if config.timeout.is_zero()
            || config.timeout > Duration::from_secs(60)
            || config.confirm_attempts == 0
            || config.confirm_attempts > 30
            || config.confirm_interval > Duration::from_secs(60)
            || config.client_ip.is_some_and(|ip| !usable_ip(ip))
            || config.ac_ip.is_some_and(|ip| !usable_ip(ip))
            || config
                .client_mac
                .as_deref()
                .is_some_and(|mac| normalize_mac(mac).is_none())
        {
            return Err(PortalError::InvalidConfig);
        }
        let base = parse_url(&config.base_url, config.allow_http)?;
        let api = if let Some(url) = &config.api_url {
            let api = parse_url(url, config.allow_http)?;
            // A different TCP port is normal (HTTPS802/HTTP801), a different
            // host or an HTTPS-to-HTTP downgrade is never inferred or followed.
            if api.host_str() != base.host_str()
                || (base.scheme() == "https" && api.scheme() != "https")
                || api.query().is_some()
            {
                return Err(PortalError::InvalidConfig);
            }
            api
        } else {
            let mut api = base.clone();
            api.set_query(None);
            api.set_path("/");
            api.set_port(Some(if base.scheme() == "https" { 802 } else { 801 }))
                .map_err(|_| PortalError::InvalidConfig)?;
            api
        };
        // The updater supplies HTTPS in every feature set with ring, including
        // static router builds. Reqwest's no-provider mode needs that provider
        // installed before building a client with its platform certificate store.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = Client::builder()
            .local_address(config.local_ip)
            .redirect(Policy::none())
            .timeout(config.timeout)
            .user_agent(concat!("drcom4scut/", env!("CARGO_PKG_VERSION")));
        // Internal loopback simulation does not use an outbound proxy. Actual
        // campus destinations retain the HTTP client's configured proxy route.
        if base
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
        {
            builder = builder.no_proxy();
        }
        let client = builder.build().map_err(|_| PortalError::InvalidConfig)?;
        Ok(Self {
            config,
            client,
            base,
            api,
        })
    }

    /// Query the actual portal session table. A successful HTTP request,
    /// result=1, or an unrelated user's session is not sufficient evidence.
    pub async fn check_status(&self) -> Result<PortalStatus, PortalError> {
        let identity = self.identity().await?;
        self.online_status(identity).await
    }

    /// Query network readiness without accepting a known different account.
    /// The portal may omit account metadata; no additional request is made.
    pub async fn check_status_for(&self, username: &str) -> Result<PortalStatus, PortalError> {
        self.check_status().await?.require_account(username)
    }

    /// Authenticate and wait for a session belonging to this client. The campus
    /// ePortal protocol uses a GET query even though the password is sensitive;
    /// this method never logs URLs, request objects, bodies or remote messages.
    pub async fn login(&self, username: &str, password: &str) -> Result<PortalStatus, PortalError> {
        if [username, password]
            .iter()
            .any(|value| !crate::settings::valid_credential(value))
        {
            return Err(PortalError::InvalidCredentials);
        }
        let identity = self.identity().await?;
        let previous = self
            .online_status(identity.clone())
            .await?
            .require_account(username)?;
        if previous.online {
            return Ok(previous);
        }
        let ac_ip = self.discover_ac().await?;
        let mut url = self.endpoint("eportal/portal/login", true)?;
        url.query_pairs_mut().extend_pairs([
            ("callback", CALLBACK.to_owned()),
            ("login_method", "1".into()),
            ("user_account", username.to_owned()),
            ("user_password", password.to_owned()),
            ("wlan_user_ip", identity.ip.to_string()),
            ("wlan_user_ipv6", String::new()),
            ("wlan_user_mac", "000000000000".into()),
            ("wlan_ac_ip", ac_ip.to_string()),
            ("wlan_ac_name", String::new()),
            ("jsVersion", "4.1.3".into()),
            ("terminal_type", "1".into()),
            ("lang", "zh-cn".into()),
            ("mac_type", "0".into()),
        ]);
        let reply = self.get_json(url).await?;
        if !success(&reply["result"]) {
            return Err(PortalError::LoginRejected);
        }
        for attempt in 0..self.config.confirm_attempts {
            if attempt != 0 {
                tokio::time::sleep(self.config.confirm_interval).await;
            }
            let status = self
                .online_status(identity.clone())
                .await?
                .require_account(username)?;
            if status.online {
                return Ok(status);
            }
        }
        Err(PortalError::OnlineNotConfirmed)
    }

    pub async fn logout(&self) -> Result<PortalStatus, PortalError> {
        let identity = self.identity().await?;
        let mut url = self.endpoint("eportal/portal/logout", true)?;
        url.query_pairs_mut().extend_pairs([
            ("callback", CALLBACK.to_owned()),
            ("user_account", "drcom".into()),
            ("user_password", "123".into()),
            ("wlan_user_ip", u32::from(identity.ip).to_string()),
            (
                "wlan_user_mac",
                identity
                    .mac
                    .clone()
                    .unwrap_or_else(|| "000000000000".into()),
            ),
            ("jsVersion", "4.1.3".into()),
        ]);
        let reply = self.get_json(url).await?;
        if !success(&reply["result"]) {
            return Err(PortalError::LogoutNotConfirmed);
        }
        let status = self.online_status(identity).await?;
        if status.online {
            return Err(PortalError::LogoutNotConfirmed);
        }
        Ok(status)
    }

    /// Reconnect an opt-in portal session with cancellable request/poll waits.
    /// The caller owns backoff/status policy; this convenience runner uses a
    /// fixed bounded interval and never starts detached tasks.
    pub async fn maintain(
        &self,
        username: &str,
        password: &str,
        interval: Duration,
        mut shutdown: watch::Receiver<bool>,
        once: bool,
    ) -> Result<(), PortalError> {
        if interval.is_zero() || interval > Duration::from_secs(3600) {
            return Err(PortalError::InvalidConfig);
        }
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            let operation = self.login(username, password);
            tokio::select! {
                result = operation => {
                    result?;
                    if once { return Ok(()); }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return Ok(()); }
                    continue;
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(interval) => (),
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return Ok(()); }
                }
            }
        }
    }

    async fn identity(&self) -> Result<Identity, PortalError> {
        let mut url = self.endpoint("drcom/chkstatus", false)?;
        url.query_pairs_mut().append_pair("callback", CALLBACK);
        let reply = self.get_json(url).await?;
        let ip = self
            .config
            .client_ip
            .or_else(|| {
                ["v46ip", "client_ip", "online_ip", "lip"]
                    .into_iter()
                    .find_map(|key| value_ipv4(&reply[key]))
            })
            .filter(|ip| usable_ip(*ip))
            .ok_or(PortalError::MissingClientIp)?;
        let mac = self
            .config
            .client_mac
            .as_deref()
            .and_then(normalize_mac)
            .or_else(|| reply["olmac"].as_str().and_then(normalize_mac))
            .filter(|mac| mac != "000000000000");
        Ok(Identity { ip, mac })
    }

    async fn online_status(&self, identity: Identity) -> Result<PortalStatus, PortalError> {
        log::debug!("Checking this device's portal session.");
        let mut url = self.endpoint("eportal/portal/online_list", true)?;
        url.query_pairs_mut().extend_pairs([
            ("callback", CALLBACK.to_owned()),
            ("user_account", String::new()),
            ("user_password", "123".into()),
            (
                "wlan_user_mac",
                identity
                    .mac
                    .clone()
                    .unwrap_or_else(|| "000000000000".into()),
            ),
            ("wlan_user_ip", u32::from(identity.ip).to_string()),
            ("curr_user_ip", u32::from(identity.ip).to_string()),
            ("jsVersion", "4.1.3".into()),
            ("lang", "zh".into()),
        ]);
        let reply = self.get_json(url).await?;
        let sessions = reply["list"]
            .as_array()
            .ok_or(PortalError::InvalidResponse)?;
        if !success(&reply["result"]) {
            return Err(PortalError::InvalidResponse);
        }
        let session = sessions.iter().find(|session| {
            if value_ipv4(&session["online_ip"]) != Some(identity.ip) {
                return false;
            }
            match (
                &identity.mac,
                session["online_mac"].as_str().and_then(normalize_mac),
            ) {
                (Some(expected), Some(actual)) => *expected == actual,
                (Some(_), None) => false,
                (None, _) => true,
            }
        });
        Ok(PortalStatus {
            online: session.is_some(),
            client_ip: identity.ip,
            user_account: session
                .and_then(|session| session["user_account"].as_str())
                .filter(|account| !account.is_empty())
                .map(str::to_owned),
        })
    }

    async fn discover_ac(&self) -> Result<Ipv4Addr, PortalError> {
        if let Some(ip) = self.config.ac_ip {
            return Ok(ip);
        }
        if let Some(ip) = query_ip(&self.base, "wlanacip") {
            return Ok(ip);
        }
        let mut url = self.base.clone();
        for _ in 0..4 {
            let response = self
                .client
                .get(url.clone())
                .send()
                .await
                .map_err(|_| PortalError::RequestFailed)?;
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(PortalError::RedirectRejected)?;
                let next = url
                    .join(location)
                    .map_err(|_| PortalError::RedirectRejected)?;
                if next.origin() != self.base.origin()
                    || !next.username().is_empty()
                    || next.password().is_some()
                {
                    return Err(PortalError::RedirectRejected);
                }
                if let Some(ip) = query_ip(&next, "wlanacip") {
                    return Ok(ip);
                }
                url = next;
            } else {
                let text = self.response_text(response).await?;
                return page_ipv4(&text, "wlanacip").ok_or(PortalError::MissingAcIp);
            }
        }
        Err(PortalError::RedirectRejected)
    }

    fn endpoint(&self, path: &str, api: bool) -> Result<Url, PortalError> {
        let mut url = if api {
            self.api.clone()
        } else {
            self.base.clone()
        };
        url.set_path(&format!("/{path}"));
        url.set_query(None);
        Ok(url)
    }

    async fn get_json(&self, url: Url) -> Result<Value, PortalError> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::REFERER, self.base.as_str())
            .send()
            .await
            .map_err(|_| PortalError::RequestFailed)?;
        if response.status().is_redirection() {
            return Err(PortalError::RedirectRejected);
        }
        parse_jsonp(&self.response_text(response).await?)
    }

    async fn response_text(&self, mut response: Response) -> Result<String, PortalError> {
        if !response.status().is_success() {
            return Err(PortalError::HttpStatus);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE as u64)
        {
            return Err(PortalError::ResponseTooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| PortalError::RequestFailed)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE {
                return Err(PortalError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        decode_response(&bytes)
    }
}

#[derive(Clone)]
struct Identity {
    ip: Ipv4Addr,
    mac: Option<String>,
}

fn parse_url(value: &str, allow_http: bool) -> Result<Url, PortalError> {
    let url = Url::parse(value).map_err(|_| PortalError::InvalidConfig)?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !safe_entry_query(&url)
    {
        return Err(PortalError::InvalidConfig);
    }
    match url.scheme() {
        "http" if !allow_http => return Err(PortalError::HttpRequiresOptIn),
        "http" => (),
        "https" => {
            #[cfg(not(feature = "portal-tls"))]
            return Err(PortalError::TlsNotAvailable);
        }
        _ => return Err(PortalError::InvalidConfig),
    }
    Ok(url)
}

// The configured entry URL is saved as ordinary, non-secret configuration.
// Accept only the public network metadata used by portal entry redirects, not
// pasted login URLs, account names, bearer tokens or arbitrary unknown fields.
// query_pairs decodes percent-encoded names before this allowlist is applied.
fn safe_entry_query(url: &Url) -> bool {
    url.query_pairs().all(|(key, _)| {
        let name: String = key
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .map(|ch| ch.to_ascii_lowercase())
            .collect();
        matches!(
            name.as_str(),
            "wlanacip"
                | "wlanuserip"
                | "wlanusermac"
                | "wlanacname"
                | "acip"
                | "userip"
                | "mac"
                | "clientip"
                | "clientmac"
                | "wlanvlanid"
                | "vlan"
                | "vlanid"
                | "nasip"
                | "nasid"
                | "gwport"
                | "gwaddress"
                | "gwid"
                | "ssid"
                | "wlanacssid"
                | "networkid"
        )
    })
}

fn usable_ip(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

fn value_ipv4(value: &Value) -> Option<Ipv4Addr> {
    value
        .as_str()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        .or_else(|| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .map(Ipv4Addr::from)
        })
}

fn query_ip(url: &Url, key: &str) -> Option<Ipv4Addr> {
    url.query_pairs()
        .filter(|(name, _)| name == key)
        .filter_map(|(_, value)| value.parse().ok())
        .find(|ip| usable_ip(*ip))
}

fn page_ipv4(page: &str, name: &str) -> Option<Ipv4Addr> {
    // Read a simple assignment from the trusted portal page; never execute JS.
    page.match_indices(name).find_map(|(offset, _)| {
        if page[..offset]
            .chars()
            .next_back()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return None;
        }
        let tail = page[offset + name.len()..]
            .trim_start()
            .strip_prefix('=')?
            .trim_start();
        let quote = tail.chars().next().filter(|ch| *ch == '\'' || *ch == '"')?;
        let value = tail[1..].split(quote).next()?;
        value.parse().ok().filter(|ip| usable_ip(*ip))
    })
}

fn normalize_mac(value: &str) -> Option<String> {
    let result: String = value
        .chars()
        .filter(|ch| !matches!(ch, ':' | '-'))
        .collect();
    (result.len() == 12 && result.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| result.to_ascii_uppercase())
}

fn success(value: &Value) -> bool {
    value == &Value::from(1) || value == &Value::from("1") || value == &Value::from("ok")
}

fn decode_response(bytes: &[u8]) -> Result<String, PortalError> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Ok(text.to_owned());
    }
    // Older campus portals return GB18030/GBK strings inside otherwise ordinary
    // JSONP. Decode text without interpreting or echoing server-side messages.
    let (text, malformed) = encoding_rs::GB18030.decode_without_bom_handling(bytes);
    if malformed {
        return Err(PortalError::InvalidResponse);
    }
    Ok(text.into_owned())
}

fn parse_jsonp(text: &str) -> Result<Value, PortalError> {
    let text = text.trim().trim_start_matches('\u{feff}').trim();
    let json = if text.starts_with('{') {
        text
    } else {
        let tail = text
            .strip_prefix(CALLBACK)
            .and_then(|tail| tail.strip_prefix('('))
            .ok_or(PortalError::InvalidResponse)?;
        let tail = tail.strip_suffix(';').unwrap_or(tail);
        tail.strip_suffix(')').ok_or(PortalError::InvalidResponse)?
    };
    let value: Value = serde_json::from_str(json).map_err(|_| PortalError::InvalidResponse)?;
    if !value.is_object() {
        return Err(PortalError::InvalidResponse);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    struct Reply {
        status: u16,
        headers: String,
        body: String,
        delay: Duration,
        release: Option<Arc<tokio::sync::Notify>>,
    }
    impl Reply {
        fn json(body: &str) -> Self {
            Self {
                status: 200,
                headers: String::new(),
                body: format!("{CALLBACK}({body});"),
                delay: Duration::ZERO,
                release: None,
            }
        }
        fn redirect(url: &str) -> Self {
            Self {
                status: 302,
                headers: format!("Location: {url}\r\n"),
                body: String::new(),
                delay: Duration::ZERO,
                release: None,
            }
        }
    }
    struct Mock {
        config: PortalConfig,
        paths: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn mock(handler: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let paths = Arc::new(Mutex::new(Vec::new()));
        let saved = paths.clone();
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = handler.clone();
                let saved = saved.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    loop {
                        if stream.readable().await.is_err() {
                            return;
                        }
                        let mut buffer = [0; 1024];
                        match stream.try_read(&mut buffer) {
                            Ok(0) => return,
                            Ok(count) => request.extend_from_slice(&buffer[..count]),
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                continue;
                            }
                            Err(_) => return,
                        }
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                        if request.len() > 16384 {
                            return;
                        }
                    }
                    let text = String::from_utf8(request).unwrap();
                    let path = text
                        .lines()
                        .next()
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap();
                    saved.lock().unwrap().push(path.to_owned());
                    let reply = handler(path);
                    if let Some(release) = &reply.release {
                        release.notified().await;
                    }
                    tokio::time::sleep(reply.delay).await;
                    let response = format!(
                        "HTTP/1.1 {} Test\r\nConnection: close\r\nContent-Length: {}\r\n{}\r\n{}",
                        reply.status,
                        reply.body.len(),
                        reply.headers,
                        reply.body
                    );
                    send(&stream, response.as_bytes()).await;
                });
            }
        });
        let base = format!("http://{address}");
        Mock {
            config: PortalConfig {
                base_url: base.clone(),
                api_url: Some(base),
                allow_http: true,
                ac_ip: Some("192.0.2.254".parse().unwrap()),
                // Identity tests use the production request deadline. A shorter
                // timeout measures emulator scheduling pressure, not protocol correctness.
                confirm_interval: Duration::ZERO,
                ..PortalConfig::default()
            },
            paths,
            task,
        }
    }
    async fn send(stream: &TcpStream, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if stream.writable().await.is_err() {
                return;
            }
            match stream.try_write(bytes) {
                Ok(0) => return,
                Ok(size) => bytes = &bytes[size..],
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => return,
            }
        }
    }
    fn identity() -> Reply {
        Reply::json(r#"{"result":1,"v46ip":"192.0.2.10","olmac":"020000000001"}"#)
    }
    fn offline() -> Reply {
        Reply::json(r#"{"result":1,"list":[]}"#)
    }
    fn online() -> Reply {
        Reply::json(
            r#"{"result":1,"list":[{"online_ip":"192.0.2.11","online_mac":"020000000002","is_owner_ip":1},{"online_ip":"192.0.2.10","online_mac":"020000000001"}]}"#,
        )
    }
    fn online_account(account: Option<&str>) -> Reply {
        let mut session = serde_json::json!({
            "online_ip": "192.0.2.10",
            "online_mac": "020000000001",
        });
        if let Some(account) = account {
            session["user_account"] = account.into();
        }
        Reply::json(&serde_json::json!({"result": 1, "list": [session]}).to_string())
    }

    #[test]
    fn plaintext_http_requires_explicit_opt_in() {
        let config = PortalConfig {
            base_url: "http://s.scut.edu.cn".into(),
            ..PortalConfig::default()
        };
        assert!(matches!(
            PortalClient::new(config),
            Err(PortalError::HttpRequiresOptIn)
        ));
    }

    #[test]
    fn configuration_rejects_credential_urls_wrong_hosts_and_invalid_limits() {
        for config in [
            PortalConfig {
                base_url: "http://user:password@portal.example".into(),
                allow_http: true,
                ..PortalConfig::default()
            },
            PortalConfig {
                base_url: "http://portal.example".into(),
                api_url: Some("http://attacker.example".into()),
                allow_http: true,
                ..PortalConfig::default()
            },
            PortalConfig {
                timeout: Duration::ZERO,
                ..PortalConfig::default()
            },
            PortalConfig {
                confirm_attempts: 0,
                ..PortalConfig::default()
            },
            PortalConfig {
                client_mac: Some("not-a-mac".into()),
                ..PortalConfig::default()
            },
            PortalConfig {
                client_ip: Some(Ipv4Addr::UNSPECIFIED),
                ..PortalConfig::default()
            },
        ] {
            assert!(PortalClient::new(config).is_err());
        }
    }

    #[cfg(feature = "portal-tls")]
    #[test]
    fn https_to_http_api_downgrade_is_rejected() {
        let config = PortalConfig {
            api_url: Some("http://s.scut.edu.cn:801".into()),
            allow_http: true,
            ..PortalConfig::default()
        };
        assert!(matches!(
            PortalClient::new(config),
            Err(PortalError::InvalidConfig)
        ));
    }

    #[cfg(not(feature = "portal-tls"))]
    #[test]
    fn minimal_binary_never_silently_downgrades_https() {
        assert!(matches!(
            PortalClient::new(PortalConfig::default()),
            Err(PortalError::TlsNotAvailable)
        ));
    }

    #[test]
    fn configuration_urls_reject_plain_encoded_and_case_variant_credentials() {
        for key in [
            "user_password",
            "User_Password",
            "%75ser_password",
            "%55ser%5FPassword",
            "password",
            "passwd",
            "pwd",
            "user_account",
            "username",
            "token",
            "access_token",
            "Authorization",
            "api_key",
            "secret",
            "unknown",
        ] {
            let value = format!("http://portal.example/a79.htm?{key}=test-secret-from-url");
            let config = PortalConfig {
                base_url: value.clone(),
                allow_http: true,
                ..PortalConfig::default()
            };
            let error = PortalClient::new(config)
                .err()
                .expect("entry URL must reject private or unknown query fields");
            assert_eq!(error, PortalError::InvalidConfig);
            assert!(!format!("{error:?}: {error}").contains("test-secret-from-url"));
            let config = PortalConfig {
                base_url: "http://portal.example".into(),
                api_url: Some(value),
                allow_http: true,
                ..PortalConfig::default()
            };
            assert!(matches!(
                PortalClient::new(config),
                Err(PortalError::InvalidConfig)
            ));
        }
        let config = PortalConfig {
            base_url: "http://portal.example/a79.htm?wlanacip=192.0.2.254&wlanuserip=192.0.2.10&wlanusermac=020000000001".into(),
            allow_http: true, ..PortalConfig::default()
        };
        assert!(PortalClient::new(config).is_ok());
    }

    #[test]
    fn jsonp_parser_never_accepts_executable_suffix_or_foreign_callback() {
        for input in [
            r#"evil({"result":1});"#,
            r#"drcom4scut({"result":1});alert(1)"#,
            "drcom4scut([]);",
            "drcom4scut({)",
            "drcom4scut({\"result\":1}",
        ] {
            assert_eq!(parse_jsonp(input), Err(PortalError::InvalidResponse));
        }
        assert_eq!(
            parse_jsonp("drcom4scut({\"result\":1});").unwrap()["result"],
            1
        );
        assert_eq!(parse_jsonp("{\"result\":1}").unwrap()["result"], 1);
    }

    #[test]
    fn legacy_gb18030_response_text_is_decoded_without_executing_jsonp() {
        let text = "drcom4scut({\"result\":1,\"msg\":\"认证成功\",\"list\":[]});";
        let (bytes, _, malformed) = encoding_rs::GB18030.encode(text);
        assert!(!malformed);
        assert_eq!(
            parse_jsonp(&decode_response(&bytes).unwrap()).unwrap()["result"],
            1
        );
        assert_eq!(decode_response(&[0x81]), Err(PortalError::InvalidResponse));
    }

    #[tokio::test]
    async fn loopback_login_uses_encoded_query_and_confirms_own_session() {
        let logged_in = Arc::new(AtomicBool::new(false));
        let flag = logged_in.clone();
        let server = mock(move |path| {
            if path.starts_with("/drcom/chkstatus") {
                identity()
            } else if path.starts_with("/eportal/portal/login?") {
                flag.store(true, Ordering::SeqCst);
                Reply::json(r#"{"result":1}"#)
            } else if flag.load(Ordering::SeqCst) {
                online()
            } else {
                offline()
            }
        })
        .await;
        let client = PortalClient::new(server.config.clone()).unwrap();
        let status = client.login("student@wifi", "test +&=密码").await.unwrap();
        assert!(status.online);
        let paths = server.paths.lock().unwrap();
        let request = paths
            .iter()
            .find(|path| path.starts_with("/eportal/portal/login?"))
            .unwrap();
        let url = Url::parse(&format!("http://localhost{request}")).unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(query["user_account"], "student@wifi");
        assert_eq!(query["user_password"], "test +&=密码");
        assert_eq!(query["wlan_ac_ip"], "192.0.2.254");
        assert_eq!(query["wlan_user_ip"], "192.0.2.10");
        assert_eq!(query["wlan_user_mac"], "000000000000");
        assert!(
            paths
                .iter()
                .any(|path| path.contains("wlan_user_ip=3221225994"))
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn transport_source_binding_is_independent_of_portal_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base = format!("http://{address}");
        let config = PortalConfig {
            base_url: base.clone(),
            api_url: Some(base),
            allow_http: true,
            local_ip: Some("127.0.0.2".parse().unwrap()),
            client_ip: Some("192.0.2.10".parse().unwrap()),
            ..PortalConfig::default()
        };
        let server = tokio::spawn(async move {
            for (path, json) in [
                ("/drcom/chkstatus?", r#"{"result":1,"v46ip":"192.0.2.10"}"#),
                (
                    "/eportal/portal/online_list?",
                    r#"{"result":1,"list":[{"online_ip":"192.0.2.10"}]}"#,
                ),
            ] {
                let (stream, peer) = listener.accept().await.unwrap();
                assert_eq!(peer.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
                let mut request = Vec::new();
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    stream.readable().await.unwrap();
                    let mut buffer = [0; 2048];
                    match stream.try_read(&mut buffer) {
                        Ok(0) => panic!("unexpected end of request"),
                        Ok(size) => request.extend_from_slice(&buffer[..size]),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(error) => panic!("request read failed: {error}"),
                    }
                }
                let text = String::from_utf8(request).unwrap();
                assert!(text.starts_with(&format!("GET {path}")));
                if path.contains("online_list") {
                    assert!(text.contains("wlan_user_ip=3221225994"));
                }
                let body = format!("drcom4scut({json});");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                send(&stream, response.as_bytes()).await;
            }
        });
        let status = PortalClient::new(config)
            .unwrap()
            .check_status()
            .await
            .unwrap();
        assert!(status.online);
        assert_eq!(status.client_ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_foreign_owner_marker_or_mac_does_not_make_this_client_online() {
        let server = mock(|path| {
            if path.starts_with("/drcom/") { identity() }
            else { Reply::json(r#"{"result":1,"list":[{"online_ip":"192.0.2.11","is_owner_ip":1},{"online_ip":"192.0.2.10","online_mac":"020000000099"}]}"#) }
        }).await;
        assert!(
            !PortalClient::new(server.config.clone())
                .unwrap()
                .check_status()
                .await
                .unwrap()
                .online
        );
    }

    #[tokio::test]
    async fn known_client_mac_requires_a_valid_matching_session_mac() {
        for (field, expected) in [
            (String::new(), false),
            (r#","online_mac":"invalid""#.to_owned(), false),
            (r#","online_mac":"020000000099""#.to_owned(), false),
            (r#","online_mac":"02:00:00:00:00:01""#.to_owned(), true),
        ] {
            let server = mock(move |path| {
                if path.starts_with("/drcom/") {
                    identity()
                } else {
                    Reply::json(&format!(
                        r#"{{"result":1,"list":[{{"online_ip":"192.0.2.10"{field}}}]}}"#
                    ))
                }
            })
            .await;
            let status = PortalClient::new(server.config.clone())
                .unwrap()
                .check_status()
                .await
                .unwrap();
            assert_eq!(status.online, expected);
        }
    }

    #[tokio::test]
    async fn known_different_account_is_neither_reused_nor_disconnected() {
        for account in [
            "other-student@wifi",
            "Student@wifi",
            "student@other.example",
        ] {
            let server = mock(move |path| {
                if path.starts_with("/drcom/") {
                    identity()
                } else {
                    online_account(Some(account))
                }
            })
            .await;
            let client = PortalClient::new(server.config.clone()).unwrap();
            let status = client.check_status().await.unwrap();
            assert!(status.online);
            assert_eq!(status.user_account.as_deref(), Some(account));
            assert!(!status.account_matches("student"));
            assert_eq!(
                client.check_status_for("student").await,
                Err(PortalError::AccountMismatch)
            );
            let error = client.login("student", "test-password").await.unwrap_err();
            assert_eq!(error, PortalError::AccountMismatch);
            assert!(!format!("{error:?}: {error}").contains(account));
            let paths = server.paths.lock().unwrap();
            assert_eq!(paths.len(), 6);
            assert!(paths.iter().all(|path| {
                path.starts_with("/drcom/chkstatus?")
                    || path.starts_with("/eportal/portal/online_list?")
            }));
        }
    }

    #[tokio::test]
    async fn matching_wifi_account_or_missing_metadata_reuses_ready_session() {
        for (username, account) in [
            ("student", Some("student")),
            ("student", Some("student@wifi")),
            ("student@wifi", Some("student")),
            ("student@wifi", Some("student@wifi")),
            ("student", None),
        ] {
            let server = mock(move |path| {
                if path.starts_with("/drcom/") {
                    identity()
                } else {
                    online_account(account)
                }
            })
            .await;
            let client = PortalClient::new(server.config.clone()).unwrap();
            assert!(client.check_status_for(username).await.unwrap().online);
            let status = client.login(username, "test-password").await.unwrap();
            assert!(status.online);
            assert_eq!(status.user_account.as_deref(), account);
            let paths = server.paths.lock().unwrap();
            assert_eq!(paths.len(), 4);
            assert!(paths.iter().all(|path| {
                path.starts_with("/drcom/chkstatus?")
                    || path.starts_with("/eportal/portal/online_list?")
            }));
        }
    }

    #[tokio::test]
    async fn accepted_login_cannot_confirm_a_known_different_account() {
        let logged_in = Arc::new(AtomicBool::new(false));
        let flag = logged_in.clone();
        let server = mock(move |path| {
            if path.starts_with("/drcom/") {
                identity()
            } else if path.starts_with("/eportal/portal/login?") {
                flag.store(true, Ordering::SeqCst);
                Reply::json(r#"{"result":1}"#)
            } else if flag.load(Ordering::SeqCst) {
                online_account(Some("other-student@wifi"))
            } else {
                offline()
            }
        })
        .await;
        let client = PortalClient::new(server.config.clone()).unwrap();
        assert_eq!(
            client.login("student", "test-password").await,
            Err(PortalError::AccountMismatch)
        );
        let paths = server.paths.lock().unwrap();
        assert_eq!(paths.len(), 4);
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.starts_with("/eportal/portal/login?"))
                .count(),
            1
        );
        assert!(
            !paths
                .iter()
                .any(|path| path.starts_with("/eportal/portal/logout?"))
        );
    }

    #[tokio::test]
    async fn accepted_login_is_not_success_until_session_confirmation() {
        let server = mock(|path| {
            if path.starts_with("/drcom/") {
                identity()
            } else if path.starts_with("/eportal/portal/login?") {
                Reply::json(r#"{"result":1}"#)
            } else {
                offline()
            }
        })
        .await;
        let client = PortalClient::new(server.config.clone()).unwrap();
        assert_eq!(
            client.login("test-student", "test-password").await,
            Err(PortalError::OnlineNotConfirmed)
        );
    }

    #[tokio::test]
    async fn login_rejection_never_echoes_remote_messages_or_password() {
        let server = mock(|path| {
            if path.starts_with("/drcom/") {
                identity()
            } else if path.starts_with("/eportal/portal/login?") {
                Reply::json(r#"{"result":0,"msg":"reflected-test-password"}"#)
            } else {
                offline()
            }
        })
        .await;
        let client = PortalClient::new(server.config.clone()).unwrap();
        let error = client
            .login("test-student", "reflected-test-password")
            .await
            .unwrap_err();
        assert_eq!(error, PortalError::LoginRejected);
        assert!(!format!("{error:?}: {error}").contains("reflected-test-password"));
    }

    #[tokio::test]
    async fn discovery_follows_only_trusted_same_origin_ac_redirect() {
        let mut server = mock(|path| {
            if path.starts_with("/drcom/") {
                identity()
            } else if path.starts_with("/eportal/portal/online_list?") {
                offline()
            } else {
                Reply::redirect("/a79.htm?wlanacip=192.0.2.254")
            }
        })
        .await;
        server.config.ac_ip = None;
        let client = PortalClient::new(server.config.clone()).unwrap();
        assert_eq!(
            client.discover_ac().await.unwrap(),
            "192.0.2.254".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[tokio::test]
    async fn discovery_rejects_cross_origin_without_contacting_or_authenticating_it() {
        let target = mock(|_| panic!("untrusted redirect destination must not be contacted")).await;
        let redirect = target.config.base_url.clone();
        let mut server =
            mock(move |_| Reply::redirect(&format!("{redirect}/?wlanacip=192.0.2.254"))).await;
        server.config.ac_ip = None;
        let client = PortalClient::new(server.config.clone()).unwrap();
        assert_eq!(
            client.discover_ac().await,
            Err(PortalError::RedirectRejected)
        );
        assert!(target.paths.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn credential_request_redirect_is_not_followed() {
        let target = mock(|_| panic!("credential redirect must never be followed")).await;
        let redirect = target.config.base_url.clone();
        let server = mock(move |path| {
            if path.starts_with("/drcom/") {
                identity()
            } else if path.starts_with("/eportal/portal/login?") {
                Reply::redirect(&redirect)
            } else {
                offline()
            }
        })
        .await;
        let client = PortalClient::new(server.config.clone()).unwrap();
        assert_eq!(
            client.login("test-student", "test-password").await,
            Err(PortalError::RedirectRejected)
        );
        assert!(target.paths.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_and_oversized_responses_are_bounded() {
        let server =
            mock(|_| Reply::json(&format!("{{\"padding\":\"{}\"}}", "x".repeat(MAX_RESPONSE))))
                .await;
        assert_eq!(
            PortalClient::new(server.config.clone())
                .unwrap()
                .check_status()
                .await,
            Err(PortalError::ResponseTooLarge)
        );
        let server = mock(|_| Reply::json("not-json")).await;
        assert_eq!(
            PortalClient::new(server.config.clone())
                .unwrap()
                .check_status()
                .await,
            Err(PortalError::InvalidResponse)
        );
    }

    #[tokio::test]
    async fn logout_requires_offline_confirmation() {
        let online_flag = Arc::new(AtomicBool::new(true));
        let flag = online_flag.clone();
        let server = mock(move |path| {
            if path.starts_with("/drcom/") {
                identity()
            } else if path.starts_with("/eportal/portal/logout?") {
                flag.store(false, Ordering::SeqCst);
                Reply::json(r#"{"result":1}"#)
            } else if flag.load(Ordering::SeqCst) {
                online()
            } else {
                offline()
            }
        })
        .await;
        let client = PortalClient::new(server.config.clone()).unwrap();
        assert!(client.check_status().await.unwrap().online);
        assert!(!client.logout().await.unwrap().online);
    }

    #[tokio::test]
    async fn status_timeouts_and_cancellation_do_not_leave_background_retries() {
        // Keep the timeout probe separate: a request that timed out in the
        // client may still be waiting for the mock server to read its headers.
        let timeout_release = Arc::new(tokio::sync::Notify::new());
        let mut timeout_server = mock(move |_| Reply {
            release: Some(timeout_release.clone()),
            ..identity()
        })
        .await;
        timeout_server.config.timeout = Duration::from_millis(20);
        let client = PortalClient::new(timeout_server.config.clone()).unwrap();
        assert_eq!(client.check_status().await, Err(PortalError::RequestFailed));
        drop(timeout_server);

        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let (seen, received, response_gate) = (count.clone(), observed.clone(), release.clone());
        let mut server = mock(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            received.notify_one();
            Reply {
                release: Some(response_gate.clone()),
                ..identity()
            }
        })
        .await;
        server.config.timeout = Duration::from_secs(30);
        let client = PortalClient::new(server.config.clone()).unwrap();
        let (shutdown, receiver) = watch::channel(false);
        let operation = client.maintain(
            "test-student",
            "test-password",
            Duration::from_secs(1),
            receiver,
            false,
        );
        tokio::pin!(operation);
        tokio::select! {
            // The server must have consumed the request before cancellation.
            // A fixed 10ms delay does not establish this under CPU emulation.
            biased;
            _ = observed.notified() => (),
            result = &mut operation => panic!("must still await server: {result:?}"),
            _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("mock did not observe the request"),
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        shutdown.send_replace(true);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), operation)
                .await
                .expect("cancellation must terminate promptly"),
            Ok(())
        );
        // Finish the already-observed request after cancellation. A detached
        // protocol worker would now continue with online_list or another retry.
        release.notify_one();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
