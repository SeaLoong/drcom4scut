//! Client lifecycle shared by interactive console and Windows service hosts.
use crate::{
    device, eap,
    settings::Settings,
    socket::{self, Socket},
    udp,
    util::{ChannelData, State, sleep_at},
};
use log::{error, info};
use serde::Serialize;
use std::{net::IpAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    time::{Instant, sleep},
};

/// Retry delay grows only on consecutive failures and never exceeds its cap.
#[derive(Debug)]
pub struct Backoff {
    initial: u64,
    maximum: u64,
    next: u64,
}
impl Backoff {
    pub fn new(initial: u64, maximum: u64) -> Self {
        Self {
            initial,
            maximum: maximum.max(initial),
            next: initial,
        }
    }
    pub fn reset(&mut self) {
        self.next = self.initial;
    }
    pub fn delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(self.maximum);
        Duration::from_secs(delay)
    }
}

#[derive(Serialize)]
struct Status<'a> {
    schema: u8,
    pid: u32,
    version: &'static str,
    phase: &'a str,
    interface: &'a str,
    local_ip: Option<IpAddr>,
    eap_authenticated: bool,
    online: bool,
    updated_at: String,
}

/// Never include account data, authentication hashes or raw network packets.
fn write_status(
    settings: &Settings,
    phase: &str,
    interface: &str,
    ip: Option<IpAddr>,
    eap: bool,
    online: bool,
) -> Result<(), String> {
    let Some(path) = &settings.status_file else {
        return Ok(());
    };
    let status = Status {
        schema: 1,
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION"),
        phase,
        interface,
        local_ip: ip,
        eap_authenticated: eap,
        online,
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    let bytes =
        serde_json::to_vec_pretty(&status).map_err(|_| "Cannot serialize connection status")?;
    atomic_private_file(path, &bytes)
}

fn atomic_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let file_name = path
        .file_name()
        .ok_or("Invalid status file path")?
        .to_string_lossy();
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| "Cannot create private status file")?;
    let result = (|| {
        file.write_all(data)
            .map_err(|_| "Cannot write status file")?;
        file.sync_all()
            .map_err(|_| "Cannot synchronize status file")?;
        std::fs::rename(&temporary, path).map_err(|_| "Cannot publish status file")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result.map_err(str::to_owned)
}

async fn shutdown(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn open(settings: &Settings, preferred: Option<&str>) -> Result<device::Device, String> {
    let name = settings
        .interface
        .clone()
        .or_else(|| preferred.map(str::to_owned));
    let mac = settings.mac;
    let ip = settings.ip;
    tokio::task::spawn_blocking(move || device::get_device_on(name.as_deref(), mac, ip))
        .await
        .map_err(|_| "Ethernet initialization task failed".to_owned())?
        .map_err(|error| {
            format!(
                "Cannot open Ethernet capture (check --doctor, Npcap/permissions and IPv4): {error}"
            )
        })
}

/// All protocol futures belong to this scope; shutdown cancels timers/socket
/// waits before making one bounded best-effort EAPOL-Logoff transmission.
pub async fn run(settings: Settings, mut stop: watch::Receiver<bool>) -> Result<(), String> {
    crate::logger::init(&settings)?;
    if settings.mode == crate::settings::Mode::Portal {
        #[cfg(feature = "portal")]
        {
            return run_portal(&settings, stop).await;
        }
        #[cfg(not(feature = "portal"))]
        {
            return Err("This build does not include portal support".into());
        }
    }
    let mut preferred = settings.interface.clone();
    let mut backoff = Backoff::new(settings.reconnect, settings.reconnect_max);
    loop {
        write_status(
            &settings,
            "waiting-interface",
            preferred.as_deref().unwrap_or(""),
            None,
            false,
            false,
        )?;
        let device = tokio::select! {
            _ = shutdown(&mut stop) => return Ok(()),
            result = open(&settings, preferred.as_deref()) => match result {
                Ok(device) => Arc::new(device),
                Err(error) if settings.once => return Err(error),
                Err(error) => { error!("{error}"); tokio::select! { _ = shutdown(&mut stop) => return Ok(()), _ = sleep(backoff.delay()) => () } continue; }
            }
        };
        let name = device.interface.name.clone();
        preferred = Some(name.clone());
        let mac = device.mac;
        let ip = device.ip_net.ip();
        info!("Start asynchronous client on {name} ({mac}, {ip})");
        let (auth_tx, mut auth_rx) = watch::channel(ChannelData::stopped());
        let (ready_tx, mut ready_rx) = watch::channel(false);
        let mut process = eap::Process::new(&settings, device.clone(), auth_tx);
        let eap_session = process.start();
        let udp_session = udp_supervisor(&settings, auth_rx.clone(), ready_tx, mac, ip);
        let mut established = false;
        let mut reported_online = false;
        let monitor = async {
            let mut link_check = tokio::time::interval(Duration::from_secs(5));
            link_check.tick().await;
            loop {
                let authorized = auth_rx.borrow().state == State::Success;
                let online = if settings.no_udp {
                    authorized
                } else {
                    *ready_rx.borrow() && authorized
                };
                write_status(
                    &settings,
                    if online {
                        "online"
                    } else if authorized {
                        "udp-authentication"
                    } else {
                        "eap-authentication"
                    },
                    &name,
                    Some(ip),
                    authorized,
                    online,
                )?;
                if online {
                    established = true;
                }
                if online != reported_online {
                    let command = if online {
                        &settings.hooks.online
                    } else {
                        &settings.hooks.offline
                    };
                    let label = if online { "online" } else { "offline" };
                    tokio::select! {
                        _ = shutdown(&mut stop) => return Ok::<SessionEnd, String>(SessionEnd::Shutdown),
                        result = crate::hooks::run(command, label, &name, Some(ip), settings.hooks.timeout) => { if let Err(error) = result { error!("{error}"); } }
                    }
                    reported_online = online;
                }
                if online && settings.once {
                    return Ok::<SessionEnd, String>(SessionEnd::Completed);
                }
                tokio::select! {
                    _ = shutdown(&mut stop) => return Ok::<SessionEnd, String>(SessionEnd::Shutdown),
                    changed = auth_rx.changed() => { if changed.is_err() { return Ok::<SessionEnd, String>(SessionEnd::Restart); } }
                    changed = ready_rx.changed(), if !settings.no_udp => { if changed.is_err() { return Ok::<SessionEnd, String>(SessionEnd::Restart); } }
                    _ = link_check.tick() => {
                        // Respect a deliberately fixed local IP, otherwise reopen
                        // both transports when DHCP removes or changes the address.
                        if settings.ip.is_none() && device::current_ipv4(&name).map(IpAddr::V4) != Some(ip) {
                            info!("Ethernet IPv4 changed; rediscovering link and restarting authentication.");
                            return Ok::<SessionEnd, String>(SessionEnd::Restart);
                        }
                    }
                }
            }
        };
        let outcome = {
            tokio::pin!(eap_session, udp_session, monitor);
            tokio::select! {
                state = &mut eap_session => Ok(SessionEnd::Eap(state)),
                _ = &mut udp_session, if !settings.no_udp => Ok(SessionEnd::Restart),
                outcome = &mut monitor => outcome,
            }
        };
        // End the EAP borrow before issuing Logoff. The retained capture read is
        // finite on Unix and nonblocking on Windows; no old protocol task lives on.
        let _ = tokio::time::timeout(Duration::from_secs(1), process.logoff()).await;
        write_status(&settings, "offline", &name, Some(ip), false, false)?;
        if reported_online
            && let Err(error) = crate::hooks::run(
                &settings.hooks.offline,
                "offline",
                &name,
                Some(ip),
                settings.hooks.timeout,
            )
            .await
        {
            error!("{error}");
        }
        match outcome? {
            SessionEnd::Completed | SessionEnd::Shutdown => return Ok(()),
            _ if settings.once => return Err("Authentication did not complete".into()),
            SessionEnd::Eap(State::Sleep) => {
                tokio::select! { _ = shutdown(&mut stop) => return Ok(()), _ = sleep_at(settings.time) => () }
                backoff.reset();
            }
            _ => {
                // An established session that later drops is a new retry series.
                if established {
                    backoff.reset();
                }
                tokio::select! { _ = shutdown(&mut stop) => return Ok(()), _ = sleep(backoff.delay()) => () }
            }
        }
    }
}

enum SessionEnd {
    Completed,
    Shutdown,
    Restart,
    Eap(State),
}

async fn udp_supervisor(
    settings: &Settings,
    mut auth: watch::Receiver<ChannelData>,
    ready: watch::Sender<bool>,
    mac: pnet::datalink::MacAddr,
    source: IpAddr,
) {
    let mut backoff = Backoff::new(settings.reconnect, settings.reconnect_max);
    loop {
        while auth.borrow().state != State::Success {
            if auth.changed().await.is_err() {
                return;
            }
        }
        let started = Instant::now();
        let state = match socket::resolve_dns_from(settings, source).await {
            Some((server, dns)) => match socket::socket_bind_from(
                server,
                source,
                settings.local_port,
                settings.server_port,
            )
            .await
            {
                Some(socket) => {
                    let mut process = udp::Process::new(
                        settings,
                        Arc::new(Socket::new(socket)),
                        auth.clone(),
                        mac,
                        source,
                        dns,
                    )
                    .with_ready(ready.clone());
                    process.start().await
                }
                None => {
                    error!("Cannot bind UDP socket to selected interface address {source}");
                    State::Quit
                }
            },
            None => {
                error!("Cannot resolve {} using selected interface", settings.host);
                State::Stop
            }
        };
        ready.send_replace(false);
        error!("UDP session ended: {state:?}");
        if settings.once {
            return;
        }
        if started.elapsed() >= Duration::from_secs(settings.heartbeat.udp_timeout as u64) {
            backoff.reset();
        }
        if state == State::Sleep {
            sleep_at(settings.time).await;
        } else {
            sleep(backoff.delay()).await;
        }
    }
}

#[cfg(feature = "portal")]
async fn run_portal(settings: &Settings, mut stop: watch::Receiver<bool>) -> Result<(), String> {
    let client = crate::portal::PortalClient::new(settings.portal_config())
        .map_err(|error| error.to_string())?;
    let mut current_ip = settings.portal_client_ip.map(IpAddr::V4);
    if settings.logoff {
        let status = client.logout().await.map_err(|error| error.to_string())?;
        write_status(
            settings,
            "offline",
            "portal",
            Some(status.client_ip.into()),
            false,
            false,
        )?;
        return Ok(());
    }
    let mut online_hook_active = false;
    let outcome = {
        let session = async {
            let mut backoff = Backoff::new(settings.reconnect, settings.reconnect_max);
            loop {
                write_status(
                    settings,
                    "portal-authentication",
                    "portal",
                    current_ip,
                    false,
                    false,
                )?;
                match client.login(&settings.username, &settings.password).await {
                    Ok(status) if status.online => {
                        current_ip = Some(status.client_ip.into());
                        info!("Portal authorization confirmed online.");
                        write_status(settings, "online", "portal", current_ip, true, true)?;
                        backoff.reset();
                        online_hook_active = true;
                        if let Err(error) = crate::hooks::run(
                            &settings.hooks.online,
                            "online",
                            "portal",
                            current_ip,
                            settings.hooks.timeout,
                        )
                        .await
                        {
                            error!("{error}");
                        }
                        if settings.once {
                            return Ok::<bool, String>(true);
                        }
                        loop {
                            sleep(Duration::from_secs(settings.heartbeat.udp_timeout as u64)).await;
                            match client.check_status().await {
                                Ok(current) if current.online => {
                                    current_ip = Some(current.client_ip.into());
                                    write_status(
                                        settings, "online", "portal", current_ip, true, true,
                                    )?;
                                }
                                _ => break,
                            }
                        }
                        write_status(settings, "offline", "portal", current_ip, false, false)?;
                        if let Err(error) = crate::hooks::run(
                            &settings.hooks.offline,
                            "offline",
                            "portal",
                            current_ip,
                            settings.hooks.timeout,
                        )
                        .await
                        {
                            error!("{error}");
                        }
                        online_hook_active = false;
                    }
                    Ok(_) => {
                        if settings.once {
                            return Err("Portal authentication did not complete".into());
                        }
                        error!("Portal authentication could not be confirmed online.");
                    }
                    Err(error) => {
                        // PortalError is a fixed category and never retains a
                        // request URL, response text or credentials.
                        if settings.once {
                            return Err(error.to_string());
                        }
                        error!("Portal authentication failed: {error}");
                    }
                }
                write_status(settings, "offline", "portal", current_ip, false, false)?;
                sleep(backoff.delay()).await;
            }
        };
        tokio::pin!(session);
        tokio::select! {
            result = &mut session => result,
            _ = shutdown(&mut stop) => Ok(false),
        }
    };
    // This single cleanup path handles cancellation during login, an online
    // check, a retry delay or a lifecycle hook equally. The operation future has
    // already been dropped, so its pending HTTP request/hook is canceled first.
    if !matches!(outcome, Ok(true)) {
        let _ = tokio::time::timeout(Duration::from_secs(1), client.logout()).await;
        write_status(settings, "offline", "portal", current_ip, false, false)?;
        if online_hook_active
            && let Err(error) = crate::hooks::run(
                &settings.hooks.offline,
                "offline",
                "portal",
                current_ip,
                settings.hooks.timeout.min(1),
            )
            .await
        {
            error!("{error}");
        }
    }
    outcome.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backoff_caps_resets_and_cannot_overflow() {
        let mut delay = Backoff::new(15, 100);
        assert_eq!(
            (0..6).map(|_| delay.delay().as_secs()).collect::<Vec<_>>(),
            [15, 30, 60, 100, 100, 100]
        );
        delay.reset();
        assert_eq!(delay.delay().as_secs(), 15);
        let mut huge = Backoff::new(u64::MAX - 1, u64::MAX);
        assert_eq!(huge.delay().as_secs(), u64::MAX - 1);
        assert_eq!(huge.delay().as_secs(), u64::MAX);
    }
    #[test]
    fn private_status_contains_no_authentication_material() {
        let status = Status {
            schema: 1,
            pid: 42,
            version: "test",
            phase: "online",
            interface: "eth0",
            local_ip: Some(std::net::Ipv4Addr::LOCALHOST.into()),
            eap_authenticated: true,
            online: true,
            updated_at: "test".into(),
        };
        let text = serde_json::to_string(&status).unwrap();
        assert!(text.contains("\"online\":true"));
        for secret in ["password", "username", "md5", "challenge"] {
            assert!(!text.contains(secret));
        }
    }
}
