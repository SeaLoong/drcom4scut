use chrono::NaiveTime;
use clap::ArgMatches;
use config::{Config, FileFormat, ValueKind};
use pnet::datalink::MacAddr;
use std::io::{BufRead, IsTerminal, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

/// Build the command separately so parsing and configuration are testable without
/// reading process arguments or initializing global state.
pub fn command() -> clap::Command {
    use clap::*;
    const SERVICE_ACTIONS: [&str; 6] = [
        "service-run",
        "service-install",
        "service-start",
        "service-stop",
        "service-status",
        "service-uninstall",
    ];
    command!(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .args([
            arg!(-c --config <config> "Path to config file.").default_value("config.yml"),
            arg!(-D --debug "Enable debug mode.").action(ArgAction::SetTrue),
            arg!(-m --mac <mac> "Ethernet Device MAC address."),
            arg!(-i --ip <ip> "IP address of the selected Ethernet Device."),
            arg!(-u --username <username> "Username to authorize."),
            arg!(-p --password <password> "Legacy password argument; prefer --password-stdin or --password-file.").conflicts_with_all(["password-stdin", "password-file"]),
            arg!(--"password-stdin" "Read one UTF-8 password line from redirected standard input.").action(ArgAction::SetTrue).conflicts_with("password-file"),
            arg!(--"password-file" <PATH> "Read password from a private file (0600 on Unix)."),
            arg!(--interface <NAME> "Select the Ethernet interface by name."),
            arg!(--"list-interfaces" "List interfaces without opening capture or requiring credentials.").action(ArgAction::SetTrue),
            arg!(--doctor "Inspect interface and capture prerequisites without authentication.").action(ArgAction::SetTrue),
            arg!(--"init-config" "Create a configuration template without authentication.").action(ArgAction::SetTrue),
            arg!(--update "Download and install the latest formal core release, if newer.").action(ArgAction::SetTrue).conflicts_with("check-update"),
            arg!(--"check-update" "Check the latest formal core release without authentication.").action(ArgAction::SetTrue),
            arg!(--"no-update-check" "Disable automatic core update checks for this run.").action(ArgAction::SetTrue),
            arg!(--"update-proxy" <URL> "HTTPS GitHub proxy prefix (default https://gh-proxy.com/)."),
            arg!(--"no-udp" "Use EAP-only authentication.").action(ArgAction::SetTrue).conflicts_with("with-udp"),
            arg!(--"with-udp" "Use full EAP and UDP, overriding no_udp in config.").action(ArgAction::SetTrue),
            arg!(--"no-log" "Disable file logs.").action(ArgAction::SetTrue),
            arg!(--once "Exit successfully after the first complete authentication/heartbeat.").action(ArgAction::SetTrue),
            arg!(--"status-file" <PATH> "Write sanitized connection status as atomic JSON."),
            arg!(--"control-pipe" <NAME> "Private Windows GUI lifecycle control pipe.").conflicts_with("control-socket"),
            arg!(--"control-socket" <PATH> "Private Unix GUI lifecycle control socket."),
            arg!(--"service-run" "Internal Windows service host.").action(ArgAction::SetTrue).hide(true),
            arg!(--"service-install" "Install Windows SCM service using an admin-secured --config path.").action(ArgAction::SetTrue),
            arg!(--"service-start" "Start the Windows service.").action(ArgAction::SetTrue),
            arg!(--"service-stop" "Stop the Windows service.").action(ArgAction::SetTrue),
            arg!(--"service-status" "Query the Windows service.").action(ArgAction::SetTrue),
            arg!(--"service-uninstall" "Remove the Windows service (requires it stopped).").action(ArgAction::SetTrue),
            arg!(--mode <MODE> "Authentication provider.").value_parser(["eap", "portal"]),
            arg!(--"portal-base" <URL> "Explicit trusted wireless portal origin."),
            arg!(--"portal-api" <URL> "Explicit portal API origin (same trusted hostname)."),
            arg!(--"allow-insecure-portal" "Allow campus portal HTTP, which exposes the remote password on the network.").action(ArgAction::SetTrue).conflicts_with("require-https-portal"),
            arg!(--"require-https-portal" "Require HTTPS even if config allows an HTTP portal.").action(ArgAction::SetTrue),
            arg!(--"portal-ac-ip" <IP> "Explicit portal access controller IPv4."),
            arg!(--"portal-client-ip" <IP> "Explicit portal client IPv4."),
            arg!(--logoff "Send one bounded Logoff/logout without starting authentication.").action(ArgAction::SetTrue).conflicts_with_all(SERVICE_ACTIONS),
            arg!(--"profile" <NAME> "Wire profile: legacy or windows31.").value_parser(["legacy", "legacy-2a", "windows31", "windows-31"]),
            arg!(--"eap-ip" <IP> "Override IPv4 encoded in EAP (does not select the local source)."),
            arg!(--"udp-ip" <IP> "Override IPv4 encoded in UDP (does not select the local source)."),
            arg!(--"local-port" <PORT> "UDP source port (default 36144)."),
            arg!(--"server-port" <PORT> "UDP server port (default 61440)."),
            arg!(-d --dns <IP> "Override campus DNS servers (repeatable).").action(ArgAction::Append),
            arg!(-H --host <host> "UDP server hostname or IPv4 address."),
            arg!(-N --hostname <hostname> "Host name sent to the server."),
            arg!(-t --time <time> "Time to reconnect (HH:MM)."),
            arg!(--"check-config" "Validate configuration without opening network devices.")
                .action(ArgAction::SetTrue).conflicts_with_all(SERVICE_ACTIONS),
        ].map(|argument| {
            // Global arguments propagate to subcommands; groups do not. Attach
            // conflicts to the arguments so `run --service-start --service-stop`
            // is rejected before any service operation on every platform.
            if SERVICE_ACTIONS.contains(&argument.get_id().as_str()) {
                let conflicts: Vec<_> = SERVICE_ACTIONS.into_iter()
                    .filter(|name| *name != argument.get_id().as_str()).collect();
                argument.conflicts_with_all(conflicts).global(true)
            } else {
                argument.global(true)
            }
        }))
        .subcommand(clap::Command::new("run").about("Run the authentication client (default)."))
        .subcommand(clap::Command::new("doctor").about("Inspect interfaces and capture prerequisites."))
        .subcommand(clap::Command::new("init").about("Create a configuration template."))
        .subcommand(clap::Command::new("status").about("Read --status-file without credentials."))
        .subcommand(clap::Command::new("logs").about("Show the configured local log file."))
}

pub fn load() -> Result<Settings, String> {
    Settings::from_matches(&command().get_matches())
}

const DEFAULT_CONFIG_FILE: &str = include_str!("default_config.yml");
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, Default)]
pub enum Profile {
    #[default]
    Legacy,
    Windows31,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, Default)]
pub enum Mode {
    #[default]
    Eap,
    Portal,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct UpdateSettings {
    pub enabled: bool,
    pub proxy: String,
    pub interval_hours: u64,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: crate::update::UpdateOptions::default().proxy,
            interval_hours: 24,
        }
    }
}

impl UpdateSettings {
    fn resolve(matches: &ArgMatches, cfg: &Config) -> Result<Self, String> {
        if let Ok(value) = cfg.get::<config::Value>("update")
            && value.kind != ValueKind::Nil
            && !matches!(value.kind, ValueKind::Table(_))
        {
            return Err("Invalid update: expected a mapping".into());
        }
        let defaults = Self::default();
        let proxy =
            text_from(matches, cfg, "update-proxy", "update.proxy")?.unwrap_or(defaults.proxy);
        crate::update::validate_proxy(&proxy).map_err(|error| error.to_string())?;
        let interval_hours = integer(cfg, "update.interval_hours", 24, 1)?;
        if interval_hours > 8760 {
            return Err("Invalid update.interval_hours: expected integer in 1..=8760".into());
        }
        Ok(Self {
            enabled: !matches.get_flag("no-update-check") && boolean(cfg, "update.enabled", true)?,
            proxy,
            interval_hours: interval_hours as u64,
        })
    }

    pub fn options(&self) -> crate::update::UpdateOptions {
        crate::update::UpdateOptions {
            proxy: self.proxy.clone(),
        }
    }
}

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Settings {
    pub update: UpdateSettings,
    pub control_pipe: Option<String>,
    pub control_socket: Option<PathBuf>,
    pub hooks: crate::hooks::Hooks,
    pub mode: Mode,
    pub portal_base: String,
    pub portal_api: Option<String>,
    pub portal_allow_http: bool,
    pub portal_ac_ip: Option<Ipv4Addr>,
    pub portal_client_ip: Option<Ipv4Addr>,
    pub logoff: bool,
    pub interface: Option<String>,
    pub eap_ip: Option<Ipv4Addr>,
    pub udp_ip: Option<Ipv4Addr>,
    pub gateway: Ipv4Addr,
    pub dns2: Ipv4Addr,
    pub profile: Profile,
    pub local_port: u16,
    pub server_port: u16,
    pub reconnect_max: u64,
    pub no_udp: bool,
    pub no_log: bool,
    pub once: bool,
    pub status_file: Option<PathBuf>,
    pub debug: bool,
    pub check_config: bool,
    pub mac: Option<MacAddr>,
    pub ip: Option<IpAddr>,
    pub username: String,
    pub password: String,
    pub dns: Vec<SocketAddr>,
    pub host: String,
    pub hostname: String,
    pub time: NaiveTime,
    pub reconnect: u64,
    pub heartbeat: Heartbeat,
    pub retry: Retry,
    pub data: Data,
    #[cfg(feature = "log4rs")]
    pub log: Log,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            update: UpdateSettings::default(),
            control_pipe: None,
            control_socket: None,
            hooks: crate::hooks::Hooks::default(),
            mode: Mode::Eap,
            portal_base: "https://s.scut.edu.cn".into(),
            portal_api: None,
            portal_allow_http: false,
            portal_ac_ip: None,
            portal_client_ip: None,
            logoff: false,
            interface: None,
            eap_ip: None,
            udp_ip: None,
            gateway: Ipv4Addr::UNSPECIFIED,
            dns2: Ipv4Addr::UNSPECIFIED,
            profile: Profile::Legacy,
            local_port: 36144,
            server_port: 61440,
            reconnect_max: 300,
            no_udp: false,
            no_log: false,
            once: false,
            status_file: None,
            debug: false,
            check_config: false,
            mac: None,
            ip: None,
            username: String::new(),
            password: String::new(),
            dns: Vec::new(),
            host: String::from("s.scut.edu.cn"),
            hostname: String::new(),
            time: NaiveTime::from_hms_opt(7, 0, 0).unwrap(),
            reconnect: 15,
            heartbeat: Heartbeat::default(),
            retry: Retry::default(),
            data: Data::default(),
            #[cfg(feature = "log4rs")]
            log: Log::default(),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Heartbeat {
    pub eap_timeout: i32,
    pub udp_timeout: i32,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Heartbeat {
            eap_timeout: 60,
            udp_timeout: 12,
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Retry {
    pub count: i32,
    pub interval: i32,
}

impl Default for Retry {
    fn default() -> Self {
        Retry {
            count: 2,
            interval: 5000,
        }
    }
}

#[cfg(feature = "log4rs")]
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Log {
    pub enable_console: bool,
    pub enable_file: bool,
    pub file_directory: String,
    pub level_filter: log::LevelFilter,
}

#[cfg(feature = "log4rs")]
impl Default for Log {
    fn default() -> Self {
        Log {
            enable_console: true,
            enable_file: true,
            file_directory: String::from("./logs"),
            level_filter: log::LevelFilter::Info,
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Default)]
pub struct Data {
    pub response_identity: ResponseIdentity,
    pub response_md5_challenge: ResponseMd5Challenge,
    pub misc_info: MiscInfo,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct ResponseIdentity {
    pub unknown: Vec<u8>,
}

impl Default for ResponseIdentity {
    fn default() -> Self {
        ResponseIdentity {
            unknown: hex::decode("0044610000").unwrap(),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct ResponseMd5Challenge {
    pub unknown: Vec<u8>,
}

impl Default for ResponseMd5Challenge {
    fn default() -> Self {
        ResponseMd5Challenge {
            unknown: hex::decode("0044612a00").unwrap(),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct MiscInfo {
    pub unknown1: Vec<u8>,
    pub cks32_param: Vec<u8>,
    pub unknown2: Vec<u8>,
    pub os_major: Vec<u8>,
    pub os_minor: Vec<u8>,
    pub os_build: Vec<u8>,
    pub os_unknown: Vec<u8>,
    pub version: Vec<u8>,
    pub hash: String,
    pub trailer: Vec<u8>,
}

impl Default for MiscInfo {
    fn default() -> Self {
        MiscInfo {
            unknown1: hex::decode("0222002a").unwrap(),
            cks32_param: hex::decode("c72f3101").unwrap(),
            unknown2: hex::decode("94000000").unwrap(),
            os_major: hex::decode("06000000").unwrap(),
            os_minor: hex::decode("02000000").unwrap(),
            os_build: hex::decode("f0230000").unwrap(),
            os_unknown: hex::decode("02000000").unwrap(),
            version: hex::decode("4472434f4d0096022a").unwrap(),
            hash: String::from("4eb81fc048a5585b7dfe1783155241a328b103c6"),
            trailer: vec![0; 16],
        }
    }
}

/// Null values in the template mean "use the built-in default". Invalid values
/// must fail explicitly instead of silently falling back or wrapping integers.
fn string(cfg: &Config, key: &str) -> Result<Option<String>, String> {
    match cfg.get::<config::Value>(key) {
        Err(config::ConfigError::NotFound(_)) => Ok(None),
        Ok(value) if value.kind == ValueKind::Nil => Ok(None),
        Ok(value) => match value.kind {
            ValueKind::String(value) => Ok(Some(value)),
            _ => Err(format!("Invalid {key}: expected a string")),
        },
        Err(_) => Err(format!("Invalid {key}")),
    }
}

fn text(matches: &ArgMatches, cfg: &Config, key: &str) -> Result<Option<String>, String> {
    text_from(matches, cfg, key, key)
}

fn text_from(
    matches: &ArgMatches,
    cfg: &Config,
    cli: &str,
    key: &str,
) -> Result<Option<String>, String> {
    if let Some(value) = matches.try_get_one::<String>(cli).ok().flatten() {
        return Ok(Some(value.clone()));
    }
    string(cfg, key)
}

fn integer(cfg: &Config, key: &str, default: i32, minimum: i32) -> Result<i32, String> {
    match cfg.get::<config::Value>(key) {
        Err(config::ConfigError::NotFound(_)) => Ok(default),
        Ok(value) if value.kind == ValueKind::Nil => Ok(default),
        Ok(value) => {
            let number = match value.kind {
                ValueKind::I64(number) => i32::try_from(number).ok(),
                ValueKind::U64(number) => i32::try_from(number).ok(),
                _ => None,
            };
            number.filter(|number| *number >= minimum).ok_or_else(|| {
                format!(
                    "Invalid {key}: expected integer in {minimum}..={}",
                    i32::MAX
                )
            })
        }
        Err(_) => Err(format!("Invalid {key}")),
    }
}

fn boolean(cfg: &Config, key: &str, default: bool) -> Result<bool, String> {
    match cfg.get::<config::Value>(key) {
        Err(config::ConfigError::NotFound(_)) => Ok(default),
        Ok(value) if value.kind == ValueKind::Nil => Ok(default),
        Ok(value) => match value.kind {
            ValueKind::Boolean(value) => Ok(value),
            _ => Err(format!("Invalid {key}: expected boolean")),
        },
        Err(_) => Err(format!("Invalid {key}")),
    }
}

fn hex_field(
    cfg: &Config,
    key: &str,
    current: &mut Vec<u8>,
    size: Option<usize>,
) -> Result<(), String> {
    if let Some(value) = string(cfg, key)? {
        let bytes =
            hex::decode(value).map_err(|_| format!("Invalid {key}: expected hexadecimal bytes"))?;
        if size.is_some_and(|size| bytes.len() != size) || bytes.len() > 64 {
            return Err(format!("Invalid {key}: incorrect byte length"));
        }
        *current = bytes;
    }
    Ok(())
}

impl Settings {
    pub fn read_config(config_path: &str) -> Result<Config, String> {
        let path = Path::new(config_path);
        // create_new prevents overwriting a user file created concurrently.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(DEFAULT_CONFIG_FILE.as_bytes())
                    .map_err(|_| "Cannot write default configuration".to_owned())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("Cannot create configuration file".to_owned()),
        }
        Self::read_config_file(path)
    }

    fn read_config_file(path: &Path) -> Result<Config, String> {
        // Inspect the opened handle as well as the path. O_NONBLOCK prevents a
        // path replaced by a FIFO from hanging startup between stat and open.
        // Symlinks to ordinary files remain supported for managed deployments.
        if !std::fs::metadata(path)
            .map_err(|_| "Cannot inspect configuration file")?
            .is_file()
        {
            return Err("Configuration must be a regular file".into());
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options
            .open(path)
            .map_err(|_| "Cannot open configuration file")?;
        let metadata = file
            .metadata()
            .map_err(|_| "Cannot inspect configuration file")?;
        if !metadata.is_file() {
            return Err("Configuration must be a regular file".into());
        }
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err("Configuration file exceeds the 1 MiB size limit".into());
        }
        // The limit also applies if another process grows the file after stat.
        let mut source = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut source)
            .map_err(|_| "Cannot read configuration: expected UTF-8 YAML")?;
        if source.len() as u64 > MAX_CONFIG_BYTES {
            return Err("Configuration file exceeds the 1 MiB size limit".into());
        }
        // Match config::File's Windows-editor compatibility. A leading UTF-8
        // BOM belongs to the encoding, not to the first YAML key.
        let source = source.strip_prefix('\u{feff}').unwrap_or(&source);
        Config::builder()
            .add_source(config::File::from_str(source, FileFormat::Yaml))
            .build()
            // Parser diagnostics can contain complete YAML lines, including passwords.
            .map_err(|_| "Cannot read configuration: expected valid YAML".to_owned())
    }

    /// Update actions inspect only update options. They never create a template,
    /// read credentials, initialize logging or validate authentication settings.
    pub fn update_from_matches(matches: &ArgMatches) -> Result<UpdateSettings, String> {
        let path = Path::new(
            matches
                .get_one::<String>("config")
                .ok_or("Missing config path")?,
        );
        let cfg = match std::fs::metadata(path) {
            Ok(_) => Self::read_config_file(path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(_) => return Err("Cannot inspect configuration file".into()),
        };
        UpdateSettings::resolve(matches, &cfg)
    }

    fn resolve(matches: &ArgMatches, cfg: &Config) -> Result<Self, String> {
        for key in [
            "heartbeat",
            "hooks",
            "portal",
            "retry",
            "log",
            "data",
            "data.response_identity",
            "data.response_md5_challenge",
            "data.misc_info",
        ] {
            if let Ok(value) = cfg.get::<config::Value>(key)
                && value.kind != ValueKind::Nil
                && !matches!(value.kind, ValueKind::Table(_))
            {
                return Err(format!("Invalid {key}: expected a mapping"));
            }
        }
        let mut settings = Self {
            update: UpdateSettings::resolve(matches, cfg)?,
            debug: matches.get_flag("debug"),
            check_config: matches.get_flag("check-config"),
            ..Self::default()
        };
        settings.control_pipe = matches.get_one::<String>("control-pipe").cloned();
        if let Some(name) = &settings.control_pipe {
            crate::control::validate_name(name)?;
        }
        settings.control_socket = matches
            .get_one::<String>("control-socket")
            .map(PathBuf::from);
        if let Some(path) = &settings.control_socket {
            crate::control::validate_socket_path(path)?;
        }
        settings.hooks.online = command_array(cfg, "hooks.online")?;
        settings.hooks.offline = command_array(cfg, "hooks.offline")?;
        settings.hooks.timeout = integer(cfg, "hooks.timeout", 10, 1)? as u64;
        settings.mode = match text(matches, cfg, "mode")?.as_deref().unwrap_or("eap") {
            "eap" => Mode::Eap,
            "portal" => Mode::Portal,
            _ => return Err("Invalid mode: expected eap or portal".into()),
        };
        settings.logoff = matches.get_flag("logoff");
        settings.portal_base = text_from(matches, cfg, "portal-base", "portal.base_url")?
            .unwrap_or(settings.portal_base);
        settings.portal_api = text_from(matches, cfg, "portal-api", "portal.api_url")?;
        settings.portal_allow_http = !matches.get_flag("require-https-portal")
            && (matches.get_flag("allow-insecure-portal")
                || boolean(cfg, "portal.allow_http", false)?);
        settings.portal_ac_ip = ipv4_option(matches, cfg, "portal-ac-ip", "portal.ac_ip")?;
        settings.portal_client_ip =
            ipv4_option(matches, cfg, "portal-client-ip", "portal.client_ip")?;
        #[cfg(not(feature = "portal"))]
        if settings.mode == Mode::Portal {
            return Err("This build does not include the portal feature".into());
        }
        settings.interface = text(matches, cfg, "interface")?.filter(|name| !name.is_empty());
        settings.no_udp = !matches.get_flag("with-udp")
            && (matches.get_flag("no-udp") || boolean(cfg, "no_udp", false)?);
        settings.no_log = matches.get_flag("no-log") || boolean(cfg, "no_log", false)?;
        settings.once = matches.get_flag("once") || boolean(cfg, "once", false)?;
        settings.status_file = match text(matches, cfg, "status-file")? {
            Some(value) => Some(value),
            None => string(cfg, "status_file")?,
        }
        .map(PathBuf::from);
        settings.eap_ip = ipv4_option(matches, cfg, "eap-ip", "eap_ip")?;
        settings.udp_ip = ipv4_option(matches, cfg, "udp-ip", "udp_ip")?;
        settings.gateway = string(cfg, "gateway")?
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| "Invalid gateway IPv4 address")?
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        settings.dns2 = string(cfg, "dns2")?
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| "Invalid dns2 IPv4 address")?
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        settings.local_port = port(matches, cfg, "local-port", "local_port", 36144)?;
        settings.server_port = port(matches, cfg, "server-port", "server_port", 61440)?;
        let profile = text(matches, cfg, "profile")?.unwrap_or_else(|| "legacy".into());
        settings.profile = match profile.as_str() {
            "legacy" | "legacy-2a" => Profile::Legacy,
            "windows31" | "windows-31" => Profile::Windows31,
            _ => return Err("Invalid profile: expected legacy or windows31".into()),
        };
        if settings.profile == Profile::Windows31 {
            settings.data.response_md5_challenge.unknown[3] = 0x31;
            let misc = &mut settings.data.misc_info;
            misc.unknown1 = vec![2, 0x22, 0, 0x31];
            misc.unknown2.fill(0);
            misc.os_major.fill(0);
            misc.os_minor.fill(0);
            misc.os_build.fill(0);
            misc.os_unknown.fill(0);
            misc.version = hex::decode("4472434f4d00960231").expect("constant hex");
            misc.hash = "b1b54da1eb64ed14592830f7f895c373d507472a".into();
            misc.trailer = hex::decode("2001025030007004aa0cb7dee93f3c65")
                .expect("published Windows31 trailer");
        }
        if let Some(value) = text(matches, cfg, "mac")? {
            settings.mac = Some(MacAddr::from_str(&value).map_err(|_| "Invalid mac address")?);
        }
        if let Some(value) = text(matches, cfg, "ip")? {
            let ip: IpAddr = value.parse().map_err(|_| "Invalid ip address")?;
            if !ip.is_ipv4() {
                return Err("Invalid ip: DrCOM requires IPv4".to_owned());
            }
            settings.ip = Some(ip);
        }
        // Logout does not require account credentials. In particular, a portal
        // logout must not inspect an unrelated account, password file or stdin.
        if !settings.logoff {
            settings.username = text(matches, cfg, "username")?.unwrap_or_default();
            if settings.username.trim().is_empty() {
                return Err("Username is REQUIRED; fill the configuration file".into());
            }
            if !valid_credential(&settings.username) {
                return Err(
                    "Invalid username: expected one nonempty UTF-8 line of at most 4096 bytes"
                        .into(),
                );
            }
            settings.password = if matches.get_flag("password-stdin") {
                if std::io::stdin().is_terminal() {
                    return Err("--password-stdin requires redirected standard input".into());
                }
                read_password(std::io::stdin().lock())?
            } else if let Some(path) = matches.get_one::<String>("password-file") {
                read_password_file(Path::new(path))?
            } else if let Some(password) = matches.get_one::<String>("password") {
                password.clone()
            } else if let Some(path) = string(cfg, "password_file")? {
                if string(cfg, "password")?.is_some_and(|value| !value.is_empty()) {
                    return Err("Specify either password or password_file, not both".into());
                }
                let mut path = PathBuf::from(path);
                if path.is_relative() {
                    let config_path = matches
                        .get_one::<String>("config")
                        .expect("config argument");
                    path = Path::new(config_path)
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(path);
                }
                read_password_file(&path)?
            } else {
                string(cfg, "password")?.unwrap_or_default()
            };
            if settings.password.is_empty() {
                return Err("Password is REQUIRED; use password_file or --password-stdin".into());
            }
            validate_password(&settings.password)?;
        }
        if settings.mode == Mode::Eap && settings.username.len() > 25 {
            return Err("Invalid username: maximum 25 UTF-8 bytes".to_owned());
        }
        if let Some(values) = matches.get_many::<String>("dns") {
            for value in values {
                let address = parse_dns(value)?;
                if !settings.dns.contains(&address) {
                    settings.dns.push(address);
                }
            }
        }
        if settings.dns.is_empty()
            && let Some(value) = cfg
                .get::<config::Value>("dns")
                .ok()
                .filter(|value| value.kind != ValueKind::Nil)
        {
            let ValueKind::Array(values) = value.kind else {
                return Err("Invalid dns: expected an array".to_owned());
            };
            for value in values {
                let ValueKind::String(value) = value.kind else {
                    return Err("Invalid dns: expected IPv4 addresses".to_owned());
                };
                let address = if let Ok(ip) = value.parse::<std::net::Ipv4Addr>() {
                    SocketAddr::new(IpAddr::V4(ip), 53)
                } else {
                    value
                        .parse::<SocketAddr>()
                        .map_err(|_| "Invalid dns address")?
                };
                if !address.is_ipv4() || address.port() == 0 {
                    return Err(
                        "Invalid dns: expected an IPv4 address with a nonzero port".to_owned()
                    );
                }
                if !settings.dns.contains(&address) {
                    settings.dns.push(address);
                }
            }
        }
        if settings.dns.is_empty() {
            settings.dns = [
                "202.38.193.33:53",
                "222.201.130.30:53",
                "202.112.17.33:53",
                "222.201.130.33:53",
            ]
            .map(|value| value.parse().expect("constant DNS address"))
            .to_vec();
        }
        if settings.profile == Profile::Windows31 && settings.dns2.is_unspecified() {
            settings.dns2 = settings
                .dns
                .get(1)
                .and_then(|address| match address.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    _ => None,
                })
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
        }
        if let Some(value) = text(matches, cfg, "host")? {
            let name = value.strip_suffix('.').unwrap_or(&value);
            if name.is_empty()
                || name.len() > 253
                || !name.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
            {
                return Err("Invalid host: expected a DNS hostname or IPv4 address".to_owned());
            }
            settings.host = value;
        }
        settings.hostname = if let Some(value) = text(matches, cfg, "hostname")? {
            if settings.mode == Mode::Eap && value.len() + settings.username.len() > 44 {
                return Err(
                    "Invalid hostname: username and hostname must fit in 44 UTF-8 bytes".to_owned(),
                );
            }
            value
        } else {
            let mut value = hostname::get()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "drcom4scut".to_owned());
            // Retain the historical truncation for automatically detected machine
            // names, but never split UTF-8 midway through a character.
            let available = if settings.mode == Mode::Eap {
                44 - settings.username.len()
            } else {
                256
            };
            let mut length = available.min(value.len());
            while !value.is_char_boundary(length) {
                length -= 1;
            }
            value.truncate(length);
            value
        };
        if let Some(value) = text(matches, cfg, "time")? {
            settings.time = NaiveTime::parse_from_str(&value, "%H:%M")
                .map_err(|_| "Invalid time: expected HH:MM")?;
        }
        settings.reconnect = integer(cfg, "reconnect", settings.reconnect as i32, 1)? as u64;
        settings.reconnect_max =
            integer(cfg, "reconnect_max", settings.reconnect_max as i32, 1)? as u64;
        if settings.reconnect_max < settings.reconnect {
            return Err("reconnect_max must be at least reconnect".into());
        }
        settings.heartbeat.eap_timeout = integer(
            cfg,
            "heartbeat.eap_timeout",
            settings.heartbeat.eap_timeout,
            1,
        )?;
        settings.heartbeat.udp_timeout = integer(
            cfg,
            "heartbeat.udp_timeout",
            settings.heartbeat.udp_timeout,
            1,
        )?;
        settings.retry.count = integer(cfg, "retry.count", settings.retry.count, 0)?;
        settings.retry.interval = integer(cfg, "retry.interval", settings.retry.interval, 1)?;
        #[cfg(feature = "log4rs")]
        {
            settings.log.enable_console =
                boolean(cfg, "log.enable_console", settings.log.enable_console)?;
            settings.log.enable_file = boolean(cfg, "log.enable_file", settings.log.enable_file)?;
            if let Some(value) = string(cfg, "log.file_directory")? {
                settings.log.file_directory = value;
            }
            if settings.no_log {
                settings.log.enable_file = false;
            }
            if let Some(value) = string(cfg, "log.level")? {
                settings.log.level_filter =
                    log::LevelFilter::from_str(&value).map_err(|_| "Invalid log.level")?;
            }
        }
        hex_field(
            cfg,
            "data.response_identity.unknown",
            &mut settings.data.response_identity.unknown,
            Some(5),
        )?;
        hex_field(
            cfg,
            "data.response_md5_challenge.unknown",
            &mut settings.data.response_md5_challenge.unknown,
            Some(5),
        )?;
        let misc = &mut settings.data.misc_info;
        for (key, value) in [
            ("unknown1", &mut misc.unknown1),
            ("cks32_param", &mut misc.cks32_param),
            ("unknown2", &mut misc.unknown2),
            ("os_major", &mut misc.os_major),
            ("os_minor", &mut misc.os_minor),
            ("os_build", &mut misc.os_build),
            ("os_unknown", &mut misc.os_unknown),
        ] {
            hex_field(cfg, &format!("data.misc_info.{key}"), value, Some(4))?;
        }
        hex_field(cfg, "data.misc_info.version", &mut misc.version, None)?;
        hex_field(cfg, "data.misc_info.trailer", &mut misc.trailer, Some(16))?;
        if let Some(value) = string(cfg, "data.misc_info.hash")? {
            if value.len() > 64 {
                return Err("Invalid data.misc_info.hash: maximum 64 bytes".to_owned());
            }
            misc.hash = value;
        }
        Ok(settings)
    }

    #[cfg(feature = "portal")]
    pub fn portal_config(&self) -> crate::portal::PortalConfig {
        crate::portal::PortalConfig {
            base_url: self.portal_base.clone(),
            api_url: self.portal_api.clone(),
            ac_ip: self.portal_ac_ip,
            client_ip: self.portal_client_ip,
            client_mac: self.mac.map(|mac| mac.to_string()),
            local_ip: self.ip,
            allow_http: self.portal_allow_http,
            ..crate::portal::PortalConfig::default()
        }
    }

    pub fn from_matches(matches: &ArgMatches) -> Result<Self, String> {
        let path = matches
            .get_one::<String>("config")
            .ok_or("Missing config path")?;
        let settings = Self::resolve(matches, &Self::read_config(path)?)?;
        #[cfg(feature = "portal")]
        if settings.mode == Mode::Portal {
            crate::portal::PortalClient::new(settings.portal_config())
                .map_err(|error| error.to_string())?;
        }
        Ok(settings)
    }
}

// Debug output is intentionally incomplete: a Settings value contains a secret.
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("interface", &self.interface)
            .field("ip", &self.ip)
            .field("profile", &self.profile)
            .field("host", &self.host)
            .field("password", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn ipv4_option(
    matches: &ArgMatches,
    cfg: &Config,
    cli: &str,
    key: &str,
) -> Result<Option<Ipv4Addr>, String> {
    let value = text_from(matches, cfg, cli, key)?;
    value
        .map(|value| {
            value
                .parse()
                .map_err(|_| format!("Invalid {key}: expected IPv4"))
        })
        .transpose()
}

fn port(
    matches: &ArgMatches,
    cfg: &Config,
    cli: &str,
    key: &str,
    default: u16,
) -> Result<u16, String> {
    if let Some(value) = matches.get_one::<String>(cli) {
        return value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("Invalid {key}: expected 1..=65535"));
    }
    u16::try_from(integer(cfg, key, i32::from(default), 1)?)
        .map_err(|_| format!("Invalid {key}: expected 1..=65535"))
}

fn parse_dns(value: &str) -> Result<SocketAddr, String> {
    let address = value
        .parse::<Ipv4Addr>()
        .map(|ip| SocketAddr::new(ip.into(), 53))
        .or_else(|_| value.parse::<SocketAddr>())
        .map_err(|_| "Invalid dns address")?;
    if !address.is_ipv4() || address.port() == 0 {
        return Err("Invalid dns address".into());
    }
    Ok(address)
}

pub(crate) fn valid_credential(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.contains(['\n', '\r', '\0'])
}

fn validate_password(value: &str) -> Result<(), String> {
    if !valid_credential(value) {
        return Err(
            "Invalid password: expected one nonempty UTF-8 line of at most 4096 bytes".into(),
        );
    }
    Ok(())
}

fn read_password(reader: impl BufRead) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader
        .take(4099)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read password input")?;
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    let password = String::from_utf8(bytes).map_err(|_| "Password input must be UTF-8")?;
    validate_password(&password)?;
    Ok(password)
}

fn read_password_file(path: &Path) -> Result<String, String> {
    if !std::fs::metadata(path)
        .map_err(|_| "Cannot inspect password file")?
        .is_file()
    {
        return Err("Password file must be a regular file".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A regular path may be replaced with a FIFO between metadata and open.
        // Never wait for a writer; inspect the opened handle before reading it.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "Cannot open password file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect password file")?;
    if !metadata.is_file() {
        return Err("Password file must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(
                "Password file must have private permissions (0600 or0400), with no hard links"
                    .into(),
            );
        }
    }
    read_password(std::io::BufReader::new(file))
}

fn command_array(cfg: &Config, key: &str) -> Result<Vec<String>, String> {
    match cfg.get::<config::Value>(key) {
        Err(config::ConfigError::NotFound(_)) => Ok(Vec::new()),
        Ok(value) if value.kind == ValueKind::Nil => Ok(Vec::new()),
        Ok(value) => match value.kind {
            ValueKind::Array(values) => values
                .into_iter()
                .map(|value| match value.kind {
                    ValueKind::String(argument) if !argument.contains('\0') => Ok(argument),
                    _ => Err(format!("Invalid {key}: expected an argument array")),
                })
                .collect(),
            _ => Err(format!("Invalid {key}: expected an argument array")),
        },
        Err(_) => Err(format!("Invalid {key}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str, args: &[&str]) -> Result<Settings, String> {
        let cfg = Config::builder()
            .add_source(config::File::from_str(yaml, FileFormat::Yaml))
            .build()
            .unwrap();
        let matches = command()
            .try_get_matches_from(std::iter::once("drcom4scut").chain(args.iter().copied()))
            .unwrap();
        Settings::resolve(&matches, &cfg)
    }

    fn credentials(extra: &str) -> String {
        format!("username: student\npassword: test-password\nhostname: test-pc\n{extra}")
    }

    #[test]
    fn update_defaults_overrides_and_opt_out_are_validated() {
        let settings = parse(&credentials(""), &[]).unwrap();
        assert_eq!(settings.update, UpdateSettings::default());
        let settings = parse(
            &credentials("update: {enabled: false, proxy: 'https://mirror.example/prefix/', interval_hours: 48}"),
            &["--update-proxy", "https://override.example/"],
        )
        .unwrap();
        assert!(!settings.update.enabled);
        assert_eq!(settings.update.proxy, "https://override.example/");
        assert_eq!(settings.update.interval_hours, 48);
        let settings = parse(&credentials(""), &["--no-update-check"]).unwrap();
        assert!(!settings.update.enabled);
        for update in [
            "false",
            "{enabled: 'true'}",
            "{proxy: 42}",
            "{proxy: 'http://mirror.example/'}",
            "{interval_hours: 0}",
            "{interval_hours: -1}",
            "{interval_hours: 8761}",
            "{interval_hours: '24'}",
            "{interval_hours: true}",
        ] {
            assert!(
                parse(&credentials(&format!("update: {update}")), &[]).is_err(),
                "{update}"
            );
        }
    }

    #[test]
    fn standalone_update_options_ignore_authentication_configuration_and_password_input() {
        let cfg = Config::builder()
            .add_source(config::File::from_str(
                "username: 42\npassword_file: /not/a/password\nmode: invalid\nportal: false\nupdate: {interval_hours: 72}",
                FileFormat::Yaml,
            ))
            .build()
            .unwrap();
        let matches = command()
            .try_get_matches_from(["drcom4scut", "--update", "--password-stdin"])
            .unwrap();
        let settings = UpdateSettings::resolve(&matches, &cfg).unwrap();
        assert_eq!(settings.interval_hours, 72);
        assert_eq!(settings.proxy, "https://gh-proxy.com/");
    }

    #[test]
    fn defaults_and_null_template_fields_are_resolved() {
        let yaml = DEFAULT_CONFIG_FILE
            .replace("username:", "username: student")
            .replace("password:", "password: test-password");
        let settings = parse(&yaml, &["--hostname", "test-pc"]).unwrap();
        assert_eq!(settings.retry, Retry::default());
        assert_eq!(settings.heartbeat, Heartbeat::default());
        assert_eq!(settings.dns.len(), 4);
        assert_eq!(settings.time, NaiveTime::from_hms_opt(7, 0, 0).unwrap());
    }

    #[test]
    fn cli_overrides_configuration_including_credentials() {
        let settings = parse(
            &credentials("host: old.example\ntime: '08:15'"),
            &[
                "-u",
                "other",
                "-p",
                "another-password",
                "-H",
                "new.example",
                "-i",
                "192.0.2.2",
                "-m",
                "01:02:03:04:05:06",
                "-t",
                "09:30",
                "-D",
                "--check-config",
            ],
        )
        .unwrap();
        assert_eq!(settings.username, "other");
        assert_eq!(settings.password, "another-password");
        assert_eq!(settings.host, "new.example");
        assert_eq!(settings.ip, Some("192.0.2.2".parse().unwrap()));
        assert_eq!(settings.mac, Some(MacAddr(1, 2, 3, 4, 5, 6)));
        assert_eq!(settings.time, NaiveTime::from_hms_opt(9, 30, 0).unwrap());
        assert!(settings.debug && settings.check_config);
    }

    #[test]
    fn cli_overrides_do_not_validate_shadowed_configuration_types() {
        let fields = [
            (
                "portal: {base_url: 42}",
                "--portal-base",
                "http://portal.example",
            ),
            (
                "portal: {api_url: 42}",
                "--portal-api",
                "http://portal.example:801",
            ),
            ("portal: {ac_ip: 42}", "--portal-ac-ip", "192.0.2.1"),
            ("portal: {client_ip: 42}", "--portal-client-ip", "192.0.2.2"),
            ("eap_ip: 42", "--eap-ip", "192.0.2.3"),
            ("udp_ip: 42", "--udp-ip", "192.0.2.4"),
            ("status_file: 42", "--status-file", "current.json"),
            ("status-file: 42", "--status-file", "current.json"),
        ];
        for (extra, option, value) in fields {
            let yaml = credentials(extra);
            assert!(parse(&yaml, &[]).is_err(), "{extra}");
            let settings = parse(&yaml, &[option, value]).unwrap();
            match option {
                "--portal-base" => assert_eq!(settings.portal_base, value),
                "--portal-api" => assert_eq!(settings.portal_api.as_deref(), Some(value)),
                "--portal-ac-ip" => assert_eq!(settings.portal_ac_ip, Some(value.parse().unwrap())),
                "--portal-client-ip" => {
                    assert_eq!(settings.portal_client_ip, Some(value.parse().unwrap()))
                }
                "--eap-ip" => assert_eq!(settings.eap_ip, Some(value.parse().unwrap())),
                "--udp-ip" => assert_eq!(settings.udp_ip, Some(value.parse().unwrap())),
                "--status-file" => assert_eq!(settings.status_file, Some(PathBuf::from(value))),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn dns_accepts_ipv4_port_and_removes_duplicates() {
        let settings = parse(
            &credentials("dns: ['192.0.2.53', '192.0.2.53:53', '127.0.0.1:15353']"),
            &[],
        )
        .unwrap();
        assert_eq!(
            settings.dns,
            vec![
                "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:15353".parse::<SocketAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn rejects_negative_zero_overflow_and_wrong_type_timers() {
        for key in [
            "reconnect",
            "heartbeat.eap_timeout",
            "heartbeat.udp_timeout",
            "retry.interval",
        ] {
            let (parent, child) = key.split_once('.').unwrap_or((key, ""));
            for value in ["-1", "0", "2147483648", "'5'", "true"] {
                let extra = if child.is_empty() {
                    format!("{parent}: {value}")
                } else {
                    format!("{parent}:\n  {child}: {value}")
                };
                let error = parse(&credentials(&extra), &[]).unwrap_err();
                assert!(error.contains(key), "{key}: {error}");
            }
        }
    }

    #[test]
    fn malformed_nested_tables_are_not_silently_ignored() {
        for extra in [
            "heartbeat: 5",
            "retry: false",
            "log: false",
            "log: INFO",
            "data: bad",
            "data: {misc_info: false}",
        ] {
            assert!(parse(&credentials(extra), &[]).is_err(), "{extra}");
        }
    }

    #[test]
    fn retry_count_accepts_zero_but_rejects_negative() {
        assert_eq!(
            parse(&credentials("retry: {count: 0}"), &[])
                .unwrap()
                .retry
                .count,
            0
        );
        assert!(parse(&credentials("retry: {count: -1}"), &[]).is_err());
    }

    #[test]
    fn rejects_ipv6_and_invalid_addresses_before_network() {
        for extra in [
            "ip: '::1'",
            "mac: wrong",
            "ip: wrong",
            "dns: ['[::1]:53']",
            "dns: ['127.0.0.1:0']",
            "dns: [15]",
            "dns: bad",
            "host: 'https://example.com'",
            "host: ''",
            "host: '-bad.example'",
            "time: '25:00'",
        ] {
            assert!(parse(&credentials(extra), &[]).is_err(), "{extra}");
        }
    }

    #[test]
    fn validates_wire_field_lengths_and_hex() {
        for extra in [
            "data: {misc_info: {version: 'ff', os_major: 'ff'}}",
            "data: {misc_info: {version: 'zz'}}",
            "data: {response_identity: {unknown: 'ff'}}",
        ] {
            assert!(parse(&credentials(extra), &[]).is_err());
        }
        for extra in [
            format!("username: '{}'", "x".repeat(26)),
            format!("hostname: '{}'", "x".repeat(38)),
            format!("data: {{misc_info: {{hash: '{}'}}}}", "x".repeat(65)),
            format!("data: {{misc_info: {{version: '{}'}}}}", "ff".repeat(65)),
        ] {
            let yaml = if extra.starts_with("username:") {
                format!("password: secret\nhostname: pc\n{extra}")
            } else if extra.starts_with("hostname:") {
                format!("username: student\npassword: secret\n{extra}")
            } else {
                credentials(&extra)
            };
            assert!(parse(&yaml, &[]).is_err(), "{extra}");
        }
    }

    #[test]
    fn byte_limits_apply_to_multibyte_names() {
        let settings = parse("username: '学生'\npassword: secret\nhostname: pc", &[]).unwrap();
        assert_eq!(settings.username.len(), 6);
        assert!(
            parse(
                &format!(
                    "username: '{}'\npassword: secret\nhostname: pc",
                    "学".repeat(9)
                ),
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn account_control_characters_are_rejected_before_authentication() {
        for username in ["first\nsecond", "first\rsecond", "first\0second"] {
            let error = parse(&credentials(""), &["--username", username]).unwrap_err();
            assert!(error.starts_with("Invalid username:"));
            assert!(!error.contains(username));
        }
    }

    #[test]
    fn errors_do_not_echo_secret_values() {
        let error = parse("username: student\npassword: 123456789", &[]).unwrap_err();
        assert!(error.contains("password"));
        assert!(!error.contains("123456789"));
    }

    #[test]
    fn required_credentials_report_field_without_panicking() {
        for yaml in [
            "{}",
            "username: student",
            "username: ''\npassword: secret",
            "username: student\npassword: ''",
        ] {
            assert!(parse(yaml, &[]).is_err());
        }
    }

    #[test]
    fn explicit_gui_eap_choice_overrides_saved_no_udp() {
        let settings = parse(
            &credentials("no_udp: true"),
            &["--mode", "eap", "--with-udp"],
        )
        .unwrap();
        assert_eq!(settings.mode, Mode::Eap);
        assert!(!settings.no_udp);
    }

    #[cfg(feature = "portal")]
    #[test]
    fn https_requirement_overrides_saved_http_permission() {
        let settings = parse(
            &credentials("mode: portal\nportal: {allow_http: true}"),
            &["--require-https-portal"],
        )
        .unwrap();
        assert!(!settings.portal_allow_http);
    }

    #[cfg(feature = "portal")]
    #[test]
    fn portal_identity_is_not_limited_by_ethernet_packet_width() {
        let account = "a".repeat(80);
        let settings = parse(
            &format!("username: {account}\npassword: test\nmode: portal"),
            &[],
        )
        .unwrap();
        assert_eq!(settings.username, account);
        let boundary = "学".repeat(1365) + "a";
        let settings = parse(&credentials("mode: portal"), &["--username", &boundary]).unwrap();
        assert_eq!(settings.username.len(), 4096);
        for username in ["line\nbreak".to_owned(), "a".repeat(4097)] {
            assert!(
                parse(&credentials("mode: portal"), &["--username", &username])
                    .unwrap_err()
                    .starts_with("Invalid username:")
            );
        }
    }

    #[test]
    fn logout_does_not_validate_or_read_unrelated_login_credentials() {
        for yaml in [
            "username: [not, a, login]\npassword: false\npassword_file: 42\n".to_owned(),
            format!(
                "username: {}\npassword_file: /not/a/password\n",
                "u".repeat(80)
            ),
        ] {
            let settings = parse(&yaml, &["--logoff", "--password-stdin"]).unwrap();
            assert!(settings.username.is_empty() && settings.password.is_empty());
            assert!(parse(&yaml, &["--check-config"]).is_err());
        }
    }

    #[test]
    fn profile_aliases_and_explicit_overrides_are_consistent() {
        let settings = parse(
            &credentials("profile: windows-31\ndata: {misc_info: {unknown1: '01020304'}}"),
            &[],
        )
        .unwrap();
        assert_eq!(settings.profile, Profile::Windows31);
        assert_eq!(settings.data.misc_info.unknown1, [1, 2, 3, 4]);
        assert_eq!(settings.data.misc_info.trailer.len(), 16);
    }
}
