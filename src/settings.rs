use chrono::NaiveTime;
use clap::ArgMatches;
use config::{Config, FileFormat, Value};
use log::error;
use pnet::datalink::MacAddr;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::LazyLock;

fn get_matches() -> ArgMatches {
    use clap::*;
    command!(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .args(&[
            arg!(-c --config <config> "Path to config file.").default_value("config.yml"),
            arg!(-D --debug "Enable debug mode.").action(ArgAction::SetTrue),
            arg!(-m --mac <mac> "Ethernet Device MAC address.").required(false),
            arg!(-i --ip <ip> "IP address of the selected Ethernet Device.").required(false),
            arg!(-u --username <username> "Username to authorize.").required(false),
            arg!(-p --password <password> "Password to authorize.").required(false),
            arg!(-H --host <host> "Host to connect UDP server. Default value is 's.scut.edu.cn'.").required(false),
            arg!(-N --hostname <hostname> "Default value is current computer host name.").required(false),
            arg!(-t --time <time> "Time to reconnect automatically after you are not allowed to access Internet. Default value is 7:00.").required(false),
        ])
        .get_matches()
}

static MATCHES: LazyLock<ArgMatches> = LazyLock::new(get_matches);
pub static DEBUG: LazyLock<bool> = LazyLock::new(|| MATCHES.get_flag("debug"));
pub static SETTINGS: LazyLock<Settings> = LazyLock::new(|| Settings::parse(&MATCHES));

const DEFAULT_CONFIG_FILE: &str = include_str!("default_config.yml");

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Settings {
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
        }
    }
}

fn get_str_from_map(map: &HashMap<String, Value>, k: &str) -> Option<String> {
    map.get(k)?.to_owned().into_string().ok()
}

fn get_int_from_map(map: &HashMap<String, Value>, k: &str) -> Option<i64> {
    map.get(k)?.to_owned().into_int().ok()
}

fn get_bool_from_map(map: &HashMap<String, Value>, k: &str) -> Option<bool> {
    map.get(k)?.to_owned().into_bool().ok()
}

fn get_map_from_map(map: &HashMap<String, Value>, k: &str) -> Option<HashMap<String, Value>> {
    map.get(k)?.to_owned().into_table().ok()
}

fn get_str(matches: &ArgMatches, cfg: &Config, k: &str) -> Option<String> {
    matches
        .try_get_one::<String>(k)
        .ok()
        .flatten()
        .cloned()
        .or_else(|| cfg.get_string(k).ok())
        .filter(|s| !s.trim().is_empty())
}

fn get_u64(matches: &ArgMatches, cfg: &Config, k: &str) -> Option<u64> {
    matches
        .try_get_one::<u64>(k)
        .ok()
        .flatten()
        .copied()
        .or_else(|| cfg.get_int(k).ok().map(|x| x as u64))
}

impl Settings {
    fn read_config(config_path: &str) -> Config {
        //  使用path读取配置文件
        let path = Path::new(config_path);
        if !path.is_file() && std::fs::write(path, DEFAULT_CONFIG_FILE).is_err() {
            error!("Can't create default config file 'config.yml', use default config.");
        }
        Config::builder()
            .add_source(config::File::new(config_path, FileFormat::Yaml).required(false))
            .build()
            .expect("Can't read config file.")
    }
    fn resolve(mut settings: Settings, matches: &ArgMatches, cfg: Config) -> Settings {
        // 解析配置文件
        if let Some(s) = get_str(matches, &cfg, "mac") {
            settings.mac = Some(MacAddr::from_str(&s).expect("Can't parse MAC address!"));
        }

        if let Some(s) = get_str(matches, &cfg, "ip") {
            settings.ip = Some(IpAddr::from_str(&s).expect("Can't parse IP Address!"));
        }

        settings.username = get_str(matches, &cfg, "username").expect("Username is REQUIRED!");
        settings.password = get_str(matches, &cfg, "password").expect("Password is REQUIRED!");

        if let Some(mut s) = matches.try_get_one::<String>("dns").ok().flatten().cloned() {
            if (s.contains(']') && !s.contains("]:")) || !s.contains(':') {
                s += ":53";
            }
            settings
                .dns
                .push(SocketAddr::from_str(&s).expect("Can't parse DNS server to socket address!"));
        }
        if let Ok(vs) = cfg.get_array("dns") {
            for v in vs {
                let mut s = v.into_string().expect("Invalid DNS server!");
                if (s.contains(']') && !s.contains("]:")) || !s.contains(':') {
                    s += ":53";
                }
                let x =
                    SocketAddr::from_str(&s).expect("Can't parse DNS server to socket address!");
                if !settings.dns.contains(&x) {
                    settings.dns.push(x);
                }
            }
        }

        if let Some(s) = get_str(matches, &cfg, "host") {
            settings.host = s;
        }

        settings.hostname = get_str(matches, &cfg, "hostname").unwrap_or_else(|| {
            hostname::get()
                .expect("Can't get current computer host name.")
                .into_string()
                .expect("Can't parse host name to String.")
        });

        if let Some(s) = get_str(matches, &cfg, "time") {
            settings.time = NaiveTime::parse_from_str(&s, "%H:%M")
                .expect("Can't parse time String to NativeTime.");
        }

        if let Some(x) = get_u64(matches, &cfg, "reconnect") {
            settings.reconnect = x;
        }

        if let Ok(map) = cfg.get_table("heartbeat") {
            if let Some(x) = get_int_from_map(&map, "eap_timeout") {
                settings.heartbeat.eap_timeout = x as i32;
            }
            if let Some(x) = get_int_from_map(&map, "udp_timeout") {
                settings.heartbeat.udp_timeout = x as i32;
            }
        }

        if let Ok(map) = cfg.get_table("retry") {
            if let Some(x) = get_int_from_map(&map, "count") {
                settings.retry.count = x as i32;
            }
            if let Some(x) = get_int_from_map(&map, "interval") {
                settings.retry.interval = x as i32;
            }
        }

        #[cfg(feature = "log4rs")]
        if settings.log.level_filter != log::LevelFilter::Off {
            if let Ok(map) = cfg.get_table("log") {
                if let Some(x) = get_bool_from_map(&map, "enable_console") {
                    settings.log.enable_console = x;
                }
                if let Some(x) = get_bool_from_map(&map, "enable_file") {
                    settings.log.enable_file = x;
                }
                if let Some(x) = get_str_from_map(&map, "file_directory") {
                    settings.log.file_directory = x;
                }
                if let Some(Ok(level_filter)) = get_str_from_map(&map, "level")
                    .map(|x| log::LevelFilter::from_str(x.to_ascii_uppercase().as_str()))
                {
                    settings.log.level_filter = level_filter;
                }
            }
        }

        if let Ok(data) = cfg.get_table("data") {
            if let Some(map) = get_map_from_map(&data, "response_identity") {
                if let Some(s) = get_str_from_map(&map, "unknown") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.response_identity.unknown = v;
                    } else {
                        error!("Invalid config: data.response_identity.unknown! Default value instead.")
                    }
                }
            }
            if let Some(map) = get_map_from_map(&data, "response_md5_challenge") {
                if let Some(s) = get_str_from_map(&map, "unknown") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.response_md5_challenge.unknown = v;
                    } else {
                        error!("Invalid config: data.response_md5_challenge.unknown! Default value instead.")
                    }
                }
            }
            if let Some(map) = get_map_from_map(&data, "misc_info") {
                if let Some(s) = get_str_from_map(&map, "unknown1") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.misc_info.unknown1 = v;
                    } else {
                        error!("Invalid config: data.misc_info.unknown1! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "cks32_param") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.misc_info.cks32_param = v;
                    } else {
                        error!("Invalid config: data.misc_info.cks32_param! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "unknown2") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.misc_info.unknown2 = v;
                    } else {
                        error!("Invalid config: data.misc_info.unknown2! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "os_major") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.misc_info.os_major = v;
                    } else {
                        error!("Invalid config: data.misc_info.os_major! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "os_minor") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.misc_info.os_minor = v;
                    } else {
                        error!("Invalid config: data.misc_info.os_minor! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "os_build") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.misc_info.os_build = v;
                    } else {
                        error!("Invalid config: data.misc_info.os_build! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "os_unknown") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.misc_info.os_unknown = v;
                    } else {
                        error!("Invalid config: data.misc_info.os_unknown! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "version") {
                    if let Ok(v) = hex::decode(s) {
                        settings.data.misc_info.version = v;
                    } else {
                        error!("Invalid config: data.misc_info.version! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "hash") {
                    settings.data.misc_info.hash = s;
                }
            }
        }
        settings
    }
    pub fn parse(matches: &ArgMatches) -> Settings {
        let settings = Settings::default();
        let path = matches.get_one::<String>("config").unwrap().to_owned();
        let cfg = Settings::read_config(&path);
        Settings::resolve(settings, matches, cfg)
    }
}
