use std::collections::HashMap;

#[cfg(feature = "nolog")]
use crate::{debug, error, info, log, trace, warn};
use chrono::NaiveTime;
use config::{Config, FileFormat, Value};
#[cfg(not(feature = "nolog"))]
use log::error;
use pnet::datalink::MacAddr;
use std::cmp::max;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Settings {
    pub debug: bool,
    pub noudp: bool,
    pub nolog: bool,
    pub path: String,
    pub mac: Option<MacAddr>,
    pub ip: Option<IpAddr>,
    pub username: String,
    pub password: String,
    pub dns: Vec<SocketAddr>,
    pub host: String,
    pub hostname: String,
    pub time: NaiveTime,
    pub reconnect: i32,
    pub heartbeat: Heartbeat,
    pub retry: Retry,
    #[cfg(not(feature = "nolog"))]
    pub log: Log,
    pub data: Data,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            debug: false,
            noudp: false,
            nolog: false,
            path: String::from("config.yml"),
            mac: None,
            ip: None,
            username: String::new(),
            password: String::new(),
            dns: Vec::new(),
            host: String::from("s.scut.edu.cn"),
            hostname: String::new(),
            time: NaiveTime::from_hms(7, 0, 0),
            reconnect: 120,
            heartbeat: Heartbeat::default(),
            retry: Retry::default(),
            #[cfg(not(feature = "nolog"))]
            log: Log::default(),
            data: Data::default(),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Reconnect {
    pub allowed_time: String,
    pub seconds: i32,
}

impl Default for Reconnect {
    fn default() -> Self {
        Reconnect {
            allowed_time: String::from("7:00"),
            seconds: 60,
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

#[cfg(not(feature = "nolog"))]
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Log {
    pub enable_console: bool,
    pub enable_file: bool,
    pub file_directory: String,
    pub level: String,
}

#[cfg(not(feature = "nolog"))]
impl Default for Log {
    fn default() -> Self {
        Log {
            enable_console: true,
            enable_file: true,
            file_directory: String::from("./logs"),
            level: String::from("INFO"),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Default)]
pub struct Data {
    pub response_identity: ResponseIdentity,
    pub response_md5_challenge: ResponseMD5Challenge,
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
pub struct ResponseMD5Challenge {
    pub unknown: Vec<u8>,
}

impl Default for ResponseMD5Challenge {
    fn default() -> Self {
        ResponseMD5Challenge {
            unknown: hex::decode("0044612a00").unwrap(),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct MiscInfo {
    pub unknown1: Vec<u8>,
    pub crc32_param: Vec<u8>,
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
            crc32_param: hex::decode("c72f3101").unwrap(),
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
    map.get(k).and_then(|v| v.to_owned().into_str().ok())
}

fn get_int_from_map(map: &HashMap<String, Value>, k: &str) -> Option<i64> {
    map.get(k).and_then(|v| v.to_owned().into_int().ok())
}

fn get_bool_from_map(map: &HashMap<String, Value>, k: &str) -> Option<bool> {
    map.get(k).and_then(|v| v.to_owned().into_bool().ok())
}

fn get_map_from_map(map: &HashMap<String, Value>, k: &str) -> Option<HashMap<String, Value>> {
    map.get(k).and_then(|v| v.to_owned().into_table().ok())
}

fn get_str(matches: &clap::ArgMatches, cfg: &config::Config, k: &str) -> Option<String> {
    let s = matches
        .value_of(k)
        .map(|s| s.to_string())
        .or_else(|| cfg.get_str(k).ok())?;
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

fn get_int(matches: &clap::ArgMatches, cfg: &config::Config, k: &str) -> Option<i64> {
    matches
        .value_of(k)
        .and_then(|s| i64::from_str(s).ok())
        .or_else(|| cfg.get_int(k).ok())
}

impl Settings {
    pub fn new(matches: &clap::ArgMatches) -> Result<(Settings, Config), config::ConfigError> {
        let mut settings = Settings::default();
        settings.debug = matches.is_present("debug");
        settings.noudp = matches.is_present("noudp");
        settings.nolog = matches.is_present("nolog");

        let path = Path::new(
            matches
                .value_of("config")
                .unwrap_or_else(|| settings.path.as_str()),
        );
        if !path.is_file() && std::fs::write(path, DEFAULT_CONFIG_FILE).is_err() {
            error!("Can't create default config file 'config.yml', use default config and command line args.");
        }

        let mut cfg = Config::default();
        cfg.merge(
            config::File::from(path)
                .required(false)
                .format(FileFormat::Yaml),
        )?;
        Ok((settings, cfg))
    }
    pub fn done(&mut self, matches: clap::ArgMatches, cfg: Config) {
        let cfg = &cfg;

        if let Some(s) = get_str(&matches, cfg, "mac") {
            self.mac = Some(MacAddr::from_str(&s).expect("Can't parse MAC address!"));
        }

        if let Some(s) = get_str(&matches, cfg, "ip") {
            self.ip = Some(IpAddr::from_str(&s).expect("Can't parse IP Address!"));
        }

        self.username = get_str(&matches, cfg, "username").expect("Username is REQUIRED!");
        self.password = get_str(&matches, cfg, "password").expect("Password is REQUIRED!");

        if let Some(mut s) = matches.value_of("dns").map(|s| s.to_string()) {
            if (s.contains(']') && !s.contains("]:")) || !s.contains(':') {
                s += ":53";
            }
            self.dns
                .push(SocketAddr::from_str(&s).expect("Can't parse DNS server to socket address!"));
        }
        if let Ok(vs) = cfg.get_array("dns") {
            for v in vs {
                let mut s = v.to_owned().into_str().expect("Invalid DNS server!");
                if (s.contains(']') && !s.contains("]:")) || !s.contains(':') {
                    s += ":53";
                }
                let x =
                    SocketAddr::from_str(&s).expect("Can't parse DNS server to socket address!");
                if !self.dns.contains(&x) {
                    self.dns.push(x);
                }
            }
        }

        if let Some(s) = get_str(&matches, cfg, "host") {
            self.host = s;
        }

        if let Some(s) = get_str(&matches, cfg, "hostname") {
            self.hostname = s;
        } else {
            self.hostname = hostname::get()
                .expect("Can't get current computer host name.")
                .into_string()
                .expect("Can't parse host name to String.");
        }

        if let Some(s) = get_str(&matches, cfg, "time") {
            self.time = NaiveTime::parse_from_str(&s, "%H:%M")
                .expect("Can't parse time String to NativeTime.");
        }

        if let Some(x) = get_int(&matches, cfg, "reconnect") {
            self.reconnect = x as i32;
        }

        if let Ok(map) = cfg.get_table("heartbeat") {
            if let Some(x) = get_int_from_map(&map, "eap_timeout") {
                self.heartbeat.eap_timeout = x as i32;
            }
            if let Some(x) = get_int_from_map(&map, "udp_timeout") {
                self.heartbeat.udp_timeout = x as i32;
            }
        }

        if let Ok(map) = cfg.get_table("retry") {
            if let Some(x) = get_int_from_map(&map, "count") {
                self.retry.count = max(x as i32, self.retry.count);
            }
            if let Some(x) = get_int_from_map(&map, "interval") {
                self.retry.interval = max(x as i32, self.retry.interval);
            }
        }

        #[cfg(not(feature = "nolog"))]
        if let Ok(map) = cfg.get_table("log") {
            if let Some(x) = get_bool_from_map(&map, "enable_console") {
                self.log.enable_console = x;
            }
            if let Some(x) = get_bool_from_map(&map, "enable_file") {
                self.log.enable_file = x;
            }
            if let Some(x) = get_str_from_map(&map, "file_directory") {
                self.log.file_directory = x;
            }
            if let Some(x) = get_str_from_map(&map, "level") {
                self.log.level = x;
            }
        }

        if let Ok(data) = cfg.get_table("data") {
            if let Some(map) = get_map_from_map(&data, "response_identity") {
                if let Some(s) = get_str_from_map(&map, "unknown") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.response_identity.unknown = v;
                    } else {
                        error!("Invalid config: data.response_identity.unknown! Default value instead.")
                    }
                }
            }
            if let Some(map) = get_map_from_map(&data, "response_md5_challenge") {
                if let Some(s) = get_str_from_map(&map, "unknown") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.response_md5_challenge.unknown = v;
                    } else {
                        error!("Invalid config: data.response_md5_challenge.unknown! Default value instead.")
                    }
                }
            }
            if let Some(map) = get_map_from_map(&data, "misc_info") {
                if let Some(s) = get_str_from_map(&map, "unknown1") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.misc_info.unknown1 = v;
                    } else {
                        error!("Invalid config: data.misc_info.unknown1! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "crc32_param") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.misc_info.crc32_param = v;
                    } else {
                        error!("Invalid config: data.misc_info.crc32_param! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "unknown2") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.misc_info.unknown2 = v;
                    } else {
                        error!("Invalid config: data.misc_info.unknown2! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "os_major") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.misc_info.os_major = v;
                    } else {
                        error!("Invalid config: data.misc_info.os_major! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "os_minor") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.misc_info.os_minor = v;
                    } else {
                        error!("Invalid config: data.misc_info.os_minor! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "os_build") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.misc_info.os_build = v;
                    } else {
                        error!("Invalid config: data.misc_info.os_build! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "os_unknown") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.misc_info.os_unknown = v;
                    } else {
                        error!("Invalid config: data.misc_info.os_unknown! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "version") {
                    if let Ok(v) = hex::decode(s) {
                        self.data.misc_info.version = v;
                    } else {
                        error!("Invalid config: data.misc_info.version! Default value instead.")
                    }
                }
                if let Some(s) = get_str_from_map(&map, "hash") {
                    self.data.misc_info.hash = s;
                }
            }
        }
    }
}

const DEFAULT_CONFIG_FILE: &str = "mac:
ip:
username:
password:
dns:
  - 202.38.193.33
  - 222.201.130.30
  - 202.112.17.33
  - 222.201.130.33
host: s.scut.edu.cn
hostname:
time: 7:00
reconnect: 60
heartbeat:
  eap_timeout: 60
  udp_timeout: 12
retry:
  count: 2
  interval: 5000
log:
  enable_console: true
  enable_file: true
  file_directory: ./logs
  level: INFO
data:
  response_identity:
    unknown:
  response_md5_challenge:
    unknown:
  misc_info:
    unknown1:
    crc32_param:
    unknown2:
    os_major:
    os_minor:
    os_build:
    os_unknown:
    version:
    hash:
";

#[test]
fn test_log() {
    error!("error test");
}
