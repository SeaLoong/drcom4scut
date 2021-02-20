#![feature(ip, once_cell)]
mod device;
mod eap;
mod macros;
mod settings;
mod socket;
mod udp;
mod util;

use std::lazy::SyncLazy;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::{clap_app, crate_authors, crate_description, crate_name, crate_version, ArgMatches};

use crate::settings::Settings;
use crate::socket::Socket;
use crate::util::{sleep_at, ChannelData, State};

#[cfg(feature = "enablelog")]
use log::LevelFilter::{self, Debug, Info};
#[cfg(feature = "enablelog")]
use log::{debug, error, info, trace, warn};

#[cfg(feature = "enablelog")]
fn init_logger(settings: &Settings) {
    if !settings.debug && settings.nolog {
        return;
    }
    use log4rs::{
        append::{
            console::ConsoleAppender,
            rolling_file::{
                policy::compound::{
                    roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger,
                    CompoundPolicy,
                },
                RollingFileAppender,
            },
        },
        config::{Appender, Config, Root},
        encode::pattern::PatternEncoder,
    };
    let stdout = if settings.debug || settings.log.enable_console {
        Some(
            ConsoleAppender::builder()
                .encoder(Box::new(PatternEncoder::new(
                    "{h([{d(%Y-%m-%d %H:%M:%S)}][{l}][{T}] {m}{n})}",
                )))
                .build(),
        )
    } else {
        None
    };
    let logfile = if settings.log.enable_file {
        let directory = &settings.log.file_directory;
        Some(
            RollingFileAppender::builder()
                .encoder(Box::new(PatternEncoder::new(
                    "[{d(%Y-%m-%d %H:%M:%S)}][{l}][{T}][{M}:{L}] {m}{n}",
                )))
                .build(
                    directory.clone() + "/latest.log",
                    Box::new(CompoundPolicy::new(
                        Box::new(SizeTrigger::new(1 << 20)),
                        Box::new(
                            FixedWindowRoller::builder()
                                .base(1)
                                .build(&(directory.clone() + "/log-{}.gz"), 10)
                                .expect("Can't build FixedWindowRoller!"),
                        ),
                    )),
                )
                .expect("Can't build RollingFileAppender!"),
        )
    } else {
        None
    };

    if stdout.is_none() && logfile.is_none() {
        return;
    }

    let level = if settings.debug {
        Debug
    } else {
        LevelFilter::from_str(&settings.log.level).unwrap_or(Info)
    };

    let mut config = Config::builder();
    let mut root = Root::builder();
    if let Some(stdout) = stdout {
        config = config.appender(Appender::builder().build("stdout", Box::new(stdout)));
        root = root.appender("stdout");
    }
    if let Some(logfile) = logfile {
        config = config.appender(Appender::builder().build("logfile", Box::new(logfile)));
        root = root.appender("logfile");
    }

    let config = config
        .build(root.build(level))
        .expect("Can't build log config!");

    log4rs::init_config(config).expect("Can't init log config!");
}

#[test]
fn test_logger() {
    #[cfg(feature = "enablelog")]
    init_logger(&Settings::default());
    trace!("trace test");
    debug!("debug test");
    info!("info test");
    warn!("warn test");
    error!("error test");
}

fn get_matches<'a>() -> ArgMatches<'a> {
    use clap::*;
    let app = clap_app!((crate_name!()) =>
        (version: crate_version!())
        (author: crate_authors!())
        (about: crate_description!())
        (@arg debug: --debug "Enable debug mode.")
        (@arg config: -c --config +takes_value "(Optional) Path to config file. Some settings only can be set by config file.")
        (@arg mac: -m --mac +takes_value "(Optional) Ethernet Device MAC address.")
        (@arg ip: -i --ip +takes_value "(Optional) IP address of the selected Ethernet Device.")
        (@arg username: -u --username +takes_value "Username to authorize.")
        (@arg password: -p --password +takes_value "Password to authorize.")
        (@arg dns: -d --dns +takes_value "(Optional) DNS server. If more than one, you can add the remain DNS servers to config file.")
        (@arg host: -H --host +takes_value "(Optional) Host to connect UDP server. Default value is 's.scut.edu.cn'.")
        (@arg hostname: -N --hostname +takes_value "(Optional) Default value is current computer host name.")
        (@arg time: -t --time +takes_value "(Optional) Time to reconnect automatically after you are not allowed to access Internet. Default value is 7:00.")
        (@arg noudp: --noudp "Disable UDP Process.")
    );
    #[cfg(feature = "enablelog")]
    let app = app.arg(clap::Arg::with_name("nolog").long("nolog").help(
        "Disable logger, no any output at all, unless PANIC or EXCEPTION of program occurred.",
    ));

    app.get_matches()
}

static SETTINGS: SyncLazy<Settings> = SyncLazy::new(|| {
    let matches = get_matches();
    let (mut set, cfg) = settings::Settings::new(&matches).expect("Can't read config file.");
    set.done(matches, cfg);
    set
});

fn main() {
    let settings = &SETTINGS;

    #[cfg(feature = "enablelog")]
    init_logger(settings);

    info!("Start to run...");
    let device =
        device::get_device(settings.mac, settings.ip).expect("Fail on getting ethernet device!");
    info!("Ethernet Device: {}", &device.interface.name);
    info!("MAC address: {}", &device.mac);
    info!("IP Address/Prefix: {}", &device.ip_net);
    info!("Username: {}", settings.username);
    info!("Password: {}", settings.password);
    for dns in &settings.dns {
        info!("DNS Server: {}", dns);
    }
    info!("Host: {}", settings.host);
    info!("Hostname: {}", settings.hostname);
    info!("Time to wake up: {}", settings.time);
    info!("Reconnect Interval: {}s", settings.reconnect);
    info!(
        "Heartbeat timeout of EAP: {}s",
        settings.heartbeat.eap_timeout
    );
    info!(
        "Heartbeat timeout of UDP: {}s",
        settings.heartbeat.udp_timeout
    );
    info!("Retry Count: {}", settings.retry.count);
    info!("Retry Interval: {}ms", settings.retry.interval);

    #[cfg(feature = "enablelog")]
    {
        info!("Log to console: {}", settings.log.enable_console);
        info!("Log to file: {}", settings.log.enable_file);
        info!("Log File Directory: {}", settings.log.file_directory);
        info!("Log Level: {}", settings.log.level);
    }

    let mac = device.mac;
    let ip = device.ip_net.ip();

    let (tx, rx) = crossbeam_channel::unbounded::<ChannelData>();
    let tx1 = tx.clone();

    let eap_handle = thread::Builder::new()
        .name("EAP-Process-Generator".to_owned())
        .spawn(move || {
            let device = Arc::new(device);
            let mut broke = false;
            loop {
                let mut device = device.clone();
                if broke {
                    info!("Try get the property ethernet device.");
                    loop {
                        match device::get_device(Some(mac), Some(ip)) {
                            Ok(d) => {
                                device = Arc::new(d);
                                break;
                            }
                            Err(e) => {
                                error!("Can't get ethernet device, try again in {} second(s) : {}", settings.reconnect, e);
                                thread::sleep(Duration::from_secs(settings.reconnect));
                            }
                        }
                    }
                }
                let tx = tx1.clone();
                thread::Builder::new()
                    .name("EAP-Process".to_owned())
                    .spawn(move || {
                        info!("Create EAP Process.");
                        let mut eap_process = eap::Process::new(settings, device, tx);
                        info!("Start EAP Process.");
                        loop {
                            match eap_process.start() {
                                State::Sleep => {
                                    error!("Will try reconnect at the next {}.", settings.time);
                                    if sleep_at(settings.time).is_some() {
                                        continue;
                                    }
                                    error!(
                                        "Can't create a valid DateTime! Will try reconnect in {} second(s).",
                                        settings.reconnect
                                    );
                                }
                                State::Quit => {
                                    break;
                                }
                                _ => {
                                    error!(
                                        "Failed at 802.1X Authorization! Will try reconnect in {} second(s).",
                                        settings.reconnect
                                    );
                                }
                            }
                            thread::sleep(Duration::from_secs(settings.reconnect));
                        }
                        info!("Quit EAP Process.");
                    })
                    .expect("Can't create EAP Process thread!")
                    .join()
                    .expect("Unexpected error at EAP Process thread!");

                error!(
                    "Fatal error at EAP Process thread! Will try restart in {} second(s).",
                    settings.reconnect
                );
                thread::sleep(Duration::from_secs(settings.reconnect));
                broke = true;
            }
        })
        .expect("Can't create EAP Process generator thread!");
    if settings.noudp {
        info!("UDP Process is disabled.");
    } else {
        loop {
            let rx_recv = rx.recv().expect("Unexpected! EAPtoUDP channel is closed.");
            if State::Success == rx_recv.state {
                tx.send(rx_recv).expect("Can't send initial SUCCESS!");
                break;
            }
        }

        let udp_handle = thread::Builder::new()
            .name("UDP-Process-Generator".to_owned())
            .spawn(move || {
                loop {
                    let rx = rx.clone();
                    thread::Builder::new()
                        .name("UDP-Process".to_owned())
                        .spawn(move || {
                            let (udp_ip, dns) = match socket::resolve_dns(settings) {
                                Some(r) => r,
                                None => {
                                    error!("UDP: Can't resolve '{}'.", settings.host);
                                    return;
                                }
                            };
                            let socket = Socket::new(match socket::socket_bind(udp_ip) {
                                Some(socket) => socket,
                                None => {
                                    error!("UDP: Can't create socket and connect to '{}'.", udp_ip);
                                    return;
                                }
                            });
                            info!("Create UDP Process.");
                            let mut udp_process = udp::Process::new(
                                settings,
                                Arc::new(socket),
                                rx,
                                mac,
                                ip,
                                dns,
                            );
                            info!("Start UDP Process.");
                            loop {
                                match udp_process.start() {
                                    State::Sleep => {
                                        error!(
                                            "Will try restart UDP heartbeat at the next {}.",
                                            settings.time
                                        );
                                        if sleep_at(settings.time).is_some() {
                                            continue;
                                        }
                                        error!("Can't create a valid DateTime! Will try reconnect in {} second(s).", settings.reconnect);
                                    }
                                    State::Quit => {
                                        break;
                                    }
                                    _ => {
                                        error!(
                                            "Failed at UDP Process! Will try reconnect in {} second(s).",
                                            settings.reconnect
                                        );
                                    }
                                }
                                thread::sleep(Duration::from_secs(settings.reconnect));
                            }
                            info!("Quit UDP Process.");
                        })
                        .expect("Can't create UDP Process thread!")
                        .join()
                        .expect("Unexpected Error!");
                    error!(
                        "Fatal error at UDP Process thread! Will try restart in {} second(s).",
                        settings.reconnect
                    );
                    thread::sleep(Duration::from_secs(settings.reconnect));
                }
            })
            .expect("Can't create UDP Process generator thread!");
        udp_handle
            .join()
            .expect("Fatal error! UDP Process generator thread quit!");
    }
    eap_handle
        .join()
        .expect("Fatal error! EAP Process generator thread quit!");
}
