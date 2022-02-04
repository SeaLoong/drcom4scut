#![feature(ip, once_cell)]
mod device;
mod eap;
mod settings;
mod socket;
mod udp;
mod util;

use std::lazy::SyncLazy;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::ArgMatches;
use log::{error, info, LevelFilter};

use crate::settings::Settings;
use crate::socket::Socket;
use crate::util::{sleep_at, ChannelData, State};

fn init_logger(settings: &Settings) {
    if let LevelFilter::Off = settings.log.level_filter {
        return;
    }
    #[cfg(feature = "enablelog")]
    init_log4rs(settings);
}
#[cfg(feature = "enablelog")]
fn init_log4rs(settings: &Settings) {
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
        .build(root.build(settings.log.level_filter))
        .expect("Can't build log config!");

    log4rs::init_config(config).expect("Can't init log config!");
}

#[test]
fn test_logger() {
    use log::{debug, error, info, trace, warn};
    #[cfg(feature = "enablelog")]
    init_logger(&Settings::default());
    trace!("trace test");
    debug!("debug test");
    info!("info test");
    warn!("warn test");
    error!("error test");
}
// 若改为声明式api
// example
// use clap::Parser;
// #[derive(Parser, Debug, Clone)]
// #[clap(author, version, about)]
// struct Args {
//     /// Enable debug mode.
//     #[clap(long)]
//     debug: bool,
//     /// Path to config file. Some settings only can be set by config file.
//     #[clap(long, short)]
//     config: Option<String>,
//     /// Ethernet Device MAC address.
//     #[clap(long, short)]
//     mac: Option<String>,
//     /// IP address of the selected Ethernet Device.
//     #[clap(long, short)]
//     ip: Option<String>,
//     /// Username to authorize.
//     #[clap(long, short)]
//     username: String,
//     /// Password to authorize.
//     #[clap(long, short)]
//     password: String,
//     /// DNS server. If more than one, you can add the remain DNS servers to config file.
//     #[clap(long, short)]
//     dns: Option<String>,
//     /// Host to connect UDP server. Default value is 's.scut.edu.cn'.
//     #[clap(long, short = 'H')]
//     host: Option<String>,
//     /// Default value is current computer host name.
//     #[clap(long, short = 'N')]
//     hostname: Option<String>,
//     /// Time to reconnect automatically after you are not allowed to access Internet. Default value is 7:00.
//     #[clap(long, short)]
//     time: Option<String>,
//     /// Disable UDP Process.
//     #[clap(long)]
//     noudp: bool,
//     /// Disable logger, no any output at all, unless PANIC or EXCEPTION of program occurred.
//     #[clap(long)]
//     nolog: bool,
// }

fn get_matches() -> ArgMatches {
    use clap::*;
    let app=app_from_crate!()
    .version(crate_version!())
    .author(crate_authors!())
    .about(crate_description!())
    .args(&[
        arg!(--debug "Enable debug mode."),
        arg!(--noudp "Disable UDP Process."),
        arg!(--nolog "Disable logger, no any output at all, unless PANIC or EXCEPTION of program occurred."),
        arg!(-c --config <config> "Path to config file. Some settings only can be set by config file.").required(false),
        arg!(-m --mac <mac> "Ethernet Device MAC address.").required(false),
        arg!(-i --ip <ip> "IP address of the selected Ethernet Device.").required(false),
        arg!(-u --username <username> "Username to authorize.").required(false),
        arg!(-p --password <password> "Password to authorize.").required(false),
        arg!(-d --dns <dns> "DNS server. If more than one, you can add the remain DNS servers to config file.").required(false),
        arg!(-H --host <host> "Host to connect UDP server. Default value is 's.scut.edu.cn'.").required(false),
        arg!(-N --hostname <hostname> "Default value is current computer host name.").required(false),
        arg!(-t --time <time> "Time to reconnect automatically after you are not allowed to access Internet. Default value is 7:00.").required(false),
    ]);
    app.get_matches()
}

static SETTINGS: SyncLazy<Settings> = SyncLazy::new(|| {
    let matches = get_matches();
    let mut set = settings::Settings::new(&matches);
    let cfg = set.read_config().expect("Can't read config file.");
    set.done(&matches, &cfg);
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

    info!("Log to console: {}", settings.log.enable_console);
    info!("Log to file: {}", settings.log.enable_file);
    info!("Log File Directory: {}", settings.log.file_directory);
    info!("Log Level: {}", settings.log.level_filter);

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
            if let State::Success = rx_recv.state {
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
