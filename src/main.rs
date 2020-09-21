// #![allow(unused_must_use, dead_code, unused_variables, unused_imports)]
#![feature(ip)]
extern crate lazy_static;

use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::clap_app;
use log::LevelFilter::{Debug, Info};
use log::{error, info, LevelFilter};

use crate::settings::Settings;
use crate::socket::Socket;
use crate::util::{sleep_at, ChannelData};

mod constants;
mod device;
mod eap;
mod settings;
mod socket;
mod udp;
mod util;

fn init_logger(settings: &Settings) -> log4rs::Handle {
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
    let directory = &settings.log.directory;
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{h([{d(%Y-%m-%d %H:%M:%S)}][{l}][{T}] {m}{n})}",
        )))
        .build();

    let logfile = RollingFileAppender::builder()
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
                        .unwrap(),
                ),
            )),
        )
        .unwrap();

    let level = if settings.debug {
        Debug
    } else {
        LevelFilter::from_str(&*settings.log.level).unwrap_or(Info)
    };

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            Root::builder()
                .appender("stdout")
                .appender("logfile")
                .build(level),
        )
        .unwrap();

    log4rs::init_config(config).unwrap()
}

#[test]
fn test_logger() {
    init_logger(&Settings::default());
    trace!("trace test");
    debug!("debug test");
    info!("info test");
    warn!("warn test");
    error!("error test");
}

fn main() {
    let matches = clap_app!(drcom4scut =>
        (version: "0.1.0")
        (author: "SeaLoong")
        (about: "A 3rd-party Drcom client for SCUT.")
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
    )
        .get_matches();

    let (mut settings, cfg) = settings::Settings::new(&matches).expect("Can't read config file.");
    init_logger(&settings);

    settings.done(matches, cfg);

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
    info!("Reconnect Seconds: {}s", settings.reconnect);
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
    info!("Log Directory: {}", settings.log.directory);
    info!("Log Level: {}", settings.log.level);

    let settings = Arc::new(settings);
    let device = Arc::new(device);

    let (tx, rx) = crossbeam::unbounded::<ChannelData>();

    let tx1 = tx.clone();
    let mac = device.mac;
    let ip = device.ip_net.ip();
    let settings1 = settings.clone();
    let device1 = device.clone();
    let eap_handle = thread::Builder::new()
        .name("EAP-Process-Generator".to_owned())
        .spawn(move || {
            let mut broke = false;
            loop {
                let settings = settings1.clone();
                let mut device = device1.clone();
                if broke {
                    info!("Try get the property ethernet device.");
                    loop {
                        match device::get_device(Some(mac), Some(ip)) {
                            Ok(d) => {
                                device = Arc::new(d);
                                break;
                            }
                            Err(e) => {
                                error!("Can't get ethernet device, try again in {} second(s) : {}", settings1.reconnect, e);
                                thread::sleep(Duration::from_secs(settings1.reconnect as u64));
                            }
                        }
                    }
                }
                let tx = tx1.clone();
                thread::Builder::new()
                    .name("EAP-Process".to_owned())
                    .spawn(move || {
                        let settings = settings.clone();
                        info!("Create EAP Process.");
                        let mut eap_process = eap::Process::new(settings.clone(), device.clone(), tx);
                        info!("Start EAP Process.");
                        loop {
                            match eap_process.start() {
                                constants::state::SLEEP => {
                                    error!("Will try reconnect at the next {}.", settings.time);
                                    if sleep_at(settings.time).is_some() {
                                        continue;
                                    }
                                    error!(
                                        "Can't create a valid DateTime! Will try reconnect in {} second(s).",
                                        settings.reconnect
                                    );
                                }
                                constants::state::QUIT => {
                                    break;
                                }
                                _ => {
                                    error!(
                                        "Failed at 802.1X Authorization! Will try reconnect in {} second(s).",
                                        settings.reconnect
                                    );
                                }
                            }
                            thread::sleep(Duration::from_secs(settings.reconnect as u64));
                        }
                        info!("Quit EAP Process.");
                    })
                    .expect("Can't create EAP Process thread!")
                    .join()
                    .expect("Unexpected error at EAP Process thread!");

                error!(
                    "Fatal error at EAP Process thread! Will try restart in {} second(s).",
                    settings1.reconnect
                );
                thread::sleep(Duration::from_secs(settings1.reconnect as u64));
                broke = true;
            }
        })
        .expect("Can't create EAP Process generator thread!");
    if settings.no_udp {
        info!("UDP Process is disabled.")
    } else {
        let tx = tx.clone();
        loop {
            match rx.recv() {
                Ok(x) => match x.state {
                    constants::state::SUCCESS => {
                        tx.send(x).expect("Can't send initial SUCCESS!");
                        break;
                    }
                    _ => (),
                },
                Err(_) => {
                    panic!("Unexpected! EAPtoUDP channel is closed.");
                }
            }
        }
        let mac = device.mac;
        let ip = device.ip_net.ip();
        let udp_handle = thread::Builder::new()
            .name("UDP-Process-Generator".to_owned())
            .spawn(move || {
                loop {
                    let settings2 = settings.clone();
                    let rx = rx.clone();
                    thread::Builder::new()
                        .name("UDP-Process".to_owned())
                        .spawn(move || {
                            let settings = settings2.clone();
                            let (udp_ip, dns) = match socket::resolve_dns(&settings) {
                                Some(r) => r,
                                None => {
                                    error!("UDP: Can't resolve '{}'.", &settings.host);
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
                                settings.clone(),
                                Arc::new(socket),
                                rx,
                                mac,
                                ip,
                                dns,
                            );
                            info!("Start UDP Process.");
                            loop {
                                match udp_process.start() {
                                    constants::state::SLEEP => {
                                        error!(
                                            "Will try restart UDP heartbeat at the next {}.",
                                            settings.time
                                        );
                                        if sleep_at(settings.time).is_some() {
                                            continue;
                                        }
                                        error!("Can't create a valid DateTime! Will try reconnect in {} second(s).", settings.reconnect);
                                    }
                                    constants::state::QUIT => {
                                        break;
                                    }
                                    _ => {
                                        error!(
                                            "Failed at UDP Process! Will try reconnect in {} second(s).",
                                            settings.reconnect
                                        );
                                    }
                                }
                                thread::sleep(Duration::from_secs(settings.reconnect as u64));
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
                    thread::sleep(Duration::from_secs(settings.reconnect as u64));
                }
            })
            .expect("Can't create UDP Process generator thread!");
        // tx.send(channel_data.unwrap())
        //     .expect("Can't send initial SUCCESS!");
        udp_handle
            .join()
            .expect("Fatal error! UDP Process generator thread quit!");
    }
    eap_handle
        .join()
        .expect("Fatal error! EAP Process generator thread quit!");
}
