#![feature(ip, array_chunks)]
mod device;
mod eap;
mod logger;
mod settings;
mod socket;
mod udp;
mod util;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use log::{error, info};

use crate::settings::Settings;
use crate::socket::Socket;
use crate::util::{ChannelData, State, sleep_at};

fn main() {
    let settings = &settings::SETTINGS;

    logger::init(settings);

    info!("Start to run...");
    let device =
        device::get_device(settings.mac, settings.ip).expect("Fail on getting ethernet device!");
    info!("Ethernet Device: {}", &device.interface.name);
    info!("MAC address: {}", &device.mac);
    info!("IP Address/Prefix: {}", &device.ip_net);
    info!("Username: {}", settings.username);
    info!("Password: {}", settings.password);
    for dns in &settings.dns {
        info!("DNS Server: {dns}");
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

    #[cfg(feature = "log4rs")]
    {
        info!("Log to console: {}", settings.log.enable_console);
        info!("Log to file: {}", settings.log.enable_file);
        info!("Log File Directory: {}", settings.log.file_directory);
        info!("Log Level: {}", settings.log.level_filter);
    }

    let mac = device.mac;
    let ip = device.ip_net.ip();

    let (tx, rx) = crossbeam_channel::unbounded::<ChannelData>();
    let tx1 = tx.clone();

    let _eap_handle = thread::Builder::new()
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
                                    error!("UDP: Can't create socket and connect to '{udp_ip}'.");
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
    _eap_handle
        .join()
        .expect("Fatal error! EAP Process generator thread quit!");
}
