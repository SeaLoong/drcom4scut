use std::cmp::min;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle, Thread};
use std::time::Duration;

use bytes::BytesMut;
use chrono::Local;
use crossbeam::channel::TryRecvError;
use crossbeam::channel::{Receiver, Sender};
use pnet::datalink::MacAddr;

use crate::settings::Settings;
use crate::socket::Socket;
use crate::udp::packet::{
    decrypt_info, Alive, HeaderType, HeartbeatType, MiscAlive, MiscHeartbeat1, MiscHeartbeat3,
    MiscInfo,
};
use crate::util::{self, random_vec, sleep, ChannelData, State};

#[cfg(not(feature = "enablelog"))]
use crate::{debug, error, info};
#[cfg(feature = "enablelog")]
use log::{debug, error, info};

mod packet;

#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
struct ProcessData {
    counter: u8,
    rnd: Vec<u8>,
    cks_md5: Vec<u8>,
    flux: Vec<u8>,
    decrypted_from_misc_response_info: Vec<u8>,
}

pub struct Process<'a> {
    mac: MacAddr,
    ip: IpAddr,
    dns: SocketAddr,
    settings: &'a Settings,
    socket: Arc<Socket>,
    rx: Receiver<ChannelData>,
    alive: Arc<AtomicBool>,
    timeout: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    sleep: Arc<AtomicBool>,
    data: Arc<RwLock<ProcessData>>,
    receive_channel: Option<Receiver<Vec<u8>>>,
    send_channel: Option<Sender<(Vec<u8>, bool)>>,
    send_ts: Arc<AtomicI64>,
    cancel_resend: Arc<AtomicBool>,
    receiver_handle: Option<Arc<JoinHandle<()>>>,
    resender_handle: Option<Arc<JoinHandle<()>>>,
    sender_handle: Option<Arc<JoinHandle<()>>>,
    receiving_eap_handle: Option<Arc<JoinHandle<()>>>,
    heartbeat_handle: Option<Arc<JoinHandle<()>>>,
    thread: Arc<Thread>,
}

impl<'a> Process<'a> {
    pub fn new(
        settings: &'a Settings,
        socket: Arc<Socket>,
        rx: Receiver<ChannelData>,
        mac: MacAddr,
        ip: IpAddr,
        dns: SocketAddr,
    ) -> Process<'a> {
        Process {
            alive: Arc::new(AtomicBool::new(false)),
            timeout: Arc::new(AtomicU8::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
            quit: Arc::new(AtomicBool::new(false)),
            sleep: Arc::new(AtomicBool::new(false)),
            data: Arc::new(RwLock::new(ProcessData::default())),
            receive_channel: None,
            send_channel: None,
            send_ts: Arc::new(AtomicI64::new(0)),
            cancel_resend: Arc::new(AtomicBool::new(true)),
            settings,
            socket,
            rx,
            mac,
            ip,
            dns,
            resender_handle: None,
            sender_handle: None,
            receiving_eap_handle: None,
            heartbeat_handle: None,
            thread: Arc::new(thread::current()),
            receiver_handle: None,
        }
    }

    fn start_receive_thread(&mut self) {
        if let Some(handle) = &self.receiver_handle {
            handle.thread().unpark();
            return;
        }
        let (tx, rx) = crossbeam::channel::unbounded::<Vec<u8>>();
        self.receive_channel = Some(rx);
        let quit = self.quit.clone();
        let stop = self.stop.clone();
        let count = self.settings.retry.count;
        let interval = self.settings.retry.interval;
        let socket = self.socket.clone();
        self.receiver_handle = Some(Arc::new(
            thread::Builder::new()
                .name("UDP-Receiver".to_owned())
                .spawn(move || {
                    let duration = Duration::from_millis(interval as u64);
                    let mut cnt = 0;
                    loop {
                        if quit.load(Ordering::Relaxed) {
                            debug!("UDP-Receiver thread quit!");
                            return;
                        }
                        if stop.load(Ordering::Relaxed) {
                            thread::park();
                        }
                        match socket.receive() {
                            Ok(v) => {
                                cnt = 0;
                                if tx.send(v).is_err() {
                                    error!("Unexpected! Receive channel is disconnected!");
                                    quit.store(true, Ordering::Release);
                                }
                            }
                            Err(e) => {
                                error!("Receive error: {}", e);
                                cnt += 1;
                                if cnt > count {
                                    quit.store(true, Ordering::Release);
                                } else {
                                    thread::sleep(duration);
                                }
                            }
                        }
                    }
                })
                .expect("Can't create UDP-Receiver thread."),
        ));
    }

    fn start_send_thread(&mut self) {
        if let Some(handle) = &self.resender_handle {
            handle.thread().unpark();
            if let Some(handle) = &self.sender_handle {
                handle.thread().unpark();
            }
            return;
        }
        let (tx, rx) = crossbeam::channel::unbounded::<(Vec<u8>, bool)>();
        self.send_channel = Some(tx.clone());
        let quit = self.quit.clone();
        let stop = self.stop.clone();
        let interval = self.settings.retry.interval;
        let send_ts = self.send_ts.clone();
        let cancel_resend = self.cancel_resend.clone();
        let resender_handle = Arc::new(
            thread::Builder::new()
                .name("UDP-ReSender".to_owned())
                .spawn(move || loop {
                    if quit.load(Ordering::Relaxed) {
                        debug!("UDP-Resender thread quit!");
                        return;
                    }
                    if stop.load(Ordering::Relaxed) {
                        thread::park();
                    }
                    while cancel_resend.load(Ordering::Acquire) {
                        thread::park();
                    }
                    let wait_ts = send_ts.load(Ordering::Acquire) - Local::now().timestamp_millis()
                        + (interval as i64);
                    if wait_ts > 0 {
                        thread::sleep(Duration::from_millis(wait_ts as u64));
                    } else if wait_ts > -interval as i64 {
                        debug!("Resending...");
                        cancel_resend.store(true, Ordering::Release);
                        if tx.send((Vec::new(), true)).is_err() {
                            error!("Unexpected! Send channel is disconnected!");
                            quit.store(true, Ordering::Release);
                        }
                    }
                })
                .expect("Can't create UDP-ReSender thread."),
        );
        self.resender_handle = Some(resender_handle.clone());
        let quit = self.quit.clone();
        let stop = self.stop.clone();
        let socket = self.socket.clone();
        let count = self.settings.retry.count;
        let interval = self.settings.retry.interval;
        let send_ts = self.send_ts.clone();
        let cancel_resend = self.cancel_resend.clone();
        self.sender_handle = Some(Arc::new(
            thread::Builder::new()
                .name("UDP-Sender".to_owned())
                .spawn(move || {
                    let duration = Duration::from_millis(interval as u64);
                    let mut data = Vec::new();
                    let mut resend = false;
                    loop {
                        if quit.load(Ordering::Relaxed) {
                            debug!("UDP-Sender thread quit!");
                            return;
                        }
                        if stop.load(Ordering::Relaxed) {
                            thread::park();
                        }
                        match rx.recv() {
                            Ok((v, b)) => {
                                debug!("Sender received.");
                                if !v.is_empty() {
                                    data = v;
                                    resend = b;
                                }
                            }
                            Err(_) => {
                                quit.store(true, Ordering::Release);
                                error!("Unexpected! Send channel is disconnected!");
                                continue;
                            }
                        }
                        let mut cnt = 0;
                        loop {
                            if quit.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                                break;
                            }
                            debug!("Sender is sending packet: {}", hex::encode(&data[..]));
                            match socket.send(data.clone()) {
                                Ok(_) => {
                                    send_ts
                                        .store(Local::now().timestamp_millis(), Ordering::Release);
                                    cancel_resend.store(!resend, Ordering::Release);
                                    if resend {
                                        resender_handle.thread().unpark();
                                    }
                                    break;
                                }
                                Err(e) => {
                                    error!("Send error: {}", e);
                                    cnt += 1;
                                    if cnt > count {
                                        quit.store(true, Ordering::Release);
                                    } else {
                                        thread::sleep(duration);
                                    }
                                }
                            }
                        }
                        debug!("Sender sent packet.");
                    }
                })
                .expect("Can't create UDP-Sender thread."),
        ));
    }

    fn receive(&self) -> Option<Vec<u8>> {
        let channel = self.receive_channel.as_ref().unwrap();
        match channel.try_recv() {
            Ok(v) => Some(v),
            Err(TryRecvError::Disconnected) => {
                self.quit.store(true, Ordering::Release);
                error!("Unexpected! Receive channel is disconnected!");
                None
            }
            Err(TryRecvError::Empty) => None,
        }
    }

    fn send(&self, data: Vec<u8>, resend: bool) {
        let channel = self.send_channel.as_ref().unwrap();
        debug!("Will blocking send...");
        if channel.send((data, resend)).is_err() {
            self.quit.store(true, Ordering::Release);
            error!("Unexpected! Send channel is disconnected!");
            return;
        }
        debug!("Sent.");
    }

    fn start_receive_eap_thread(&mut self) {
        if let Some(handle) = &self.receiving_eap_handle {
            handle.thread().unpark();
            return;
        }
        info!("Start to receive message from EAP.");
        let quit = self.quit.clone();
        let stop = self.stop.clone();
        let sleep = self.sleep.clone();
        let rx = self.rx.clone();
        let data = self.data.clone();
        let thread = self.thread.clone();
        self.receiving_eap_handle = Some(Arc::new(
            thread::Builder::new()
                .name("EAPtoUDP".to_owned())
                .spawn(move || loop {
                    if quit.load(Ordering::Relaxed) {
                        info!("Stop receiving message from EAP.");
                        debug!("EAPtoUDP thread quit!");
                        return;
                    }
                    if stop.load(Ordering::Relaxed) {
                        thread.unpark();
                        thread::park();
                    }
                    match rx.recv() {
                        Ok(x) => match x.state {
                            State::Suceess => {
                                info!("Receive SUCCESS from EAP.");
                                loop {
                                    if let Ok(mut r) = data.try_write() {
                                        r.cks_md5 = x.data;
                                        info!("cks_md5(md5): {}", hex::encode(&r.cks_md5));
                                        break;
                                    }
                                    util::sleep();
                                }
                                thread.unpark();
                            }
                            State::Stop => {
                                info!("Receive STOP from EAP.");
                                stop.store(true, Ordering::Release);
                            }
                            State::Sleep => {
                                info!("Receive SLEEP from EAP.");
                                sleep.store(true, Ordering::Release);
                                stop.store(true, Ordering::Release);
                            }
                            State::Quit => {
                                info!("Receive QUIT from EAP.");
                                quit.store(true, Ordering::Release);
                            }
                        },
                        Err(_) => {
                            error!("Unexpected! EAPtoUDP channel is closed.");
                            quit.store(true, Ordering::Release);
                        }
                    }
                })
                .expect("Can't create EAPtoUDP thread."),
        ));
    }

    fn cancel_resend(&self) {
        self.cancel_resend.store(true, Ordering::Release);
    }

    pub fn start(&mut self) -> State {
        self.thread = Arc::new(thread::current());
        self.stop.store(false, Ordering::Release);
        self.start_receive_eap_thread();
        self.start_receive_thread();
        self.start_send_thread();
        self.login_start();
        while !self.stop.load(Ordering::Relaxed) {
            if self.quit.load(Ordering::Relaxed) {
                debug!("UDP-Process thread quit!");
                self.start_receive_eap_thread();
                self.start_receive_thread();
                self.start_send_thread();
                self.start_heartbeat_thread();
                return State::Quit;
            }
            if self
                .alive
                .compare_exchange(true, false, Ordering::Acquire, Ordering::Acquire)
                == Ok(true)
            {
                self.send_alive();
            }
            let raw = match self.receive() {
                Some(v) => v,
                None => {
                    sleep();
                    continue;
                }
            };
            debug!("Receive packet: {}", hex::encode(&raw[..]));
            match HeaderType::from_vec(&raw[..]) {
                HeaderType::Invalid => continue,
                HeaderType::Unknown => error!("Unknown packet: {}", hex::encode(&raw[..])),
                HeaderType::UnknownMisc => error!("Unknown Misc packet: {}", hex::encode(&raw[..])),
                HeaderType::UnknownMessage => {
                    error!("Unknown Message packet: {}", hex::encode(&raw[..]))
                }
                HeaderType::MiscAlive => {
                    error!("Unexpected packet MiscAlive: {}", hex::encode(&raw[..]))
                }
                HeaderType::MiscResponseAlive => {
                    self.cancel_resend();
                    info!("Receive MiscResponseAlive.");
                    loop {
                        if let Ok(mut r) = self.data.try_write() {
                            r.flux = Vec::from(&raw[8..12]);
                            break;
                        }
                        sleep();
                    }
                    self.send_misc_info();
                }
                HeaderType::MiscInfo => {
                    error!("Unexpected packet MiscInfo: {}", hex::encode(&raw[..]))
                }
                HeaderType::MiscResponseInfo => {
                    self.cancel_resend();
                    info!("Receive MiscResponseInfo.");
                    self.on_response_info(raw);
                }
                HeaderType::MiscHeartbeat => {
                    self.cancel_resend();
                    match HeartbeatType::from_vec(&raw[..]).0 {
                        2 => {
                            info!("Receive MiscHeartbeat2.");
                            loop {
                                if let Ok(mut r) = self.data.try_write() {
                                    r.flux = Vec::from(&raw[16..20]);
                                    break;
                                }
                                sleep();
                            }
                            self.send_misc_heartbeat_3();
                        }
                        4 => {
                            info!("Receive MiscHeartbeat4.");
                            self.timeout.store(0, Ordering::Release);
                            info!("Heartbeat done.");
                        }
                        x => error!(
                            "Unexpected packet MiscHeartbeat Type{}: {}",
                            x,
                            hex::encode(&raw[..])
                        ),
                    }
                }
                HeaderType::MiscResponseHeartbeatAlive => {
                    self.cancel_resend();
                    info!("Receive MiscResponseHeartbeatAlive.");
                    self.send_misc_heartbeat_1();
                }
                HeaderType::MessageServerInformation => {
                    let (s, _) = encoding_rs::GB18030.decode_without_bom_handling(&raw[4..]);
                    info!("Server Information: {}", s);
                }
            }
        }
        if self.sleep.load(Ordering::Relaxed) {
            State::Sleep
        } else {
            State::Stop
        }
    }

    #[inline]
    fn login_start(&mut self) {
        self.alive.store(false, Ordering::Release);
        self.timeout.store(0, Ordering::Release);
        self.sleep.store(false, Ordering::Release);
        self.send_ts.store(0, Ordering::Release);
        info!("Waiting SUCCESS message from EAP.");
        thread::park();
        self.send_misc_alive()
    }

    fn on_response_info(&mut self, raw: Vec<u8>) {
        let mut v = raw[16..32].to_vec();
        decrypt_info(&mut v);
        loop {
            if let Ok(mut r) = self.data.try_write() {
                r.decrypted_from_misc_response_info = v;
                break;
            }
            sleep();
        }
        self.start_heartbeat_thread();
    }

    fn start_heartbeat_thread(&mut self) {
        if let Some(handle) = &self.heartbeat_handle {
            handle.thread().unpark();
            return;
        }
        let quit = self.quit.clone();
        let stop = self.stop.clone();
        let alive = self.alive.clone();
        let timeout = self.timeout.clone();
        let udp_timeout = self.settings.heartbeat.udp_timeout;
        let count = min(self.settings.retry.count, u8::MAX as i32) as u8;
        self.heartbeat_handle = Some(Arc::new(thread::Builder::new().name("UDP-Heartbeat".to_owned()).spawn(move || {
            let duration = std::time::Duration::from_secs(udp_timeout as u64);
            loop {
                if quit.load(Ordering::Relaxed) {
                    debug!("UDP-Heartbeat thread quit!");
                    return;
                }
                if stop.load(Ordering::Relaxed) {
                    thread::park();
                }
                alive.store(true, Ordering::Release);
                thread::sleep(duration);
                let mut cnt = timeout.load(Ordering::Relaxed);
                if cnt > count {
                    error!("Heartbeat timeout. No Misc Heartbeat packet received for {}s, but ignored.", udp_timeout * cnt as i32);
                    cnt = 0;
                }
                timeout.store(cnt + 1, Ordering::Release);
            }
        }).expect("Can't create UDP-Heartbeat thread.")));
    }

    fn send_misc_alive(&mut self) {
        info!("Send MiscAlive.");
        let data = &mut BytesMut::with_capacity(8);
        MiscAlive::append_to(data);
        self.send(data.to_vec(), true)
    }

    fn send_misc_info(&mut self) {
        info!("Send MiscInfo.");
        let data = &mut BytesMut::with_capacity(244);
        let settings = &self.settings;
        let fixed = &settings.data.misc_info;
        loop {
            if let Ok(mut dt) = self.data.try_write() {
                let cks = (MiscInfo {
                    mac: self.mac,
                    ip: self.ip,
                    unknown1: fixed.unknown1.clone(),
                    flux: dt.flux.clone(),
                    cks32_param: fixed.cks32_param.clone(),
                    username: settings.username.clone(),
                    hostname: settings.hostname.clone(),
                    dns1: self.dns.ip(),
                    dns2: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    unknown2: fixed.unknown2.clone(),
                    os_major: fixed.os_major.clone(),
                    os_minor: fixed.os_minor.clone(),
                    os_build: fixed.os_build.clone(),
                    os_unknown: fixed.os_unknown.clone(),
                    version: fixed.version.clone(),
                    hash: fixed.hash.clone(),
                })
                .append_to(data);
                info!("calculate cks and apply to md5.");
                let cks_array = cks.to_le_bytes();
                dt.cks_md5[..cks_array.len()].copy_from_slice(&cks_array);
                break;
            }
            sleep();
        }
        self.send(data.to_vec(), true)
    }

    fn send_misc_heartbeat_1(&mut self) {
        info!("Send MiscHeartbeat1.");
        let data = &mut BytesMut::with_capacity(40);
        loop {
            if let Ok(mut dt) = self.data.try_write() {
                dt.counter += 1;
                dt.rnd = random_vec(2);
                MiscHeartbeat1 {
                    counter: dt.counter,
                    rnd: dt.rnd.clone(),
                    flux: dt.flux.clone(),
                }
                .append_to(data);
                break;
            }
            sleep();
        }
        self.send(data.to_vec(), true)
    }

    fn send_misc_heartbeat_3(&mut self) {
        info!("Send MiscHeartbeat3.");
        let data = &mut BytesMut::with_capacity(40);
        loop {
            if let Ok(mut dt) = self.data.try_write() {
                dt.counter += 1;
                MiscHeartbeat3 {
                    counter: dt.counter,
                    rnd: dt.rnd.clone(),
                    flux: dt.flux.clone(),
                    ip: self.ip,
                }
                .append_to(data);
                break;
            }
            sleep();
        }
        self.send(data.to_vec(), true)
    }

    fn send_alive(&mut self) {
        info!("Send Alive.");
        let data = &mut BytesMut::with_capacity(40);
        loop {
            if let Ok(dt) = self.data.try_read() {
                Alive {
                    cks_md5: dt.cks_md5.clone(),
                    decrypted_from_misc_response_info: dt.decrypted_from_misc_response_info.clone(),
                }
                .append_to(data);
                break;
            }
            sleep();
        }
        self.send(data.to_vec(), true)
    }
}

#[test]
fn test() {
    dbg!(encoding_rs::GB18030.decode_with_bom_removal(hex::decode("d7d432303139c4ea39d4c23239c8d5c6f0a3acc8e7d0e8d4dacee5c9bdd0a3c7f8b0ecc0edcdf8c2e7d6d0d0c4cfe0b9d8d2b5cef1a3acc7ebd2c6b2bdd6c1cee5c9bdd0a3c7f831bac5c2a5caa6c9fab7fecef1d6d0d0c4d2bbc2a5b6abb2e0b4f3ccfc31d6c135bac5b4b0bfdaa1a3cfeacfb8d0c5cfa2c7ebbcfb687474703a2f2f7765622e736375742e6564752e636e2f323031392f303932352f633135323835613333353931312f706167652e68746d00").unwrap().as_slice()));
    dbg!(encoding_rs::GB18030.decode_with_bom_removal(hex::decode("d6c2d0a3d4b0cdf8d3c3bba7a3accfd6d2d1b7a2b2bcc6bbb9fbb5e7c4d4d0c2b0e6c8cfd6a4bfcdbba7b6cba3acd6a7b3d6a1be6d61634f532031302e313520436174616c696e61a1bfa3acbfc9b5bd20687474703a2f2f3230322e33382e3139332e36352f20cfc2d4d8a1a3cad7b4ceb0b2d7b0c7b0a3acd0e8cfc8b6cfbfaad3d0cfdfc1acbdd3bbf2b0ceb3f6cdf8cfdfa3acc8bbbaf3b5c7c2bdcedecfdfcdf8c2e7a3acd4d9bdf8d0d0b0b2d7b0a1a3c8e7c4fad3d0c6e4cbfcd2c9cecaa3acbbb6d3add6").unwrap().as_slice()));
}

#[test]
fn test_log() {
    debug!("debug test");
}
