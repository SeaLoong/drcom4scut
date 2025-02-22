use std::cmp::min;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::Local;
use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};
use log::{debug, error, info, warn};
use md5::Digest;
use pnet::datalink::MacAddr;

use crate::device::Device;
use crate::eap::packet::*;
use crate::settings::Settings;
use crate::util::{ChannelData, State, ip_to_vec, sleep};

mod packet;

const MULTICAST_MAC: MacAddr = MacAddr(0x01, 0x80, 0xc2, 0x00, 0x00, 0x03);

#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
struct ProcessData {
    ip: Vec<u8>,
    md5_extra_data: Vec<u8>,
    md5: Vec<u8>,
    response_identity_packet: Option<Vec<u8>>,
}

pub struct Process<'a> {
    eth_header: EthernetHeader,
    settings: &'a Settings,
    device: Arc<Device>,
    tx: Sender<ChannelData>,
    timeout: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    data: ProcessData,
    receive_channel: Option<Receiver<Vec<u8>>>,
    send_channel: Option<Sender<(Vec<u8>, bool)>>,
    send_ts: Arc<AtomicI64>,
    cancel_resend: Arc<AtomicBool>,
    receiver_handle: Option<Arc<JoinHandle<()>>>,
    resender_handle: Option<Arc<JoinHandle<()>>>,
    sender_handle: Option<Arc<JoinHandle<()>>>,
    heartbeat_handle: Option<Arc<JoinHandle<()>>>,
}

impl Process<'_> {
    pub fn new(settings: &Settings, device: Arc<Device>, tx: Sender<ChannelData>) -> Process {
        Process {
            eth_header: EthernetHeader {
                destination: MULTICAST_MAC,
                source: device.mac,
                ethernet_type: ethernet_types::IEEE8021X,
            },
            data: ProcessData {
                ip: ip_to_vec(&device.ip_net.ip()),
                ..Default::default()
            },
            tx,
            timeout: Arc::new(AtomicU8::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
            quit: Arc::new(AtomicBool::new(false)),
            settings,
            device,
            receive_channel: None,
            send_channel: None,
            send_ts: Arc::new(AtomicI64::new(0)),
            cancel_resend: Arc::new(AtomicBool::new(true)),
            receiver_handle: None,
            resender_handle: None,
            sender_handle: None,
            heartbeat_handle: None,
        }
    }

    fn start_receive_thread(&mut self) {
        if let Some(handle) = &self.receiver_handle {
            handle.thread().unpark();
            return;
        }
        let (tx, rx) = unbounded::<Vec<u8>>();
        self.receive_channel = Some(rx);
        let quit = self.quit.clone();
        let stop = self.stop.clone();
        let count = self.settings.retry.count;
        let interval = self.settings.retry.interval;
        let device = self.device.clone();
        self.receiver_handle = Some(Arc::new(
            thread::Builder::new()
                .name("EAP-Receiver".to_owned())
                .spawn(move || {
                    let duration = Duration::from_millis(interval as u64);
                    let mut cnt = 0;
                    loop {
                        if quit.load(Ordering::Relaxed) {
                            debug!("EAP-Receiver thread quit!");
                            return;
                        }
                        if stop.load(Ordering::Relaxed) {
                            thread::park();
                        }
                        match device.receive() {
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
                .expect("Can't create EAP-Receiver thread."),
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
        let (tx, rx) = unbounded::<(Vec<u8>, bool)>();
        self.send_channel = Some(tx.clone());
        let quit = self.quit.clone();
        let stop = self.stop.clone();
        let interval = self.settings.retry.interval;
        let send_ts = self.send_ts.clone();
        let cancel_resend = self.cancel_resend.clone();
        let resender_handle = Arc::new(
            thread::Builder::new()
                .name("EAP-Resender".to_owned())
                .spawn(move || {
                    loop {
                        if quit.load(Ordering::Relaxed) {
                            debug!("EAP-Resender thread quit!");
                            return;
                        }
                        if stop.load(Ordering::Relaxed) {
                            thread::park();
                        }
                        while cancel_resend.load(Ordering::Acquire) {
                            thread::park();
                        }
                        let wait_ts = send_ts.load(Ordering::Acquire)
                            - Local::now().timestamp_millis()
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
                    }
                })
                .expect("Can't create EAP-ReSender thread."),
        );
        self.resender_handle = Some(resender_handle.clone());
        let quit = self.quit.clone();
        let stop = self.stop.clone();
        let device = self.device.clone();
        let count = self.settings.retry.count;
        let interval = self.settings.retry.interval;
        let send_ts = self.send_ts.clone();
        let cancel_resend = self.cancel_resend.clone();
        self.sender_handle = Some(Arc::new(
            thread::Builder::new()
                .name("EAP-Sender".to_owned())
                .spawn(move || {
                    let duration = Duration::from_millis(interval as u64);
                    let mut data = Vec::new();
                    let mut resend = false;
                    loop {
                        if quit.load(Ordering::Relaxed) {
                            debug!("EAP-Sender thread quit!");
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
                            match device.send(data.clone()) {
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
                .expect("Can't create EAP-Sender thread."),
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
        let mut data = data;
        let l = 96 - data.len();
        if l > 0 {
            data.extend_from_slice(&[0u8].repeat(l));
        }
        debug!("Will blocking send...");
        let channel = self.send_channel.as_ref().unwrap();
        if channel.send((data, resend)).is_err() {
            self.quit.store(true, Ordering::Release);
            error!("Unexpected! Send channel is disconnected!");
            return;
        }
        debug!("Sent.");
    }

    fn cancel_resend(&self) {
        self.cancel_resend.store(true, Ordering::Release);
    }

    pub fn start(&mut self) -> State {
        self.stop.store(false, Ordering::Release);
        self.start_receive_thread();
        self.start_send_thread();
        self.login_start();
        let mut ret = false;
        while !self.stop.load(Ordering::Relaxed) {
            if self.quit.load(Ordering::Relaxed) {
                debug!("EAP-Process thread quit!");
                if let Err(e) = self.tx.try_send(ChannelData {
                    state: State::Quit,
                    data: Vec::new(),
                }) {
                    error!("Can't send STOP message to UDP receiver. {}", e);
                }
                return State::Quit;
            }
            let raw = match self.receive() {
                Some(v) => v,
                None => {
                    sleep();
                    continue;
                }
            };
            let bytes = &mut Bytes::copy_from_slice(&raw[..]);
            let header = Header::from_bytes(bytes);
            // check ethernet header
            if header.ethernet_header.is_none() {
                continue;
            }
            let eth_header = header.ethernet_header.unwrap();
            if eth_header.ethernet_type != ethernet_types::IEEE8021X
                || !eth_header.is_send_to(&self.eth_header)
            {
                continue;
            }
            // check eapol header
            if header.eapol_header.is_none() {
                continue;
            }
            let eapol_header = header.eapol_header.unwrap();
            if eapol_header.version != 1 {
                continue;
            }
            match eapol_header.eapol_type {
                eapol_types::EAP_PACKET => {
                    // check eap header
                    if header.eap_header.is_none() {
                        continue;
                    }
                    debug!("Received: {}", hex::encode(&raw));
                    let eap_header = header.eap_header.unwrap();
                    match eap_header.code {
                        eap_codes::REQUEST => {
                            if eap_header.eap_type.is_none() {
                                continue;
                            }
                            match eap_header.eap_type.unwrap() {
                                EAPType::Identity => {
                                    self.on_request_identity(&eth_header, &eap_header)
                                }
                                EAPType::Notification => {
                                    ret = self.on_request_notification(&eap_header, bytes); // sleep if true
                                    if ret {
                                        if let Err(e) = self.tx.try_send(ChannelData {
                                            state: State::Sleep,
                                            data: Vec::new(),
                                        }) {
                                            error!(
                                                "Can't send SLEEP message to UDP receiver. {}",
                                                e
                                            );
                                        }
                                    }
                                    self.stop.store(true, Ordering::Release);
                                }
                                EAPType::Md5Challenge => {
                                    self.on_request_md5_challenge(&eap_header, bytes)
                                }
                            }
                        }
                        eap_codes::RESPONSE => {
                            error!("Unexpected packet received: RESPONSE");
                        }
                        eap_codes::SUCCESS => self.on_success(),
                        eap_codes::FAILURE => {
                            debug!("Received: FAILURE");
                        }
                        _ => error!("Unexpected packet EAP Code: {}", eap_header.code.0),
                    }
                }
                eapol_types::EAPOL_START => {
                    error!("Unexpected packet received: EAPOL_START");
                }
                eapol_types::EAPOL_LOGOFF => {
                    error!("Unexpected packet received: EAPOL_LOGOFF");
                }
                _ => error!(
                    "Unexpected packet EAPOL Type: {}",
                    eapol_header.eapol_type.0
                ),
            }
        }
        if ret { State::Sleep } else { State::Stop }
    }

    #[inline]
    fn login_start(&mut self) {
        self.timeout.store(0, Ordering::Release);
        self.data.response_identity_packet = None;
        self.send_logoff();
        thread::sleep(Duration::from_secs(2));
        self.send_start();
    }

    fn on_request_identity(&mut self, eth_header: &EthernetHeader, eap_header: &EAPHeader) {
        self.cancel_resend();
        self.timeout.store(0, Ordering::Release);
        if let Some(ref mut v) = self.data.response_identity_packet {
            v[19] = eap_header.identifier;
            let v = v.clone();
            info!("Send Heartbeat(Response, Identity) packet.");
            self.send(v, false);
        } else if eap_header.identifier > 1 {
            warn!("Maybe you have been login.");
            self.login_start()
        } else {
            self.eth_header.destination = eth_header.source;
            self.send_response_identity(eap_header)
        }
    }

    fn on_request_notification(&mut self, eap_header: &EAPHeader, bytes: &mut Bytes) -> bool {
        if bytes.len() < (eap_header.length - 5) as usize {
            error!("NOTIFICATION: Unexpected payload!");
        } else {
            self.cancel_resend();
            match String::from_utf8(bytes.split_to((eap_header.length - 5) as usize).to_vec()) {
                Ok(s) => {
                    error!("{}", s);
                    if let Some(s) = s.strip_prefix("userid error") {
                        if let Ok(x) = i32::from_str(s) {
                            match x {
                                1 => error!("Account does not exist."),
                                2 | 3 => error!("Username or password invalid."),
                                4 => error!("This account might be expended."),
                                _ => (),
                            }
                        }
                    } else if let Some(s) = s.strip_prefix("Authentication Fail ErrCode=") {
                        if let Ok(x) = i32::from_str(s) {
                            match x {
                                0 => error!("Username or password invalid."),
                                5 => error!("This account is suspended."),
                                9 => error!("This account might be expended."),
                                11 => error!(
                                    "You are not allowed to perform a radius authentication."
                                ),
                                16 => {
                                    error!("You are not allowed to access the internet now.");
                                    return true;
                                }
                                30 | 63 => error!("No more time available for this account."),
                                _ => (),
                            }
                        }
                    } else if s.strip_prefix("AdminReset").is_some() {
                        error!("AdminReset.")
                    } else if s.strip_prefix("Mac, IP, NASip, PORT").is_some() {
                        error!("You are not allowed to login using current IP/MAC address.")
                    } else if s.strip_prefix("flowover").is_some() {
                        error!("Data usage has reached the limit.")
                    } else if s.strip_prefix("In use").is_some() {
                        error!("This account is in use.")
                    }
                }
                Err(_) => {
                    error!("NOTIFICATION: Parse string failed!");
                }
            }
        }
        false
    }

    fn on_request_md5_challenge(&mut self, eap_header: &EAPHeader, bytes: &mut Bytes) {
        if bytes.len() < (eap_header.length - 5) as usize {
            error!("MD5 Challenge: Unexpected payload!");
        } else {
            self.cancel_resend();
            self.send_response_md5_challenge(eap_header, bytes)
        }
    }

    fn on_success(&mut self) {
        self.cancel_resend();
        info!("802.1X Authorization success!");
        // notify UDP process should start
        if let Err(e) = self.tx.try_send(ChannelData {
            state: State::Success,
            data: self.data.md5.clone(),
        }) {
            error!("Can't send SUCCESS message to UDP receiver. {}", e);
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
        let timeout = self.timeout.clone();
        let eap_timeout = self.settings.heartbeat.eap_timeout;
        let count = min(self.settings.retry.count, u8::MAX as i32) as u8;
        let tx = self.tx.clone();
        self.heartbeat_handle = Some(Arc::new(
            thread::Builder::new()
                .name("EAP-Heartbeat".to_owned())
                .spawn(move || {
                    let duration = Duration::from_secs(eap_timeout as u64);
                    loop {
                        if quit.load(Ordering::Relaxed) {
                            debug!("EAP-Heartbeat thread quit!");
                            return;
                        }
                        if stop.load(Ordering::Relaxed) {
                            thread::park();
                        }
                        thread::sleep(duration);
                        let cnt = timeout.load(Ordering::Relaxed);
                        if cnt > count {
                            error!(
                                "Heartbeat timeout! No Request, Identity packet received for {}s.",
                                eap_timeout * cnt as i32
                            );
                            stop.store(true, Ordering::Release);
                            if tx
                                .send(ChannelData {
                                    state: State::Stop,
                                    data: Vec::new(),
                                })
                                .is_err()
                            {
                                error!("Can't send STOP message to UDP receiver.");
                                quit.store(true, Ordering::Release);
                                continue;
                            }
                        }
                        timeout.store(cnt + 1, Ordering::Relaxed);
                    }
                })
                .expect("Can't create EAP-Heartbeat thread!"),
        ));
    }

    fn send_logoff(&mut self) {
        info!("Send Logoff packet.");
        let data = &mut BytesMut::with_capacity(96);
        self.eth_header.destination = MULTICAST_MAC;
        self.eth_header.append_to(data);
        EAPOL_HEADER_LOGOFF.append_to(data);
        self.send(data.to_vec(), false)
        // Failure
    }

    fn send_start(&mut self) {
        info!("Send Start packet.");
        let data = &mut BytesMut::with_capacity(96);
        self.eth_header.destination = MULTICAST_MAC;
        self.eth_header.append_to(data);
        EAPOL_HEADER_START.append_to(data);
        self.send(data.to_vec(), true)
        // Request, Identity
    }

    fn send_response_identity(&mut self, eap_header: &EAPHeader) {
        info!("Send Response, Identity packet.");
        let payload = &mut BytesMut::with_capacity(96);
        payload.put(self.settings.username.as_bytes());
        payload.put(&self.settings.data.response_identity.unknown[..]);
        payload.put(&self.data.ip[..]);
        let length = payload.len() as u16 + 5;
        let data = &mut BytesMut::with_capacity(96);
        self.eth_header.append_to(data);
        EAPOLHeader {
            version: 1,
            eapol_type: eapol_types::EAP_PACKET,
            length,
        }
        .append_to(data);
        EAPHeader {
            code: eap_codes::RESPONSE,
            identifier: eap_header.identifier,
            length,
            eap_type: Some(EAPType::Identity),
        }
        .append_to(data);
        data.put(payload);
        self.data.response_identity_packet = Some(data.to_vec());
        self.send(data.to_vec(), true)
        // Request, MD5-Challenge
    }

    fn send_response_md5_challenge(&mut self, eap_header: &EAPHeader, bytes: &mut Bytes) {
        info!("Send Response, MD5-Challenge packet.");
        let md5_size = bytes.get_u8() as usize;
        let md5_value = bytes.split_to(md5_size).to_vec();
        self.data.md5_extra_data = bytes
            .split_to((eap_header.length as usize) - md5_size - 6)
            .to_vec();
        let md5 = &md5::Md5::digest(&{
            let mut not_encrypt =
                BytesMut::with_capacity(1 + self.settings.password.len() + md5_value.len());
            not_encrypt.put_u8(eap_header.identifier);
            not_encrypt.put(self.settings.password.as_bytes());
            not_encrypt.put(&md5_value[..]);
            not_encrypt
        })[..];
        self.data.md5 = md5.to_vec();
        let payload = &mut BytesMut::with_capacity(96);
        payload.put_u8(md5.len() as u8);
        payload.put(md5);
        payload.put(self.settings.username.as_bytes());
        payload.put(&self.settings.data.response_md5_challenge.unknown[..]);
        payload.put(&self.data.ip[..]);
        let data = &mut BytesMut::with_capacity(96);
        self.eth_header.append_to(data);
        let length = payload.len() as u16 + 5;
        EAPOLHeader {
            version: 1,
            eapol_type: eapol_types::EAP_PACKET,
            length,
        }
        .append_to(data);
        EAPHeader {
            code: eap_codes::RESPONSE,
            identifier: eap_header.identifier,
            length,
            eap_type: Some(EAPType::Md5Challenge),
        }
        .append_to(data);
        data.put(payload);
        self.send(data.to_vec(), true)
        // Success
    }
}

#[test]
fn test_md5_calc() {
    let mut data = BytesMut::new();
    data.put_u8(0);
    data.put("qwert12345".as_bytes());
    data.put(&hex::decode("ff62b079ca26d283ca26d28300000000").unwrap()[..]);
    let r = hex::encode(md5::Md5::digest(&data)).to_lowercase();
    assert_eq!(&r, "313a3758ad589ce03dc6af0371c31239");
}
