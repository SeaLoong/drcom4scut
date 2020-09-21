use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{debug, error, info, warn};
use md5::Digest;
use pnet::datalink::MacAddr;

use crate::constants;
use crate::device::Device;
use crate::eap::packet::*;
use crate::settings::Settings;
use crate::util::*;
use chrono::Local;
use crossbeam::{Receiver, Sender, TryRecvError};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::thread;
use std::thread::JoinHandle;

mod packet;

const MULTICAST_MAC: MacAddr = MacAddr(0x01, 0x80, 0xc2, 0x00, 0x00, 0x03);

#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
struct ProcessData {
    ip: Vec<u8>,
    md5_extra_data: Vec<u8>,
    md5: Vec<u8>,
    response_identity_packet: Option<Vec<u8>>,
}

pub struct Process {
    eth_header: EthernetHeader,
    settings: Arc<Settings>,
    device: Arc<Device>,
    tx: Sender<ChannelData>,
    timeout: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
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

impl Process {
    pub fn new(settings: Arc<Settings>, device: Arc<Device>, tx: Sender<ChannelData>) -> Process {
        Process {
            eth_header: EthernetHeader {
                destination: MULTICAST_MAC,
                source: device.mac,
                ethernet_type: ethernet_types::IEEE8021X,
            },
            data: {
                let mut d = ProcessData::default();
                d.ip = ip_to_vec(&device.ip_net.ip());
                d
            },
            tx,
            timeout: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
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
        let (tx, rx) = crossbeam::unbounded::<Vec<u8>>();
        self.receive_channel = Some(rx);
        let stop = self.stop.clone();
        let interval = self.settings.retry_interval;
        let device = self.device.clone();
        self.receiver_handle = Some(Arc::new(
            thread::Builder::new()
                .name("EAP-Receiver".to_owned())
                .spawn(move || {
                    let duration = Duration::from_millis(interval as u64);
                    loop {
                        while stop.load(Ordering::Relaxed) {
                            thread::park();
                        }
                        match device.receive() {
                            Ok(v) => {
                                tx.send(v)
                                    .expect("Unexpected! Receive channel is disconnected!");
                            }
                            Err(e) => {
                                error!("Receive error: {}", e);
                                thread::sleep(duration);
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
        let (tx, rx) = crossbeam::unbounded::<(Vec<u8>, bool)>();
        self.send_channel = Some(tx.clone());
        let stop = self.stop.clone();
        let interval = self.settings.retry_interval;
        let send_ts = self.send_ts.clone();
        let cancel_resend = self.cancel_resend.clone();
        let resender_handle = Arc::new(
            thread::Builder::new()
                .name("EAP-Resender".to_owned())
                .spawn(move || loop {
                    while stop.load(Ordering::Relaxed) {
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
                        tx.send((Vec::new(), true))
                            .expect("Unexpected! Send channel is disconnected!");
                        cancel_resend.store(true, Ordering::Release);
                    }
                })
                .expect("Can't create EAP-ReSender thread."),
        );
        self.resender_handle = Some(resender_handle.clone());
        let stop = self.stop.clone();
        let device = self.device.clone();
        let interval = self.settings.retry_interval;
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
                        while stop.load(Ordering::Relaxed) {
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
                            Err(_) => panic!("Unexpected! Send channel is disconnected!"),
                        }
                        loop {
                            while stop.load(Ordering::Relaxed) {
                                thread::park();
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
                                    thread::sleep(duration);
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
                panic!("Unexpected! Receive channel is disconnected!");
            }
            Err(TryRecvError::Empty) => None,
        }
    }

    fn send(&self, data: Vec<u8>, resend: bool) {
        let mut data = Vec::from(data);
        let l = 96 - data.len();
        if l > 0 {
            data.extend_from_slice(&[0u8].repeat(l));
        }
        debug!("Will blocking send...");
        let channel = self.send_channel.as_ref().unwrap();
        channel
            .send((data, resend))
            .expect("Unexpected! Send channel is disconnected!");
        debug!("Sent.");
    }

    fn cancel_resend(&self) {
        self.cancel_resend.store(true, Ordering::Release);
    }

    pub fn start(&mut self) -> bool {
        self.stop.store(false, Ordering::Relaxed);
        self.start_receive_thread();
        self.start_send_thread();
        self.login_start();
        let mut ret = false;
        while !self.stop.load(Ordering::Relaxed) {
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
                                eap_types::IDENTITY => {
                                    self.on_request_identity(&eth_header, &eap_header)
                                }
                                eap_types::NOTIFICATION => {
                                    ret = self.on_request_notification(&eap_header, bytes); // sleep if true
                                    if ret {
                                        self.tx
                                            .send(ChannelData {
                                                state: constants::state::SLEEP,
                                                data: Vec::new(),
                                            })
                                            .expect("Can't send SLEEP message to UDP receiver.");
                                    }
                                    self.stop.store(true, Ordering::Relaxed);
                                }
                                eap_types::MD5_CHALLENGE => {
                                    self.on_request_md5_challenge(&eap_header, bytes)
                                }
                                _ => error!(
                                    "Unexpected packet EAP Type: {}",
                                    eap_header.eap_type.unwrap().0
                                ),
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
        ret
    }

    #[inline]
    fn login_start(&mut self) {
        self.timeout.store(false, Ordering::Relaxed);
        self.data.response_identity_packet = None;
        self.send_logoff();
        thread::sleep(Duration::from_secs(3));
        self.send_start();
    }

    fn on_request_identity(&mut self, eth_header: &EthernetHeader, eap_header: &EAPHeader) {
        self.cancel_resend();
        self.timeout.store(false, Ordering::Relaxed);
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
            self.send_response_identity(&eap_header)
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
            self.send_response_md5_challenge(&eap_header, bytes)
        }
    }

    fn on_success(&mut self) {
        self.cancel_resend();
        info!("802.1X Authorization success!");
        self.start_heartbeat_thread();
    }

    fn start_heartbeat_thread(&mut self) {
        if let Some(handle) = &self.heartbeat_handle {
            handle.thread().unpark();
            return;
        }
        let stop = self.stop.clone();
        let eap_timeout = self.settings.heartbeat.eap_timeout;
        let timeout = self.timeout.clone();
        let tx = self.tx.clone();
        self.heartbeat_handle = Some(Arc::new(
            thread::Builder::new()
                .name("EAP-Heartbeat".to_owned())
                .spawn(move || {
                    let duration = Duration::from_secs(eap_timeout as u64);
                    loop {
                        while stop.load(Ordering::Relaxed) {
                            thread::park();
                        }
                        if timeout.load(Ordering::Relaxed) {
                            error!(
                                "Heartbeat timeout! No Request, Identity packet received for {}s.",
                                eap_timeout
                            );
                            stop.store(true, Ordering::Relaxed);
                            tx.send(ChannelData {
                                state: constants::state::STOP,
                                data: Vec::new(),
                            })
                            .expect("Can't send STOP message to UDP receiver.");
                            break;
                        }
                        timeout.store(true, Ordering::Relaxed);
                        std::thread::sleep(duration);
                    }
                })
                .expect("Can't create EAP-Heartbeat thread!"),
        ));
        // notify UDP process should start
        self.tx
            .send(ChannelData {
                state: constants::state::SUCCESS,
                data: self.data.md5.clone(),
            })
            .expect("Can't send SUCCESS message to UDP receiver.");
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
            eap_type: Some(eap_types::IDENTITY),
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
        let md5 = &md5::Md5::digest(
            &{
                let mut not_encrypt =
                    BytesMut::with_capacity(1 + self.settings.password.len() + md5_value.len());
                not_encrypt.put_u8(eap_header.identifier);
                not_encrypt.put(self.settings.password.as_bytes());
                not_encrypt.put(&md5_value[..]);
                not_encrypt
            }
            .bytes(),
        )[..];
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
            eap_type: Some(eap_types::MD5_CHALLENGE),
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
    let r = hex::encode(md5::Md5::digest(data.bytes())).to_lowercase();
    assert_eq!(&r, "313a3758ad589ce03dc6af0371c31239");
}