use std::net::IpAddr;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{Local, NaiveTime};
use pnet::datalink::MacAddr;
use rand::random;

const MILLI_SEC: Duration = Duration::from_millis(10);
const SEC: Duration = Duration::from_secs(1);

#[inline]
pub fn sleep() {
    std::thread::sleep(MILLI_SEC);
}

#[inline]
pub fn ip_to_vec(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

#[inline]
pub fn put_mac(data: &mut BytesMut, mac: &MacAddr) {
    data.put_u8(mac.0);
    data.put_u8(mac.1);
    data.put_u8(mac.2);
    data.put_u8(mac.3);
    data.put_u8(mac.4);
    data.put_u8(mac.5);
}

#[inline]
pub fn get_mac(data: &mut Bytes) -> MacAddr {
    let mut mac = MacAddr::zero();
    mac.0 = data.get_u8();
    mac.1 = data.get_u8();
    mac.2 = data.get_u8();
    mac.3 = data.get_u8();
    mac.4 = data.get_u8();
    mac.5 = data.get_u8();
    mac
}

#[inline]
pub fn sleep_at(time: NaiveTime) -> Option<()> {
    let mut dt = Local::today().and_time(time)?;
    while dt < Local::now() {
        dt += chrono::Duration::days(1);
    }
    while dt > Local::now() {
        std::thread::sleep(SEC);
    }
    Some(())
}

#[inline]
pub fn random_vec(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(random::<u8>());
    }
    v
}

/// enum of ChannelData.state
///
/// # State
pub enum State {
    Success,
    Stop,
    Sleep,
    Quit,
}

pub struct ChannelData {
    pub state: State,
    pub data: Vec<u8>,
}
