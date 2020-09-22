use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{Local, NaiveTime};
use pnet::datalink::MacAddr;
use rand::random;
use std::net::IpAddr;
use std::ops::Add;
use std::time::Duration;

#[cfg(feature = "nolog")]
#[macro_export]
macro_rules! log {
    ($($_:tt)+) => {
        ()
    };
}
#[cfg(feature = "nolog")]
#[macro_export]
macro_rules! trace {
    ($($_:tt)+) => {
        ()
    };
}
#[cfg(feature = "nolog")]
#[macro_export]
macro_rules! debug {
    ($($_:tt)+) => {
        ()
    };
}
#[cfg(feature = "nolog")]
#[macro_export]
macro_rules! info {
    ($($_:tt)+) => {
        ()
    };
}
#[cfg(feature = "nolog")]
#[macro_export]
macro_rules! warn {
    ($($_:tt)+) => {
        ()
    };
}
#[cfg(feature = "nolog")]
#[macro_export]
macro_rules! error {
    ($($_:tt)+) => {
        ()
    };
}

const MS: Duration = Duration::from_millis(10);

#[inline]
pub fn sleep() {
    std::thread::sleep(MS);
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
    if dt < Local::now() {
        dt = dt.add(chrono::Duration::from_std(Duration::new(86400, 0)).ok()?);
    }
    let duration = dt - Local::now();
    std::thread::sleep(duration.to_std().ok()?);
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

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct ChannelData {
    pub state: u8,
    pub data: Vec<u8>,
}
