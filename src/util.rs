use std::net::IpAddr;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{Local, NaiveTime, TimeZone};
use pnet::datalink::MacAddr;
use rand::random;

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

/// Wait until the next local occurrence of `time` without blocking an executor.
/// A short recheck tolerates wall-clock changes while retries use monotonic time.
pub async fn sleep_at(time: NaiveTime) -> Option<()> {
    let now = Local::now();
    let mut date = now.date_naive();
    let target = loop {
        if let Some(target) = Local.from_local_datetime(&date.and_time(time)).earliest()
            && target > now
        {
            break target;
        }
        date = date.succ_opt()?;
    };
    loop {
        let remaining = target.signed_duration_since(Local::now());
        if remaining <= chrono::Duration::zero() {
            return Some(());
        }
        tokio::time::sleep(remaining.to_std().ok()?.min(Duration::from_secs(30))).await;
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Success,
    Stop,
    Sleep,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelData {
    pub state: State,
    pub data: Vec<u8>,
}

impl ChannelData {
    pub fn stopped() -> Self {
        Self {
            state: State::Stop,
            data: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ip_octets_preserve_network_order() {
        assert_eq!(
            ip_to_vec(&Ipv4Addr::new(192, 0, 2, 17).into()),
            [192, 0, 2, 17]
        );
        assert_eq!(
            ip_to_vec(&Ipv6Addr::LOCALHOST.into()),
            Ipv6Addr::LOCALHOST.octets()
        );
    }

    #[test]
    fn mac_network_order_round_trip() {
        let mac = MacAddr::new(0x02, 0x11, 0x22, 0xaa, 0xbb, 0xff);
        let mut data = BytesMut::new();
        put_mac(&mut data, &mac);
        assert_eq!(&data[..], &[0x02, 0x11, 0x22, 0xaa, 0xbb, 0xff]);
        assert_eq!(get_mac(&mut data.freeze()), mac);
    }

    #[test]
    fn random_bytes_obey_requested_length() {
        for n in [0, 1, 2, 16, 2048] {
            assert_eq!(random_vec(n).len(), n);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_until_local_time_is_cancellable() {
        let waiting = sleep_at(Local::now().time());
        assert!(
            tokio::time::timeout(Duration::from_millis(1), waiting)
                .await
                .is_err()
        );
    }
}
