use std::net::IpAddr;

use crate::util::{ip_to_vec, put_mac};
use bytes::{BufMut, BytesMut};
use pnet::datalink::MacAddr;
use std::cmp::min;

pub enum HeaderType {
    MiscAlive,
    MiscResponseAlive,
    MiscInfo,
    MiscResponseInfo,
    MiscHeartbeat,
    MiscResponseHeartbeatAlive,
    MessageServerInformation,
    Invalid,
    Unknown,
    UnknownMisc,
    UnknownMessage,
}

impl HeaderType {
    pub fn from_vec(data: &[u8]) -> HeaderType {
        if data.len() < 5 {
            return HeaderType::Invalid;
        }
        match data[0] {
            0x07 => match data[4] {
                0x01 => HeaderType::MiscAlive,
                0x02 => HeaderType::MiscResponseAlive,
                0x03 => HeaderType::MiscInfo,
                0x04 => HeaderType::MiscResponseInfo,
                0x0b => HeaderType::MiscHeartbeat,
                0x06 => HeaderType::MiscResponseHeartbeatAlive,
                _ => HeaderType::UnknownMisc,
            },
            0x4d => match data[1] {
                0x38 => HeaderType::MessageServerInformation,
                _ => HeaderType::UnknownMessage,
            },
            _ => HeaderType::Unknown,
        }
    }
}

pub struct HeartbeatType(pub u8);

impl HeartbeatType {
    pub fn from_vec(data: &[u8]) -> HeartbeatType {
        HeartbeatType(if data.len() < 6 { 0 } else { data[5] })
    }
}

pub struct MiscAlive {}

impl MiscAlive {
    #[inline]
    pub fn append_to(data: &mut BytesMut) {
        data.put(&[0x07, 0, 0x08, 0, 0x01, 0, 0, 0u8][..]);
    }
}

fn append_cks32(v: &mut [u8]) -> u32 {
    let len = (v[2] >> 2) as usize;
    v[28] = 126;
    let s = v[0..4 * len]
        .array_chunks()
        .map(|v| u32::from_le_bytes(*v))
        .fold(0, |a, b| a ^ b);
    let s = ((s.to_le() as u64) * 19680126) as u32;
    v[24..28].copy_from_slice(&s.to_le_bytes());
    v[28] = 0;
    s
}

pub struct MiscInfo {
    pub mac: MacAddr,
    pub ip: IpAddr,
    pub unknown1: Vec<u8>,
    pub flux: Vec<u8>,
    pub cks32_param: Vec<u8>,
    pub username: String,
    pub hostname: String,
    pub dns1: IpAddr,
    pub dns2: IpAddr,
    pub unknown2: Vec<u8>,
    pub os_major: Vec<u8>,
    pub os_minor: Vec<u8>,
    pub os_build: Vec<u8>,
    pub os_unknown: Vec<u8>,
    pub version: Vec<u8>,
    pub hash: String,
}

impl MiscInfo {
    pub fn append_to(&self, bytes: &mut BytesMut) -> u32 {
        let data = &mut BytesMut::with_capacity(244);

        data.put(&[0x07, 0x01, 0xf4, 0u8, 0x03][..]); // +5
        let username_len = min(self.username.len(), 25);
        data.put_u8(username_len as u8); // +1

        put_mac(data, &self.mac); // +6

        data.put(&ip_to_vec(&self.ip)[..]); // +4

        data.put(&self.unknown1[..]); // +4

        data.put(&self.flux[..]); // +4

        // cks32
        data.put(&self.cks32_param[..]); // +4

        data.put(&[0u8].repeat(4)[..]); // +4

        data.put(&self.username.as_bytes()[..username_len]);

        let hostname_len = min(self.hostname.len(), 44 - username_len);
        data.put(&self.hostname.as_bytes()[..hostname_len]);
        if username_len + hostname_len < 44 {
            data.put(&[0u8].repeat(44 - username_len - hostname_len)[..]);
        }
        // +44

        data.put(&ip_to_vec(&self.dns1)[..]);
        data.put(&[0u8].repeat(4)[..]);
        data.put(&ip_to_vec(&self.dns2)[..]);
        data.put(&[0u8].repeat(8)[..]);
        // +20
        data.put(&self.unknown2[..]);

        data.put(&self.os_major[..]);
        data.put(&self.os_minor[..]);
        data.put(&self.os_build[..]);
        data.put(&self.os_unknown[..]);
        // +16

        let padding_len = 64 - self.version.len();
        data.put(&self.version[..]);
        data.put(&[0u8].repeat(padding_len)[..]);
        // +64
        let padding_len = 64 - self.hash.len();
        data.put(self.hash.as_bytes());
        data.put(&[0u8].repeat(padding_len)[..]);
        // +64

        let r = data.len() % 4;
        if r > 0 {
            data.put(&[0u8].repeat(4 - r)[..]);
        }

        let v = &mut data.to_vec();
        let r = append_cks32(v);
        bytes.put(&v[..]);
        r
    }
}

pub struct MiscHeartbeat1 {
    pub counter: u8,
    pub rnd: Vec<u8>,
    pub flux: Vec<u8>,
}

impl MiscHeartbeat1 {
    pub fn append_to(&self, data: &mut BytesMut) {
        data.put(&[0x07, self.counter, 0x28, 0u8, 0x0b, 0x01, 0xdc, 0x02][..]); // +8
        data.put(&self.rnd[..]); // +2
        data.put(&[0u8].repeat(6)[..]); // +6
        data.put(&self.flux[..]); // +4
        data.put(&[0u8].repeat(20)[..]); // +20
    }
}

fn append_cks16(v: &mut [u8]) -> u32 {
    let s = v[0..40]
        .array_chunks()
        .map(|x| u16::from_le_bytes(*x))
        .fold(0, |a, b| a ^ b) as u32;
    let s = s.to_le() * 711;
    v[24..28].copy_from_slice(&s.to_le_bytes());
    s
}

pub struct MiscHeartbeat3 {
    pub counter: u8,
    pub rnd: Vec<u8>,
    pub flux: Vec<u8>,
    pub ip: IpAddr,
}

impl MiscHeartbeat3 {
    pub fn append_to(&self, bytes: &mut BytesMut) -> u32 {
        let data = &mut BytesMut::with_capacity(40);
        data.put(&[0x07, self.counter, 0x28, 0u8, 0x0b, 0x03, 0xdc, 0x02][..]); // +8
        data.put(&self.rnd[..]); // +2
        data.put(&[0u8].repeat(6)[..]); // +6
        data.put(&self.flux[..]); // +4
        data.put(&[0u8].repeat(4)[..]); // +4

        // cks16
        data.put(&[0u8].repeat(4)[..]); // +4

        data.put(&ip_to_vec(&self.ip)[..]); // +4
        data.put(&[0u8].repeat(8)[..]); // +8

        let v = &mut data.to_vec();
        let r = append_cks16(v);
        bytes.put(&v[..]);
        r
    }
}

pub fn decrypt_info(v: &mut [u8]) {
    for (i, val) in v.iter_mut().enumerate() {
        let x = i & 0x07;
        *val = (((*val as u16) << x) + ((*val as u16) >> (8 - x))) as u8;
    }
}

pub struct Alive {
    pub cks_md5: Vec<u8>,
    pub decrypted_from_misc_response_info: Vec<u8>,
}

impl Alive {
    pub fn append_to(&self, data: &mut BytesMut) {
        data.put_u8(0xff); // +1
        data.put(&self.cks_md5[..]); // +16
        data.put(&[0u8].repeat(3)[..]); // +3
        data.put(&self.decrypted_from_misc_response_info[..]); // +16
        data.put_u16_le(chrono::Local::now().timestamp() as u16); // +2
    }
}

#[test]
fn test() {
    let mut v = hex::decode("0701f400030cb025aa286db97dd9fee10222002a3bab4e04c72f3101000000003230313833363433313135345365614c6f6f6e67000000000000000000000000000000000000000000000000ca26c12100000000ca7011210000000000000000940000000600000002000000f0230000020000004472434f4d0096022a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034656238316663303438613535383562376466653137383331353532343161333238623130336336000000000000000000000000000000000000000000000000").unwrap();
    append_cks32(&mut v);
    assert_eq!(
        hex::encode(v),
        "0701f400030cb025aa286db97dd9fee10222002a3bab4e044af8a726000000003230313833363433313135345365614c6f6f6e67000000000000000000000000000000000000000000000000ca26c12100000000ca7011210000000000000000940000000600000002000000f0230000020000004472434f4d0096022a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034656238316663303438613535383562376466653137383331353532343161333238623130336336000000000000000000000000000000000000000000000000"
    );

    let mut v = hex::decode("0701f400030cb025aa286db97dd9fee10222002a53513f04c72f3101000000003230313833363433313135345365614c6f6f6e67000000000000000000000000000000000000000000000000ca26c12100000000ca7011210000000000000000940000000600000002000000f0230000020000004472434f4d0096022a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034656238316663303438613535383562376466653137383331353532343161333238623130336336000000000000000000000000000000000000000000000000").unwrap();
    append_cks32(&mut v);
    assert_eq!(
        hex::encode(v),
        "0701f400030cb025aa286db97dd9fee10222002a53513f049adf0351000000003230313833363433313135345365614c6f6f6e67000000000000000000000000000000000000000000000000ca26c12100000000ca7011210000000000000000940000000600000002000000f0230000020000004472434f4d0096022a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034656238316663303438613535383562376466653137383331353532343161333238623130336336000000000000000000000000000000000000000000000000"
    );

    let mut v = hex::decode(
        "075628000b03dc02b91900000000000067513f0400000000000000007dd9fee10000000000000000",
    )
    .unwrap();
    append_cks16(&mut v);
    assert_eq!(
        hex::encode(v),
        "075628000b03dc02b91900000000000067513f0400000000b6e062007dd9fee10000000000000000"
    );

    let mut v = hex::decode("4439d8edac314b07dd8c5f3bef0f04d8").unwrap();
    decrypt_info(&mut v);
    assert_eq!(hex::encode(v), "4472636fca26d283dd197dd9fee1016c");
}
