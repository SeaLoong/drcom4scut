use crate::util::{ip_to_vec, put_mac};
use bytes::{BufMut, BytesMut};
use pnet::datalink::MacAddr;
use std::cmp::min;
use std::mem::size_of;
use std::net::IpAddr;
use std::ops::BitXor;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
                0x02 if data.len() >= 12 => HeaderType::MiscResponseAlive,
                0x02 => HeaderType::Invalid,
                0x03 => HeaderType::MiscInfo,
                0x04 if data.len() >= 32 => HeaderType::MiscResponseInfo,
                0x04 => HeaderType::Invalid,
                0x0b if data.len() >= 6 && matches!(data[5], 4 | 6) => HeaderType::MiscHeartbeat,
                0x0b if data.len() >= 20 => HeaderType::MiscHeartbeat,
                0x0b => HeaderType::Invalid,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatType(pub u8);

impl HeartbeatType {
    pub fn from_vec(data: &[u8]) -> HeartbeatType {
        HeartbeatType(if data.len() < 6 { 0 } else { data[5] })
    }
}

// Every protocol field has a fixed width. A malformed local override must not
// shift later fields or underflow padding arithmetic.
fn put_fixed(data: &mut BytesMut, value: &[u8], width: usize) {
    let count = min(value.len(), width);
    data.extend_from_slice(&value[..count]);
    data.resize(data.len() + width - count, 0);
}

pub struct MiscAlive {}

impl MiscAlive {
    #[inline]
    pub fn append_to(data: &mut BytesMut) {
        data.put(&[0x07, 0, 0x08, 0, 0x01, 0, 0, 0u8][..]);
    }
}

fn append_cks32(v: &mut [u8]) -> u32 {
    const TRUNK_SIZE: usize = size_of::<u32>();
    let len = usize::from(u16::from_le_bytes([v[2], v[3]])) / 4;
    v[28] = 126;
    let s = v[0..4 * len]
        .as_chunks::<TRUNK_SIZE>()
        .0
        .iter()
        .map(|v| u32::from_le_bytes(*v))
        .fold(0, BitXor::bitxor);
    let s = s.wrapping_mul(19_680_126);
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
        self.append_packet(bytes, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), None)
    }

    /// The current Windows 0x31 variant advertises a gateway and a 16-byte
    /// suffix. Keep legacy encoding separate so opting in cannot alter old peers.
    pub fn append_windows31_to(
        &self,
        bytes: &mut BytesMut,
        gateway: IpAddr,
        trailer: &[u8],
    ) -> u32 {
        self.append_packet(bytes, gateway, Some(trailer))
    }

    fn append_packet(&self, bytes: &mut BytesMut, gateway: IpAddr, trailer: Option<&[u8]>) -> u32 {
        let length: u16 = if trailer.is_some() { 260 } else { 244 };
        let data = &mut BytesMut::with_capacity(usize::from(length));
        data.extend_from_slice(&[0x07, 0x01]);
        data.put_u16_le(length);
        data.put_u8(0x03); // +5
        let username_len = min(self.username.len(), 25);
        data.put_u8(username_len as u8); // +1

        put_mac(data, &self.mac); // +6

        put_fixed(data, &ip_to_vec(&self.ip), 4); // +4

        put_fixed(data, &self.unknown1, 4); // +4

        put_fixed(data, &self.flux, 4); // +4

        // cks32
        put_fixed(data, &self.cks32_param, 4); // +4

        data.put(&[0u8].repeat(4)[..]); // +4

        data.put(&self.username.as_bytes()[..username_len]);

        let hostname_len = min(self.hostname.len(), 44 - username_len);
        data.put(&self.hostname.as_bytes()[..hostname_len]);
        if username_len + hostname_len < 44 {
            data.put(&[0u8].repeat(44 - username_len - hostname_len)[..]);
        }
        // +44

        put_fixed(data, &ip_to_vec(&self.dns1), 4);
        put_fixed(data, &ip_to_vec(&gateway), 4);
        put_fixed(data, &ip_to_vec(&self.dns2), 4);
        data.put(&[0u8].repeat(8)[..]);
        // +20
        put_fixed(data, &self.unknown2, 4);

        put_fixed(data, &self.os_major, 4);
        put_fixed(data, &self.os_minor, 4);
        put_fixed(data, &self.os_build, 4);
        put_fixed(data, &self.os_unknown, 4);
        // +16

        put_fixed(data, &self.version, 64);
        // +64
        put_fixed(data, self.hash.as_bytes(), 64);
        // +64

        if let Some(trailer) = trailer {
            put_fixed(data, trailer, 16);
        }

        let v = &mut data.to_vec();
        let r = append_cks32(v);
        bytes.put(&v[..]);
        r
    }
}

/// A one-off 0x31 startup exchange, distinct from normal Alive/HB1 packets.
/// The server acknowledges it with a MiscHeartbeat subtype 6.
pub struct StartupHeartbeat;

impl StartupHeartbeat {
    pub fn append_to(data: &mut BytesMut, random: &[u8]) {
        data.extend_from_slice(&[7, 0, 40, 0, 11, 1, 15, 39]);
        put_fixed(data, random, 2);
        data.extend_from_slice(&[0; 30]);
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
        put_fixed(data, &self.rnd, 2); // +2
        data.put(&[0u8].repeat(6)[..]); // +6
        put_fixed(data, &self.flux, 4); // +4
        data.put(&[0u8].repeat(20)[..]); // +20
    }
}

fn append_cks16(v: &mut [u8]) -> u32 {
    const TRUNK_SIZE: usize = size_of::<u16>();

    let s = v[0..40]
        .as_chunks::<TRUNK_SIZE>()
        .0
        .iter()
        .map(|x| u16::from_le_bytes(*x))
        .fold(0, BitXor::bitxor) as u32;
    let s = s * 711;
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
        put_fixed(data, &self.rnd, 2); // +2
        data.put(&[0u8].repeat(6)[..]); // +6
        put_fixed(data, &self.flux, 4); // +4
        data.put(&[0u8].repeat(4)[..]); // +4

        // cks16
        data.put(&[0u8].repeat(4)[..]); // +4

        put_fixed(data, &ip_to_vec(&self.ip), 4); // +4
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
        self.append_at(data, chrono::Local::now().timestamp() as u16);
    }

    fn append_at(&self, data: &mut BytesMut, timestamp: u16) {
        data.put_u8(0xff); // +1
        put_fixed(data, &self.cks_md5, 16); // +16
        data.put(&[0u8].repeat(3)[..]); // +3
        put_fixed(data, &self.decrypted_from_misc_response_info, 16); // +16
        data.put_u16_le(timestamp); // +2
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const INFO_PACKET: &str = "0701f400030cb025aa286db97dd9fee10222002a3bab4e044af8a726000000003230313833363433313135345365614c6f6f6e67000000000000000000000000000000000000000000000000ca26c12100000000ca7011210000000000000000940000000600000002000000f0230000020000004472434f4d0096022a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034656238316663303438613535383562376466653137383331353532343161333238623130336336000000000000000000000000000000000000000000000000";

    fn info() -> MiscInfo {
        MiscInfo {
            mac: MacAddr(0xb0, 0x25, 0xaa, 0x28, 0x6d, 0xb9),
            ip: Ipv4Addr::new(125, 217, 254, 225).into(),
            unknown1: hex::decode("0222002a").unwrap(),
            flux: hex::decode("3bab4e04").unwrap(),
            cks32_param: hex::decode("c72f3101").unwrap(),
            username: "201836431154".into(),
            hostname: "SeaLoong".into(),
            dns1: Ipv4Addr::new(202, 38, 193, 33).into(),
            dns2: Ipv4Addr::new(202, 112, 17, 33).into(),
            unknown2: hex::decode("94000000").unwrap(),
            os_major: hex::decode("06000000").unwrap(),
            os_minor: hex::decode("02000000").unwrap(),
            os_build: hex::decode("f0230000").unwrap(),
            os_unknown: hex::decode("02000000").unwrap(),
            version: hex::decode("4472434f4d0096022a").unwrap(),
            hash: "4eb81fc048a5585b7dfe1783155241a328b103c6".into(),
        }
    }

    #[test]
    fn misc_alive_matches_wire_fixture() {
        let mut data = BytesMut::new();
        MiscAlive::append_to(&mut data);
        assert_eq!(hex::encode(data), "0700080001000000");
    }

    #[test]
    fn misc_info_encoder_matches_captured_packet_and_checksum() {
        let mut data = BytesMut::new();
        let checksum = info().append_to(&mut data);
        assert_eq!(data.len(), 244);
        assert_eq!(checksum, 0x26a7f84a);
        assert_eq!(hex::encode(data), INFO_PACKET);
    }

    #[test]
    fn windows31_info_matches_independent_synthetic_wire_vector() {
        let mut packet = info();
        packet.mac = MacAddr(2, 0, 0, 0, 0, 9);
        packet.ip = "192.0.2.9".parse().unwrap();
        packet.username = "example00000".into();
        packet.hostname = "test-host".into();
        packet.dns1 = "192.0.2.53".parse().unwrap();
        packet.dns2 = "192.0.2.54".parse().unwrap();
        packet.flux = vec![1, 2, 3, 4];
        packet.unknown1 = vec![2, 0x22, 0, 0x31];
        packet.unknown2.fill(0);
        packet.os_major.fill(0);
        packet.os_minor.fill(0);
        packet.os_build.fill(0);
        packet.os_unknown.fill(0);
        packet.version = hex::decode("4472434f4d00960231").unwrap();
        packet.hash = "b1b54da1eb64ed14592830f7f895c373d507472a".into();
        let trailer = hex::decode("2001025030007004aa0cb7dee93f3c65").unwrap();
        let mut data = BytesMut::new();
        let checksum =
            packet.append_windows31_to(&mut data, "192.0.2.1".parse().unwrap(), &trailer);
        assert_eq!(data.len(), 260);
        assert_eq!(checksum, 0x3f0b4250);
        assert_eq!(
            hex::encode(data),
            "07010401030c020000000009c0000209022200310102030450420b3f000000006578616d706c653030303030746573742d686f73740000000000000000000000000000000000000000000000c0000235c0000201c0000236000000000000000000000000000000000000000000000000000000004472434f4d0096023100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000623162353464613165623634656431343539323833306637663839356333373364353037343732610000000000000000000000000000000000000000000000002001025030007004aa0cb7dee93f3c65"
        );
    }

    #[test]
    fn windows31_checksum_covers_trailer_and_gateway() {
        let packet = info();
        let mut first = BytesMut::new();
        let mut second = BytesMut::new();
        let mut trailer = vec![0; 16];
        packet.append_windows31_to(&mut first, "192.0.2.1".parse().unwrap(), &trailer);
        trailer[15] = 1;
        packet.append_windows31_to(&mut second, "192.0.2.1".parse().unwrap(), &trailer);
        assert_ne!(&first[24..28], &second[24..28]);
        assert_eq!(&first[80..84], &[192, 0, 2, 1]);
        let mut third = BytesMut::new();
        packet.append_windows31_to(&mut third, "192.0.2.2".parse().unwrap(), &trailer);
        assert_ne!(&second[24..28], &third[24..28]);
    }

    #[test]
    fn windows31_startup_heartbeat_is_distinct_from_regular_heartbeat() {
        let mut bytes = BytesMut::new();
        StartupHeartbeat::append_to(&mut bytes, &[0x12, 0x34]);
        assert_eq!(
            hex::encode(bytes),
            "070028000b010f271234000000000000000000000000000000000000000000000000000000000000"
        );
        for subtype in [4, 6] {
            assert_eq!(
                HeaderType::from_vec(&[7, 0, 6, 0, 11, subtype]),
                HeaderType::MiscHeartbeat
            );
        }
        assert_eq!(HeaderType::from_vec(&[7, 0, 6, 0, 11]), HeaderType::Invalid);
    }

    #[test]
    fn misc_info_preserves_output_prefix() {
        let mut data = BytesMut::from(&b"prefix"[..]);
        info().append_to(&mut data);
        assert_eq!(&data[..6], b"prefix");
        assert_eq!(hex::encode(&data[6..]), INFO_PACKET);
    }

    #[test]
    fn misc_info_checksum_changes_when_flux_changes() {
        let mut data = BytesMut::new();
        let mut packet = info();
        packet.flux = hex::decode("53513f04").unwrap();
        assert_eq!(packet.append_to(&mut data), 0x5103df9a);
        assert_eq!(&data[24..28], &[0x9a, 0xdf, 0x03, 0x51]);
        assert_eq!(data[28], 0);
    }

    #[test]
    fn misc_info_username_and_hostname_share_fixed_44_byte_field() {
        let mut packet = info();
        packet.username = "u".repeat(80);
        packet.hostname = "h".repeat(80);
        let mut data = BytesMut::new();
        packet.append_to(&mut data);
        assert_eq!(data.len(), 244);
        assert_eq!(data[5], 25);
        assert_eq!(&data[32..57], &[b'u'; 25]);
        assert_eq!(&data[57..76], &[b'h'; 19]);
        assert_eq!(&data[76..80], &[202, 38, 193, 33]);
    }

    #[test]
    fn misc_info_utf8_fields_are_bounded_as_wire_bytes() {
        let mut packet = info();
        packet.username = "中文".repeat(10);
        packet.hostname.clear();
        let mut data = BytesMut::new();
        packet.append_to(&mut data);
        assert_eq!(data.len(), 244);
        assert_eq!(data[5], 25);
        assert_eq!(&data[32..57], &packet.username.as_bytes()[..25]);
        assert_eq!(&data[57..76], &[0; 19]);
    }

    #[test]
    fn oversized_local_overrides_cannot_shift_fields_or_underflow_padding() {
        let mut packet = info();
        packet.unknown1 = vec![1; 100];
        packet.flux.clear();
        packet.cks32_param = vec![2; 100];
        packet.unknown2.clear();
        packet.os_major = vec![3; 100];
        packet.os_minor.clear();
        packet.os_build.clear();
        packet.os_unknown.clear();
        packet.version = vec![4; 100];
        packet.hash = "x".repeat(100);
        let mut data = BytesMut::new();
        packet.append_to(&mut data);
        assert_eq!(data.len(), 244);
        assert_eq!(&data[16..20], &[1; 4]);
        assert_eq!(&data[20..24], &[0; 4]);
        assert_eq!(&data[116..180], &[4; 64]);
        assert_eq!(&data[180..244], &[b'x'; 64]);
    }

    #[test]
    fn heartbeat1_encodes_counter_random_and_flux_in_fixed_positions() {
        let mut data = BytesMut::new();
        MiscHeartbeat1 {
            counter: 0x55,
            rnd: vec![0xb9, 0x19],
            flux: hex::decode("67513f04").unwrap(),
        }
        .append_to(&mut data);
        assert_eq!(
            hex::encode(data),
            "075528000b01dc02b91900000000000067513f040000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn heartbeat3_encoder_matches_captured_checksum_fixture() {
        let mut data = BytesMut::new();
        let checksum = MiscHeartbeat3 {
            counter: 0x56,
            rnd: vec![0xb9, 0x19],
            flux: hex::decode("67513f04").unwrap(),
            ip: Ipv4Addr::new(125, 217, 254, 225).into(),
        }
        .append_to(&mut data);
        assert_eq!(checksum, 0x62e0b6);
        assert_eq!(
            hex::encode(data),
            "075628000b03dc02b91900000000000067513f0400000000b6e062007dd9fee10000000000000000"
        );
    }

    #[test]
    fn heartbeat_short_and_long_values_keep_40_byte_layout() {
        let mut first = BytesMut::new();
        MiscHeartbeat1 {
            counter: 0,
            rnd: vec![],
            flux: vec![9; 20],
        }
        .append_to(&mut first);
        assert_eq!(first.len(), 40);
        assert_eq!(&first[8..10], &[0, 0]);
        assert_eq!(&first[16..20], &[9; 4]);
        let mut third = BytesMut::new();
        MiscHeartbeat3 {
            counter: 255,
            rnd: vec![8; 20],
            flux: vec![],
            ip: Ipv4Addr::UNSPECIFIED.into(),
        }
        .append_to(&mut third);
        assert_eq!(third.len(), 40);
        assert_eq!(&third[8..10], &[8; 2]);
        assert_eq!(&third[16..20], &[0; 4]);
    }

    #[test]
    fn alive_wire_fixture_has_little_endian_timestamp() {
        let mut data = BytesMut::new();
        Alive {
            cks_md5: hex::decode("00112233445566778899aabbccddeeff").unwrap(),
            decrypted_from_misc_response_info: hex::decode("4472636fca26d283dd197dd9fee1016c")
                .unwrap(),
        }
        .append_at(&mut data, 0x1234);
        assert_eq!(
            hex::encode(data),
            "ff00112233445566778899aabbccddeeff0000004472636fca26d283dd197dd9fee1016c3412"
        );
    }

    #[test]
    fn alive_zero_pads_and_bounds_authentication_tokens() {
        let mut data = BytesMut::new();
        Alive {
            cks_md5: vec![1],
            decrypted_from_misc_response_info: vec![2; 100],
        }
        .append_at(&mut data, 0);
        assert_eq!(data.len(), 38);
        assert_eq!(data[1], 1);
        assert_eq!(&data[2..20], &[0; 18]);
        assert_eq!(&data[20..36], &[2; 16]);
    }

    #[test]
    fn server_token_decryption_matches_independent_fixture() {
        let mut data = hex::decode("4439d8edac314b07dd8c5f3bef0f04d8").unwrap();
        decrypt_info(&mut data);
        assert_eq!(hex::encode(data), "4472636fca26d283dd197dd9fee1016c");
    }

    #[test]
    fn decryption_handles_empty_and_byte_rotation_boundaries() {
        decrypt_info(&mut []);
        let mut data = [0x81; 16];
        decrypt_info(&mut data);
        assert_eq!(
            data,
            [
                0x81, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0x81, 0x03, 0x06, 0x0c, 0x18, 0x30,
                0x60, 0xc0
            ]
        );
    }

    #[test]
    fn classification_rejects_every_truncated_server_packet() {
        for (kind, min_length) in [(2, 12), (4, 32), (11, 20)] {
            let mut packet = vec![0; min_length];
            packet[0] = 7;
            packet[4] = kind;
            for length in 0..min_length {
                assert_eq!(
                    HeaderType::from_vec(&packet[..length]),
                    HeaderType::Invalid,
                    "kind={kind}, length={length}"
                );
            }
            assert_ne!(HeaderType::from_vec(&packet), HeaderType::Invalid);
        }
    }

    #[test]
    fn classification_separates_known_and_unknown_header_families() {
        for (packet, expected) in [
            (&[7, 0, 0, 0, 1][..], HeaderType::MiscAlive),
            (&[7, 0, 0, 0, 3][..], HeaderType::MiscInfo),
            (&[7, 0, 0, 0, 6][..], HeaderType::MiscResponseHeartbeatAlive),
            (&[7, 0, 0, 0, 255][..], HeaderType::UnknownMisc),
            (
                &[0x4d, 0x38, 0, 0, 0][..],
                HeaderType::MessageServerInformation,
            ),
            (&[0x4d, 0, 0, 0, 0][..], HeaderType::UnknownMessage),
            (&[0, 0, 0, 0, 0][..], HeaderType::Unknown),
        ] {
            assert_eq!(HeaderType::from_vec(packet), expected);
        }
    }

    #[test]
    fn heartbeat_subtype_requires_six_bytes() {
        for length in 0..6 {
            assert_eq!(HeartbeatType::from_vec(&[7; 6][..length]), HeartbeatType(0));
        }
        assert_eq!(
            HeartbeatType::from_vec(&[7, 0, 0, 0, 11, 4]),
            HeartbeatType(4)
        );
    }
}
