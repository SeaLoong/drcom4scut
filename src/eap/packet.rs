use crate::eap::packet::eapol_types::{EAPOL_LOGOFF, EAPOL_START};
use crate::util::{get_mac, put_mac};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use pnet::datalink::MacAddr;

pub struct Header {
    pub ethernet_header: Option<EthernetHeader>,
    pub eapol_header: Option<EAPOLHeader>,
    pub eap_header: Option<EAPHeader>,
}

impl Header {
    #[inline]
    pub fn from_bytes(data: &mut Bytes) -> Header {
        let mut ethernet_header: Option<EthernetHeader> = None;
        let mut eapol_header: Option<EAPOLHeader> = None;
        let mut eap_header: Option<EAPHeader> = None;
        if let Some(pkt) = EthernetHeader::from_bytes(data) {
            let is_eap = pkt.ethernet_type == ethernet_types::IEEE8021X;
            ethernet_header = Some(pkt);
            if is_eap && let Some(pkt) = EAPOLHeader::from_bytes(data) {
                let length = usize::from(pkt.length);
                let packet_type = pkt.eapol_type;
                eapol_header = Some(pkt);
                // Ethernet padding is not part of the EAPOL payload. In particular,
                // Success/Failure packets contain a four-byte EAP header only.
                if data.len() >= length {
                    data.truncate(length);
                    if packet_type == eapol_types::EAP_PACKET {
                        eap_header = EAPHeader::from_bytes(data);
                    }
                }
            }
        }
        Header {
            ethernet_header,
            eapol_header,
            eap_header,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetType(pub u16);
pub mod ethernet_types {
    use crate::eap::packet::EthernetType;
    pub const IEEE8021X: EthernetType = EthernetType(0x888e);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetHeader {
    // 0~13
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethernet_type: EthernetType,
}

impl EthernetHeader {
    #[inline]
    pub fn is_send_to(&self, to: &EthernetHeader) -> bool {
        // Some SCUT switches send periodic Identity requests to the standard
        // PAE multicast address. Accept that destination, while still requiring
        // frames to come from the authenticator learned during discovery.
        let pae_group = MacAddr(1, 0x80, 0xc2, 0, 0, 3);
        (self.destination == to.source || self.destination == pae_group)
            && !self.source.is_zero()
            && self.source.is_unicast()
            && (to.destination.is_zero()
                || to.destination.is_broadcast()
                || to.destination.is_multicast()
                || to.destination == self.source)
    }
    #[inline]
    pub fn append_to(&self, data: &mut BytesMut) {
        put_mac(data, &self.destination);
        put_mac(data, &self.source);
        data.put_u16(self.ethernet_type.0);
    }
    #[inline]
    pub fn from_bytes(data: &mut Bytes) -> Option<EthernetHeader> {
        if data.len() < 14 {
            return None;
        }
        let data = &mut data.split_to(14);
        Some(EthernetHeader {
            destination: get_mac(data),
            source: get_mac(data),
            ethernet_type: EthernetType(data.get_u16()),
        })
    }
}

#[derive(Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Copy)]
pub struct EAPOLType(pub u8);
pub mod eapol_types {
    use crate::eap::packet::EAPOLType;
    pub const EAP_PACKET: EAPOLType = EAPOLType(0);
    pub const EAPOL_START: EAPOLType = EAPOLType(1);
    pub const EAPOL_LOGOFF: EAPOLType = EAPOLType(2);
}

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct EAPOLHeader {
    // 14~17
    pub version: u8,
    pub eapol_type: EAPOLType,
    pub length: u16,
}

impl EAPOLHeader {
    #[inline]
    pub fn append_to(&self, data: &mut BytesMut) {
        data.put_u8(self.version);
        data.put_u8(self.eapol_type.0);
        data.put_u16(self.length);
    }
    #[inline]
    pub fn from_bytes(data: &mut Bytes) -> Option<EAPOLHeader> {
        if data.len() < 4 {
            return None;
        }
        let mut data = data.split_to(4);
        Some(EAPOLHeader {
            version: data.get_u8(),
            eapol_type: EAPOLType(data.get_u8()),
            length: data.get_u16(),
        })
    }
}

#[derive(Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Copy)]
pub struct EAPCode(pub u8);
pub mod eap_codes {
    use crate::eap::packet::EAPCode;
    pub const REQUEST: EAPCode = EAPCode(1);
    pub const RESPONSE: EAPCode = EAPCode(2);
    pub const SUCCESS: EAPCode = EAPCode(3);
    pub const FAILURE: EAPCode = EAPCode(4);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EAPType {
    Identity = 1,
    Notification = 2,
    Md5Challenge = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EAPHeader {
    // 18~21/22
    pub code: EAPCode,
    pub identifier: u8,
    pub length: u16,
    pub eap_type: Option<EAPType>,
}

impl EAPHeader {
    #[inline]
    pub fn append_to(&self, data: &mut BytesMut) {
        data.put_u8(self.code.0);
        data.put_u8(self.identifier);
        data.put_u16(self.length);
        if let Some(t) = self.eap_type {
            data.put_u8(t as u8);
        }
    }
    #[inline]
    pub fn from_bytes(data: &mut Bytes) -> Option<EAPHeader> {
        if data.len() < 4 {
            return None;
        }
        let code = EAPCode(data[0]);
        let length = u16::from_be_bytes([data[2], data[3]]);
        let typed = matches!(code, eap_codes::REQUEST | eap_codes::RESPONSE);
        if usize::from(length) > data.len()
            || length < if typed { 5 } else { 4 }
            || (matches!(code, eap_codes::SUCCESS | eap_codes::FAILURE) && length != 4)
        {
            return None;
        }
        data.truncate(usize::from(length));
        let code = EAPCode(data.get_u8());
        let identifier = data.get_u8();
        let length = data.get_u16();
        let eap_type = if typed {
            match data.get_u8() {
                1 => Some(EAPType::Identity),
                2 => Some(EAPType::Notification),
                4 => Some(EAPType::Md5Challenge),
                _ => None,
            }
        } else {
            None
        };
        Some(EAPHeader {
            code,
            identifier,
            length,
            eap_type,
        })
    }
}

pub(crate) const EAPOL_HEADER_START: EAPOLHeader = EAPOLHeader {
    version: 1,
    eapol_type: EAPOL_START,
    length: 0,
};
pub(crate) const EAPOL_HEADER_LOGOFF: EAPOLHeader = EAPOLHeader {
    version: 1,
    eapol_type: EAPOL_LOGOFF,
    length: 0,
};

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: MacAddr = MacAddr(0, 1, 2, 3, 4, 5);
    const SERVER: MacAddr = MacAddr(6, 7, 8, 9, 10, 11);
    const GROUP: MacAddr = MacAddr(1, 0x80, 0xc2, 0, 0, 3);
    const IDENTITY: &str = "000102030405060708090a0b888e010000050107000501";

    fn decode(hex: &str) -> Bytes {
        Bytes::from(hex::decode(hex).unwrap())
    }

    #[test]
    fn ethernet_header_matches_independent_wire_fixture() {
        let expected = "0180c2000003000102030405888e";
        let header = EthernetHeader {
            destination: GROUP,
            source: CLIENT,
            ethernet_type: ethernet_types::IEEE8021X,
        };
        let mut encoded = BytesMut::new();
        header.append_to(&mut encoded);
        assert_eq!(hex::encode(&encoded), expected);
        let mut raw = decode(expected);
        assert_eq!(EthernetHeader::from_bytes(&mut raw), Some(header));
        assert!(raw.is_empty());
    }

    #[test]
    fn identity_request_wire_fields_and_payload() {
        let mut raw = decode(IDENTITY);
        let headers = Header::from_bytes(&mut raw);
        let ethernet = headers.ethernet_header.unwrap();
        assert_eq!(ethernet.destination, CLIENT);
        assert_eq!(ethernet.source, SERVER);
        assert_eq!(ethernet.ethernet_type, ethernet_types::IEEE8021X);
        assert_eq!(headers.eapol_header.unwrap().length, 5);
        let eap = headers.eap_header.unwrap();
        assert_eq!(eap.code, eap_codes::REQUEST);
        assert_eq!(eap.identifier, 7);
        assert_eq!(eap.length, 5);
        assert_eq!(eap.eap_type, Some(EAPType::Identity));
        assert!(raw.is_empty());
    }

    #[test]
    fn every_truncated_identity_frame_is_rejected() {
        let fixture = hex::decode(IDENTITY).unwrap();
        for length in 0..fixture.len() {
            let mut raw = Bytes::copy_from_slice(&fixture[..length]);
            assert!(
                Header::from_bytes(&mut raw).eap_header.is_none(),
                "length={length}"
            );
        }
    }

    #[test]
    fn ethernet_padding_is_excluded_from_identity_payload() {
        let mut bytes = hex::decode(IDENTITY).unwrap();
        bytes.extend([0xff; 40]);
        let mut raw = Bytes::from(bytes);
        assert!(Header::from_bytes(&mut raw).eap_header.is_some());
        assert!(raw.is_empty());
    }

    #[test]
    fn success_and_failure_do_not_interpret_padding_as_an_eap_type() {
        for code in [3, 4] {
            let mut bytes = hex::decode("000102030405060708090a0b888e0100000403000004").unwrap();
            bytes[18] = code;
            bytes.extend([1; 40]);
            let mut raw = Bytes::from(bytes);
            let eap = Header::from_bytes(&mut raw).eap_header.unwrap();
            assert_eq!(eap.code, EAPCode(code));
            assert_eq!(eap.eap_type, None);
            assert!(raw.is_empty());
        }
    }

    #[test]
    fn declared_eapol_length_cannot_read_ethernet_padding() {
        let mut bytes = hex::decode(IDENTITY).unwrap();
        bytes[17] = 4; // EAP request needs a fifth byte, outside EAPOL payload.
        let mut raw = Bytes::from(bytes);
        assert!(Header::from_bytes(&mut raw).eap_header.is_none());
    }

    #[test]
    fn invalid_nested_lengths_are_rejected_without_consuming_header() {
        for code in [1, 2, 3, 4] {
            for length in [0, 1, 2, 3, 6, u16::MAX] {
                let mut data = vec![code, 9];
                data.extend(length.to_be_bytes());
                data.push(1);
                let mut raw = Bytes::from(data);
                let original = raw.clone();
                assert!(EAPHeader::from_bytes(&mut raw).is_none());
                assert_eq!(raw, original);
            }
        }
    }

    #[test]
    fn request_and_response_require_a_type_octet() {
        for code in [1, 2] {
            let mut raw = Bytes::from(vec![code, 9, 0, 4]);
            assert!(EAPHeader::from_bytes(&mut raw).is_none());
        }
    }

    #[test]
    fn unknown_eap_type_is_preserved_as_unsupported_and_payload_is_bounded() {
        let mut raw = decode("01020007630102aabb");
        let header = EAPHeader::from_bytes(&mut raw).unwrap();
        assert_eq!(header.eap_type, None);
        assert_eq!(&raw[..], &[1, 2]);
    }

    #[test]
    fn non_eap_ethernet_payload_is_not_parsed_as_authentication() {
        let mut bytes = hex::decode(IDENTITY).unwrap();
        bytes[12..14].copy_from_slice(&[8, 0]);
        let mut raw = Bytes::from(bytes);
        let header = Header::from_bytes(&mut raw);
        assert!(header.ethernet_header.is_some());
        assert!(header.eapol_header.is_none());
        assert!(header.eap_header.is_none());
    }

    #[test]
    fn start_and_logoff_wire_fixtures_have_no_eap_payload() {
        for (header, expected) in [
            (EAPOL_HEADER_START, "01010000"),
            (EAPOL_HEADER_LOGOFF, "01020000"),
        ] {
            let mut data = BytesMut::new();
            header.append_to(&mut data);
            assert_eq!(hex::encode(data), expected);
        }
    }

    #[test]
    fn typed_eap_response_uses_network_byte_order() {
        let mut raw = BytesMut::new();
        EAPHeader {
            code: eap_codes::RESPONSE,
            identifier: 0xfe,
            length: 0x1234,
            eap_type: Some(EAPType::Md5Challenge),
        }
        .append_to(&mut raw);
        assert_eq!(hex::encode(raw), "02fe123404");
    }

    #[test]
    fn server_filter_locks_to_authenticated_unicast_peer() {
        let expected = EthernetHeader {
            destination: SERVER,
            source: CLIENT,
            ethernet_type: ethernet_types::IEEE8021X,
        };
        let valid = EthernetHeader {
            destination: CLIENT,
            source: SERVER,
            ethernet_type: ethernet_types::IEEE8021X,
        };
        assert!(valid.is_send_to(&expected));
        let forged = EthernetHeader {
            source: MacAddr(6, 6, 6, 6, 6, 6),
            ..valid
        };
        assert!(!forged.is_send_to(&expected));
    }

    #[test]
    fn pae_multicast_heartbeat_requires_the_learned_server() {
        let expected = EthernetHeader {
            destination: SERVER,
            source: CLIENT,
            ethernet_type: ethernet_types::IEEE8021X,
        };
        let multicast = EthernetHeader {
            destination: GROUP,
            source: SERVER,
            ethernet_type: ethernet_types::IEEE8021X,
        };
        assert!(multicast.is_send_to(&expected));
        assert!(
            !EthernetHeader {
                source: MacAddr(2, 2, 2, 2, 2, 2),
                ..multicast.clone()
            }
            .is_send_to(&expected)
        );
        assert!(
            !EthernetHeader {
                destination: MacAddr(1, 0, 0x5e, 0, 0, 1),
                ..multicast.clone()
            }
            .is_send_to(&expected)
        );
        assert!(
            !EthernetHeader {
                source: MacAddr::zero(),
                ..multicast.clone()
            }
            .is_send_to(&expected)
        );
        assert!(
            !EthernetHeader {
                source: GROUP,
                ..multicast
            }
            .is_send_to(&expected)
        );
    }

    #[test]
    fn discovery_allows_server_response_but_requires_client_destination() {
        let expected = EthernetHeader {
            destination: GROUP,
            source: CLIENT,
            ethernet_type: ethernet_types::IEEE8021X,
        };
        let valid = EthernetHeader {
            destination: CLIENT,
            source: SERVER,
            ethernet_type: ethernet_types::IEEE8021X,
        };
        assert!(valid.is_send_to(&expected));
        let unrelated = EthernetHeader {
            destination: MacAddr::broadcast(),
            ..valid
        };
        assert!(!unrelated.is_send_to(&expected));
    }
}

#[cfg(test)]
mod malformed_tests {
    use super::*;

    #[test]
    fn arbitrary_bounded_frames_never_panic_during_header_parsing() {
        // Deterministic malformed traffic corpus; valid fixtures in `tests`
        // ensure that rejecting all input could not make the parser pass.
        for length in 0..128 {
            for seed in 0..16u8 {
                let mut bytes: Vec<_> = (0..length)
                    .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
                    .collect();
                if length >= 14 {
                    bytes[12..14].copy_from_slice(&[0x88, 0x8e]);
                }
                Header::from_bytes(&mut Bytes::from(bytes));
            }
        }
    }

    #[test]
    fn challenge_payload_is_bounded_by_both_protocol_lengths() {
        // Ethernet + EAPOL(length=22) + EAP Request MD5(length=22) + size16 + challenge.
        let mut data = hex::decode(
            "000102030405060708090a0b888e01000016010900160410000102030405060708090a0b0c0d0e0f",
        )
        .unwrap();
        data.extend([0xaa; 20]);
        let mut data = Bytes::from(data);
        let header = Header::from_bytes(&mut data).eap_header.unwrap();
        assert_eq!(header.eap_type, Some(EAPType::Md5Challenge));
        assert_eq!(header.length, 22);
        assert_eq!(data.len(), 17);
        assert_eq!(data[0], 16);
        assert_eq!(&data[1..], &(0..16u8).collect::<Vec<_>>());
    }
}
