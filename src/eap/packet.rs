use crate::eap::packet::eapol_types::{EAPOL_LOGOFF, EAPOL_START};
use crate::util::{get_mac, put_mac};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use pnet::datalink::MacAddr;

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
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
            ethernet_header = Some(pkt);
            if let Some(pkt) = EAPOLHeader::from_bytes(data) {
                eapol_header = Some(pkt);
                if let Some(pkt) = EAPHeader::from_bytes(data) {
                    eap_header = Some(pkt);
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

#[derive(Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Copy)]
pub struct EthernetType(pub u16);
pub mod ethernet_types {
    use crate::eap::packet::EthernetType;
    pub const IEEE8021X: EthernetType = EthernetType(0x888e);
}

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct EthernetHeader {
    // 0~13
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethernet_type: EthernetType,
}

impl EthernetHeader {
    #[inline]
    pub fn is_send_to(&self, to: &EthernetHeader) -> bool {
        self.destination == to.source
            && (to.destination.is_zero()
                || to.destination.is_broadcast()
                || to.destination.is_multicast()
                || to.destination.is_unicast()
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

#[derive(Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Copy)]
pub struct EAPType(pub u8);
pub mod eap_types {
    use crate::eap::packet::EAPType;
    pub const IDENTITY: EAPType = EAPType(1);
    pub const NOTIFICATION: EAPType = EAPType(2);
    pub const MD5_CHALLENGE: EAPType = EAPType(4);
}

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
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
            data.put_u8(t.0);
        }
    }
    #[inline]
    pub fn from_bytes(data: &mut Bytes) -> Option<EAPHeader> {
        if data.len() < 4 {
            return None;
        }
        Some(EAPHeader {
            code: EAPCode(data.get_u8()),
            identifier: data.get_u8(),
            length: data.get_u16(),
            eap_type: if data.is_empty() {
                None
            } else {
                Some(EAPType(data.get_u8()))
            },
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
