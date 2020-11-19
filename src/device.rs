use pnet::datalink::{
    channel, interfaces, Channel, Config, DataLinkReceiver, DataLinkSender, MacAddr,
    NetworkInterface,
};
use pnet::ipnetwork::IpNetwork;
use std::cell::RefCell;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr};

pub struct Device {
    pub interface: NetworkInterface,
    pub mac: MacAddr,
    pub ip_net: IpNetwork,
    sender: RefCell<Box<dyn DataLinkSender>>,
    receiver: RefCell<Box<dyn DataLinkReceiver>>,
}

unsafe impl Sync for Device {}

#[inline]
fn filter_interface<P: FnMut(&NetworkInterface) -> bool>(f: P) -> Option<NetworkInterface> {
    interfaces().into_iter().find(f)
}

fn get_first_valid_ip(e: &NetworkInterface) -> Option<&IpNetwork> {
    for ip_net in &e.ips {
        if ip_net.prefix() != 0 && ip_net.ip().is_global() {
            return Some(ip_net);
        }
    }
    None
}

pub fn get_all_interfaces() -> Vec<NetworkInterface> {
    let mut all_interfaces = interfaces();
    all_interfaces.sort_by(|a, b| a.index.cmp(&b.index));
    all_interfaces
}

pub fn get_device(mac: Option<MacAddr>, ip: Option<IpAddr>) -> Result<Device> {
    if let Some(m) = mac {
        return Device::from_mac(m);
    }
    if let Some(ip) = ip {
        return Device::from_ip(ip);
    }
    Device::default()
}

impl Device {
    pub fn from_mac(mac: MacAddr) -> Result<Device> {
        let interface = filter_interface(|e| match e.mac {
            Some(ref m) => *m == mac,
            None => false,
        });
        match interface {
            Some(interface) => Device::new(interface),
            None => Err(Error::new(
                ErrorKind::NotFound,
                format!("Can't get interface which MAC address is {}.", mac),
            )),
        }
    }

    pub fn from_ip(ip: IpAddr) -> Result<Device> {
        let mut ip_net = IpNetwork::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0).unwrap();
        let interface = filter_interface(|e| {
            for i in &e.ips {
                if i.ip() == ip {
                    ip_net = *i;
                    return true;
                }
            }
            false
        });
        match interface {
            Some(interface) => Device::with_ip_net(interface, ip_net),
            None => Err(Error::new(
                ErrorKind::NotFound,
                format!("Can't get interface which IP address is {}.", ip),
            )),
        }
    }

    pub fn new(interface: NetworkInterface) -> Result<Device> {
        let ip = if let Some(ip) = get_first_valid_ip(&interface) {
            ip.to_owned()
        } else if let Some(ip) = interface.ips.get(0) {
            ip.to_owned()
        } else {
            IpNetwork::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0).unwrap()
        };
        Device::with_ip_net(interface, ip)
    }

    pub fn with_ip_net(interface: NetworkInterface, ip_net: IpNetwork) -> Result<Device> {
        if interface.mac.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "The interface {} has not a valid MAC address.",
                    interface.name
                ),
            ));
        }
        let ch = channel(&interface, Config::default());
        match ch {
            Ok(Channel::Ethernet(tx, rx)) => Ok(Device {
                sender: RefCell::new(tx),
                receiver: RefCell::new(rx),
                mac: interface.mac.unwrap(),
                ip_net,
                interface,
            }),
            Ok(_) => Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Created an unknown channel type on Device {}.",
                    interface.name
                ),
            )),
            Err(err) => Err(err),
        }
    }

    pub fn default() -> Result<Device> {
        let all_interfaces = get_all_interfaces();
        for e in &all_interfaces {
            if let Some(ip_net) = get_first_valid_ip(e) {
                return Device::with_ip_net(e.to_owned(), ip_net.to_owned());
            }
        }
        if let Some(e) = all_interfaces.get(0) {
            Device::new(e.to_owned())
        } else {
            Err(Error::new(
                ErrorKind::NotFound,
                "Can't get the default interface.",
            ))
        }
    }

    pub fn send(&self, data: Vec<u8>) -> Result<()> {
        let mut sender = self.sender.borrow_mut();
        loop {
            if let Some(r) = sender.send_to(&data[..], None) {
                return r;
            }
        }
    }

    pub fn receive(&self) -> Result<Vec<u8>> {
        Ok(self.receiver.borrow_mut().next()?.to_vec())
    }
}

#[test]
fn test_device() {
    println!("{:?}", Device::default().unwrap().mac);
    assert!(Device::from_mac(MacAddr::new(0, 0, 0, 0, 0, 0)).is_err());
    println!(
        "{:?}",
        Device::from_ip(IpAddr::from([125, 217, 254, 225]))
            .unwrap()
            .mac
    );
}
