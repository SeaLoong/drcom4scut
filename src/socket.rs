use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use log::{error, info};
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

use crate::settings::Settings;

pub fn resolve_dns(settings: &Settings) -> Option<(IpAddr, SocketAddr)> {
    info!("DNS resolving...");
    let mut r: Option<(IpAddr, SocketAddr)> = None;
    for address in &settings.dns {
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig {
            socket_addr: *address,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        info!("Use DNS: {}:{}", address.ip(), address.port());
        let resolver = match Resolver::new(config, ResolverOpts::default()) {
            Ok(r) => r,
            Err(_) => {
                error!("Failed to connect resolver.");
                continue;
            }
        };
        let lookup = match resolver.lookup_ip(&settings.host[..]) {
            Ok(r) => r,
            Err(_) => {
                error!("Failed to lookup.");
                continue;
            }
        };
        for ip in lookup {
            if r.is_some() {
                break;
            }
            r = Some((ip, *address));
        }
        if r.is_some() {
            break;
        }
        error!("No addresses returned!");
    }
    info!("Resolve result:");
    if r.is_some() {
        info!("IP: {}", &r.unwrap().0);
    } else {
        error!("Resolve failed.");
    }
    r
}

pub fn socket_bind(ip: IpAddr) -> Option<UdpSocket> {
    let mut port = 36144;
    let address = SocketAddr::new(ip, 61440);
    loop {
        match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)) {
            Ok(r) => {
                if r.connect(address).is_ok() {
                    return Some(r);
                }
            }
            Err(_) => {
                if port == u16::MAX {
                    return None;
                }
            }
        }
        port += 1;
    }
}

pub struct Socket {
    socket: UdpSocket,
}

impl Socket {
    pub fn new(socket: UdpSocket) -> Socket {
        Socket { socket }
    }

    pub fn send(&self, data: Vec<u8>) -> io::Result<()> {
        let l = data.len();
        let mut n = 0;
        while n < l {
            n += self.socket.send(&data[n..l])?;
        }
        Ok(())
    }

    pub fn receive(&self) -> io::Result<Vec<u8>> {
        let mut buffer = [0u8; 2048];
        let size = self.socket.recv(&mut buffer)?;
        let v = buffer[..size].to_vec();
        Ok(v)
    }
}
