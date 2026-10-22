use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::{RuntimeProvider, TokioRuntimeProvider};
use hickory_resolver::proto::rr::RData;
use log::{error, info};
use tokio::net::UdpSocket;

use crate::settings::Settings;

/// Try the configured campus DNS servers in order without blocking a runtime worker.
/// The wire protocol carries four-byte addresses, so only A records are usable.
pub async fn resolve_dns(settings: &Settings) -> Option<(IpAddr, SocketAddr)> {
    resolve_dns_from(settings, IpAddr::V4(Ipv4Addr::UNSPECIFIED)).await
}

/// Use the physical interface address for both DNS and DrCOM traffic. Payload
/// authentication addresses are independent and must never select the route.
pub async fn resolve_dns_from(settings: &Settings, source: IpAddr) -> Option<(IpAddr, SocketAddr)> {
    if !source.is_ipv4() {
        error!("The DrCOM DNS source address must be IPv4.");
        return None;
    }
    // Explicit IPv4 server addresses bypass DNS. The packet still advertises
    // the first configured campus DNS server, as with a successful lookup.
    if let Ok(ip) = settings.host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(_) => settings.dns.first().copied().map(|dns| (ip, dns)),
            IpAddr::V6(_) => {
                error!("The DrCOM UDP protocol requires an IPv4 server address.");
                None
            }
        };
    }
    for address in &settings.dns {
        let mut server = NameServerConfig::udp(address.ip());
        server.trust_negative_responses = false;
        server.connections[0].port = address.port();
        server.connections[0].bind_addr = Some(SocketAddr::new(source, 0));
        let config = ResolverConfig::from_name_servers(vec![server]);
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_secs(3);
        options.attempts = 1;
        let resolver = match Resolver::builder_with_config(config, InterfaceRuntime::default())
            .with_options(options)
            .build()
        {
            Ok(resolver) => resolver,
            Err(e) => {
                error!("Unable to configure DNS resolver: {e}");
                continue;
            }
        };
        info!("Use DNS: {}", address);
        match resolver.ipv4_lookup(&settings.host).await {
            Ok(lookup) => {
                if let Some(ip) = lookup
                    .answers()
                    .iter()
                    .find_map(|record| match &record.data {
                        RData::A(address) => Some(address.0),
                        _ => None,
                    })
                {
                    let ip = IpAddr::V4(ip);
                    info!("Resolved UDP server: {ip}");
                    return Some((ip, *address));
                }
            }
            Err(e) => error!("DNS lookup using {address} failed: {e}"),
        }
    }
    None
}

/// Bind an explicitly selected source address and local/server ports. An
/// occupied configured port is an error, never silently replaced by another.
pub async fn socket_bind_from(
    server: IpAddr,
    source: IpAddr,
    local_port: u16,
    server_port: u16,
) -> Option<UdpSocket> {
    if !server.is_ipv4() || !source.is_ipv4() || server_port == 0 {
        error!("DrCOM requires IPv4 addresses and a nonzero server port.");
        return None;
    }
    let socket = match UdpSocket::bind(SocketAddr::new(source, local_port)).await {
        Ok(socket) => socket,
        Err(error) => {
            error!("Cannot bind DrCOM source socket: {error}");
            return None;
        }
    };
    if let Err(error) = bind_selected_interface(&socket, source) {
        error!("Cannot bind DrCOM physical interface: {error}");
        return None;
    }
    if let Err(error) = socket.connect(SocketAddr::new(server, server_port)).await {
        error!("Cannot connect DrCOM UDP socket: {error}");
        return None;
    }
    Some(socket)
}

// Hickory owns its sockets; customize only creation to retain the selected
// source/interface instead of falling back to a Wi-Fi/VPN default route.
#[derive(Clone, Default)]
struct InterfaceRuntime(TokioRuntimeProvider);

impl RuntimeProvider for InterfaceRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

    fn create_handle(&self) -> Self::Handle {
        self.0.create_handle()
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        source: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> std::pin::Pin<Box<dyn Send + std::future::Future<Output = io::Result<Self::Tcp>>>> {
        self.0.connect_tcp(server, source, timeout)
    }

    fn bind_udp(
        &self,
        source: SocketAddr,
        _server: SocketAddr,
    ) -> std::pin::Pin<Box<dyn Send + std::future::Future<Output = io::Result<Self::Udp>>>> {
        Box::pin(async move {
            let socket = UdpSocket::bind(source).await?;
            bind_selected_interface(&socket, source.ip())?;
            Ok(socket)
        })
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn selected_interface(
    source: IpAddr,
    interfaces: &[pnet::datalink::NetworkInterface],
) -> io::Result<&pnet::datalink::NetworkInterface> {
    let mut matches = interfaces
        .iter()
        .filter(|interface| interface.ips.iter().any(|network| network.ip() == source));
    let interface = matches.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "source IPv4 is not assigned to an interface",
        )
    })?;
    if matches.any(|other| other.index != interface.index) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source IPv4 is ambiguous across interfaces",
        ));
    }
    Ok(interface)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_selected_interface(socket: &UdpSocket, source: IpAddr) -> io::Result<()> {
    if source.is_unspecified() || source.is_loopback() {
        return Ok(());
    }
    let interfaces = pnet::datalink::interfaces();
    let interface = selected_interface(source, &interfaces)?;
    // Raw Ethernet authentication already needs capture privileges. Use the same
    // device for IP packets too instead of changing system routing or Wi-Fi state.
    socket2::SockRef::from(socket).bind_device(Some(interface.name.as_bytes()))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
fn bind_selected_interface(_socket: &UdpSocket, _source: IpAddr) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn bind_selected_interface(socket: &UdpSocket, source: IpAddr) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, SOCKET_ERROR, WSAGetLastError, setsockopt,
    };
    if source.is_unspecified() || source.is_loopback() {
        return Ok(());
    }
    let interfaces = crate::device::get_all_interfaces();
    let index = selected_interface(source, &interfaces)?.index;
    let index = index.to_be();
    // SAFETY: `socket` owns a live Winsock socket throughout this call. The DWORD
    // buffer is initialized, correctly sized and remains alive until completion.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            IPPROTO_IP,
            IP_UNICAST_IF,
            (&index as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        // SAFETY: Winsock last-error inspection takes no pointers or resources.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

pub async fn socket_bind(ip: IpAddr) -> Option<UdpSocket> {
    if !ip.is_ipv4() {
        error!("The DrCOM UDP protocol requires an IPv4 server address.");
        return None;
    }
    let address = SocketAddr::new(ip, 61440);
    for port in 36144..=u16::MAX {
        match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await {
            Ok(socket) => {
                // A connect failure is unrelated to the chosen local port.
                if let Err(e) = socket.connect(address).await {
                    error!("Unable to connect UDP socket: {e}");
                    return None;
                }
                return Some(socket);
            }
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
            Err(e) => {
                error!("Unable to bind UDP socket: {e}");
                return None;
            }
        }
    }
    None
}

/// A connected datagram socket. Each send is exactly one protocol datagram.
pub struct Socket {
    socket: UdpSocket,
}

impl Socket {
    pub fn new(socket: UdpSocket) -> Socket {
        Socket { socket }
    }

    pub async fn send(&self, data: Vec<u8>) -> io::Result<()> {
        let sent = self.socket.send(&data).await?;
        if sent != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial UDP datagram",
            ));
        }
        Ok(())
    }

    pub async fn receive(&self) -> io::Result<Vec<u8>> {
        // Oversized datagrams cannot become a valid truncated protocol packet.
        let mut buffer = [0u8; 65536];
        let size = self.socket.recv(&mut buffer).await?;
        Ok(buffer[..size].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn socket_preserves_datagram_boundaries_and_empty_payloads() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();
        let a = Socket::new(a);
        let b = Socket::new(b);
        a.send(vec![1, 2, 3]).await.unwrap();
        a.send(Vec::new()).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), b.receive())
                .await
                .unwrap()
                .unwrap(),
            [1, 2, 3]
        );
        assert!(
            timeout(Duration::from_secs(1), b.receive())
                .await
                .unwrap()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cancelled_receive_does_not_consume_the_next_datagram() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();
        let a = Socket::new(a);
        let b = Socket::new(b);
        assert!(
            timeout(Duration::from_millis(5), a.receive())
                .await
                .is_err()
        );
        b.send(vec![42]).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), a.receive())
                .await
                .unwrap()
                .unwrap(),
            [42]
        );
    }

    #[tokio::test]
    async fn dns_uses_configured_server_and_filters_ipv4_records() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (size, peer) = server.recv_from(&mut buffer).await.unwrap();
            let query = &buffer[..size];
            let mut question_end = 12;
            while query[question_end] != 0 {
                question_end += query[question_end] as usize + 1;
            }
            question_end += 5;
            let mut response = query[..question_end].to_vec();
            response[2..4].copy_from_slice(&[0x81, 0x80]);
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response[8..12].fill(0);
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 7]);
            server.send_to(&response, peer).await.unwrap();
        });
        let settings = Settings {
            host: "drcom.test.".into(),
            dns: vec![address],
            ..Settings::default()
        };
        assert_eq!(
            timeout(Duration::from_secs(2), resolve_dns(&settings))
                .await
                .unwrap(),
            Some((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)), address))
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn literal_ipv4_bypasses_dns_and_keeps_configured_dns_metadata() {
        // A real socket remains deliberately unanswered: even a single DNS
        // query would be observed here, and resolving must complete immediately.
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = dns.local_addr().unwrap();
        let settings = Settings {
            host: "192.0.2.7".into(),
            dns: vec![address, "192.0.2.53:53".parse().unwrap()],
            ..Settings::default()
        };
        assert_eq!(
            timeout(Duration::from_millis(50), resolve_dns(&settings))
                .await
                .unwrap(),
            Some(("192.0.2.7".parse().unwrap(), address))
        );
        let mut buffer = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(10), dns.recv_from(&mut buffer))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn literal_host_still_requires_dns_metadata_and_rejects_ipv6() {
        let mut settings = Settings {
            host: "192.0.2.7".into(),
            ..Settings::default()
        };
        assert!(resolve_dns(&settings).await.is_none());
        settings.host = "::1".into();
        settings.dns = vec!["127.0.0.1:53".parse().unwrap()];
        assert!(
            timeout(Duration::from_millis(50), resolve_dns(&settings))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    #[test]
    fn physical_source_selection_rejects_missing_and_ambiguous_adapters() {
        use pnet::datalink::NetworkInterface;
        use pnet::ipnetwork::IpNetwork;
        let source: IpAddr = "192.0.2.10".parse().unwrap();
        let first = NetworkInterface {
            name: "wired".into(),
            description: String::new(),
            index: 7,
            mac: None,
            flags: 0,
            ips: vec![IpNetwork::new(source, 24).unwrap()],
        };
        let mut second = first.clone();
        second.name = "wifi".into();
        second.index = 8;
        assert_eq!(
            selected_interface(source, std::slice::from_ref(&first))
                .unwrap()
                .index,
            7
        );
        assert_eq!(
            selected_interface("192.0.2.11".parse().unwrap(), std::slice::from_ref(&first))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrNotAvailable
        );
        assert_eq!(
            selected_interface(source, &[first.clone(), second])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        // An inventory may repeat an entry for the same physical index.
        assert_eq!(
            selected_interface(source, &[first.clone(), first])
                .unwrap()
                .index,
            7
        );
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn dns_packets_use_selected_physical_source_address() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let source: IpAddr = "127.0.0.2".parse().unwrap();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (size, peer) = server.recv_from(&mut bytes).await.unwrap();
            assert_eq!(
                peer.ip(),
                source,
                "DNS must not follow another interface's source"
            );
            let query = &bytes[..size];
            let mut end = 12;
            while query[end] != 0 {
                end += query[end] as usize + 1;
            }
            end += 5;
            let mut reply = query[..end].to_vec();
            reply[2..4].copy_from_slice(&[0x81, 0x80]);
            reply[6..8].copy_from_slice(&1u16.to_be_bytes());
            reply[8..12].fill(0);
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 7]);
            server.send_to(&reply, peer).await.unwrap();
        });
        let settings = Settings {
            host: "source.test.".into(),
            dns: vec![address],
            ..Settings::default()
        };
        assert_eq!(
            timeout(Duration::from_secs(2), resolve_dns_from(&settings, source))
                .await
                .unwrap(),
            Some(("192.0.2.7".parse().unwrap(), address))
        );
        task.await.unwrap();
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn udp_packets_use_selected_source_and_configured_server_port() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source: IpAddr = "127.0.0.2".parse().unwrap();
        let socket = socket_bind_from(
            server.local_addr().unwrap().ip(),
            source,
            0,
            server.local_addr().unwrap().port(),
        )
        .await
        .unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), source);
        socket.send(b"bound-source").await.unwrap();
        let mut bytes = [0; 32];
        let (size, peer) = timeout(Duration::from_secs(1), server.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer.ip(), source);
        assert_eq!(&bytes[..size], b"bound-source");
    }

    #[tokio::test]
    async fn configured_source_port_collision_is_reported_without_fallback() {
        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = occupied.local_addr().unwrap();
        assert!(
            socket_bind_from(address.ip(), address.ip(), address.port(), 61440)
                .await
                .is_none()
        );
        assert!(
            socket_bind_from("::1".parse().unwrap(), address.ip(), 0, 61440)
                .await
                .is_none()
        );
        assert!(
            socket_bind_from(address.ip(), "::1".parse().unwrap(), 0, 61440)
                .await
                .is_none()
        );
        assert!(
            socket_bind_from(address.ip(), address.ip(), 0, 0)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn ipv6_server_is_rejected_without_binding() {
        assert!(socket_bind("::1".parse().unwrap()).await.is_none());
    }
}
