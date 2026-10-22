#[cfg(not(windows))]
use pnet::datalink::{Channel, Config, channel, interfaces};
use pnet::datalink::{DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;

pub struct Device {
    pub interface: NetworkInterface,
    pub mac: MacAddr,
    pub ip_net: IpNetwork,
    sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
    receiver: Arc<Mutex<Box<dyn DataLinkReceiver>>>,
    pending_receive: tokio::sync::Mutex<Option<JoinHandle<Result<Vec<u8>>>>>,
}

fn get_first_valid_ip(e: &NetworkInterface) -> Option<&IpNetwork> {
    e.ips
        .iter()
        .find(|&ip_net| ip_net.prefix() != 0 && usable_ipv4(ip_net.ip()))
}

pub fn get_all_interfaces() -> Vec<NetworkInterface> {
    #[cfg(not(windows))]
    let mut all_interfaces = interfaces();
    #[cfg(windows)]
    let mut all_interfaces = windows_inventory::interfaces();
    #[cfg(windows)]
    for interface in &mut all_interfaces {
        use windows_sys::Win32::NetworkManagement::{
            IpHelper::{GetIfEntry2, MIB_IF_ROW2},
            Ndis::IfOperStatusUp,
        };
        let mut row = MIB_IF_ROW2 {
            InterfaceIndex: interface.index,
            ..MIB_IF_ROW2::default()
        };
        // SAFETY: row is initialized, correctly sized and exclusively borrowed;
        // GetIfEntry2 writes only this structure and retains no pointer.
        if unsafe { GetIfEntry2(&mut row) } == 0 {
            // pnet's Windows backend leaves all flags at zero. These are its
            // documented Windows IFF_UP / IFF_LOOPBACK values, not Unix flags.
            interface.flags = if row.OperStatus == IfOperStatusUp {
                0x1
            } else {
                0
            };
            if row.Type == 24 {
                interface.flags |= 0x4;
            } // IF_TYPE_SOFTWARE_LOOPBACK
        }
    }
    all_interfaces.sort_by_key(|interface| interface.index);
    all_interfaces
}

#[cfg(windows)]
mod windows_inventory {
    use super::*;
    use windows_sys::Win32::{
        NetworkManagement::{
            IpHelper::{
                GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
                GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
            },
            Ndis::IfOperStatusUp,
        },
        Networking::WinSock::{AF_INET, SOCKADDR_IN},
    };

    // pnet's Windows inventory invokes PacketGetAdapterNames. Inventory must
    // remain available before Npcap installation, including for wireless Portal.
    // IP Helper also retains loopback and links awaiting their first DHCP lease.
    pub(super) fn interfaces() -> Vec<NetworkInterface> {
        let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size = 15_000u32;
        for _ in 0..3 {
            if size == 0 || size > 16 * 1024 * 1024 {
                return Vec::new();
            }
            // Typed storage provides the alignment required by the native API.
            let count = (size as usize).div_ceil(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
            let mut storage = vec![IP_ADAPTER_ADDRESSES_LH::default(); count];
            // SAFETY: storage is aligned, initialized and at least `size` bytes;
            // the API retains no pointers after return. Its linked records and
            // strings remain alive until all fields are copied into owned Rust data.
            let result = unsafe {
                GetAdaptersAddresses(
                    AF_INET as u32,
                    flags,
                    std::ptr::null(),
                    storage.as_mut_ptr(),
                    &mut size,
                )
            };
            if result == 111 {
                continue; // ERROR_BUFFER_OVERFLOW: adapter topology changed.
            }
            if result != 0 {
                return Vec::new();
            }
            let mut interfaces = Vec::new();
            let mut cursor = storage.as_ptr();
            while !cursor.is_null() {
                // SAFETY: a successful GetAdaptersAddresses call supplies a
                // valid linked list, kept alive by storage throughout this walk.
                let adapter = unsafe { &*cursor };
                // SAFETY: all adapter pointers refer to the same live API buffer.
                interfaces.push(unsafe { from_adapter(adapter) });
                cursor = adapter.Next;
            }
            return interfaces;
        }
        Vec::new()
    }

    // SAFETY: embedded pointers must reference initialized, live IP Helper records
    // and NUL-terminated strings until this function has copied their contents.
    unsafe fn from_adapter(adapter: &IP_ADAPTER_ADDRESSES_LH) -> NetworkInterface {
        // SAFETY: AdapterName is the native API's live NUL-terminated ANSI name.
        let name = if adapter.AdapterName.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(adapter.AdapterName.cast()) }
                .to_string_lossy()
                .into_owned()
        };
        // SAFETY: both fields are live API-owned NUL-terminated UTF-16 strings.
        let mut description = unsafe { wide_string(adapter.FriendlyName) };
        if description.is_empty() {
            description = unsafe { wide_string(adapter.Description) };
        }
        let mut ips = Vec::new();
        let mut cursor = adapter.FirstUnicastAddress;
        while !cursor.is_null() {
            // SAFETY: the caller keeps the linked unicast records alive.
            let address = unsafe { &*cursor };
            if !address.Address.lpSockaddr.is_null()
                && address.Address.iSockaddrLength >= std::mem::size_of::<SOCKADDR_IN>() as i32
            {
                // SAFETY: the length is sufficient for sockaddr_in; reading
                // unaligned also supports buffers whose sockaddr lacks alignment.
                let socket = unsafe {
                    std::ptr::read_unaligned(address.Address.lpSockaddr.cast::<SOCKADDR_IN>())
                };
                if socket.sin_family == AF_INET {
                    // SAFETY: AF_INET selects the IPv4 member. to_ne_bytes
                    // preserves its network-order bytes on either CPU endian.
                    let ip = Ipv4Addr::from(unsafe { socket.sin_addr.S_un.S_addr }.to_ne_bytes());
                    if let Ok(network) = IpNetwork::new(ip.into(), address.OnLinkPrefixLength) {
                        ips.push(network);
                    }
                }
            }
            cursor = address.Next;
        }
        let mac = (adapter.PhysicalAddressLength == 6).then(|| {
            let bytes = adapter.PhysicalAddress;
            MacAddr::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
        });
        // SAFETY: the documented anonymous header contains initialized IfIndex.
        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let mut flags = if adapter.OperStatus == IfOperStatusUp {
            1
        } else {
            0
        };
        if adapter.IfType == 24 {
            flags |= 4; // Windows pnet IFF_LOOPBACK / IF_TYPE_SOFTWARE_LOOPBACK.
        }
        NetworkInterface {
            name: format!(r"\Device\NPF_{name}"),
            description,
            index,
            mac,
            ips,
            flags,
        }
    }

    unsafe fn wide_string(pointer: *const u16) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let mut length = 0;
        // SAFETY: the caller guarantees a live NUL-terminated UTF-16 string.
        while unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: the preceding scan found the initialized string's terminator.
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::{
            NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
            Networking::WinSock::{IN_ADDR, IN_ADDR_0, SOCKET_ADDRESS},
        };

        #[test]
        fn inventory_preserves_capture_name_unicode_mac_and_ipv4_prefix() {
            let mut name = b"{12345678-1234-1234-1234-123456789ABC}\0".to_vec();
            let mut friendly: Vec<u16> = "校园以太网".encode_utf16().chain(Some(0)).collect();
            let mut socket = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes([192, 0, 2, 17]),
                    },
                },
                ..SOCKADDR_IN::default()
            };
            let mut unicast = IP_ADAPTER_UNICAST_ADDRESS_LH {
                Address: SOCKET_ADDRESS {
                    lpSockaddr: (&mut socket as *mut SOCKADDR_IN).cast(),
                    iSockaddrLength: std::mem::size_of::<SOCKADDR_IN>() as i32,
                },
                OnLinkPrefixLength: 24,
                ..IP_ADAPTER_UNICAST_ADDRESS_LH::default()
            };
            let mut adapter = IP_ADAPTER_ADDRESSES_LH {
                AdapterName: name.as_mut_ptr(),
                FriendlyName: friendly.as_mut_ptr(),
                FirstUnicastAddress: &mut unicast,
                PhysicalAddressLength: 6,
                PhysicalAddress: [2, 1, 2, 3, 4, 5, 0, 0],
                OperStatus: IfOperStatusUp,
                ..IP_ADAPTER_ADDRESSES_LH::default()
            };
            adapter.Anonymous1.Anonymous.IfIndex = 17;
            // SAFETY: fixture strings, sockaddr and unicast records remain alive.
            let interface = unsafe { from_adapter(&adapter) };
            assert_eq!(
                interface.name,
                r"\Device\NPF_{12345678-1234-1234-1234-123456789ABC}"
            );
            assert_eq!(interface.description, "校园以太网");
            assert_eq!(interface.index, 17);
            assert_eq!(interface.mac, Some(MacAddr::new(2, 1, 2, 3, 4, 5)));
            assert_eq!(
                interface.ips,
                ["192.0.2.17/24".parse::<IpNetwork>().unwrap()]
            );
            assert!(interface.is_up());
        }

        #[test]
        fn inventory_retains_loopback_and_links_before_dhcp_without_fabricating_mac() {
            let adapter = IP_ADAPTER_ADDRESSES_LH {
                IfType: 24,
                OperStatus: IfOperStatusUp,
                ..IP_ADAPTER_ADDRESSES_LH::default()
            };
            // SAFETY: all optional fixture pointers are null and no list is read.
            let interface = unsafe { from_adapter(&adapter) };
            assert!(interface.is_loopback());
            assert!(interface.is_up());
            assert!(interface.mac.is_none());
            assert!(interface.ips.is_empty());
            let adapter = IP_ADAPTER_ADDRESSES_LH {
                IfType: 6,
                ..adapter
            };
            // SAFETY: all optional fixture pointers remain null.
            let interface = unsafe { from_adapter(&adapter) };
            assert!(!interface.is_loopback());
            assert!(
                interface.ips.is_empty(),
                "a link awaiting DHCP stays in inventory"
            );
        }
    }
}

pub fn get_device(mac: Option<MacAddr>, ip: Option<IpAddr>) -> Result<Device> {
    get_device_on(None, mac, ip)
}

/// Select a named link without falling back to Wi-Fi or another adapter.
pub fn get_device_on(
    name: Option<&str>,
    mac: Option<MacAddr>,
    ip: Option<IpAddr>,
) -> Result<Device> {
    let (interface, ip_net) = select_interface(get_all_interfaces(), name, mac, ip)?;
    Device::with_ip_net(interface, ip_net)
}

fn assigned_ip(interface: &NetworkInterface, ip: Option<IpAddr>) -> Result<IpNetwork> {
    match ip {
        Some(ip) => {
            if !usable_ipv4(ip) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Selected Ethernet source must be a usable IPv4 address",
                ));
            }
            interface
                .ips
                .iter()
                .find(|network| network.ip() == ip)
                .copied()
                .ok_or_else(|| Error::new(
                    ErrorKind::AddrNotAvailable,
                    "Configured IP is not assigned to the selected Ethernet interface; use --eap-ip or --udp-ip for protocol payload overrides",
                ))
        }
        None => get_first_valid_ip(interface).copied().ok_or_else(|| {
            Error::new(
                ErrorKind::AddrNotAvailable,
                "Selected Ethernet interface has no usable IPv4 address",
            )
        }),
    }
}

// Select from one inventory snapshot before opening capture. A bridge and its
// physical port can share a MAC, so matching the MAC alone is not sufficient to
// decide where EAP frames and the selected source IP must be sent.
fn select_interface(
    interfaces: Vec<NetworkInterface>,
    name: Option<&str>,
    mac: Option<MacAddr>,
    ip: Option<IpAddr>,
) -> Result<(NetworkInterface, IpNetwork)> {
    if let Some(name) = name {
        let interface = interfaces
            .into_iter()
            .find(|interface| interface.name == name)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::NotFound,
                    format!("Ethernet interface {name} was not found"),
                )
            })?;
        if mac.is_some_and(|mac| interface.mac != Some(mac)) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Selected interface does not match configured MAC",
            ));
        }
        let ip_net = assigned_ip(&interface, ip)?;
        return Ok((interface, ip_net));
    }
    if mac.is_none() && ip.is_none() {
        return interfaces.into_iter().find_map(|interface| {
            if !interface.is_loopback()
                && interface.is_up()
                && interface.mac.is_some_and(|mac| !mac.is_zero())
            {
                get_first_valid_ip(&interface).copied().map(|ip_net| (interface, ip_net))
            } else {
                None
            }
        }).ok_or_else(|| Error::new(
            ErrorKind::NotFound,
            "No active Ethernet interface with a usable IPv4 address; use --list-interfaces or --interface",
        ));
    }
    if ip.is_some_and(|ip| !usable_ipv4(ip)) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Selected Ethernet source must be a usable IPv4 address",
        ));
    }
    let mut candidates = interfaces
        .into_iter()
        .filter(|interface| mac.is_none_or(|mac| interface.mac == Some(mac)))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            "No Ethernet interface matches the selection",
        ));
    }
    if let Some(ip) = ip {
        candidates.retain(|interface| interface.ips.iter().any(|network| network.ip() == ip));
        if candidates.is_empty() {
            return Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "Configured source IP is not assigned to an interface matching the selection; use --eap-ip or --udp-ip for protocol payload overrides",
            ));
        }
    }
    if candidates.len() > 1 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Ethernet interface selection is ambiguous; specify --interface or an assigned --ip",
        ));
    }
    let interface = candidates.pop().expect("one matching interface");
    let ip_net = assigned_ip(&interface, ip)?;
    Ok((interface, ip_net))
}

/// Inspect inventory only: no capture handle, credentials or network traffic.
pub fn current_ipv4(name: &str) -> Option<Ipv4Addr> {
    get_all_interfaces()
        .iter()
        .find(|interface| interface.name == name && interface.is_up())
        .and_then(get_first_valid_ip)
        .and_then(|network| match network.ip() {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        })
}

impl Device {
    pub fn from_mac(mac: MacAddr, ip: Option<IpAddr>) -> Result<Device> {
        get_device_on(None, Some(mac), ip)
    }

    pub fn from_ip(ip: IpAddr) -> Result<Device> {
        get_device_on(None, None, Some(ip))
    }

    pub fn new(interface: NetworkInterface) -> Result<Device> {
        let ip = assigned_ip(&interface, None)?;
        Device::with_ip_net(interface, ip)
    }

    pub fn with_ip_net(interface: NetworkInterface, ip_net: IpNetwork) -> Result<Device> {
        if !ip_net.is_ipv4() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "DrCOM requires an IPv4 address",
            ));
        }
        if interface.mac.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "The interface {} has not a valid MAC address.",
                    interface.name
                ),
            ));
        }
        let (tx, rx) = open_channel(&interface)?;
        Ok(Device {
            sender: Arc::new(Mutex::new(tx)),
            receiver: Arc::new(Mutex::new(rx)),
            pending_receive: tokio::sync::Mutex::new(None),
            mac: interface.mac.unwrap(),
            ip_net,
            interface,
        })
    }

    pub fn default_device() -> Result<Device> {
        get_device_on(None, None, None)
    }

    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        let sender = self.sender.clone();
        tokio::task::spawn_blocking(move || {
            let mut sender = sender
                .lock()
                .map_err(|_| Error::other("packet sender poisoned"))?;
            sender.send_to(&data, None).unwrap_or_else(|| {
                Err(Error::new(
                    ErrorKind::WouldBlock,
                    "packet sender has no buffer",
                ))
            })
        })
        .await
        .map_err(Error::other)?
    }

    pub async fn receive(&self) -> Result<Vec<u8>> {
        // Retain the pending read when select! cancels this future. Starting a new
        // blocking read on every deadline would lose frames and accumulate workers.
        loop {
            let mut pending = self.pending_receive.lock().await;
            if pending.is_none() {
                let receiver = self.receiver.clone();
                *pending = Some(tokio::task::spawn_blocking(move || {
                    let mut receiver = receiver
                        .lock()
                        .map_err(|_| Error::other("packet receiver poisoned"))?;
                    receiver.next().map(<[u8]>::to_vec)
                }));
            }
            let result = pending.as_mut().unwrap().await.map_err(Error::other);
            *pending = None;
            drop(pending);
            match result? {
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                    ) =>
                {
                    // Npcap is explicitly nonblocking; a small async delay avoids
                    // spinning when no Ethernet frame is available.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                result => return result,
            }
        }
    }
}

type EthernetChannel = (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>);

#[cfg(not(windows))]
fn open_channel(interface: &NetworkInterface) -> Result<EthernetChannel> {
    // Linux uses a bounded raw-socket read; macOS pnet enables immediate,
    // nonblocking BPF capture and waits through pselect with this timeout. Keep
    // both backends off the async executor and bound reads on quiet interfaces.
    let config = Config {
        read_timeout: Some(Duration::from_millis(200)),
        write_timeout: Some(Duration::from_millis(200)),
        ..Config::default()
    };
    match channel(interface, config)? {
        Channel::Ethernet(tx, rx) => Ok((tx, rx)),
        _ => Err(Error::other(format!(
            "Unknown channel type on {}",
            interface.name
        ))),
    }
}

#[cfg(windows)]
fn open_channel(interface: &NetworkInterface) -> Result<EthernetChannel> {
    windows_capture::open(interface)
}

// pnet 0.35's WinPcap backend ignores read_timeout. Use Npcap's supported
// nonblocking libpcap API on Windows instead, so shutdown cannot hang waiting
// for an Ethernet frame. No raw pointers or unsafe Send/Sync assertions needed.
#[cfg(windows)]
mod windows_capture {
    use super::*;

    struct Sender(pcap::Capture<pcap::Active>);
    struct Receiver(pcap::Capture<pcap::Active>);

    impl DataLinkSender for Sender {
        fn build_and_send(
            &mut self,
            count: usize,
            size: usize,
            build: &mut dyn FnMut(&mut [u8]),
        ) -> Option<Result<()>> {
            let mut packet = vec![0; size];
            for _ in 0..count {
                build(&mut packet);
                if let Err(error) = self.0.sendpacket(packet.as_slice()) {
                    return Some(Err(Error::other(error)));
                }
            }
            Some(Ok(()))
        }

        fn send_to(&mut self, packet: &[u8], _: Option<NetworkInterface>) -> Option<Result<()>> {
            Some(self.0.sendpacket(packet).map_err(Error::other))
        }
    }

    impl DataLinkReceiver for Receiver {
        fn next(&mut self) -> Result<&[u8]> {
            match self.0.next_packet() {
                Ok(packet) => Ok(packet.data),
                Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => {
                    Err(Error::new(ErrorKind::WouldBlock, "no packet available"))
                }
                Err(error) => Err(Error::other(error)),
            }
        }
    }

    // Delay-loaded SDK imports would otherwise raise a Windows loader exception
    // before Rust can report a missing driver. Load only trusted system paths.
    fn ensure_capture_runtime() -> Result<()> {
        static READY: std::sync::OnceLock<std::result::Result<(), String>> =
            std::sync::OnceLock::new();
        READY.get_or_init(|| {
            use windows_sys::Win32::System::{LibraryLoader::{LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32}, SystemInformation::GetSystemDirectoryW};
            let mut directory = [0u16; 32768];
            // SAFETY: writable initialized UTF-16 buffer with its exact capacity.
            let length = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
            if length == 0 || length >= directory.len() { return Err("Cannot locate the Windows system directory".into()); }
            let system = std::path::PathBuf::from(String::from_utf16_lossy(&directory[..length]));
            for root in [system.join("Npcap"), system] {
                if !["Packet.dll", "wpcap.dll"].iter().all(|name| root.join(name).is_file()) { continue; }
                let mut loaded = true;
                for name in ["Packet.dll", "wpcap.dll"] {
                    use std::os::windows::ffi::OsStrExt;
                    let path: Vec<u16> = root.join(name).as_os_str().encode_wide().chain(Some(0)).collect();
                    // SAFETY: absolute, NUL-terminated trusted system path. The
                    // search flags exclude the checkout and working directory.
                    // Handles intentionally remain loaded for delay imports until
                    // process exit; initialization occurs only once.
                    let handle = unsafe { LoadLibraryExW(path.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) };
                    if handle.is_null() { loaded = false; break; }
                }
                if loaded { return Ok(()); }
            }
            Err("Npcap runtime is missing or unavailable; install the official Npcap driver before Ethernet authentication".into())
        }).as_ref().map(|_| ()).map_err(|message| Error::other(message.clone()))
    }

    pub(super) fn open(interface: &NetworkInterface) -> Result<EthernetChannel> {
        ensure_capture_runtime()?;
        let mut capture = pcap::Capture::from_device(interface.name.as_str())
            .map_err(Error::other)?
            .promisc(true)
            .timeout(200)
            .open()
            .map_err(Error::other)?
            .setnonblock()
            .map_err(Error::other)?;
        capture
            .filter("ether proto 0x888e", true)
            .map_err(Error::other)?;
        let sender = pcap::Capture::from_device(interface.name.as_str())
            .map_err(Error::other)?
            .open()
            .map_err(Error::other)?;
        Ok((Box::new(Sender(sender)), Box::new(Receiver(capture))))
    }
}

// DrCOM's EAP extensions and UDP protocol carry an IPv4 address. Private campus
// addresses are valid; IPv6, loopback and link-local addresses cannot authenticate.
fn usable_ipv4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_usable_campus_ipv4_without_unstable_api() {
        for ip in ["202.38.193.33", "10.0.0.2", "172.16.0.2", "192.168.1.2"] {
            assert!(usable_ipv4(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.2",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "2001:db8::1",
        ] {
            assert!(!usable_ipv4(ip.parse().unwrap()), "{ip}");
        }
    }

    fn inventory_entry(name: &str, index: u32, mac: MacAddr, ips: &[&str]) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            description: "synthetic inventory".into(),
            index,
            mac: Some(mac),
            ips: ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            flags: 1,
        }
    }

    #[test]
    fn mac_and_ip_select_the_same_interface_even_when_a_bridge_shares_its_mac() {
        let mac = MacAddr::new(2, 0, 0, 0, 0, 1);
        let physical = inventory_entry("eth0", 1, mac, &["192.0.2.10/24"]);
        let bridge = inventory_entry("br-wan", 2, mac, &["198.51.100.10/24"]);
        for entries in [
            vec![physical.clone(), bridge.clone()],
            vec![bridge.clone(), physical.clone()],
        ] {
            let (selected, ip) = select_interface(
                entries,
                None,
                Some(mac),
                Some("198.51.100.10".parse().unwrap()),
            )
            .unwrap();
            assert_eq!(selected.name, "br-wan");
            assert_eq!(ip, "198.51.100.10/24".parse::<IpNetwork>().unwrap());
        }
    }

    #[test]
    fn mac_only_and_duplicated_ip_selections_reject_ambiguous_inventory() {
        let mac = MacAddr::new(2, 0, 0, 0, 0, 1);
        let physical = inventory_entry("eth0", 1, mac, &["192.0.2.10/24"]);
        let mut bridge = inventory_entry("br-wan", 2, mac, &["198.51.100.10/24"]);
        let error = select_interface(
            vec![physical.clone(), bridge.clone()],
            None,
            Some(mac),
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.to_string().contains("--interface"));
        bridge.ips = physical.ips.clone();
        let error = select_interface(
            vec![physical, bridge],
            None,
            None,
            Some("192.0.2.10".parse().unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn selected_source_ip_must_be_assigned_to_the_named_or_mac_selected_interface() {
        let mac = MacAddr::new(2, 0, 0, 0, 0, 1);
        let interface = inventory_entry("eth0", 1, mac, &["192.0.2.10/24"]);
        for name in [None, Some("eth0")] {
            let error = select_interface(
                vec![interface.clone()],
                name,
                Some(mac),
                Some("198.51.100.10".parse().unwrap()),
            )
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::AddrNotAvailable);
            assert!(error.to_string().contains("--eap-ip"));
            assert!(error.to_string().contains("--udp-ip"));
        }
        let other = inventory_entry(
            "eth1",
            2,
            MacAddr::new(2, 0, 0, 0, 0, 2),
            &["198.51.100.10/24"],
        );
        assert_eq!(
            select_interface(
                vec![interface, other],
                None,
                Some(mac),
                Some("198.51.100.10".parse().unwrap()),
            )
            .unwrap_err()
            .kind(),
            ErrorKind::AddrNotAvailable,
            "MAC and IP constraints must match one interface, not separate links",
        );
    }

    #[test]
    fn explicit_name_disambiguates_a_shared_mac_and_preserves_assigned_prefix() {
        let mac = MacAddr::new(2, 0, 0, 0, 0, 1);
        let physical = inventory_entry("eth0", 1, mac, &["192.0.2.10/24"]);
        let bridge = inventory_entry("br-wan", 2, mac, &["198.51.100.10/27"]);
        let (interface, ip) =
            select_interface(vec![physical, bridge], Some("br-wan"), Some(mac), None).unwrap();
        assert_eq!(interface.name, "br-wan");
        assert_eq!(ip, "198.51.100.10/27".parse::<IpNetwork>().unwrap());
    }

    #[test]
    fn explicit_selection_rejects_mismatched_mac_and_links_without_ipv4() {
        let mac = MacAddr::new(2, 0, 0, 0, 0, 1);
        let interface = inventory_entry("eth0", 1, mac, &["2001:db8::1/64"]);
        assert_eq!(
            select_interface(vec![interface.clone()], Some("eth0"), None, None)
                .unwrap_err()
                .kind(),
            ErrorKind::AddrNotAvailable,
        );
        assert_eq!(
            select_interface(
                vec![interface.clone()],
                Some("eth0"),
                Some(MacAddr::new(2, 0, 0, 0, 0, 2)),
                None,
            )
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidInput,
        );
        assert_eq!(
            Device::new(interface).err().unwrap().kind(),
            ErrorKind::AddrNotAvailable,
            "no usable source address must fail before capture is opened",
        );
    }

    #[test]
    fn automatic_selection_keeps_the_first_active_usable_interface() {
        let mac = MacAddr::new(2, 0, 0, 0, 0, 1);
        let mut down = inventory_entry("down", 1, mac, &["192.0.2.10/24"]);
        down.flags = 0;
        let active = inventory_entry("wan", 2, mac, &["2001:db8::1/64", "198.51.100.10/24"]);
        let (interface, ip) = select_interface(vec![down, active], None, None, None).unwrap();
        assert_eq!(interface.name, "wan");
        assert_eq!(ip, "198.51.100.10/24".parse::<IpNetwork>().unwrap());
    }

    struct Sender;

    impl DataLinkSender for Sender {
        fn build_and_send(
            &mut self,
            _: usize,
            _: usize,
            _: &mut dyn FnMut(&mut [u8]),
        ) -> Option<Result<()>> {
            Some(Ok(()))
        }
        fn send_to(&mut self, _: &[u8], _: Option<NetworkInterface>) -> Option<Result<()>> {
            Some(Ok(()))
        }
    }

    struct DelayedReceiver {
        reads: Arc<std::sync::atomic::AtomicUsize>,
        frame: Vec<u8>,
        started: Option<tokio::sync::oneshot::Sender<()>>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl DataLinkReceiver for DelayedReceiver {
        fn next(&mut self) -> Result<&[u8]> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            self.release
                .recv()
                .map_err(|_| Error::other("mock capture gate closed"))?;
            Ok(&self.frame)
        }
    }

    #[tokio::test]
    async fn canceled_receive_reuses_inflight_blocking_read_and_preserves_frame() {
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let ip_net = "10.0.0.2/24".parse().unwrap();
        let device = Device {
            interface: NetworkInterface {
                name: "fake".into(),
                description: "test adapter".into(),
                index: 1,
                mac: Some(mac),
                ips: vec![ip_net],
                flags: 0,
            },
            mac,
            ip_net,
            sender: Arc::new(Mutex::new(Box::new(Sender))),
            receiver: Arc::new(Mutex::new(Box::new(DelayedReceiver {
                reads: reads.clone(),
                frame: vec![1, 2, 3],
                started: Some(started),
                release: gate,
            }))),
            pending_receive: tokio::sync::Mutex::new(None),
        };
        {
            let receive = device.receive();
            tokio::pin!(receive);
            tokio::select! {
                _ = &mut receive => panic!("capture must remain blocked until the test opens its gate"),
                result = ready => result.unwrap(),
            }
            // The first receive future is canceled while its blocking read is
            // definitely in flight, independent of host/emulator scheduling.
        }
        release.send(()).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), device.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, vec![1, 2, 3]);
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn device_is_send_and_sync_without_unsafe_impls() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Device>();
    }
}
