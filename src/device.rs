#[cfg(not(windows))]
use pnet::datalink::{Channel, Config, channel};
use pnet::datalink::{DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface, interfaces};
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

#[inline]
fn filter_interface<P: FnMut(&NetworkInterface) -> bool>(f: P) -> Option<NetworkInterface> {
    get_all_interfaces().into_iter().find(f)
}

fn get_first_valid_ip(e: &NetworkInterface) -> Option<&IpNetwork> {
    e.ips
        .iter()
        .find(|&ip_net| ip_net.prefix() != 0 && usable_ipv4(ip_net.ip()))
}

pub fn get_all_interfaces() -> Vec<NetworkInterface> {
    let mut all_interfaces = interfaces();
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

pub fn get_device(mac: Option<MacAddr>, ip: Option<IpAddr>) -> Result<Device> {
    if let Some(m) = mac {
        return Device::from_mac(m, ip);
    }
    if let Some(ip) = ip {
        return Device::from_ip(ip);
    }
    Device::default_device()
}

/// Select a named link without falling back to Wi-Fi or another adapter.
pub fn get_device_on(
    name: Option<&str>,
    mac: Option<MacAddr>,
    ip: Option<IpAddr>,
) -> Result<Device> {
    let Some(name) = name else {
        return get_device(mac, ip);
    };
    let interface = get_all_interfaces()
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
    let ip_net = match ip {
        Some(ip) => interface
            .ips
            .iter()
            .find(|network| network.ip() == ip)
            .copied()
            .unwrap_or(
                IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 }).map_err(Error::other)?,
            ),
        None => *get_first_valid_ip(&interface).ok_or_else(|| {
            Error::new(
                ErrorKind::AddrNotAvailable,
                "Selected Ethernet interface has no usable IPv4 address",
            )
        })?,
    };
    Device::with_ip_net(interface, ip_net)
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
        let interface = filter_interface(|e| match e.mac {
            Some(ref m) => *m == mac,
            None => false,
        });
        match interface {
            Some(interface) => match ip {
                Some(ip) => {
                    let ip_net = interface
                        .ips
                        .iter()
                        .find(|i| i.ip() == ip)
                        .copied()
                        .unwrap_or_else(|| {
                            IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 }).unwrap()
                        });
                    Device::with_ip_net(interface, ip_net)
                }
                None => Device::new(interface),
            },
            None => Err(Error::new(
                ErrorKind::NotFound,
                format!("Can't get interface which MAC address is {mac}."),
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
                format!("Can't get interface which IP address is {ip}."),
            )),
        }
    }

    pub fn new(interface: NetworkInterface) -> Result<Device> {
        let ip = if let Some(ip) = get_first_valid_ip(&interface) {
            ip.to_owned()
        } else if let Some(ip) = interface.ips.first() {
            ip.to_owned()
        } else {
            IpNetwork::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0).unwrap()
        };
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
        let all_interfaces = get_all_interfaces();
        for e in &all_interfaces {
            if !e.is_loopback()
                && e.is_up()
                && e.mac.is_some_and(|mac| !mac.is_zero())
                && let Some(ip_net) = get_first_valid_ip(e)
            {
                return Device::with_ip_net(e.to_owned(), ip_net.to_owned());
            }
        }
        Err(Error::new(
            ErrorKind::NotFound,
            "No active Ethernet interface with a usable IPv4 address; use --list-interfaces or --interface",
        ))
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
    // Unix pnet backends honor read_timeout. Keep blocking packet I/O off the
    // async executor and bound the lifetime of each read on quiet interfaces.
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
