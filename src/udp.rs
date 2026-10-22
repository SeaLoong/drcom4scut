use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use log::{debug, error, info};
use pnet::datalink::MacAddr;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use crate::settings::{Profile, Settings};
use crate::socket::Socket;
use crate::udp::packet::{
    Alive, HeaderType, HeartbeatType, MiscAlive, MiscHeartbeat1, MiscHeartbeat3, MiscInfo,
    StartupHeartbeat, decrypt_info,
};
use crate::util::{ChannelData, State, random_vec};

mod packet;

#[derive(Default, Debug, PartialEq, Eq, Clone)]
struct ProcessData {
    counter: u8,
    rnd: Vec<u8>,
    cks_md5: Vec<u8>,
    flux: Vec<u8>,
    decrypted_from_misc_response_info: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    ResponseAlive,
    ResponseInfo,
    StartupDelay,
    StartupAck,
    HeartbeatAlive,
    Heartbeat2,
    Heartbeat4,
    Idle,
}

struct Pending {
    packet: Vec<u8>,
    retries: u32,
    deadline: Instant,
}

/// One UDP session owns its state. Dropping `start` cancels all pending I/O and
/// timers: it creates no detached tasks, polling loops or background threads.
pub struct Process<'a> {
    mac: MacAddr,
    ip: IpAddr,
    dns: SocketAddr,
    settings: &'a Settings,
    socket: Arc<Socket>,
    rx: watch::Receiver<ChannelData>,
    data: ProcessData,
    ready: Option<watch::Sender<bool>>,
    has_been_ready: bool,
}

impl<'a> Process<'a> {
    pub fn new(
        settings: &'a Settings,
        socket: Arc<Socket>,
        rx: watch::Receiver<ChannelData>,
        mac: MacAddr,
        ip: IpAddr,
        dns: SocketAddr,
    ) -> Process<'a> {
        Process {
            settings,
            socket,
            rx,
            mac,
            ip,
            dns,
            data: ProcessData::default(),
            ready: None,
            has_been_ready: false,
        }
    }

    /// Report actual UDP handshake readiness, independently of EAP success.
    pub fn with_ready(mut self, ready: watch::Sender<bool>) -> Self {
        ready.send_replace(false);
        self.ready = Some(ready);
        self
    }

    /// Whether this attempt completed a UDP handshake at least once, even if a
    /// later heartbeat failed or `start` has already cleared current readiness.
    pub fn has_been_ready(&self) -> bool {
        self.has_been_ready
    }

    fn set_ready(&mut self, ready: bool) {
        self.has_been_ready |= ready;
        if let Some(sender) = &self.ready {
            sender.send_replace(ready);
        }
    }

    fn retry_interval(&self) -> Duration {
        Duration::from_millis(self.settings.retry.interval.max(1) as u64)
    }

    fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.settings.heartbeat.udp_timeout.max(1) as u64)
    }

    async fn transmit(&self, packet: Vec<u8>) -> Result<Pending, State> {
        self.socket.send(packet.clone()).await.map_err(|e| {
            error!("UDP send failed: {e}");
            State::Quit
        })?;
        Ok(Pending {
            packet,
            retries: 0,
            deadline: Instant::now() + self.retry_interval(),
        })
    }

    /// Wait for current authorization, including an already-published success.
    /// A stop does not authorize UDP traffic; a closed channel terminates cleanly.
    async fn wait_for_authorization(&mut self) -> Result<Vec<u8>, State> {
        loop {
            let event = self.rx.borrow_and_update().clone();
            match event.state {
                State::Success if event.data.len() == 16 => return Ok(event.data),
                State::Success => {
                    error!("EAP success contained an invalid MD5 checksum length.");
                    return Err(State::Stop);
                }
                State::Sleep => return Err(State::Sleep),
                State::Quit => return Err(State::Quit),
                State::Stop => (),
            }
            if self.rx.changed().await.is_err() {
                return Err(State::Quit);
            }
        }
    }

    pub async fn start(&mut self) -> State {
        self.set_ready(false);
        let state = self.run().await;
        self.set_ready(false);
        state
    }

    async fn run(&mut self) -> State {
        if !self.ip.is_ipv4() || !self.dns.is_ipv4() {
            error!("DrCOM UDP session requires IPv4 client and DNS addresses.");
            return State::Stop;
        }
        let checksum = match self.wait_for_authorization().await {
            Ok(checksum) => checksum,
            Err(state) => return state,
        };
        self.data = ProcessData {
            cks_md5: checksum,
            ..ProcessData::default()
        };
        let mut phase = Phase::ResponseAlive;
        let mut pending = match self.transmit(self.misc_alive()).await {
            Ok(pending) => Some(pending),
            Err(state) => return state,
        };
        let mut heartbeat = Instant::now() + self.heartbeat_interval();
        let mut established = false;
        loop {
            let deadline = pending.as_ref().map_or(heartbeat, |p| p.deadline);
            tokio::select! {
                biased;
                changed = self.rx.changed() => {
                    if changed.is_err() { return State::Quit; }
                    let event = self.rx.borrow_and_update().clone();
                    match event.state {
                        State::Success if event.data.len() == 16 => {
                            // Reauthentication invalidates the previous session's checksum.
                            self.set_ready(false);
                            established = false;
                            self.data = ProcessData { cks_md5: event.data, ..ProcessData::default() };
                            phase = Phase::ResponseAlive;
                            pending = match self.transmit(self.misc_alive()).await {
                                Ok(pending) => Some(pending),
                                Err(state) => return state,
                            };
                        }
                        State::Success => return State::Stop,
                        state => return state,
                    }
                }
                _ = sleep_until(deadline) => {
                    if let Some(ref mut packet) = pending {
                        if packet.retries >= self.settings.retry.count.max(0) as u32 {
                            if established && matches!(phase, Phase::HeartbeatAlive | Phase::Heartbeat2 | Phase::Heartbeat4) {
                                // Some campus servers do not answer every UDP keepalive.
                                // Preserve healthy EAP authorization and try a new cycle;
                                // startup/initial handshakes still have strict deadlines.
                                error!("UDP heartbeat reply timeout; keeping EAP authorization.");
                                self.set_ready(false);
                                pending = None;
                                phase = Phase::Idle;
                                heartbeat = Instant::now() + self.heartbeat_interval();
                                continue;
                            }
                            error!("UDP response timeout after {} retries.", packet.retries);
                            return State::Stop;
                        }
                        if let Err(e) = self.socket.send(packet.packet.clone()).await {
                            error!("UDP resend failed: {e}");
                            return State::Quit;
                        }
                        packet.retries += 1;
                        packet.deadline = Instant::now() + self.retry_interval();
                    } else {
                        let packet = if phase == Phase::StartupDelay {
                            phase = Phase::StartupAck;
                            self.startup_heartbeat()
                        } else {
                            phase = Phase::HeartbeatAlive;
                            self.alive()
                        };
                        pending = match self.transmit(packet).await {
                            Ok(pending) => Some(pending),
                            Err(state) => return state,
                        };
                    }
                }
                received = self.socket.receive() => {
                    let raw = match received {
                        Ok(raw) => raw,
                        Err(e) => { error!("UDP receive failed: {e}"); return State::Quit; }
                    };
                    let next = match (phase, HeaderType::from_vec(&raw)) {
                        (Phase::ResponseAlive, HeaderType::MiscResponseAlive) if raw.len() >= 12 => {
                            self.data.flux = raw[8..12].to_vec();
                            phase = Phase::ResponseInfo;
                            Some(self.misc_info())
                        }
                        (Phase::ResponseInfo, HeaderType::MiscResponseInfo) if raw.len() >= 32 => {
                            self.data.decrypted_from_misc_response_info = raw[16..32].to_vec();
                            decrypt_info(&mut self.data.decrypted_from_misc_response_info);
                            if self.settings.profile == Profile::Windows31 {
                                phase = Phase::StartupDelay;
                                pending = None;
                                heartbeat = Instant::now() + Duration::from_millis(1400);
                                None
                            } else {
                                phase = Phase::HeartbeatAlive;
                                Some(self.alive())
                            }
                        }
                        (Phase::StartupAck, HeaderType::MiscHeartbeat) if HeartbeatType::from_vec(&raw).0 == 6 => {
                            info!("UDP startup heartbeat completed.");
                            phase = Phase::Idle;
                            pending = None;
                            established = true;
                            heartbeat = Instant::now() + self.heartbeat_interval();
                            self.set_ready(true);
                            None
                        }
                        (Phase::HeartbeatAlive, HeaderType::MiscResponseHeartbeatAlive) => {
                            phase = Phase::Heartbeat2;
                            Some(self.misc_heartbeat_1())
                        }
                        (Phase::Heartbeat2, HeaderType::MiscHeartbeat) if raw.len() >= 20 && HeartbeatType::from_vec(&raw).0 == 2 => {
                            self.data.flux = raw[16..20].to_vec();
                            phase = Phase::Heartbeat4;
                            Some(self.misc_heartbeat_3())
                        }
                        (Phase::Heartbeat4, HeaderType::MiscHeartbeat) if raw.len() >= 6 && HeartbeatType::from_vec(&raw).0 == 4 => {
                            info!("UDP heartbeat completed.");
                            established = true;
                            self.set_ready(true);
                            phase = Phase::Idle;
                            pending = None;
                            heartbeat = Instant::now() + self.heartbeat_interval();
                            None
                        }
                        (_, HeaderType::MessageServerInformation) if raw.len() >= 4 => {
                            let (message, _) = encoding_rs::GB18030.decode_without_bom_handling(&raw[4..]);
                            info!("Server information: {message}");
                            None
                        }
                        _ => { debug!("Ignoring malformed or out-of-order UDP datagram."); None }
                    };
                    if let Some(packet) = next {
                        pending = match self.transmit(packet).await {
                            Ok(pending) => Some(pending),
                            Err(state) => return state,
                        };
                    }
                }
            }
        }
    }

    fn misc_alive(&self) -> Vec<u8> {
        let mut packet = BytesMut::with_capacity(8);
        MiscAlive::append_to(&mut packet);
        packet.to_vec()
    }

    fn misc_info(&mut self) -> Vec<u8> {
        let mut packet = BytesMut::with_capacity(244);
        let fixed = &self.settings.data.misc_info;
        let info = MiscInfo {
            mac: self.mac,
            ip: self.settings.udp_ip.map_or(self.ip, IpAddr::V4),
            unknown1: fixed.unknown1.clone(),
            flux: self.data.flux.clone(),
            cks32_param: fixed.cks32_param.clone(),
            username: self.settings.username.clone(),
            hostname: self.settings.hostname.clone(),
            dns1: self.dns.ip(),
            dns2: IpAddr::V4(self.settings.dns2),
            unknown2: fixed.unknown2.clone(),
            os_major: fixed.os_major.clone(),
            os_minor: fixed.os_minor.clone(),
            os_build: fixed.os_build.clone(),
            os_unknown: fixed.os_unknown.clone(),
            version: fixed.version.clone(),
            hash: fixed.hash.clone(),
        };
        let checksum = if self.settings.profile == Profile::Windows31 {
            info.append_windows31_to(
                &mut packet,
                IpAddr::V4(self.settings.gateway),
                &fixed.trailer,
            )
        } else {
            info.append_to(&mut packet)
        };
        self.data.cks_md5[..4].copy_from_slice(&checksum.to_le_bytes());
        packet.to_vec()
    }

    fn startup_heartbeat(&self) -> Vec<u8> {
        let mut packet = BytesMut::with_capacity(40);
        StartupHeartbeat::append_to(&mut packet, &random_vec(2));
        packet.to_vec()
    }

    fn misc_heartbeat_1(&mut self) -> Vec<u8> {
        self.data.counter = self.data.counter.wrapping_add(1);
        self.data.rnd = random_vec(2);
        let mut packet = BytesMut::with_capacity(40);
        MiscHeartbeat1 {
            counter: self.data.counter,
            rnd: self.data.rnd.clone(),
            flux: self.data.flux.clone(),
        }
        .append_to(&mut packet);
        packet.to_vec()
    }

    fn misc_heartbeat_3(&mut self) -> Vec<u8> {
        self.data.counter = self.data.counter.wrapping_add(1);
        let mut packet = BytesMut::with_capacity(40);
        MiscHeartbeat3 {
            counter: self.data.counter,
            rnd: self.data.rnd.clone(),
            flux: self.data.flux.clone(),
            ip: self.settings.udp_ip.map_or(self.ip, IpAddr::V4),
        }
        .append_to(&mut packet);
        packet.to_vec()
    }

    fn alive(&self) -> Vec<u8> {
        let mut packet = BytesMut::with_capacity(38);
        Alive {
            cks_md5: self.data.cks_md5.clone(),
            decrypted_from_misc_response_info: self.data.decrypted_from_misc_response_info.clone(),
        }
        .append_to(&mut packet);
        packet.to_vec()
    }
}

impl Drop for Process<'_> {
    fn drop(&mut self) {
        self.set_ready(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    struct Session {
        control: watch::Sender<ChannelData>,
        server: UdpSocket,
        task: JoinHandle<State>,
    }

    async fn session(initial: State, retry_count: i32, interval: i32) -> Session {
        let mut settings = Settings {
            username: "201836431154".into(),
            hostname: "SeaLoong".into(),
            ..Settings::default()
        };
        settings.retry.count = retry_count;
        settings.retry.interval = interval;
        settings.heartbeat.udp_timeout = 1;
        session_settings(initial, settings, None).await
    }

    async fn session_settings(
        initial: State,
        settings: Settings,
        ready: Option<watch::Sender<bool>>,
    ) -> Session {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server.local_addr().unwrap()).await.unwrap();
        server.connect(client.local_addr().unwrap()).await.unwrap();
        let (control, rx) = watch::channel(ChannelData {
            state: initial,
            data: vec![0x55; 16],
        });
        let task = tokio::spawn(async move {
            let (mac, local, dns) = if settings.profile == Profile::Windows31 {
                (MacAddr(2, 0, 0, 0, 0, 9), "192.0.2.10", "192.0.2.53:53")
            } else {
                (
                    MacAddr(0xb0, 0x25, 0xaa, 0x28, 0x6d, 0xb9),
                    "125.217.254.225",
                    "202.38.193.33:53",
                )
            };
            let mut process = Process::new(
                &settings,
                Arc::new(Socket::new(client)),
                rx,
                mac,
                local.parse().unwrap(),
                dns.parse().unwrap(),
            );
            if let Some(ready) = ready {
                process = process.with_ready(ready);
            }
            process.start().await
        });
        Session {
            control,
            server,
            task,
        }
    }

    async fn receive(server: &UdpSocket) -> Vec<u8> {
        let mut buffer = [0u8; 2048];
        let size = timeout(Duration::from_secs(2), server.recv(&mut buffer))
            .await
            .expect("client packet timed out")
            .unwrap();
        buffer[..size].to_vec()
    }

    fn response(kind: u8, length: usize) -> Vec<u8> {
        let mut packet = vec![0u8; length];
        packet[0] = 7;
        packet[2] = length as u8;
        packet[4] = kind;
        packet
    }

    async fn login(server: &UdpSocket) -> Vec<u8> {
        assert_eq!(
            receive(server).await,
            hex::decode("0700080001000000").unwrap()
        );
        let mut challenge = response(2, 12);
        challenge[8..12].copy_from_slice(&hex::decode("3bab4e04").unwrap());
        server.send(&challenge).await.unwrap();
        let info = receive(server).await;
        let expected = "0701f400030cb025aa286db97dd9fee10222002a3bab4e04de833b02000000003230313833363433313135345365614c6f6f6e67000000000000000000000000000000000000000000000000ca26c12100000000000000000000000000000000940000000600000002000000f0230000020000004472434f4d0096022a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034656238316663303438613535383562376466653137383331353532343161333238623130336336000000000000000000000000000000000000000000000000";
        assert_eq!(
            info,
            hex::decode(expected).unwrap(),
            "MiscInfo must match legacy wire fixture"
        );
        let mut info_response = response(4, 32);
        info_response[16..32]
            .copy_from_slice(&hex::decode("4439d8edac314b07dd8c5f3bef0f04d8").unwrap());
        server.send(&info_response).await.unwrap();
        let alive = receive(server).await;
        assert_eq!(alive.len(), 38);
        assert_eq!(alive[0], 0xff);
        assert_eq!(&alive[1..5], &info[24..28]);
        assert_eq!(&alive[5..17], &[0x55; 12]);
        assert_eq!(&alive[17..20], &[0; 3]);
        assert_eq!(
            &alive[20..36],
            hex::decode("4472636fca26d283dd197dd9fee1016c").unwrap()
        );
        alive
    }

    async fn heartbeat(server: &UdpSocket) -> Vec<u8> {
        heartbeat_at_counter(server, 1).await
    }

    async fn heartbeat_at_counter(server: &UdpSocket, counter: u8) -> Vec<u8> {
        server.send(&response(6, 8)).await.unwrap();
        let heartbeat1 = receive(server).await;
        assert_eq!(heartbeat1.len(), 40);
        assert_eq!(&heartbeat1[..8], &[7, counter, 40, 0, 11, 1, 220, 2]);
        let mut heartbeat2 = response(11, 40);
        heartbeat2[5] = 2;
        heartbeat2[16..20].copy_from_slice(&[11, 22, 33, 44]);
        server.send(&heartbeat2).await.unwrap();
        let heartbeat3 = receive(server).await;
        assert_eq!(heartbeat3.len(), 40);
        assert_eq!(
            &heartbeat3[..8],
            &[7, counter.wrapping_add(1), 40, 0, 11, 3, 220, 2],
        );
        assert_eq!(&heartbeat3[8..10], &heartbeat1[8..10]);
        assert_eq!(&heartbeat3[16..20], &[11, 22, 33, 44]);
        assert_eq!(&heartbeat3[28..32], &[125, 217, 254, 225]);
        let mut heartbeat4 = response(11, 40);
        heartbeat4[5] = 4;
        server.send(&heartbeat4).await.unwrap();
        heartbeat3
    }

    #[tokio::test]
    async fn e2e_waits_for_eap_success_and_stops_immediately() {
        let session = session(State::Stop, 2, 1000).await;
        let mut buffer = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(15), session.server.recv(&mut buffer))
                .await
                .is_err()
        );
        session
            .control
            .send(ChannelData {
                state: State::Success,
                data: vec![1; 16],
            })
            .unwrap();
        assert_eq!(
            receive(&session.server).await,
            hex::decode("0700080001000000").unwrap()
        );
        session
            .control
            .send(ChannelData {
                state: State::Stop,
                data: Vec::new(),
            })
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), session.task)
                .await
                .unwrap()
                .unwrap(),
            State::Stop
        );
    }

    #[tokio::test]
    async fn e2e_login_and_heartbeat_match_legacy_packets() {
        let session = session(State::Success, 2, 1000).await;
        login(&session.server).await;
        heartbeat(&session.server).await;
        session
            .control
            .send(ChannelData {
                state: State::Quit,
                data: Vec::new(),
            })
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), session.task)
                .await
                .unwrap()
                .unwrap(),
            State::Quit
        );
    }

    #[tokio::test]
    async fn e2e_timeout_retries_same_packet_then_returns_stop() {
        let session = session(State::Success, 2, 15).await;
        let initial = receive(&session.server).await;
        assert_eq!(receive(&session.server).await, initial);
        assert_eq!(receive(&session.server).await, initial);
        assert_eq!(
            timeout(Duration::from_secs(1), session.task)
                .await
                .unwrap()
                .unwrap(),
            State::Stop
        );
        let mut buffer = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(20), session.server.recv(&mut buffer))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn e2e_ignores_truncated_and_out_of_order_responses_without_losing_retry() {
        let session = session(State::Success, 1, 40).await;
        let initial = receive(&session.server).await;
        for packet in [
            Vec::new(),
            vec![7],
            response(2, 5),
            response(4, 32),
            response(6, 8),
            response(11, 5),
        ] {
            session.server.send(&packet).await.unwrap();
        }
        assert_eq!(receive(&session.server).await, initial);
        assert_eq!(
            timeout(Duration::from_secs(1), session.task)
                .await
                .unwrap()
                .unwrap(),
            State::Stop
        );
    }

    #[tokio::test]
    async fn e2e_reauthentication_restarts_handshake() {
        let session = session(State::Success, 2, 1000).await;
        login(&session.server).await;
        session
            .control
            .send(ChannelData {
                state: State::Success,
                data: vec![7; 16],
            })
            .unwrap();
        assert_eq!(
            receive(&session.server).await,
            hex::decode("0700080001000000").unwrap()
        );
        session
            .control
            .send(ChannelData {
                state: State::Sleep,
                data: Vec::new(),
            })
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), session.task)
                .await
                .unwrap()
                .unwrap(),
            State::Sleep
        );
    }

    #[tokio::test]
    async fn e2e_closed_eap_channel_terminates_pending_io() {
        let session = session(State::Success, 2, 1000).await;
        receive(&session.server).await;
        drop(session.control);
        assert_eq!(
            timeout(Duration::from_secs(1), session.task)
                .await
                .unwrap()
                .unwrap(),
            State::Quit
        );
    }

    #[tokio::test]
    async fn invalid_authorization_checksum_is_rejected_without_network_traffic() {
        let session = session(State::Stop, 2, 1000).await;
        session
            .control
            .send(ChannelData {
                state: State::Success,
                data: vec![1; 3],
            })
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), session.task)
                .await
                .unwrap()
                .unwrap(),
            State::Stop
        );
        let mut buffer = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(10), session.server.recv(&mut buffer))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn e2e_abort_cancels_pending_retry_without_background_tasks() {
        let session = session(State::Success, 2, 30).await;
        receive(&session.server).await;
        session.task.abort();
        assert!(session.task.await.unwrap_err().is_cancelled());
        let mut buffer = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(80), session.server.recv(&mut buffer))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn e2e_lost_periodic_replies_keep_eap_authorized_and_retry_new_cycles() {
        let session = session(State::Success, 1, 30).await;
        login(&session.server).await;
        heartbeat(&session.server).await;
        for _ in 0..2 {
            let alive = receive(&session.server).await;
            assert_eq!(alive[0], 0xff);
            assert_eq!(alive.len(), 38);
            assert_eq!(
                receive(&session.server).await,
                alive,
                "retry must preserve timestamp and checksum bytes"
            );
            assert_eq!(session.control.borrow().state, State::Success);
            assert!(
                !session.task.is_finished(),
                "UDP loss must not terminate healthy authorization"
            );
        }
        session.control.send_replace(ChannelData::stopped());
        assert_eq!(
            timeout(Duration::from_secs(1), session.task)
                .await
                .unwrap()
                .unwrap(),
            State::Stop
        );
    }

    #[tokio::test]
    async fn e2e_udp_liveness_loss_and_recovery_preserve_eap_and_attempt_history() {
        // Advance protocol deadlines, then resume the real clock before socket
        // I/O. Paused-time auto-advancement must not race kernel UDP readiness.
        async fn elapse(duration: Duration) {
            tokio::time::pause();
            tokio::time::advance(duration).await;
            tokio::time::resume();
        }

        let mut settings = Settings {
            username: "201836431154".into(),
            hostname: "SeaLoong".into(),
            ..Settings::default()
        };
        settings.retry.count = 1;
        settings.retry.interval = 5000;
        settings.heartbeat.udp_timeout = 1;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server.local_addr().unwrap()).await.unwrap();
        server.connect(client.local_addr().unwrap()).await.unwrap();
        let socket = Arc::new(Socket::new(client));
        let (authorization, auth) = watch::channel(ChannelData {
            state: State::Success,
            data: vec![0x55; 16],
        });
        let (ready_tx, mut ready) = watch::channel(false);
        let mut process = Process::new(
            &settings,
            socket.clone(),
            auth,
            MacAddr(0xb0, 0x25, 0xaa, 0x28, 0x6d, 0xb9),
            "125.217.254.225".parse().unwrap(),
            "202.38.193.33:53".parse().unwrap(),
        )
        .with_ready(ready_tx);
        assert!(!process.has_been_ready());
        let exchange = async {
            login(&server).await;
            heartbeat(&server).await;
            assert!(
                *timeout(Duration::from_secs(2), ready.wait_for(|value| *value))
                    .await
                    .unwrap()
                    .unwrap(),
            );
            elapse(Duration::from_secs(1)).await;
            let alive = receive(&server).await;
            assert_eq!(alive[0], 0xff);
            elapse(Duration::from_secs(5)).await;
            assert_eq!(receive(&server).await, alive, "one identical retry");
            elapse(Duration::from_secs(5)).await;
            assert!(
                !*timeout(Duration::from_secs(2), ready.wait_for(|value| !*value))
                    .await
                    .unwrap()
                    .unwrap(),
                "exhausted periodic replies must clear UDP readiness",
            );
            assert_eq!(authorization.borrow().state, State::Success);

            // The same session retries another periodic exchange without EAP
            // Logoff, reauthentication or a new UDP information handshake.
            elapse(Duration::from_secs(1)).await;
            assert_eq!(receive(&server).await[0], 0xff);
            heartbeat_at_counter(&server, 3).await;
            assert!(
                *timeout(Duration::from_secs(2), ready.wait_for(|value| *value))
                    .await
                    .unwrap()
                    .unwrap(),
                "a complete recovered heartbeat must restore readiness",
            );
            assert_eq!(authorization.borrow().state, State::Success);
            authorization.send_replace(ChannelData {
                state: State::Quit,
                data: Vec::new(),
            });
        };
        let (state, ()) = tokio::join!(process.start(), exchange);
        assert_eq!(state, State::Quit);
        assert!(!*ready.borrow(), "an ended session cannot remain ready");
        assert!(process.has_been_ready(), "attempt history survives cleanup");

        let (_authorization, auth) = watch::channel(ChannelData {
            state: State::Quit,
            data: Vec::new(),
        });
        let mut fresh = Process::new(
            &settings,
            socket,
            auth,
            MacAddr::zero(),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.53:53".parse().unwrap(),
        );
        assert!(
            !fresh.has_been_ready(),
            "a new attempt has no inherited history"
        );
        assert_eq!(fresh.start().await, State::Quit);
        assert!(!fresh.has_been_ready(), "an unready attempt stays unready");
    }

    fn windows31_settings() -> Settings {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "drcom4scut-udp-profile-{}-{}.yml",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let yaml = "username: example00000\npassword: fake-test-password\nhostname: test-host\nprofile: windows31\nudp_ip: 192.0.2.9\ngateway: 192.0.2.1\ndns2: 192.0.2.54\nretry: {count: 1, interval: 5000}\nheartbeat: {udp_timeout: 1}\ndata: {misc_info: {trailer: '2001025030007004aa0cb7dee93f3c65'}}\n";
        std::fs::write(&path, yaml).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let matches = crate::settings::command()
            .try_get_matches_from([
                "drcom4scut",
                "--config",
                path.to_str().unwrap(),
                "--check-config",
            ])
            .unwrap();
        let settings = Settings::from_matches(&matches).unwrap();
        std::fs::remove_file(path).unwrap();
        settings
    }

    async fn windows31_info_exchange(server: &UdpSocket) -> Vec<u8> {
        assert_eq!(receive(server).await, [7, 0, 8, 0, 1, 0, 0, 0]);
        let mut alive_response = response(2, 12);
        alive_response[8..12].copy_from_slice(&[1, 2, 3, 4]);
        server.send(&alive_response).await.unwrap();
        let info = receive(server).await;
        assert_eq!(info.len(), 260);
        assert_eq!(&info[..6], &[7, 1, 4, 1, 3, 12]);
        assert_eq!(
            &info[12..16],
            &[192, 0, 2, 9],
            "payload override must not use the physical source"
        );
        assert_eq!(&info[16..20], &[2, 0x22, 0, 0x31]);
        assert_eq!(&info[80..88], &[192, 0, 2, 1, 192, 0, 2, 54]);
        assert!(info[96..116].iter().all(|byte| *byte == 0));
        assert_eq!(
            &info[244..],
            hex::decode("2001025030007004aa0cb7dee93f3c65").unwrap()
        );
        let mut reply = response(4, 32);
        reply[16..32].copy_from_slice(&hex::decode("4439d8edac314b07dd8c5f3bef0f04d8").unwrap());
        server.send(&reply).await.unwrap();
        info
    }

    #[tokio::test]
    async fn e2e_windows31_gates_readiness_on_distinct_startup_exchange() {
        let (ready_tx, mut ready) = watch::channel(false);
        let session = session_settings(State::Success, windows31_settings(), Some(ready_tx)).await;
        let info = windows31_info_exchange(&session.server).await;
        assert!(
            timeout(Duration::from_millis(100), receive(&session.server))
                .await
                .is_err(),
            "startup exchange must respect its delay, not send a legacy Alive immediately"
        );
        let startup = receive(&session.server).await;
        assert_eq!(startup.len(), 40);
        assert_eq!(&startup[..8], &[7, 0, 40, 0, 11, 1, 15, 39]);
        assert!(!*ready.borrow_and_update());
        session.server.send(&response(6, 8)).await.unwrap(); // normal Alive ACK is not startup ACK
        assert!(
            timeout(Duration::from_millis(10), ready.wait_for(|value| *value))
                .await
                .is_err()
        );
        let mut ack = response(11, 6);
        ack[5] = 6;
        session.server.send(&ack).await.unwrap();
        assert!(
            *timeout(Duration::from_secs(1), ready.wait_for(|value| *value))
                .await
                .unwrap()
                .unwrap()
        );
        let alive = receive(&session.server).await;
        assert_eq!(alive.len(), 38);
        assert_eq!(&alive[1..5], &info[24..28]);
        session.server.send(&response(6, 8)).await.unwrap();
        let first = receive(&session.server).await;
        assert_eq!(&first[..8], &[7, 1, 40, 0, 11, 1, 220, 2]);
        let mut second = response(11, 40);
        second[5] = 2;
        second[16..20].copy_from_slice(&[9, 8, 7, 6]);
        session.server.send(&second).await.unwrap();
        let third = receive(&session.server).await;
        assert_eq!(&third[28..32], &[192, 0, 2, 9]);
        assert_eq!(&third[8..10], &first[8..10]);
        second[5] = 4;
        session.server.send(&second).await.unwrap();
        session.task.abort();
        assert!(session.task.await.unwrap_err().is_cancelled());
        assert!(!*ready.borrow(), "dropping a session must clear readiness");
    }

    #[tokio::test]
    async fn e2e_windows31_startup_timeout_remains_strict_and_cannot_authorize() {
        let (ready_tx, ready) = watch::channel(false);
        let mut settings = windows31_settings();
        settings.retry.count = 0;
        // The real UDP handshake must not race a short timer under QEMU or
        // overloaded CI. Only the post-startup timeout is under test here.
        settings.retry.interval = 5000;
        let session = session_settings(State::Success, settings, Some(ready_tx)).await;
        windows31_info_exchange(&session.server).await;
        let startup = receive(&session.server).await;
        assert_eq!(&startup[..8], &[7, 0, 40, 0, 11, 1, 15, 39]);
        assert!(!session.task.is_finished());
        // Pause only after actual socket traffic has completed; auto-advancing
        // virtual time while waiting for OS I/O can exhaust handshake retries.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(
            timeout(Duration::from_secs(1), session.task)
                .await
                .unwrap()
                .unwrap(),
            State::Stop
        );
        assert!(!*ready.borrow());
        assert_eq!(
            session.control.borrow().state,
            State::Success,
            "UDP never rewrites EAP authorization"
        );
    }

    #[tokio::test]
    async fn counters_wrap_after_full_byte_range() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server.local_addr().unwrap()).await.unwrap();
        let settings = Settings::default();
        let (_tx, rx) = watch::channel(ChannelData {
            state: State::Stop,
            data: Vec::new(),
        });
        let mut process = Process::new(
            &settings,
            Arc::new(Socket::new(client)),
            rx,
            MacAddr::zero(),
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1:53".parse().unwrap(),
        );
        process.data.counter = 255;
        process.data.flux = vec![0; 4];
        let first = process.misc_heartbeat_1();
        let third = process.misc_heartbeat_3();
        assert_eq!(first[1], 0);
        assert_eq!(third[1], 1);
    }
}
