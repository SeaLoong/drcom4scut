use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use log::{debug, error, info, warn};
use md5::Digest;
use pnet::datalink::MacAddr;
use tokio::sync::watch;
use tokio::time::{Instant, sleep, sleep_until};

use crate::device::Device;
use crate::eap::packet::*;
use crate::settings::Settings;
use crate::util::{ChannelData, State, ip_to_vec};

mod packet;

const MULTICAST_MAC: MacAddr = MacAddr(0x01, 0x80, 0xc2, 0x00, 0x00, 0x03);
const LOGOFF_DELAY: Duration = Duration::from_secs(2);

/// The blocking packet-capture boundary is replaceable by an in-memory link in
/// tests. Protocol tasks themselves never create threads or poll shared flags.
pub trait Transport: Send + Sync {
    fn send(&self, data: Vec<u8>) -> impl Future<Output = io::Result<()>> + Send;
    fn receive(&self) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

impl Transport for Device {
    async fn send(&self, data: Vec<u8>) -> io::Result<()> {
        Device::send(self, data).await
    }

    async fn receive(&self) -> io::Result<Vec<u8>> {
        Device::receive(self).await
    }
}

#[derive(Default)]
struct ProcessData {
    ip: Vec<u8>,
    md5: Vec<u8>,
    response_identity_packet: Option<Vec<u8>>,
    challenge_id: Option<u8>,
}

struct PendingPacket {
    bytes: Vec<u8>,
    retries: u32,
    deadline: Instant,
}

pub struct Process<'a, T = Device> {
    eth_header: EthernetHeader,
    settings: &'a Settings,
    device: Arc<T>,
    tx: watch::Sender<ChannelData>,
    data: ProcessData,
    pending: Option<PendingPacket>,
    heartbeat: Option<Instant>,
}

impl<'a> Process<'a> {
    pub fn new(
        settings: &'a Settings,
        device: Arc<Device>,
        tx: watch::Sender<ChannelData>,
    ) -> Self {
        let mac = device.mac;
        let ip = device.ip_net.ip();
        Self::with_transport(settings, device, mac, ip, tx)
    }
}

impl<'a, T: Transport> Process<'a, T> {
    pub(crate) fn with_transport(
        settings: &'a Settings,
        device: Arc<T>,
        mac: MacAddr,
        ip: IpAddr,
        tx: watch::Sender<ChannelData>,
    ) -> Self {
        Self {
            eth_header: EthernetHeader {
                destination: MULTICAST_MAC,
                source: mac,
                ethernet_type: ethernet_types::IEEE8021X,
            },
            settings,
            device,
            tx,
            data: ProcessData {
                ip: ip_to_vec(&settings.eap_ip.map(IpAddr::V4).unwrap_or(ip)),
                ..Default::default()
            },
            pending: None,
            heartbeat: None,
        }
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(self.settings.retry.interval.max(1) as u64)
    }

    fn retry_count(&self) -> u32 {
        self.settings.retry.count.max(0) as u32
    }

    fn heartbeat_duration(&self) -> Duration {
        Duration::from_secs(self.settings.heartbeat.eap_timeout.max(1) as u64)
            .saturating_mul(self.retry_count().saturating_add(1))
    }

    fn notify(&self, state: State) {
        self.tx.send_replace(ChannelData {
            state,
            data: if matches!(state, State::Success) {
                self.data.md5.clone()
            } else {
                Vec::new()
            },
        });
    }

    async fn transmit(&self, bytes: Vec<u8>) -> io::Result<()> {
        let mut bytes = bytes;
        // Ethernet frames shorter than 96 bytes are padded by the original client.
        // resize only grows, so long usernames cannot underflow a subtraction.
        bytes.resize(bytes.len().max(96), 0);
        for attempt in 0..=self.retry_count() {
            match self.device.send(bytes.clone()).await {
                Ok(()) => return Ok(()),
                Err(err) if attempt == self.retry_count() => return Err(err),
                Err(err) => warn!("EAP send failed, retrying: {err}"),
            }
            sleep(self.interval()).await;
        }
        unreachable!()
    }

    async fn send(&mut self, bytes: Vec<u8>, expect_response: bool) -> io::Result<()> {
        self.transmit(bytes.clone()).await?;
        self.pending = expect_response.then(|| PendingPacket {
            bytes,
            retries: 0,
            deadline: Instant::now() + self.interval(),
        });
        Ok(())
    }

    async fn login_start(&mut self) -> io::Result<()> {
        self.pending = None;
        self.heartbeat = None;
        self.data.md5.clear();
        self.data.challenge_id = None;
        self.data.response_identity_packet = None;
        self.eth_header.destination = MULTICAST_MAC;
        self.notify(State::Stop);
        info!("Send Logoff packet.");
        self.send(self.eapol_packet(&EAPOL_HEADER_LOGOFF), false)
            .await?;
        sleep(LOGOFF_DELAY).await;
        info!("Send Start packet.");
        self.send(self.eapol_packet(&EAPOL_HEADER_START), true)
            .await
    }

    /// Send one best-effort EAPOL-Logoff when the caller shuts down a session.
    /// The supervisor bounds this operation independently of normal retry policy.
    /// A learned authenticator remains the destination; unauthenticated sessions
    /// use the standard PAE group, matching the initial cleanup frame.
    pub async fn logoff(&self) -> io::Result<()> {
        self.notify(State::Stop);
        let mut packet = self.eapol_packet(&EAPOL_HEADER_LOGOFF);
        packet.resize(96, 0);
        self.device.send(packet).await
    }

    /// Run one authentication session. Dropping this future cancels all protocol
    /// deadlines and sends; no detached heartbeat or resender tasks survive it.
    pub async fn start(&mut self) -> State {
        let result = self.run().await;
        let state = match result {
            Ok(state) => state,
            Err(err) => {
                error!("EAP transport error: {err}");
                State::Quit
            }
        };
        self.pending = None;
        self.heartbeat = None;
        self.notify(state);
        state
    }

    async fn run(&mut self) -> io::Result<State> {
        self.login_start().await?;
        let mut receive_errors = 0;
        loop {
            let resend_at = self.pending.as_ref().map(|p| p.deadline);
            let heartbeat_at = self.heartbeat;
            tokio::select! {
                // Deadlines have priority even if irrelevant traffic is continuous.
                biased;
                _ = wait_deadline(heartbeat_at) => {
                    error!("EAP heartbeat timed out.");
                    return Ok(State::Stop);
                }
                _ = wait_deadline(resend_at) => {
                    let mut pending = self.pending.take().unwrap();
                    if pending.retries >= self.retry_count() {
                        error!("EAP response timed out after {} retries.", pending.retries);
                        return Ok(State::Stop);
                    }
                    self.transmit(pending.bytes.clone()).await?;
                    pending.retries += 1;
                    pending.deadline = Instant::now() + self.interval();
                    self.pending = Some(pending);
                }
                result = self.device.receive() => {
                    let raw = match result {
                        Ok(raw) => { receive_errors = 0; raw }
                        Err(err) if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => continue,
                        Err(err) => {
                            if receive_errors >= self.retry_count() { return Err(err); }
                            receive_errors += 1;
                            warn!("EAP receive failed, retrying: {err}");
                            sleep(self.interval()).await;
                            continue;
                        }
                    };
                    if let Some(state) = self.handle_packet(&raw).await? {
                        return Ok(state);
                    }
                }
            }
        }
    }

    async fn handle_packet(&mut self, raw: &[u8]) -> io::Result<Option<State>> {
        let mut bytes = Bytes::copy_from_slice(raw);
        let header = Header::from_bytes(&mut bytes);
        let (Some(ethernet), Some(eapol), Some(eap)) = (
            header.ethernet_header,
            header.eapol_header,
            header.eap_header,
        ) else {
            return Ok(None);
        };
        if ethernet.ethernet_type != ethernet_types::IEEE8021X
            || !ethernet.is_send_to(&self.eth_header)
            || eapol.version != 1
            || eapol.eapol_type != eapol_types::EAP_PACKET
        {
            return Ok(None);
        }
        match eap.code {
            eap_codes::REQUEST => match eap.eap_type {
                Some(EAPType::Identity) => {
                    self.pending = None;
                    if self.heartbeat.is_some() {
                        self.heartbeat = Some(Instant::now() + self.heartbeat_duration());
                    }
                    if self.heartbeat.is_none() {
                        self.data.challenge_id = None;
                    }
                    if let Some(mut packet) = self.data.response_identity_packet.clone() {
                        packet[19] = eap.identifier;
                        info!("Send Heartbeat(Response, Identity) packet.");
                        self.send(packet, self.heartbeat.is_none()).await?;
                    } else {
                        // EAP identifiers are opaque bytes, not login counters.
                        // Initial requests can legitimately use values above one;
                        // restarting here caused endless Logoff/Start loops (#46).
                        self.eth_header.destination = ethernet.source;
                        let packet = self.identity_packet(eap.identifier);
                        self.data.response_identity_packet = Some(packet.clone());
                        self.send(packet, true).await?;
                    }
                }
                Some(EAPType::Md5Challenge) => {
                    if self.data.response_identity_packet.is_none() {
                        return Ok(None);
                    }
                    // EAP length includes code, id, length and type. A challenge
                    // also includes one value-size octet before its 16-byte hash.
                    let Some(payload_len) = eap.length.checked_sub(5).map(usize::from) else {
                        return Ok(None);
                    };
                    let Some(payload) = bytes.get(..payload_len) else {
                        return Ok(None);
                    };
                    let Some((&size, rest)) = payload.split_first() else {
                        return Ok(None);
                    };
                    if size != 16 || rest.len() < usize::from(size) {
                        warn!("Discard malformed EAP MD5 challenge.");
                        return Ok(None);
                    }
                    self.pending = None;
                    self.heartbeat = None;
                    self.notify(State::Stop);
                    self.data.challenge_id = Some(eap.identifier);
                    let challenge = &rest[..usize::from(size)];
                    let packet = self.md5_packet(eap.identifier, challenge);
                    self.send(packet, true).await?;
                }
                Some(EAPType::Notification) => {
                    let Some(length) = eap.length.checked_sub(5).map(usize::from) else {
                        return Ok(None);
                    };
                    let Some(payload) = bytes.get(..length) else {
                        return Ok(None);
                    };
                    let Ok(message) = std::str::from_utf8(payload) else {
                        return Ok(None);
                    };
                    let display = crate::util::server_message(
                        message,
                        &self.settings.username,
                        &self.settings.password,
                    );
                    error!("EAP server notification: {display}");
                    return Ok(Some(notification_state(message)));
                }
                None => (),
            },
            eap_codes::SUCCESS
                if self.data.md5.len() == 16
                    && self.data.challenge_id == Some(eap.identifier)
                    && self.heartbeat.is_none() =>
            {
                self.pending = None;
                self.heartbeat = Some(Instant::now() + self.heartbeat_duration());
                info!("802.1X Authorization success!");
                self.notify(State::Success);
            }
            eap_codes::FAILURE if self.data.challenge_id == Some(eap.identifier) => {
                debug!("EAP authentication failure.");
                return Ok(Some(State::Stop));
            }
            _ => (),
        }
        Ok(None)
    }

    fn eapol_packet(&self, eapol: &EAPOLHeader) -> Vec<u8> {
        let mut data = BytesMut::with_capacity(96);
        self.eth_header.append_to(&mut data);
        eapol.append_to(&mut data);
        data.to_vec()
    }

    fn response_packet(&self, identifier: u8, eap_type: EAPType, payload: &[u8]) -> Vec<u8> {
        let mut data = BytesMut::with_capacity(96);
        self.eth_header.append_to(&mut data);
        let length = (payload.len() + 5) as u16;
        EAPOLHeader {
            version: 1,
            eapol_type: eapol_types::EAP_PACKET,
            length,
        }
        .append_to(&mut data);
        EAPHeader {
            code: eap_codes::RESPONSE,
            identifier,
            length,
            eap_type: Some(eap_type),
        }
        .append_to(&mut data);
        data.put_slice(payload);
        data.to_vec()
    }

    fn identity_packet(&self, identifier: u8) -> Vec<u8> {
        let mut payload = BytesMut::with_capacity(96);
        payload.put_slice(self.settings.username.as_bytes());
        payload.put_slice(&self.settings.data.response_identity.unknown);
        payload.put_slice(&self.data.ip);
        self.response_packet(identifier, EAPType::Identity, &payload)
    }

    fn md5_packet(&mut self, identifier: u8, challenge: &[u8]) -> Vec<u8> {
        let mut digest_input = BytesMut::new();
        digest_input.put_u8(identifier);
        digest_input.put_slice(self.settings.password.as_bytes());
        digest_input.put_slice(challenge);
        self.data.md5 = md5::Md5::digest(&digest_input).to_vec();
        let mut payload = BytesMut::with_capacity(96);
        payload.put_u8(16);
        payload.put_slice(&self.data.md5);
        payload.put_slice(self.settings.username.as_bytes());
        payload.put_slice(&self.settings.data.response_md5_challenge.unknown);
        payload.put_slice(&self.data.ip);
        self.response_packet(identifier, EAPType::Md5Challenge, &payload)
    }
}

async fn wait_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn notification_state(message: &str) -> State {
    if message
        .strip_prefix("Authentication Fail ErrCode=")
        .and_then(|code| code.parse::<i32>().ok())
        == Some(16)
    {
        State::Sleep
    } else {
        State::Stop
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{Mutex, mpsc};

    const CLIENT: MacAddr = MacAddr(0, 1, 2, 3, 4, 5);
    const SERVER: MacAddr = MacAddr(6, 7, 8, 9, 10, 11);

    struct Link {
        incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
        outgoing: mpsc::Sender<Vec<u8>>,
    }

    impl Transport for Link {
        async fn send(&self, bytes: Vec<u8>) -> io::Result<()> {
            self.outgoing
                .send(bytes)
                .await
                .map_err(|_| io::Error::other("server closed"))
        }
        async fn receive(&self) -> io::Result<Vec<u8>> {
            self.incoming
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "server closed"))
        }
    }

    fn link() -> (Arc<Link>, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (to_client, incoming) = mpsc::channel(32);
        let (outgoing, from_client) = mpsc::channel(32);
        (
            Arc::new(Link {
                incoming: Mutex::new(incoming),
                outgoing,
            }),
            to_client,
            from_client,
        )
    }

    fn settings() -> Settings {
        Settings {
            username: "alice".into(),
            password: "qwert12345".into(),
            ..Settings::default()
        }
    }

    fn process(
        settings: &Settings,
        link: Arc<Link>,
        tx: watch::Sender<ChannelData>,
    ) -> Process<'_, Link> {
        Process::with_transport(settings, link, CLIENT, "202.38.193.33".parse().unwrap(), tx)
    }

    fn watch() -> (watch::Sender<ChannelData>, watch::Receiver<ChannelData>) {
        watch::channel(ChannelData {
            state: State::Stop,
            data: Vec::new(),
        })
    }

    fn frame(code: EAPCode, id: u8, kind: Option<EAPType>, payload: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        EthernetHeader {
            destination: CLIENT,
            source: SERVER,
            ethernet_type: ethernet_types::IEEE8021X,
        }
        .append_to(&mut out);
        let length = 4 + u16::from(kind.is_some()) + payload.len() as u16;
        EAPOLHeader {
            version: 1,
            eapol_type: eapol_types::EAP_PACKET,
            length,
        }
        .append_to(&mut out);
        EAPHeader {
            code,
            identifier: id,
            length,
            eap_type: kind,
        }
        .append_to(&mut out);
        out.put_slice(payload);
        out.resize(96, 0);
        out.to_vec()
    }

    #[test]
    fn md5_response_matches_legacy_golden_vector() {
        let settings = settings();
        let (link, _, _) = link();
        let (tx, _) = watch();
        let mut process = process(&settings, link, tx);
        let packet =
            process.md5_packet(0, &hex::decode("ff62b079ca26d283ca26d28300000000").unwrap());
        assert_eq!(
            hex::encode(&process.data.md5),
            "313a3758ad589ce03dc6af0371c31239"
        );
        assert_eq!(
            &packet[23..40],
            &hex::decode("10313a3758ad589ce03dc6af0371c31239").unwrap()
        );
        assert_eq!(&packet[40..45], b"alice");
    }

    #[test]
    fn identity_response_matches_wire_layout() {
        let settings = settings();
        let (link, _, _) = link();
        let (tx, _) = watch();
        let process = process(&settings, link, tx);
        assert_eq!(
            hex::encode(process.identity_packet(1)),
            "0180c2000003000102030405888e010000130201001301616c6963650044610000ca26c121"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn full_authentication_and_heartbeat_transcript() {
        let settings = settings();
        let (link, server, mut outgoing) = link();
        let (tx, mut state) = watch();
        let mut process = process(&settings, link, tx);
        let server_task = async {
            assert_eq!(
                &outgoing.recv().await.unwrap()[..18],
                &hex::decode("0180c2000003000102030405888e01020000").unwrap()
            );
            assert_eq!(outgoing.recv().await.unwrap()[15], 1);
            server
                .send(frame(eap_codes::REQUEST, 1, Some(EAPType::Identity), &[]))
                .await
                .unwrap();
            let identity = outgoing.recv().await.unwrap();
            assert_eq!(&identity[..6], &SERVER.octets());
            assert_eq!(&identity[18..23], &[2, 1, 0, 19, 1]);
            let mut challenge = vec![16];
            challenge.extend_from_slice(&[7; 16]);
            server
                .send(frame(
                    eap_codes::REQUEST,
                    2,
                    Some(EAPType::Md5Challenge),
                    &challenge,
                ))
                .await
                .unwrap();
            let answer = outgoing.recv().await.unwrap();
            assert_eq!(&answer[18..24], &[2, 2, 0, 36, 4, 16]);
            server
                .send(frame(eap_codes::SUCCESS, 2, None, &[]))
                .await
                .unwrap();
            loop {
                state.changed().await.unwrap();
                if state.borrow().state == State::Success {
                    break;
                }
            }
            let expected = md5::Md5::digest([&[2][..], b"qwert12345", &[7; 16]].concat());
            assert_eq!(state.borrow().data, expected.to_vec());
            let mut group_heartbeat = frame(eap_codes::REQUEST, 3, Some(EAPType::Identity), &[]);
            group_heartbeat[..6].copy_from_slice(&MULTICAST_MAC.octets());
            server.send(group_heartbeat).await.unwrap();
            let heartbeat = outgoing.recv().await.unwrap();
            assert_eq!(&heartbeat[..6], &SERVER.octets());
            assert_eq!(heartbeat[19], 3);
            assert_eq!(&heartbeat[23..], &identity[23..]);
            server
                .send(frame(eap_codes::FAILURE, 2, None, &[]))
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(process.start(), server_task);
        assert_eq!(result, State::Stop);
    }

    #[tokio::test(start_paused = true)]
    async fn opaque_initial_identifiers_complete_authentication_without_logoff_loop() {
        for identifier in [2u8, 128, 255] {
            let settings = settings();
            let (link, server, mut outgoing) = link();
            let (tx, mut state) = watch();
            let mut process = process(&settings, link, tx);
            let server_task = async {
                assert_eq!(outgoing.recv().await.unwrap()[15], 2);
                assert_eq!(outgoing.recv().await.unwrap()[15], 1);
                server
                    .send(frame(
                        eap_codes::REQUEST,
                        identifier,
                        Some(EAPType::Identity),
                        &[],
                    ))
                    .await
                    .unwrap();
                let answer = outgoing.recv().await.unwrap();
                assert_eq!(
                    answer[15], 0,
                    "Identity must be answered, not restart login"
                );
                assert_eq!(&answer[18..20], &[2, identifier]);
                let challenge_id = identifier.wrapping_add(1);
                let mut challenge = vec![16];
                challenge.extend_from_slice(&[7; 16]);
                server
                    .send(frame(
                        eap_codes::REQUEST,
                        challenge_id,
                        Some(EAPType::Md5Challenge),
                        &challenge,
                    ))
                    .await
                    .unwrap();
                assert_eq!(&outgoing.recv().await.unwrap()[18..20], &[2, challenge_id]);
                server
                    .send(frame(eap_codes::SUCCESS, challenge_id, None, &[]))
                    .await
                    .unwrap();
                loop {
                    state.changed().await.unwrap();
                    if state.borrow().state == State::Success {
                        break;
                    }
                }
                server
                    .send(frame(eap_codes::FAILURE, challenge_id, None, &[]))
                    .await
                    .unwrap();
            };
            let (result, ()) = tokio::join!(process.start(), server_task);
            assert_eq!(result, State::Stop);
            assert!(outgoing.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn explicit_logoff_uses_learned_peer_and_revokes_udp_authorization() {
        let settings = settings();
        let (link, _, mut outgoing) = link();
        let (tx, state) = watch();
        let mut process = process(&settings, link, tx);
        process
            .handle_packet(&frame(eap_codes::REQUEST, 42, Some(EAPType::Identity), &[]))
            .await
            .unwrap();
        outgoing.recv().await.unwrap();
        process.logoff().await.unwrap();
        let packet = outgoing.recv().await.unwrap();
        assert_eq!(packet.len(), 96);
        assert_eq!(&packet[..6], &SERVER.octets());
        assert_eq!(&packet[12..18], &[0x88, 0x8e, 1, 2, 0, 0]);
        assert!(packet[18..].iter().all(|byte| *byte == 0));
        assert_eq!(state.borrow().state, State::Stop);
        assert!(outgoing.try_recv().is_err());
    }

    #[test]
    fn configured_eap_ip_is_encoded_in_both_authentication_payloads() {
        let mut settings = settings();
        settings.eap_ip = Some("10.0.0.99".parse().unwrap());
        let (link, _, _) = link();
        let (tx, _) = watch();
        let mut process = process(&settings, link, tx);
        let packet = process.identity_packet(7);
        assert_eq!(&packet[packet.len() - 4..], &[10, 0, 0, 99]);
        let packet = process.md5_packet(8, &[0; 16]);
        assert_eq!(&packet[packet.len() - 4..], &[10, 0, 0, 99]);
    }

    #[tokio::test(start_paused = true)]
    async fn silence_exhausts_bounded_start_retries() {
        let settings = settings();
        let (link, _server, mut outgoing) = link();
        let (tx, state) = watch();
        let mut process = process(&settings, link, tx);
        assert_eq!(process.start().await, State::Stop);
        let mut packets = Vec::new();
        while let Ok(packet) = outgoing.try_recv() {
            packets.push(packet);
        }
        assert_eq!(packets.len(), 4); // logoff, start, two retransmissions
        assert!(packets[1..].windows(2).all(|p| p[0] == p[1]));
        assert_eq!(state.borrow().state, State::Stop);
    }

    #[tokio::test(start_paused = true)]
    async fn notification_propagates_scheduled_sleep() {
        // The code is also a synthetic password: logging masks it, while the
        // protocol must continue to interpret the original server notification.
        let settings = Settings {
            password: "16".into(),
            ..settings()
        };
        let (link, server, mut outgoing) = link();
        let (tx, state) = watch();
        let mut process = process(&settings, link, tx);
        let server_task = async {
            outgoing.recv().await.unwrap();
            outgoing.recv().await.unwrap();
            server
                .send(frame(
                    eap_codes::REQUEST,
                    1,
                    Some(EAPType::Notification),
                    b"Authentication Fail ErrCode=16",
                ))
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(process.start(), server_task);
        assert_eq!(result, State::Sleep);
        assert_eq!(state.borrow().state, State::Sleep);
    }

    #[tokio::test]
    async fn malformed_challenges_do_not_panic_or_cancel_pending_request() {
        let settings = settings();
        let (link, _server, mut outgoing) = link();
        let (tx, state) = watch();
        let mut process = process(&settings, link, tx);
        process
            .send(process.eapol_packet(&EAPOL_HEADER_START), true)
            .await
            .unwrap();
        outgoing.recv().await.unwrap();
        process.data.response_identity_packet = Some(process.identity_packet(1));
        for payload in [vec![], vec![16], vec![255, 1, 2], vec![0], vec![15; 16]] {
            assert!(
                process
                    .handle_packet(&frame(
                        eap_codes::REQUEST,
                        1,
                        Some(EAPType::Md5Challenge),
                        &payload
                    ))
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(process.data.md5.is_empty());
            assert!(process.pending.is_some());
        }
        assert_eq!(state.borrow().state, State::Stop);
        assert!(outgoing.try_recv().is_err());
    }

    #[tokio::test]
    async fn unsolicited_success_does_not_authorize_udp() {
        let settings = settings();
        let (link, _, _) = link();
        let (tx, state) = watch();
        let mut process = process(&settings, link, tx);
        process
            .handle_packet(&frame(eap_codes::SUCCESS, 1, None, &[]))
            .await
            .unwrap();
        assert_eq!(state.borrow().state, State::Stop);
        assert!(process.heartbeat.is_none());
    }

    #[tokio::test]
    async fn wrong_destination_is_ignored() {
        let settings = settings();
        let (link, _, mut outgoing) = link();
        let (tx, _) = watch();
        let mut process = process(&settings, link, tx);
        let mut packet = frame(eap_codes::REQUEST, 1, Some(EAPType::Identity), &[]);
        packet[0] = 99;
        process.handle_packet(&packet).await.unwrap();
        assert!(outgoing.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn quiet_authenticated_session_expires_without_background_tasks() {
        let settings = settings();
        let (link, server, mut outgoing) = link();
        let (tx, mut state) = watch();
        let mut process = process(&settings, link, tx);
        let server_task = async {
            outgoing.recv().await.unwrap();
            outgoing.recv().await.unwrap();
            server
                .send(frame(eap_codes::REQUEST, 1, Some(EAPType::Identity), &[]))
                .await
                .unwrap();
            outgoing.recv().await.unwrap();
            let mut challenge = vec![16];
            challenge.extend_from_slice(&[7; 16]);
            server
                .send(frame(
                    eap_codes::REQUEST,
                    2,
                    Some(EAPType::Md5Challenge),
                    &challenge,
                ))
                .await
                .unwrap();
            outgoing.recv().await.unwrap();
            server
                .send(frame(eap_codes::SUCCESS, 2, None, &[]))
                .await
                .unwrap();
            loop {
                state.changed().await.unwrap();
                if state.borrow().state == State::Success {
                    break;
                }
            }
            let authenticated_at = Instant::now();
            loop {
                state.changed().await.unwrap();
                if state.borrow().state == State::Stop {
                    break;
                }
            }
            assert_eq!(
                Instant::now().duration_since(authenticated_at),
                Duration::from_secs(180)
            );
        };
        let (result, ()) = tokio::join!(process.start(), server_task);
        assert_eq!(result, State::Stop);
    }

    #[tokio::test(start_paused = true)]
    async fn identity_heartbeat_refreshes_authenticated_session_deadline() {
        let settings = settings();
        let (link, server, mut outgoing) = link();
        let (tx, mut state) = watch();
        let mut process = process(&settings, link, tx);
        let server_task = async {
            outgoing.recv().await.unwrap();
            outgoing.recv().await.unwrap();
            server
                .send(frame(eap_codes::REQUEST, 1, Some(EAPType::Identity), &[]))
                .await
                .unwrap();
            outgoing.recv().await.unwrap();
            let mut challenge = vec![16];
            challenge.extend_from_slice(&[7; 16]);
            server
                .send(frame(
                    eap_codes::REQUEST,
                    2,
                    Some(EAPType::Md5Challenge),
                    &challenge,
                ))
                .await
                .unwrap();
            outgoing.recv().await.unwrap();
            server
                .send(frame(eap_codes::SUCCESS, 2, None, &[]))
                .await
                .unwrap();
            loop {
                state.changed().await.unwrap();
                if state.borrow().state == State::Success {
                    break;
                }
            }
            let authenticated_at = Instant::now();
            tokio::time::advance(Duration::from_secs(120)).await;
            server
                .send(frame(eap_codes::REQUEST, 3, Some(EAPType::Identity), &[]))
                .await
                .unwrap();
            assert_eq!(outgoing.recv().await.unwrap()[19], 3);
            tokio::time::advance(Duration::from_secs(120)).await;
            assert_eq!(state.borrow().state, State::Success);
            loop {
                state.changed().await.unwrap();
                if state.borrow().state == State::Stop {
                    break;
                }
            }
            assert_eq!(
                Instant::now().duration_since(authenticated_at),
                Duration::from_secs(300)
            );
        };
        let (result, ()) = tokio::join!(process.start(), server_task);
        assert_eq!(result, State::Stop);
    }

    #[tokio::test]
    async fn reordered_and_replayed_challenge_results_do_not_change_authorization() {
        let settings = settings();
        let (link, _server, mut outgoing) = link();
        let (tx, state) = watch();
        let mut process = process(&settings, link, tx);
        let mut challenge = vec![16];
        challenge.extend_from_slice(&[7; 16]);
        process
            .handle_packet(&frame(
                eap_codes::REQUEST,
                2,
                Some(EAPType::Md5Challenge),
                &challenge,
            ))
            .await
            .unwrap();
        assert!(outgoing.try_recv().is_err()); // identity has not happened yet
        process
            .handle_packet(&frame(eap_codes::REQUEST, 1, Some(EAPType::Identity), &[]))
            .await
            .unwrap();
        outgoing.recv().await.unwrap();
        process
            .handle_packet(&frame(
                eap_codes::REQUEST,
                2,
                Some(EAPType::Md5Challenge),
                &challenge,
            ))
            .await
            .unwrap();
        outgoing.recv().await.unwrap();
        process
            .handle_packet(&frame(eap_codes::SUCCESS, 99, None, &[]))
            .await
            .unwrap();
        assert_eq!(state.borrow().state, State::Stop);
        process
            .handle_packet(&frame(eap_codes::SUCCESS, 2, None, &[]))
            .await
            .unwrap();
        assert_eq!(state.borrow().state, State::Success);
        let deadline = process.heartbeat;
        process
            .handle_packet(&frame(eap_codes::SUCCESS, 2, None, &[]))
            .await
            .unwrap();
        assert_eq!(process.heartbeat, deadline); // duplicate SUCCESS cannot extend liveness
    }

    #[tokio::test]
    async fn authenticated_server_can_reauthenticate_with_a_new_md5_challenge() {
        let settings = settings();
        let (link, _server, mut outgoing) = link();
        let (tx, state) = watch();
        let mut process = process(&settings, link, tx);
        process
            .handle_packet(&frame(eap_codes::REQUEST, 1, Some(EAPType::Identity), &[]))
            .await
            .unwrap();
        outgoing.recv().await.unwrap();
        let mut challenge = vec![16];
        challenge.extend_from_slice(&[7; 16]);
        process
            .handle_packet(&frame(
                eap_codes::REQUEST,
                2,
                Some(EAPType::Md5Challenge),
                &challenge,
            ))
            .await
            .unwrap();
        outgoing.recv().await.unwrap();
        process
            .handle_packet(&frame(eap_codes::SUCCESS, 2, None, &[]))
            .await
            .unwrap();
        let first_digest = state.borrow().data.clone();
        assert_eq!(state.borrow().state, State::Success);
        process
            .handle_packet(&frame(eap_codes::REQUEST, 3, Some(EAPType::Identity), &[]))
            .await
            .unwrap();
        outgoing.recv().await.unwrap();
        challenge[1..].fill(8);
        process
            .handle_packet(&frame(
                eap_codes::REQUEST,
                4,
                Some(EAPType::Md5Challenge),
                &challenge,
            ))
            .await
            .unwrap();
        outgoing.recv().await.unwrap();
        assert_eq!(state.borrow().state, State::Stop);
        assert!(process.heartbeat.is_none());
        process
            .handle_packet(&frame(eap_codes::SUCCESS, 2, None, &[]))
            .await
            .unwrap();
        assert_eq!(state.borrow().state, State::Stop); // old success is stale
        process
            .handle_packet(&frame(eap_codes::SUCCESS, 4, None, &[]))
            .await
            .unwrap();
        assert_eq!(state.borrow().state, State::Success);
        assert_ne!(state.borrow().data, first_digest);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_session_cancels_pending_login() {
        let settings = settings();
        let (link, _server, mut outgoing) = link();
        let (tx, _) = watch();
        let mut process = process(&settings, link, tx);
        {
            let session = process.start();
            tokio::pin!(session);
            tokio::select! {
                result = &mut session => panic!("session ended unexpectedly: {result:?}"),
                packet = outgoing.recv() => assert_eq!(packet.unwrap()[15], 2),
            }
        }
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(outgoing.try_recv().is_err());
    }

    #[tokio::test]
    async fn long_username_is_sent_without_padding_underflow() {
        let mut settings = settings();
        settings.username = "x".repeat(200);
        let (link, _, mut outgoing) = link();
        let (tx, _) = watch();
        let mut process = process(&settings, link, tx);
        process
            .send(process.identity_packet(1), false)
            .await
            .unwrap();
        let packet = outgoing.recv().await.unwrap();
        assert!(packet.len() > 96);
        assert_eq!(&packet[23..223], settings.username.as_bytes());
    }

    #[tokio::test(start_paused = true)]
    async fn unavailable_link_returns_quit_after_transport_retries() {
        let settings = settings();
        let (link, _, outgoing) = link();
        drop(outgoing);
        let (tx, state) = watch();
        let mut process = process(&settings, link, tx);
        assert_eq!(process.start().await, State::Quit);
        assert_eq!(state.borrow().state, State::Quit);
    }

    #[test]
    fn only_time_restriction_notification_schedules_sleep() {
        assert_eq!(
            notification_state("Authentication Fail ErrCode=16"),
            State::Sleep
        );
        for message in [
            "userid error2",
            "Authentication Fail ErrCode=0",
            "Authentication Fail ErrCode=x",
            "In use",
            "",
        ] {
            assert_eq!(notification_state(message), State::Stop);
        }
    }
}
