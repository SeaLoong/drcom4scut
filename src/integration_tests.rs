//! Complete in-process client transcript: a simulated Ethernet authenticator and
//! a real loopback UDP server share the same authentication channel as production.
use std::{io, sync::Arc, time::Duration};

use pnet::datalink::MacAddr;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc, watch},
    time::timeout,
};

use crate::{
    eap,
    settings::Settings,
    socket::Socket,
    udp,
    util::{ChannelData, State},
};

const CLIENT: MacAddr = MacAddr(2, 0, 0, 0, 0, 1);
const SERVER: MacAddr = MacAddr(2, 0, 0, 0, 0, 2);

struct EthernetLink {
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

impl eap::Transport for EthernetLink {
    async fn send(&self, data: Vec<u8>) -> io::Result<()> {
        self.outgoing
            .send(data)
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
    async fn receive(&self) -> io::Result<Vec<u8>> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::UnexpectedEof.into())
    }
}

// Construct server frames independently of the client's encoders. Ethernet
// padding deliberately contains nonzero bytes so declared lengths are exercised.
fn frame(code: u8, id: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[CLIENT.0, CLIENT.1, CLIENT.2, CLIENT.3, CLIENT.4, CLIENT.5]);
    bytes.extend_from_slice(&[SERVER.0, SERVER.1, SERVER.2, SERVER.3, SERVER.4, SERVER.5]);
    bytes.extend_from_slice(&[0x88, 0x8e, 1, 0]);
    let length = 4 + payload.len() as u16;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&[code, id]);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(96, 0xaa);
    bytes
}

async fn datagram(socket: &UdpSocket) -> Vec<u8> {
    let mut bytes = [0; 2048];
    let size = timeout(Duration::from_secs(2), socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes[..size].to_vec()
}

#[tokio::test]
async fn e2e_eap_authorization_controls_udp_handshake_heartbeat_and_disconnect() {
    let settings = Settings {
        username: "student".into(),
        password: "qwert12345".into(),
        hostname: "test-pc".into(),
        ..Settings::default()
    };
    let (to_client, incoming) = mpsc::channel(16);
    let (outgoing, mut from_client) = mpsc::channel(16);
    let link = Arc::new(EthernetLink {
        incoming: Mutex::new(incoming),
        outgoing,
    });
    let (auth, state) = watch::channel(ChannelData::stopped());
    let mut eap =
        eap::Process::with_transport(&settings, link, CLIENT, "192.0.2.1".parse().unwrap(), auth);

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(server.local_addr().unwrap()).await.unwrap();
    server.connect(client.local_addr().unwrap()).await.unwrap();
    let mut udp = udp::Process::new(
        &settings,
        Arc::new(Socket::new(client)),
        state,
        CLIENT,
        "192.0.2.1".parse().unwrap(),
        "192.0.2.53:53".parse().unwrap(),
    );

    let authenticator = async {
        let logoff = from_client.recv().await.unwrap();
        assert_eq!(&logoff[12..18], &[0x88, 0x8e, 1, 2, 0, 0]);
        assert!(
            timeout(Duration::from_millis(20), datagram(&server))
                .await
                .is_err()
        );
        let start = from_client.recv().await.unwrap();
        assert_eq!(&start[12..18], &[0x88, 0x8e, 1, 1, 0, 0]);
        to_client.send(frame(1, 1, &[1])).await.unwrap();
        let identity = from_client.recv().await.unwrap();
        assert_eq!(&identity[18..23], &[2, 1, 0, 21, 1]);
        assert_eq!(&identity[23..30], b"student");
        let mut challenge = vec![4, 16];
        challenge.extend(hex::decode("ff62b079ca26d283ca26d28300000000").unwrap());
        to_client.send(frame(1, 0, &challenge)).await.unwrap();
        let response = from_client.recv().await.unwrap();
        assert_eq!(
            hex::encode(&response[24..40]),
            "313a3758ad589ce03dc6af0371c31239"
        );
        to_client.send(frame(3, 0, &[])).await.unwrap();

        assert_eq!(datagram(&server).await, [7, 0, 8, 0, 1, 0, 0, 0]);
        server
            .send(&[7, 0, 0, 0, 2, 0, 0, 0, 1, 2, 3, 4])
            .await
            .unwrap();
        let info = datagram(&server).await;
        assert_eq!(info.len(), 244);
        assert_eq!(&info[32..39], b"student");
        let mut info_response = vec![0; 32];
        info_response[0] = 7;
        info_response[4] = 4;
        info_response[16..32]
            .copy_from_slice(&hex::decode("4439d8edac314b07dd8c5f3bef0f04d8").unwrap());
        server.send(&info_response).await.unwrap();
        let alive = datagram(&server).await;
        assert_eq!(alive[0], 0xff);
        assert_eq!(alive.len(), 38);
        assert_eq!(
            &alive[20..36],
            &hex::decode("4472636fca26d283dd197dd9fee1016c").unwrap()
        );
        server.send(&[7, 0, 0, 0, 6]).await.unwrap();
        let heartbeat1 = datagram(&server).await;
        assert_eq!(&heartbeat1[..8], &[7, 1, 40, 0, 11, 1, 220, 2]);
        let mut heartbeat2 = vec![0; 40];
        heartbeat2[..6].copy_from_slice(&[7, 1, 40, 0, 11, 2]);
        heartbeat2[16..20].copy_from_slice(&[5, 6, 7, 8]);
        server.send(&heartbeat2).await.unwrap();
        let heartbeat3 = datagram(&server).await;
        assert_eq!(&heartbeat3[..6], &[7, 2, 40, 0, 11, 3]);
        assert_eq!(&heartbeat3[16..20], &[5, 6, 7, 8]);
        heartbeat2[5] = 4;
        server.send(&heartbeat2).await.unwrap();
        to_client.send(frame(4, 0, &[])).await.unwrap();
    };
    let (eap_state, udp_state, ()) = timeout(Duration::from_secs(6), async {
        tokio::join!(eap.start(), udp.start(), authenticator)
    })
    .await
    .expect("complete authentication transcript must terminate");
    assert_eq!(eap_state, State::Stop);
    assert_eq!(udp_state, State::Stop);
    assert!(
        timeout(Duration::from_millis(20), datagram(&server))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn e2e_expired_udp_session_is_refreshed_while_eap_stays_authenticated() {
    async fn receive_from(socket: &UdpSocket) -> (Vec<u8>, std::net::SocketAddr) {
        let mut bytes = [0; 2048];
        let (size, peer) = timeout(Duration::from_secs(3), socket.recv_from(&mut bytes))
            .await
            .expect("UDP transcript stalled")
            .unwrap();
        (bytes[..size].to_vec(), peer)
    }

    async fn heartbeat(socket: &UdpSocket, peer: std::net::SocketAddr) {
        socket.send_to(&[7, 0, 0, 0, 6], peer).await.unwrap();
        let (first, sender) = receive_from(socket).await;
        assert_eq!(sender, peer);
        assert_eq!(&first[..8], &[7, 1, 40, 0, 11, 1, 220, 2]);
        let mut second = vec![0; 40];
        second[..6].copy_from_slice(&[7, 1, 40, 0, 11, 2]);
        second[16..20].copy_from_slice(&[5, 6, 7, 8]);
        socket.send_to(&second, peer).await.unwrap();
        let (third, sender) = receive_from(socket).await;
        assert_eq!(sender, peer);
        assert_eq!(&third[..6], &[7, 2, 40, 0, 11, 3]);
        second[5] = 4;
        socket.send_to(&second, peer).await.unwrap();
    }

    async fn handshake(socket: &UdpSocket, token: u8) -> std::net::SocketAddr {
        let (alive, peer) = receive_from(socket).await;
        assert_eq!(alive, [7, 0, 8, 0, 1, 0, 0, 0]);
        socket
            .send_to(&[7, 0, 0, 0, 2, 0, 0, 0, 1, 2, 3, 4], peer)
            .await
            .unwrap();
        let (info, sender) = receive_from(socket).await;
        assert_eq!(sender, peer);
        assert_eq!(info.len(), 244);
        let mut info_response = vec![0; 32];
        info_response[0] = 7;
        info_response[4] = 4;
        info_response[16..32].fill(token);
        socket.send_to(&info_response, peer).await.unwrap();
        let (alive, sender) = receive_from(socket).await;
        assert_eq!(sender, peer);
        assert_eq!(alive.len(), 38);
        assert_eq!(alive[0], 0xff);
        for index in 0..16 {
            assert_eq!(alive[20 + index], token.rotate_left((index % 8) as u32));
        }
        // Every new UDP session starts at counter one and receives a new token.
        heartbeat(socket, peer).await;
        peer
    }

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut settings = Settings {
        username: "student".into(),
        password: "fake-password".into(),
        host: "127.0.0.1".into(),
        dns: vec!["127.0.0.1:53".parse().unwrap()],
        local_port: 0,
        server_port: server.local_addr().unwrap().port(),
        reconnect: 1,
        reconnect_max: 1,
        ..Settings::default()
    };
    settings.retry.count = 0;
    settings.retry.interval = 5000;
    settings.heartbeat.udp_timeout = 1;
    settings.heartbeat.eap_timeout = 300;
    let (to_client, incoming) = mpsc::channel(16);
    let (outgoing, mut from_client) = mpsc::channel(16);
    let link = Arc::new(EthernetLink {
        incoming: Mutex::new(incoming),
        outgoing,
    });
    let (auth, state) = watch::channel(ChannelData::stopped());
    let (ready_tx, mut ready) = watch::channel(false);
    let mut eap =
        eap::Process::with_transport(&settings, link, CLIENT, "127.0.0.1".parse().unwrap(), auth);
    let udp = crate::client::udp_supervisor(
        &settings,
        state.clone(),
        ready_tx,
        CLIENT,
        "127.0.0.1".parse().unwrap(),
    );
    let server_exchange = async {
        assert_eq!(from_client.recv().await.unwrap()[15], 2);
        assert_eq!(from_client.recv().await.unwrap()[15], 1);
        to_client.send(frame(1, 1, &[1])).await.unwrap();
        assert_eq!(from_client.recv().await.unwrap()[22], 1);
        let mut challenge = vec![4, 16];
        challenge.extend([0x33; 16]);
        to_client.send(frame(1, 2, &challenge)).await.unwrap();
        assert_eq!(from_client.recv().await.unwrap()[22], 4);
        to_client.send(frame(3, 2, &[])).await.unwrap();

        let peer = handshake(&server, 0x21).await;
        timeout(Duration::from_secs(2), ready.wait_for(|online| *online))
            .await
            .unwrap()
            .unwrap();
        let original_checksum = state.borrow().data.clone();
        for cycle in 0..3 {
            let (alive, sender) = receive_from(&server).await;
            assert_eq!(sender, peer);
            assert_eq!(alive[0], 0xff, "short outages keep the current session");
            // Keep the Ethernet session active throughout UDP loss.
            to_client.send(frame(1, 10 + cycle, &[1])).await.unwrap();
            let reply = from_client.recv().await.unwrap();
            assert_eq!(&reply[18..20], &[2, 10 + cycle]);
            assert_eq!(reply[22], 1);
            assert_eq!(state.borrow().state, State::Success);
            assert_eq!(state.borrow().data, original_checksum);
            // Real socket traffic finishes before advancing the missing reply's
            // deadline. This keeps the test reliable under QEMU and busy runners.
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(5)).await;
            tokio::time::resume();
        }
        let _new_peer = handshake(&server, 0x42).await;
        timeout(Duration::from_secs(2), ready.wait_for(|online| *online))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.borrow().state, State::Success);
        assert_eq!(state.borrow().data, original_checksum);
        assert!(
            from_client.try_recv().is_err(),
            "UDP recovery sends no EAP Logoff/Start"
        );
        to_client.send(frame(4, 2, &[])).await.unwrap();
    };
    let (eap_state, ()) = timeout(Duration::from_secs(60), async {
        tokio::join!(eap.start(), async {
            tokio::select! {
                _ = udp => panic!("UDP supervisor exited before recovery"),
                () = server_exchange => (),
            }
        })
    })
    .await
    .expect("session refresh transcript must finish");
    assert_eq!(eap_state, State::Stop);
    assert!(!*ready.borrow(), "dropping the supervisor clears readiness");
}
