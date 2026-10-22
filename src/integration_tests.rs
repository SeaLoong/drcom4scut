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
