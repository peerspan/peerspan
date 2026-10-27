//! Membership-independent relay/4 client. Only opaque end-to-end QUIC packets
//! cross this channel; registrations and acknowledgments grant no peer access.
use super::*;
const ALPN_V4: &[u8] = b"peerspan-relay/4";
const AUTH: u8 = 0;
const AUTH_OK: u8 = 7;
const AUTH_REFUSED: u8 = 8;
enum Incoming {
    Packet(Frame),
    Accepted,
    Refused,
}
async fn read(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> anyhow::Result<Incoming> {
    let mut header = [0; 3];
    reader.read_exact(&mut header).await?;
    let length = u16::from_be_bytes([header[1], header[2]]) as usize;
    anyhow::ensure!(
        match header[0] {
            RECEIVE => (HOST_ID + 1..=HOST_ID + MAX_DATAGRAM).contains(&length),
            UNREACHABLE => length == HOST_ID,
            PING | AUTH_OK | AUTH_REFUSED => length == 0,
            _ => false,
        },
        "invalid optional relay frame"
    );
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(match header[0] {
        AUTH_OK => Incoming::Accepted,
        AUTH_REFUSED => Incoming::Refused,
        RECEIVE => Incoming::Packet(Frame::Receive {
            host: payload[..HOST_ID].try_into()?,
            datagram: payload[HOST_ID..].to_vec(),
        }),
        UNREACHABLE => Incoming::Packet(Frame::Unreachable {
            host: payload
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid relay destination"))?,
        }),
        _ => Incoming::Packet(Frame::Ping),
    })
}
fn auth(token: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        token.len() <= 1024
            && std::str::from_utf8(token).is_ok()
            && !token.iter().any(|b| matches!(b, 0 | 10 | 13)),
        "invalid relay resource credential"
    );
    let mut frame = vec![AUTH];
    frame.extend_from_slice(&(token.len() as u16).to_be_bytes());
    frame.extend_from_slice(token);
    Ok(frame)
}
async fn write(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    frame: &[u8],
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), writer.write_all(frame))
        .await
        .map_err(|_| anyhow::anyhow!("optional relay write timed out"))??;
    Ok(())
}
async fn connect(
    store: &Arc<Store>,
    endpoint: &Coordinator,
    token: &[u8],
) -> anyhow::Result<(
    tokio_rustls::client::TlsStream<TcpStream>,
    tokio::time::Instant,
)> {
    let config = pinned_client_config(store.clone(), endpoint.key.clone(), ALPN_V4)?;
    let (host, _) = membership::split_host_port(&endpoint.address)
        .map_err(|_| anyhow::anyhow!("invalid optional relay endpoint"))?;
    let name = rustls::pki_types::ServerName::try_from(host)?;
    let stream = tokio::time::timeout(Duration::from_secs(5), async {
        let socket = TcpStream::connect(&endpoint.address).await?;
        socket.set_nodelay(true)?;
        Ok::<_, anyhow::Error>(
            TlsConnector::from(Arc::new(config))
                .connect(name, socket)
                .await?,
        )
    })
    .await
    .map_err(|_| anyhow::anyhow!("optional relay connect timed out"))??;
    anyhow::ensure!(
        stream.get_ref().1.alpn_protocol() == Some(ALPN_V4),
        "optional relay protocol mismatch"
    );
    let mut stream = stream;
    let frame = auth(token)?;
    let started = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(&frame).await?;
        anyhow::ensure!(
            matches!(read(&mut stream).await?, Incoming::Accepted),
            "optional relay resource authentication refused"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("optional relay authentication timed out"))??;
    Ok((stream, started))
}
struct ReaderTask(tokio::task::JoinHandle<()>);
impl Drop for ReaderTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn session(
    relays: &Arc<Relays>,
    store: &Arc<Store>,
    endpoint: &Coordinator,
    token: &[u8],
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    outgoing: &mut mpsc::Receiver<Vec<u8>>,
    initial_auth: tokio::time::Instant,
) -> anyhow::Result<()> {
    let actual_source = stream.get_ref().0.peer_addr()?.ip();
    let (mut reader, mut writer) = tokio::io::split(stream);
    // A separate reader keeps partial headers/bodies across other select arms.
    // The bounded queue is at most32 datagrams plus one in-flight frame.
    let (received, mut input) = mpsc::channel(32);
    let _reader = ReaderTask(tokio::spawn(async move {
        loop {
            let result = read(&mut reader).await;
            let failed = result.is_err();
            if received.send(result).await.is_err() || failed {
                break;
            }
        }
    }));
    let mut auth_started = initial_auth;
    let mut registered_until = auth_started + Duration::from_secs(300);
    let mut renewal = auth_started + Duration::from_secs(240);
    let mut auth_deadline = registered_until;
    let mut pending = false;
    let mut ping = tokio::time::interval(PING_AFTER);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ping.tick().await;
    loop {
        tokio::select! {
            _=tokio::time::sleep_until(registered_until)=>anyhow::bail!("optional relay registration expired"),
            _=tokio::time::sleep_until(auth_deadline),if pending=>anyhow::bail!("optional relay renewal timed out"),
            _=tokio::time::sleep_until(renewal),if !pending=>{
                pending=true;auth_started=tokio::time::Instant::now();auth_deadline=auth_started+Duration::from_secs(5);
                write(&mut writer,&auth(token)?).await?;
            },
            _=ping.tick()=>write(&mut writer,&encode(&Frame::Ping)).await?,
            frame=outgoing.recv(),if !pending=>{
                let Some(frame)=frame else{return Ok(())};
                anyhow::ensure!(matches!(frame.first(),Some(&SEND)|Some(&PING)),"invalid optional relay outbound frame");
                write(&mut writer,&frame).await?;
            },
            frame=input.recv()=>{
                let frame=frame.ok_or_else(||anyhow::anyhow!("optional relay closed"))??;
                let observed=tokio::time::Instant::now();
                anyhow::ensure!(observed<registered_until&&(!pending||observed<auth_deadline),"optional relay registration timed out");
                match frame {
                    Incoming::Accepted=>{
                        anyhow::ensure!(pending,"unsolicited optional relay acknowledgment");
                        pending=false;registered_until=auth_started+Duration::from_secs(300);renewal=auth_started+Duration::from_secs(240);
                    },
                    Incoming::Refused=>anyhow::bail!("optional relay authentication refused"),
                    Incoming::Packet(Frame::Receive{host,datagram})=>{
                        relays.receive_resource(store,host,datagram,endpoint,actual_source);
                    },
                    Incoming::Packet(Frame::Unreachable{..}|Frame::Ping)=>{},
                    _=>anyhow::bail!("invalid optional relay direction"),
                }
            },
        }
    }
}
pub(super) async fn run(
    relays: Arc<Relays>,
    store: Arc<Store>,
    endpoint: Coordinator,
    token: Arc<Vec<u8>>,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    status: watch::Sender<bool>,
    version: Arc<AtomicU8>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if let Ok((stream, initial_auth)) = connect(&store, &endpoint, &token).await {
            version.store(4, Ordering::Release);
            let _ = status.send(true);
            backoff = Duration::from_secs(1);
            let _ = session(
                &relays,
                &store,
                &endpoint,
                &token,
                stream,
                &mut outgoing,
                initial_auth,
            )
            .await;
            version.store(0, Ordering::Release);
            let _ = status.send(false);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}
