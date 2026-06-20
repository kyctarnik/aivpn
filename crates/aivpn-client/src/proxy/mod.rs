pub mod device;
pub mod socks5;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::proxy::device::VpnDevice;
use crate::proxy::socks5::{
    build_udp_response, parse_udp_request, Socks5Command,
    Socks5UdpTarget, Socks5Session, TargetAddr,
    REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE, REP_SUCCESS,
};

use smoltcp::socket::dns;
use smoltcp::wire::DnsQueryType as DnsType;

/// MTU: совпадает с WAN_SAFE_TUN_MTU в tunnel.rs
const PROXY_MTU: usize = 1280;
const TCP_BUF: usize = 65536;
const UDP_PACKET_BUF: usize = 128;
const UDP_PAYLOAD_BUF: usize = 65536;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_ASSOCIATE_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

static SRC_PORT: AtomicU16 = AtomicU16::new(49152);

pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub vpn_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub prefix_len: u8,
}

pub struct ProxyHandle {
    pub rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub wake_tx: std::sync::mpsc::Sender<()>
}

struct ManagedConn {
    handle: SocketHandle,
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    close_flag: Arc<AtomicBool>,
    ready_tx: Option<std::sync::mpsc::SyncSender<bool>>,
}

struct NewConn {
    target: IpEndpoint,
    src_port: u16,
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    close_flag: Arc<AtomicBool>,
    ready_tx: std::sync::mpsc::SyncSender<bool>,
}

struct ManagedUdpAssoc {
    handle: SocketHandle,
    relay_port: u16,
    outbound_tx: mpsc::Sender<UdpRelayResponse>,
    close_flag: Arc<AtomicBool>,
    ready_tx: Option<std::sync::mpsc::SyncSender<bool>>,
    last_seen: Instant,
}

struct NewUdpAssoc {
    relay_port: u16,
    outbound_tx: mpsc::Sender<UdpRelayResponse>,
    close_flag: Arc<AtomicBool>,
    ready_tx: std::sync::mpsc::SyncSender<bool>,
}

struct UdpPacketCommand {
    relay_port: u16,
    target: IpEndpoint,
    payload: Vec<u8>,
}

#[allow(dead_code)]
struct UdpRelayResponse {
    relay_port: u16,
    remote: IpEndpoint,
    payload: Vec<u8>,
}

struct DnsResolve {
    name: String,
    qtype: DnsType,                                  // A или Aaaa
    reply: std::sync::mpsc::SyncSender<Option<IpAddr>>,
}

struct PendingDns {
    handle: dns::QueryHandle,
    reply: std::sync::mpsc::SyncSender<Option<IpAddr>>,
    started: Instant,
}

enum UdpStackCommand {
    CreateAssoc(NewUdpAssoc),
    SendPacket(UdpPacketCommand),
    Resolve(DnsResolve),                             // ← добавили
}

/// Запустить smoltcp-стек и SOCKS5-слушатель.
pub async fn spawn_proxy(
    config: ProxyConfig,
    tun_to_udp_tx: mpsc::Sender<Vec<u8>>,
) -> std::io::Result<ProxyHandle> {
    let rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
    let tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<NewConn>();
    let (udp_cmd_tx, udp_cmd_rx) = std::sync::mpsc::channel::<UdpStackCommand>();
    let (wake_tx, wake_rx) = std::sync::mpsc::channel::<()>();

    let vpn_ip = config.vpn_ip;
    let gateway_ip = config.gateway_ip;
    let prefix_len = config.prefix_len;
    let rx_clone = Arc::clone(&rx_queue);
    let tx_clone = Arc::clone(&tx_queue);

    std::thread::spawn(move || {
        run_stack(
             rx_clone,
             tx_clone,
             tun_to_udp_tx,
             cmd_rx,
             udp_cmd_rx,
             wake_rx,
             vpn_ip,
             gateway_ip,
             prefix_len,
        );
    });

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!("SOCKS5 proxy listening on {}", config.listen_addr);

    let proxy_ip = config.listen_addr.ip();
    let wake_tx_accept = wake_tx.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    debug!("Proxy: connection from {}", peer);
                    let tx = cmd_tx.clone();
                    let udp_tx = udp_cmd_tx.clone();
                    let wtx = wake_tx_accept.clone();
                    tokio::spawn(handle_socks5(stream, tx, udp_tx, wtx, proxy_ip));
                }
                Err(e) => {
                    error!("Proxy accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(ProxyHandle { rx_queue, wake_tx })
}

fn smoltcp_now() -> SmolInstant {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    SmolInstant::from_millis(d.as_millis() as i64)
}

fn alloc_src_port() -> u16 {
    let p = SRC_PORT.fetch_add(1, Ordering::Relaxed);
    if p > 65000 {
        SRC_PORT.store(49152, Ordering::Relaxed);
    }
    p
}

#[allow(clippy::too_many_arguments)]
fn run_stack(
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tun_to_udp_tx: mpsc::Sender<Vec<u8>>,
    cmd_rx: std::sync::mpsc::Receiver<NewConn>,
    udp_cmd_rx: std::sync::mpsc::Receiver<UdpStackCommand>,
    wake_rx: std::sync::mpsc::Receiver<()>,
    vpn_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    prefix_len: u8,
) {
    let mut device = VpnDevice::new(Arc::clone(&rx_queue), Arc::clone(&tx_queue), PROXY_MTU);

    let cfg = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(cfg, &mut device, smoltcp_now());

    let [a, b, c, d] = vpn_ip.octets();
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(a, b, c, d), prefix_len));
    });

    let [ga, gb, gc, gd] = gateway_ip.octets();
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(ga, gb, gc, gd));

    let mut sockets = SocketSet::new(vec![]);
    let mut tcp_conns: Vec<ManagedConn> = Vec::new();
    let mut udp_assocs: HashMap<u16, ManagedUdpAssoc> = HashMap::new();

    let dns_servers = [IpAddress::v4(1, 1, 1, 1)]; // TODO: получать адреса извне, важно: работает ток с одним адресом :(
    // Vec даёт owned-слоты; find_free_query() сам делает push при нехватке.
    let dns_socket = dns::Socket::new(&dns_servers, Vec::<Option<dns::DnsQuery>>::new());
    let dns_handle = sockets.add(dns_socket);
    let mut pending_dns: Vec<PendingDns> = Vec::new();

    loop {
        // Принимаем новые TCP CONNECT-запросы.
        loop {
            match cmd_rx.try_recv() {
                Ok(nc) => {
                    let rx_buf = TcpSocketBuffer::new(vec![0u8; TCP_BUF]);
                    let tx_buf = TcpSocketBuffer::new(vec![0u8; TCP_BUF]);
                    let mut socket = TcpSocket::new(rx_buf, tx_buf);
                    socket.set_ack_delay(None);
                    socket.set_nagle_enabled(false);

                    let mut cx = iface.context();
                    match socket.connect(&mut cx, nc.target, nc.src_port) {
                        Ok(()) => {
                            let handle = sockets.add(socket);
                            tcp_conns.push(ManagedConn {
                                handle,
                                inbound: nc.inbound,
                                outbound_tx: nc.outbound_tx,
                                close_flag: nc.close_flag,
                                ready_tx: Some(nc.ready_tx),
                            });
                        }
                        Err(e) => {
                            error!("smoltcp connect error: {}", e);
                            let _ = nc.ready_tx.send(false);
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            }
        }

        // Принимаем команды UDP ASSOCIATE и пакеты на отправку.
        loop {
            match udp_cmd_rx.try_recv() {
                Ok(UdpStackCommand::CreateAssoc(nc)) => {
                    if udp_assocs.contains_key(&nc.relay_port) {
                        let _ = nc.ready_tx.send(false);
                        continue;
                    }

                    let rx_meta = vec![UdpPacketMetadata::EMPTY; UDP_PACKET_BUF];
                    let tx_meta = vec![UdpPacketMetadata::EMPTY; UDP_PACKET_BUF];
                    let rx_buf = UdpPacketBuffer::new(rx_meta, vec![0u8; UDP_PAYLOAD_BUF]);
                    let tx_buf = UdpPacketBuffer::new(tx_meta, vec![0u8; UDP_PAYLOAD_BUF]);
                    let mut socket = UdpSocket::new(rx_buf, tx_buf);

                    if let Err(e) = socket.bind(nc.relay_port) {
                        error!("smoltcp udp bind error on {}: {}", nc.relay_port, e);
                        let _ = nc.ready_tx.send(false);
                        continue;
                    }

                    let handle = sockets.add(socket);
                    udp_assocs.insert(
                        nc.relay_port,
                        ManagedUdpAssoc {
                            handle,
                            relay_port: nc.relay_port,
                            outbound_tx: nc.outbound_tx,
                            close_flag: nc.close_flag,
                            ready_tx: Some(nc.ready_tx),
                            last_seen: Instant::now(),
                        },
                    );
                }
                Ok(UdpStackCommand::SendPacket(pkt)) => {
                    if let Some(assoc) = udp_assocs.get_mut(&pkt.relay_port) {
                        assoc.last_seen = Instant::now();
                        let socket = sockets.get_mut::<UdpSocket>(assoc.handle);
                        if let Err(e) = socket.send_slice(&pkt.payload, pkt.target) {
                            warn!(
                                "SOCKS5 UDP send failed on relay port {}: {}",
                                pkt.relay_port, e
                            );
                        }
                    }
                }
                Ok(UdpStackCommand::Resolve(r)) => {
                    let dns_sock = sockets.get_mut::<dns::Socket>(dns_handle);
                    let mut cx = iface.context();
                    match dns_sock.start_query(&mut cx, &r.name, r.qtype) {
                        Ok(handle) => pending_dns.push(PendingDns {
                            handle,
                            reply: r.reply,
                            started: Instant::now(),
                        }),
                        Err(e) => {
                            warn!("dns start_query '{}' failed: {}", r.name, e);
                            let _ = r.reply.send(None);
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            }
        }

        iface.poll(smoltcp_now(), &mut device, &mut sockets);

        // Отправляем в транспорт все IP-пакеты, которые smoltcp подготовил.
        {
            let mut q = tx_queue.lock().unwrap_or_else(|e| e.into_inner());
            while let Some(pkt) = q.pop_front() {
                match tun_to_udp_tx.try_send(pkt) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(pkt)) => {
                        q.push_front(pkt);   // транспорт занят — вернём в очередь, попробуем в след. тик
                        break;               // но НЕ морозим весь стек
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                }
            }
        }
        // {
        //     let mut q = tx_queue.lock().unwrap();
        //     while let Some(pkt) = q.pop_front() {
        //         if tun_to_udp_tx.blocking_send(pkt).is_err() {
        //             return;
        //         }
        //     }
        // }

        // Обслуживаем DNS-резолв через туннель.
        if !pending_dns.is_empty() {
            let dns_sock = sockets.get_mut::<dns::Socket>(dns_handle);
            pending_dns.retain_mut(|p| match dns_sock.get_query_result(p.handle) {
                Ok(addrs) => {
                    let _ = p.reply.send(addrs.iter().next().copied().map(smol_ip_to_std));
                    false
                }
                Err(dns::GetQueryResultError::Pending) => {
                    if p.started.elapsed() > DNS_QUERY_TIMEOUT {
                        dns_sock.cancel_query(p.handle); // освобождаем слот
                        let _ = p.reply.send(None);
                        false
                    } else {
                        true
                    }
                }
                Err(dns::GetQueryResultError::Failed) => {
                    let _ = p.reply.send(None);
                    false
                }
            });
        }

        // Обслуживаем TCP-соединения.
        let mut remove_tcp: Vec<usize> = Vec::new();
        for (i, conn) in tcp_conns.iter_mut().enumerate() {
            if service_tcp_conn(conn, &mut sockets) {
                remove_tcp.push(i);
            }
        }
        for i in remove_tcp.into_iter().rev() {
            let conn = tcp_conns.remove(i);
            sockets.remove(conn.handle);
        }

        // Обслуживаем UDP relay.
        let mut remove_udp_ports: Vec<u16> = Vec::new();
        for assoc in udp_assocs.values_mut() {
            if service_udp_assoc(assoc, &mut sockets) {
                remove_udp_ports.push(assoc.relay_port);
            }
        }
        for relay_port in remove_udp_ports {
            if let Some(assoc) = udp_assocs.remove(&relay_port) {
                sockets.remove(assoc.handle);
            }
        }
        let timeout: std::time::Duration = iface
            .poll_delay(smoltcp_now(), &sockets)
            .map(Into::into)                                   // если From не найдётся:
            .unwrap_or(std::time::Duration::from_millis(100)); // Duration::from_micros(d.total_micros())

        match wake_rx.recv_timeout(timeout) {
            Ok(()) => { while wake_rx.try_recv().is_ok() {} }  // сдренировать пачку сигналов
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

async fn resolve_via_tunnel(
    cmd_tx: &std::sync::mpsc::Sender<UdpStackCommand>,
    wake_tx: &std::sync::mpsc::Sender<()>,
    host: &str,
    port: u16,
    want_v6: bool,
) -> std::io::Result<SocketAddr> {
    let order: &[DnsType] = if want_v6 {
        &[DnsType::Aaaa, DnsType::A]
    } else {
        &[DnsType::A]
    };

    for &qtype in order {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Option<IpAddr>>(1);
        if cmd_tx
            .send(UdpStackCommand::Resolve(DnsResolve {
                name: host.to_string(),
                qtype,
                reply: tx,
            }))
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stack thread gone",
            ));
        }
        let _ = wake_tx.send(()); // разбудить стек: DNS-запрос
        let ip = tokio::task::spawn_blocking(move || {
            rx.recv_timeout(DNS_QUERY_TIMEOUT).ok().flatten()
        })
        .await
        .unwrap_or(None);

        if let Some(ip) = ip {
            return Ok(SocketAddr::new(ip, port));
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("DNS via tunnel: no result for {host}:{port}"),
    ))
}

/// Возвращает `true`, когда TCP-соединение нужно удалить.
fn service_tcp_conn(conn: &mut ManagedConn, sockets: &mut SocketSet) -> bool {
    let socket = sockets.get_mut::<TcpSocket>(conn.handle);

    if let Some(ready_tx) = conn.ready_tx.take() {
        match socket.state() {
            State::Established => {
                let _ = ready_tx.send(true);
            }
            State::Closed | State::TimeWait | State::CloseWait => {
                let _ = ready_tx.send(false);
                return true;
            }
            _ => {
                conn.ready_tx = Some(ready_tx);
                return false;
            }
        }
    }

    if conn.close_flag.load(Ordering::Relaxed) {
        socket.abort();
        return true;
    }

    if socket.may_send() {
        let mut q = conn.inbound.lock().unwrap();
        while !q.is_empty() && socket.can_send() {
            let chunk = q.pop_front().unwrap();
            match socket.send_slice(&chunk) {
                Ok(n) if n < chunk.len() => {
                    q.push_front(chunk[n..].to_vec());
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    // if socket.can_recv() {
    //     let mut tmp = vec![0u8; 4096];
    //     if let Ok(n) = socket.recv_slice(&mut tmp) {
    //         if n > 0 {
    //             tmp.truncate(n);
    //             if conn.outbound_tx.try_send(tmp).is_err() {
    //                 socket.abort();
    //                 return true;
    //             }
    //         }
    //     }
    // }
    if socket.can_recv() {
        // Сливаем всё, что smoltcp набуферил, но только под наличие места в канале.
        // Нет места → не читаем (TCP-окно придержит сервер). НЕ abort.
        loop {
            let permit = match conn.outbound_tx.try_reserve() {
                Ok(p) => p,
                Err(tokio::sync::mpsc::error::TrySendError::Full(())) => break,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                    socket.abort();
                    return true;
                }
            };
            if !socket.can_recv() {
                break;
            }
            let mut tmp = vec![0u8; 16384];
            match socket.recv_slice(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    tmp.truncate(n);
                    permit.send(tmp);
                }
                Err(_) => break,
            }
        }
    }

    matches!(
        socket.state(),
        State::Closed | State::TimeWait | State::FinWait2
    )
}

/// Возвращает `true`, когда UDP-ассоциацию нужно закрыть.
fn service_udp_assoc(assoc: &mut ManagedUdpAssoc, sockets: &mut SocketSet) -> bool {
    if let Some(ready_tx) = assoc.ready_tx.take() {
        let _ = ready_tx.send(true);
    }

    if assoc.close_flag.load(Ordering::Relaxed) {
        return true;
    }

    if assoc.last_seen.elapsed() > UDP_ASSOCIATE_IDLE_TIMEOUT {
        info!("UDP ASSOCIATE port {} timed out", assoc.relay_port);
        return true;
    }

    let socket = sockets.get_mut::<UdpSocket>(assoc.handle);
    let mut tmp = vec![0u8; UDP_PAYLOAD_BUF];
    while socket.can_recv() {
        let (len, remote_meta) = match socket.recv_slice(&mut tmp) {
            Ok(v) => v,
            Err(_) => break,
        };

        if len == 0 {
            continue;
        }

        let response = UdpRelayResponse {
            relay_port: assoc.relay_port,
            remote: remote_meta.endpoint,
            payload: tmp[..len].to_vec(),
        };

        if assoc.outbound_tx.try_send(response).is_err() {
            warn!(
                "UDP relay response queue full for port {}",
                assoc.relay_port
            );
            break;
        }

        assoc.last_seen = Instant::now();
        debug!(
            "UDP relay received {} bytes on port {}",
            len, assoc.relay_port
        );
    }

    false
}

fn socket_endpoint_to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    let ip = match endpoint.addr {
        IpAddress::Ipv4(ip) => IpAddr::V4(Ipv4Addr::from(ip.0)),
        IpAddress::Ipv6(ip) => IpAddr::V6(std::net::Ipv6Addr::from(ip.0)),
    };
    SocketAddr::new(ip, endpoint.port)
}

fn socket_addr_to_ip_endpoint(addr: SocketAddr) -> IpEndpoint {
    match addr.ip() {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            IpEndpoint::new(IpAddress::v4(a, b, c, d), addr.port())
        }
        IpAddr::V6(ip) => {
            IpEndpoint::new(IpAddress::Ipv6(Ipv6Address(ip.octets())), addr.port())
        }
    }
}

async fn handle_socks5(
    stream: tokio::net::TcpStream,
    cmd_tx: std::sync::mpsc::Sender<NewConn>,
    udp_cmd_tx: std::sync::mpsc::Sender<UdpStackCommand>,
    wake_tx: std::sync::mpsc::Sender<()>,
    proxy_ip: IpAddr,
) {
    let mut session = Socks5Session::new(stream);

    let req = match session.negotiate().await {
        Ok(req) => req,
        Err(e) => {
            warn!("SOCKS5 negotiate: {}", e);
            let _ = session.send_reply(REP_GENERAL_FAILURE).await;
            return;
        }
    };

    match req {
        Socks5Command::Connect(target) => {
            handle_connect(session, cmd_tx, udp_cmd_tx, wake_tx, target).await;  // ← +udp_cmd_tx
        }
        Socks5Command::UdpAssociate(_) => {
            handle_udp_associate(session, udp_cmd_tx, wake_tx, proxy_ip).await;
        }
    }
}

async fn handle_connect(
    mut session: Socks5Session,
    cmd_tx: std::sync::mpsc::Sender<NewConn>,
    udp_cmd_tx: std::sync::mpsc::Sender<UdpStackCommand>,
    wake_tx: std::sync::mpsc::Sender<()>,
    target_addr: TargetAddr,
) {
    let target: SocketAddr = match target_addr {
        TargetAddr::Ip(a) => a,
        TargetAddr::Domain(host, port) => {
            match resolve_via_tunnel(&udp_cmd_tx, &wake_tx, &host, port, /*want_v6=*/ false).await {
                Ok(a) => a,
                Err(e) => {
                    warn!("TCP CONNECT DNS error {host}:{port}: {e}");
                    let _ = session.send_reply(REP_HOST_UNREACHABLE).await;
                    return;
                }
            }
        }
    };

    let target_ipv4 = match target.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            warn!(
                "Proxy: IPv6 targets not supported for TCP CONNECT: {}",
                target
            );
            let _ = session.send_reply(REP_HOST_UNREACHABLE).await;
            return;
        }
    };

    let [ta, tb, tc, td] = target_ipv4.octets();
    debug!("TCP CONNECT target {}.{}.{}.{}:{}", ta, tb, tc, td, target.port());
    let smol_target = IpEndpoint::new(IpAddress::v4(ta, tb, tc, td), target.port());
    let src_port = alloc_src_port();

    let inbound: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
    let close_flag = Arc::new(AtomicBool::new(false));
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);

    if cmd_tx
        .send(NewConn {
            target: smol_target,
            src_port,
            inbound: Arc::clone(&inbound),
            outbound_tx,
            close_flag: Arc::clone(&close_flag),
            ready_tx,
        })
        .is_err()
    {
        let _ = session.send_reply(REP_GENERAL_FAILURE).await;
        return;
    }
    let _ = wake_tx.send(()); // разбудить стек: новый CONNECT

    let connected = tokio::task::spawn_blocking(move || {
        ready_rx.recv_timeout(CONNECT_TIMEOUT).unwrap_or(false)
    })
    .await
    .unwrap_or(false);

    if !connected {
        let _ = session.send_reply(REP_HOST_UNREACHABLE).await;
        return;
    }

    if session.send_reply(REP_SUCCESS).await.is_err() {
        close_flag.store(true, Ordering::Relaxed);
        return;
    }

    let (mut socks_rd, mut socks_wr) = session.stream.into_split();
    let inbound_clone = Arc::clone(&inbound);
    let close_flag_rd = Arc::clone(&close_flag);
    let wake_tx_rd = wake_tx.clone();

    let read_half = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match socks_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    inbound_clone.lock().unwrap().push_back(buf[..n].to_vec());
                    let _ = wake_tx_rd.send(()); // разбудить стек: данные от клиента
                }
            }
        }
        close_flag_rd.store(true, Ordering::Relaxed);
    });

    let write_half = tokio::spawn(async move {
        while let Some(data) = outbound_rx.recv().await {
            if socks_wr.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = read_half => {}
        _ = write_half => {}
    }

    close_flag.store(true, Ordering::Relaxed);
}

fn smol_ip_to_std(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::Ipv4(v4) => IpAddr::V4(Ipv4Addr::from(v4.0)),
        IpAddress::Ipv6(v6) => IpAddr::V6(std::net::Ipv6Addr::from(v6.0)),
    }
}

/// Обработчик команды UDP ASSOCIATE по RFC 1928.
///
/// Схема работы:
/// 1. Открываем реальный OS UDP-сокет (`relay_socket`) на адресе прокси.
/// 2. Сообщаем клиенту адрес этого сокета в SOCKS5-ответе (RFC 1928 §6).
/// 3. Регистрируем smoltcp UDP-сокет с тем же портом для приёма ответов через VPN.
/// 4. Читаем SOCKS5 UDP Request (RFC 1928 §7) от клиента, извлекаем payload и цель.
/// 5. Пересылаем payload через smoltcp в VPN-туннель.
/// 6. Получаем UDP-ответы из VPN, оборачиваем в SOCKS5 UDP Response и отправляем клиенту.
async fn handle_udp_associate(
    mut session: Socks5Session,
    udp_cmd_tx: std::sync::mpsc::Sender<UdpStackCommand>,
    wake_tx: std::sync::mpsc::Sender<()>,
    proxy_ip: IpAddr,
) {
    // Слушаем на том же IP, что и прокси (эфемерный порт).
    let relay_socket = match tokio::net::UdpSocket::bind(SocketAddr::new(proxy_ip, 0)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!("Failed to bind UDP relay socket: {}", e);
            let _ = session.send_reply(REP_GENERAL_FAILURE).await;
            return;
        }
    };

    let relay_addr = match relay_socket.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to read UDP relay local addr: {}", e);
            let _ = session.send_reply(REP_GENERAL_FAILURE).await;
            return;
        }
    };

    let relay_port = relay_addr.port();
    let close_flag = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpRelayResponse>(256);

    if udp_cmd_tx
        .send(UdpStackCommand::CreateAssoc(NewUdpAssoc {
            relay_port,
            outbound_tx: reply_tx,
            close_flag: Arc::clone(&close_flag),
            ready_tx,
        }))
        .is_err()
    {
        let _ = session.send_reply(REP_GENERAL_FAILURE).await;
        return;
    }
    let _ = wake_tx.send(()); // разбудить стек: новая UDP-ассоциация

    // Ждём, пока smoltcp-поток зарегистрирует UDP-сокет.
    let ready = tokio::task::spawn_blocking(move || {
        ready_rx.recv_timeout(UDP_ASSOCIATE_TIMEOUT).unwrap_or(false)
    })
    .await
    .unwrap_or(false);

    if !ready {
        let _ = session.send_reply(REP_HOST_UNREACHABLE).await;
        return;
    }

    debug!("UDP ASSOCIATE: binding relay on {}, advertising port {}", relay_addr, relay_port);

    // RFC 1928 §6: отправляем клиенту адрес UDP relay-сокета.
    if session
        .send_reply_with_addr(REP_SUCCESS, relay_addr)
        .await
        .is_err()
    {
        close_flag.store(true, Ordering::Relaxed);
        return;
    }

    // IP клиента запомним при первом пакете (RFC 1928 разрешает 0.0.0.0:0 = «любой»).
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let relay_socket_read = Arc::clone(&relay_socket);
    let relay_socket_write = Arc::clone(&relay_socket);
    let close_flag_rd = Arc::clone(&close_flag);
    let client_addr_rd = Arc::clone(&client_addr);
    let udp_tx = udp_cmd_tx.clone();
    let wake_tx_rd = wake_tx.clone();

    // Задача «клиент → VPN».
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let mut dns_cache: HashMap<(String, u16), SocketAddr> = HashMap::new();
        loop {
            if close_flag_rd.load(Ordering::Relaxed) {
                break;
            }

            let (len, addr) = match relay_socket_read.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };

            if len == 0 {
                continue;
            }

            // Запоминаем адрес клиента при первом пакете; игнорируем пакеты от других.
            {
                let mut guard = client_addr_rd.lock().unwrap();
                match &*guard {
                    None => *guard = Some(addr),
                    Some(known) if known != &addr => continue,
                    Some(_) => {}
                }
            }

            let request = match parse_udp_request(&buf[..len]) {
                Ok(req) => req,
                Err(e) => {
                    warn!("SOCKS5 UDP parse error from {}: {}", addr, e);
                    continue;
                }
            };

            if request.frag != 0 {
                // RFC 1928 §7: фрагментация опциональна; не поддерживаем.
                warn!(
                    "SOCKS5 UDP fragments not supported (frag={})",
                    request.frag
                );
                continue;
            }

            let target_sock = match &request.target {
                Socks5UdpTarget::Ip(a) => *a,
                Socks5UdpTarget::Domain(host, port) => {
                    let key = (host.clone(), *port);
                    if let Some(a) = dns_cache.get(&key) {
                        *a
                    } else {
                        match resolve_via_tunnel(&udp_tx, &wake_tx_rd, host, *port, /*want_v6=*/ false).await {
                            Ok(a) => { dns_cache.insert(key, a); a }
                            Err(e) => { warn!("SOCKS5 UDP DNS error {host}:{port}: {e}"); continue; }
                        }
                    }
                }
            };

            if udp_tx
                .send(UdpStackCommand::SendPacket(UdpPacketCommand {
                    relay_port,
                    target: socket_addr_to_ip_endpoint(target_sock),
                    payload: request.data,
                }))
                .is_err()
            {
                break;
            }
            let _ = wake_tx_rd.send(()); // разбудить стек: исходящий UDP-пакет
        }

        close_flag_rd.store(true, Ordering::Relaxed);
    });

    // Задача «VPN → клиент».
    let close_flag_wr = Arc::clone(&close_flag);
    let client_addr_wr = Arc::clone(&client_addr);
    let write_task = tokio::spawn(async move {
        while let Some(response) = reply_rx.recv().await {
            if close_flag_wr.load(Ordering::Relaxed) {
                break;
            }

            let client = {
                let guard = client_addr_wr.lock().unwrap();
                *guard
            };
            let client = match client {
                Some(a) => a,
                None => continue,
            };

            let packet = match build_udp_response(
                &Socks5UdpTarget::Ip(socket_endpoint_to_socket_addr(response.remote)),
                &response.payload,
            ) {
                Ok(pkt) => pkt,
                Err(e) => {
                    warn!("SOCKS5 UDP response build error: {}", e);
                    continue;
                }
            };

            if relay_socket_write.send_to(&packet, client).await.is_err() {
                break;
            }
        }

        close_flag_wr.store(true, Ordering::Relaxed);
    });

    // Слушаем TCP-канал управления: закрытие клиентом → завершаем UDP ASSOCIATE (RFC 1928 §6).
    let mut ctrl_stream = session.stream;
    let mut ctrl_buf = [0u8; 1];
    let ctrl_task = tokio::spawn(async move {
        loop {
            match ctrl_stream.read(&mut ctrl_buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
        _ = ctrl_task => {}
    }

    close_flag.store(true, Ordering::Relaxed);
}
