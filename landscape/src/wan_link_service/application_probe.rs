//! Application probes never use the router's default DNS or proxy. Both the
//! DNS socket and HTTP socket are confined to the WAN under test.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use landscape_common::wan_link::{RuntimeWanHealthProbe, WanProbeTarget};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;

use super::probe::ProbeError;

pub(super) async fn probe(
    dev: &str,
    src: Ipv4Addr,
    method: &RuntimeWanHealthProbe,
    timeout: Duration,
    mark: u32,
) -> Result<Option<Duration>, ProbeError> {
    let target = match method {
        RuntimeWanHealthProbe::Dns { server, domain } => {
            WanProbeTarget::Dns { server: (*server).into(), domain: domain.clone() }
        }
        RuntimeWanHealthProbe::Http { url, dns_server } => {
            WanProbeTarget::Http { url: url.clone(), dns_server: (*dns_server).into() }
        }
        _ => return Err(ProbeError::Config("expected an application probe".into())),
    };
    probe_target(dev, src.into(), &target, timeout, mark).await
}

pub(super) async fn probe_target(
    dev: &str,
    src: IpAddr,
    method: &WanProbeTarget,
    timeout: Duration,
    mark: u32,
) -> Result<Option<Duration>, ProbeError> {
    let start = Instant::now();
    let round = async {
        match method {
            WanProbeTarget::Dns { server, domain } => {
                Ok(!resolve(dev, src, *server, domain, mark).await?.is_empty())
            }
            WanProbeTarget::Http { url, dns_server } => {
                let url =
                    reqwest::Url::parse(url).map_err(|e| ProbeError::Config(e.to_string()))?;
                let host =
                    url.host_str().ok_or_else(|| ProbeError::Config("missing HTTP host".into()))?;
                let addresses = match host.trim_matches(['[', ']']).parse::<IpAddr>() {
                    Ok(ip) => vec![ip],
                    Err(_) => resolve(dev, src, *dns_server, host, mark).await?,
                };
                if addresses.is_empty() {
                    return Ok(false);
                }
                let port = url
                    .port_or_known_default()
                    .ok_or_else(|| ProbeError::Config("unsupported HTTP scheme".into()))?;
                for address in addresses {
                    if address.is_ipv6() != src.is_ipv6() {
                        continue;
                    }
                    if http_request(dev, src, SocketAddr::new(address, port), &url, mark)
                        .await
                        .unwrap_or(false)
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            WanProbeTarget::Icmp { address } => {
                Ok(super::probe::ping_ip(dev, src, *address, timeout, mark).await?.is_some())
            }
        }
    };
    match tokio::time::timeout(timeout, round).await {
        Ok(Ok(true)) => Ok(Some(start.elapsed())),
        Ok(Ok(false)) | Err(_) => Ok(None),
        Ok(Err(error)) => Err(error),
    }
}

async fn resolve(
    dev: &str,
    src: IpAddr,
    server: IpAddr,
    domain: &str,
    mark: u32,
) -> Result<Vec<IpAddr>, ProbeError> {
    resolve_at(dev, src, SocketAddr::from((server, 53)), domain, mark).await
}

async fn resolve_at(
    dev: &str,
    src: IpAddr,
    server: SocketAddr,
    domain: &str,
    mark: u32,
) -> Result<Vec<IpAddr>, ProbeError> {
    let socket = Socket::new(
        if src.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    socket.bind_device(Some(dev.as_bytes()))?;
    if mark != 0 {
        socket.set_mark(mark)?;
    }
    socket.bind(&SockAddr::from(SocketAddr::from((src, 0))))?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket.into())?;
    let mut name = Name::from_ascii(domain).map_err(|e| ProbeError::Config(e.to_string()))?;
    // DNS wire names always include the root label. Normalize user input
    // before comparing the echoed question ("example.com" == "example.com.").
    name.set_fqdn(true);
    let mut request = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request
        .queries
        .push(Query::query(name, if src.is_ipv6() { RecordType::AAAA } else { RecordType::A }));
    let bytes = request.to_vec().map_err(|e| ProbeError::Config(e.to_string()))?;
    // Network errors are link evidence, not local checker failures.
    if socket.connect(server).await.is_err() || socket.send(&bytes).await.is_err() {
        return Ok(Vec::new());
    }
    let mut buf = [0u8; 4096];
    loop {
        let len = match socket.recv(&mut buf).await {
            Ok(len) => len,
            Err(_) => return Ok(Vec::new()),
        };
        let Ok(reply) = Message::from_vec(&buf[..len]) else { continue };
        if !matches_query(&request, &reply) {
            continue;
        }
        if reply.metadata.response_code != ResponseCode::NoError || reply.metadata.truncation {
            return Ok(Vec::new());
        }
        return Ok(reply
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(address) if src.is_ipv4() => Some(IpAddr::V4(address.0)),
                RData::AAAA(address) if src.is_ipv6() => Some(IpAddr::V6(address.0)),
                _ => None,
            })
            .collect());
    }
}

async fn http_request(
    dev: &str,
    src: IpAddr,
    peer: SocketAddr,
    url: &reqwest::Url,
    mark: u32,
) -> Result<bool, ProbeError> {
    let socket = if src.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    let sockref = socket2::SockRef::from(&socket);
    sockref.bind_device(Some(dev.as_bytes()))?;
    if mark != 0 {
        sockref.set_mark(mark)?;
    }
    socket.bind(SocketAddr::new(src, 0))?;
    let stream = match socket.connect(peer).await {
        Ok(stream) => stream,
        Err(_) => return Ok(false),
    };
    if url.scheme() == "https" {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| ProbeError::Config(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']).to_owned();
        let name = rustls_pki_types::ServerName::try_from(host)
            .map_err(|e| ProbeError::Config(e.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls));
        match connector.connect(name, stream).await {
            Ok(stream) => http_status(stream, url).await,
            Err(_) => Ok(false),
        }
    } else {
        http_status(stream, url).await
    }
}

async fn http_status<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    url: &reqwest::Url,
) -> Result<bool, ProbeError> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: Landscape-WAN-Probe\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return Ok(false);
    }
    let mut reader = tokio::io::BufReader::new(stream).take(4096);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() || !line.ends_with("\r\n") {
        return Ok(false);
    }
    let mut words = line.split_whitespace();
    let version = words.next();
    let code = words.next().and_then(|s| s.parse::<u16>().ok());
    Ok(matches!(version, Some("HTTP/1.0" | "HTTP/1.1"))
        && code.is_some_and(|code| (200..400).contains(&code)))
}

fn matches_query(request: &Message, reply: &Message) -> bool {
    reply.metadata.id == request.metadata.id
        && reply.metadata.message_type == MessageType::Response
        && reply.metadata.op_code == OpCode::Query
        && reply.queries == request.queries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_unrelated_dns_replies() {
        let mut request = Message::new(7, MessageType::Query, OpCode::Query);
        request
            .queries
            .push(Query::query(Name::from_ascii("www.baidu.com.").unwrap(), RecordType::A));
        let mut reply = Message::response(7, OpCode::Query);
        reply.queries = request.queries.clone();
        assert!(matches_query(&request, &reply));
        reply.metadata.id = 8;
        assert!(!matches_query(&request, &reply));
        reply.metadata.id = 7;
        reply.queries.clear();
        assert!(!matches_query(&request, &reply));
        assert!(!matches_query(&request, &request));
    }
    #[tokio::test]
    async fn dns_probe_requires_a_matching_successful_answer() {
        use hickory_proto::rr::{Record, rdata::A};
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0; 4096];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();
            let mut reply = Message::response(request.metadata.id, OpCode::Query);
            reply.queries = request.queries.clone();
            reply.answers.push(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
            ));
            server.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
        });
        let addresses = tokio::time::timeout(
            Duration::from_secs(2),
            resolve_at("lo", Ipv4Addr::LOCALHOST.into(), addr, "test.example", 0),
        )
        .await
        .unwrap()
        .unwrap();
        task.await.unwrap();
        assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
    }

    #[tokio::test]
    async fn http_probe_checks_status_and_never_follows_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (status, healthy) in [("200 OK", true), ("302 Found", true), ("503 Unavailable", false)]
        {
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0; 4096];
                socket.read(&mut buf).await.unwrap();
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nLocation: http://unreachable.invalid/\r\nConnection: close\r\n\r\n"
                );
                socket.write_all(reply.as_bytes()).await.unwrap();
            });
            let method = RuntimeWanHealthProbe::Http {
                url: format!("http://{addr}"),
                dns_server: Ipv4Addr::new(192, 0, 2, 1),
            };
            let result =
                probe("lo", Ipv4Addr::LOCALHOST, &method, Duration::from_secs(2), 0).await.unwrap();
            assert_eq!(result.is_some(), healthy);
            task.await.unwrap();
        }
    }
}
