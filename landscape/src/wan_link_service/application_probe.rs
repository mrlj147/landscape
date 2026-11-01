//! Application probes never use the router's default DNS or proxy. Both the
//! DNS socket and HTTP socket are confined to the WAN under test.
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use landscape_common::wan_link::RuntimeWanHealthProbe;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;

use super::probe::ProbeError;

pub(super) async fn probe(
    dev: &str,
    src: Ipv4Addr,
    method: &RuntimeWanHealthProbe,
    timeout: Duration,
) -> Result<Option<Duration>, ProbeError> {
    let start = Instant::now();
    let round = async {
        match method {
            RuntimeWanHealthProbe::Dns { server, domain } => {
                Ok(!resolve(dev, src, *server, domain).await?.is_empty())
            }
            RuntimeWanHealthProbe::Http { url, dns_server } => {
                let url =
                    reqwest::Url::parse(url).map_err(|e| ProbeError::Config(e.to_string()))?;
                let host =
                    url.host_str().ok_or_else(|| ProbeError::Config("missing HTTP host".into()))?;
                let addresses = match host.parse::<Ipv4Addr>() {
                    Ok(ip) => vec![ip],
                    Err(_) => resolve(dev, src, *dns_server, host).await?,
                };
                if addresses.is_empty() {
                    return Ok(false);
                }
                let addresses: Vec<SocketAddr> =
                    addresses.into_iter().map(|ip| SocketAddr::from((ip, 0))).collect();
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .interface(dev)
                    .local_address(std::net::IpAddr::V4(src))
                    .resolve_to_addrs(host, &addresses)
                    // Following redirects could introduce a new hostname resolved
                    // by the system. A 3xx itself is an answered HTTP request.
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(timeout)
                    .build()
                    .map_err(|e| ProbeError::Config(e.to_string()))?;
                Ok(client.get(url).send().await.is_ok_and(|response| {
                    response.status().is_success() || response.status().is_redirection()
                }))
            }
            RuntimeWanHealthProbe::Icmp { .. } => unreachable!("ICMP uses the injected ping probe"),
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
    src: Ipv4Addr,
    server: Ipv4Addr,
    domain: &str,
) -> Result<Vec<Ipv4Addr>, ProbeError> {
    resolve_at(dev, src, SocketAddr::from((server, 53)), domain).await
}

async fn resolve_at(
    dev: &str,
    src: Ipv4Addr,
    server: SocketAddr,
    domain: &str,
) -> Result<Vec<Ipv4Addr>, ProbeError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind_device(Some(dev.as_bytes()))?;
    socket.bind(&SockAddr::from(SocketAddr::from((src, 0))))?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket.into())?;
    let mut name = Name::from_ascii(domain).map_err(|e| ProbeError::Config(e.to_string()))?;
    // DNS wire names always include the root label. Normalize user input
    // before comparing the echoed question ("example.com" == "example.com.").
    name.set_fqdn(true);
    let mut request = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.queries.push(Query::query(name, RecordType::A));
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
                RData::A(address) => Some(address.0),
                _ => None,
            })
            .collect());
    }
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
            resolve_at("lo", Ipv4Addr::LOCALHOST, addr, "test.example"),
        )
        .await
        .unwrap()
        .unwrap();
        task.await.unwrap();
        assert_eq!(addresses, [Ipv4Addr::new(192, 0, 2, 10)]);
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
                probe("lo", Ipv4Addr::LOCALHOST, &method, Duration::from_secs(2)).await.unwrap();
            assert_eq!(result.is_some(), healthy);
            task.await.unwrap();
        }
    }
}
