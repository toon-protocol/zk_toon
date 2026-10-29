//! Reaching Mina GraphQL: directly, or when opted in only through a SOCKS5 proxy, with no direct
//! fallback. And the builder's relay, which sends its GraphQL the same way.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use zk_toon_challenger_mina::{Endpoint, Endpoints, Graphql, HttpGraphql, Relay};

/// A GraphQL server that answers every POST with `{"data": {"path": <path>, "echo": <body>}}`, and
/// counts its connections.
struct Server {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

fn server() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || answer(stream));
        }
    });
    Server { addr, connections }
}

fn answer(stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut out = stream;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
        let mut length = 0;
        loop {
            let mut h = String::new();
            reader.read_line(&mut h).unwrap();
            let h = h.trim_end().to_string();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    length = v.trim().parse().unwrap();
                }
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let echo: Value = serde_json::from_slice(&body).unwrap();
        let reply = json!({ "data": { "path": path, "echo": echo } }).to_string();
        let _ = write!(out, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}", reply.len());
    }
}

/// A SOCKS5 proxy (no authentication, CONNECT only) that records each destination it is asked for
/// and connects every one of them to `to`.
fn socks(to: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = asked.clone();
    thread::spawn(move || {
        for mut client in listener.incoming().flatten() {
            let log = log.clone();
            thread::spawn(move || {
                let mut b = [0u8; 2];
                client.read_exact(&mut b).unwrap();
                let mut methods = vec![0u8; b[1] as usize];
                client.read_exact(&mut methods).unwrap();
                client.write_all(&[5, 0]).unwrap();
                let mut head = [0u8; 4];
                client.read_exact(&mut head).unwrap();
                let destination = match head[3] {
                    3 => {
                        let mut n = [0u8; 1];
                        client.read_exact(&mut n).unwrap();
                        let mut name = vec![0u8; n[0] as usize];
                        client.read_exact(&mut name).unwrap();
                        format!("domain {}", String::from_utf8(name).unwrap())
                    }
                    1 => {
                        let mut ip = [0u8; 4];
                        client.read_exact(&mut ip).unwrap();
                        format!("ip {ip:?}")
                    }
                    t => panic!("address type {t}"),
                };
                let mut port = [0u8; 2];
                client.read_exact(&mut port).unwrap();
                log.lock().unwrap().push(format!("{destination}:{}", u16::from_be_bytes(port)));
                let upstream = TcpStream::connect(to).unwrap();
                client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                let (mut c2, mut u2) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
                thread::spawn(move || {
                    let _ = std::io::copy(&mut u2, &mut c2);
                });
                let mut upstream = upstream;
                let _ = std::io::copy(&mut client, &mut upstream);
            });
        }
    });
    (addr, asked)
}

fn endpoints(host: &str, socks5: Option<String>) -> Endpoints {
    Endpoints {
        mina: format!("http://{host}/graphql"),
        archive: format!("http://{host}/archive"),
        socks5,
        timeout: Duration::from_secs(5),
    }
}

fn request() -> Value {
    json!({ "operationName": "VaultState", "query": "query VaultState { x }", "variables": {} })
}

#[test]
fn graphql_is_posted_to_each_endpoint() {
    let s = server();
    let g = HttpGraphql::new(endpoints(&s.addr.to_string(), None)).unwrap();
    assert_eq!(g.post(Endpoint::Mina, &request()).unwrap()["data"]["path"], "/graphql");
    let archive = g.post(Endpoint::Archive, &request()).unwrap();
    assert_eq!(archive["data"]["path"], "/archive");
    assert_eq!(archive["data"]["echo"], request());
}

#[test]
fn when_opted_in_graphql_goes_through_the_socks_proxy_which_resolves_the_host() {
    let s = server();
    let (proxy, asked) = socks(s.addr);
    // `.invalid` never resolves locally: only the proxy can reach it.
    let g = HttpGraphql::new(endpoints("mina-graphql.invalid:8080", Some(proxy.to_string()))).unwrap();
    assert_eq!(g.post(Endpoint::Mina, &request()).unwrap()["data"]["path"], "/graphql");
    assert_eq!(asked.lock().unwrap().as_slice(), ["domain mina-graphql.invalid:8080"]);
}

#[test]
fn when_the_socks_proxy_is_down_nothing_is_reached_directly() {
    let s = server();
    // A port nothing listens on.
    let down = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let g = HttpGraphql::new(endpoints(&s.addr.to_string(), Some(down.to_string()))).unwrap();
    assert!(g.post(Endpoint::Mina, &request()).is_err());
    assert!(g.post(Endpoint::Archive, &request()).is_err());
    assert_eq!(s.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn the_builders_relay_sends_its_graphql_through_the_adapters() {
    let s = server();
    let (proxy, asked) = socks(s.addr);
    let g = HttpGraphql::new(endpoints("archive.invalid", Some(proxy.to_string()))).unwrap();
    let relay = Relay::start(Arc::new(g)).unwrap();

    let direct = HttpGraphql::new(Endpoints {
        mina: relay.mina_url(),
        archive: relay.archive_url(),
        socks5: None,
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    assert_eq!(direct.post(Endpoint::Archive, &request()).unwrap()["data"]["path"], "/archive");
    assert_eq!(direct.post(Endpoint::Mina, &request()).unwrap()["data"]["path"], "/graphql");
    assert!(asked.lock().unwrap().iter().all(|a| a == "domain archive.invalid:80"));
    assert!(!asked.lock().unwrap().is_empty());
}
