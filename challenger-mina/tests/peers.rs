//! Reading an evidence copy from a peer and catching up from peers (ADR 0014): who may read, and what a
//! peer that is down, lying or behind does to a copy.
mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{keypair, vault_key};
use mina_signer::{Keypair, NetworkId};
use zk_evidence::{extend_running_hash, frame, scan_records, Checkpoint, Close, FileCopy, Push, Record};
use zk_note::Field;
use zk_toon_challenger_mina::{Listener, Peers, Receiver};

const NETWORK: NetworkId = NetworkId::TESTNET;
const TOKEN: &str = "peer-token";

fn state_key() -> Keypair {
    keypair(4242)
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("zk-peers-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn open(path: &std::path::Path) -> Receiver {
    Receiver::open(path, vault_key(), &state_key().public.into_compressed()).unwrap()
}

fn close(n: u64) -> Vec<u8> {
    frame(&Record::Close(Close { nullifier: Field::from(n), allowance_id: vec![n as u8], charge: n }).encode().unwrap())
}

fn push(copy: &FileCopy, bytes: &[u8], signer: &Keypair) -> Push {
    let scan = scan_records(bytes, 0).unwrap();
    let checkpoint = Checkpoint {
        vault: vault_key(),
        length: copy.length + bytes.len() as u64,
        running_hash: scan.records.iter().fold(copy.running_hash, |h, r| extend_running_hash(&h, r.payload)),
    };
    Push { offset: copy.length, bytes: bytes.to_vec(), signature: checkpoint.sign(NETWORK, signer) }
}

/// A peer holding records 1..=`n`, serving with `token`.
fn peer(name: &str, n: u64, token: Option<&str>) -> (Listener, PathBuf, Arc<Mutex<Receiver>>) {
    let path = dir(name).join("copy");
    let mut receiver = open(&path);
    let mut copy = FileCopy::empty();
    for i in 1..=n {
        let p = push(&copy, &close(i), &state_key());
        receiver.receive(&p.encode());
        copy = FileCopy::of_file(&std::fs::read(&path).unwrap()).unwrap();
    }
    let receiver = Arc::new(Mutex::new(receiver));
    let listener = Listener::start_shared("127.0.0.1:0".parse().unwrap(), receiver.clone(), token.map(Into::into), |_| {}).unwrap();
    (listener, path, receiver)
}

fn get(addr: SocketAddr, offset: u64, auth: Option<&str>) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    let auth = auth.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    write!(s, "GET /?offset={offset} HTTP/1.1\r\n{auth}Connection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let status = String::from_utf8_lossy(&raw[..split]).split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, raw[split..].to_vec())
}

fn url(addr: SocketAddr) -> String {
    format!("http://{addr}/")
}

fn peers(urls: Vec<String>, token: &str, receiver: Arc<Mutex<Receiver>>) -> Peers {
    Peers::new(urls, token.into(), None, Duration::from_secs(5), receiver).unwrap()
}

/// A peer that answers every request with `status` and `body`.
fn stub(status: &str, body: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status.to_string();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = s.write_all(&body);
        }
    });
    addr
}

fn empty_copy(name: &str) -> (PathBuf, Arc<Mutex<Receiver>>) {
    let path = dir(name).join("copy");
    (path.clone(), Arc::new(Mutex::new(open(&path))))
}

#[test]
fn a_read_without_the_token_or_with_a_wrong_one_serves_nothing() {
    let (listener, _, _) = peer("auth", 2, Some(TOKEN));
    let addr = listener.local_addr();
    for auth in [None, Some("wrong"), Some("peer-toke"), Some("peer-token-and-more")] {
        let (status, body) = get(addr, FileCopy::empty().length, auth);
        assert_eq!(status, 401, "{auth:?}");
        assert!(!body.windows(4).any(|w| w == &close(1)[..4]) && body.len() < 100, "{auth:?}: {body:?}");
    }
    assert_eq!(get(addr, FileCopy::empty().length, Some(TOKEN)).0, 200);
}

#[test]
fn reads_are_refused_when_no_token_is_set() {
    let (listener, _, _) = peer("no-token", 1, None);
    for auth in [None, Some(""), Some("anything")] {
        let (status, body) = get(listener.local_addr(), FileCopy::empty().length, auth);
        assert_eq!(status, 403, "{auth:?}");
        assert!(body.len() < 100);
    }
}

#[test]
fn a_read_gives_the_bytes_from_the_offset_and_the_latest_signature() {
    let (listener, path, _) = peer("serve", 3, Some(TOKEN));
    let file = std::fs::read(&path).unwrap();
    let from = FileCopy::empty().length + close(1).len() as u64;
    let (status, body) = get(listener.local_addr(), from, Some(TOKEN));
    assert_eq!(status, 200);
    let served = Push::decode(&body).unwrap();
    assert_eq!((served.offset, &served.bytes[..]), (from, &file[from as usize..]));
    // It checks as a push against a copy of the first record.
    let copy = FileCopy::of_file(&file[..from as usize]).unwrap();
    let state = state_key().public;
    assert!(zk_evidence::check_push(NETWORK, &state, &vault_key(), &copy, &served).is_ok());
    // At the copy's end there is nothing to give; past it there is nothing to serve.
    assert_eq!(get(listener.local_addr(), file.len() as u64, Some(TOKEN)).0, 204);
    assert_eq!(get(listener.local_addr(), file.len() as u64 + 1, Some(TOKEN)).0, 416);
}

#[test]
fn a_challenger_catches_up_from_a_peer_and_skips_one_that_is_down() {
    let (a, a_path, _) = peer("catch-a", 3, Some(TOKEN));
    let (_path, mine) = empty_copy("catch-mine");
    let down = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let lines = peers(vec![url(down), url(a.local_addr())], TOKEN, mine.clone()).catch_up();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].starts_with(&format!("peer {}", url(down))) && lines[0].contains("unreachable"), "{lines:?}");
    assert!(lines[1].contains("caught up"), "{lines:?}");
    assert_eq!(mine.lock().unwrap().length(), std::fs::metadata(&a_path).unwrap().len());
    // Caught up: asking again changes nothing and says nothing.
    assert!(peers(vec![url(a.local_addr())], TOKEN, mine).catch_up().is_empty());
}

#[test]
fn a_peer_ahead_by_a_record_gives_the_close_it_lacked() {
    let (behind, _, _) = peer("close-a", 1, Some(TOKEN));
    let (ahead, ahead_path, _) = peer("close-b", 2, Some(TOKEN));
    let mine = Arc::new(Mutex::new(open(&dir("close-mine").join("copy"))));
    // The first peer gives record 1, then the second gives record 2 in the same pass.
    let lines = peers(vec![url(behind.local_addr()), url(ahead.local_addr())], TOKEN, mine.clone()).catch_up();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(mine.lock().unwrap().length(), std::fs::metadata(&ahead_path).unwrap().len());
}

#[test]
fn a_peer_that_refuses_us_or_lies_changes_nothing() {
    let (good_peer, _, _) = peer("lies-good", 1, Some(TOKEN));
    let (path, mine) = empty_copy("lies-mine");
    let copy = FileCopy::empty();
    let bad_signature = push(&copy, &close(1), &keypair(1)).encode();
    let not_extending = Push { offset: 0, ..push(&copy, &close(1), &state_key()) }.encode();
    let mut torn = close(1);
    torn.pop();
    let torn_push = push(&copy, &close(1), &state_key());
    let torn = Push { bytes: torn, ..torn_push }.encode();
    let before = std::fs::read(&path).unwrap();
    for (name, addr) in [
        ("bad signature", stub("200 OK", bad_signature)),
        ("not extending", stub("200 OK", not_extending)),
        ("torn", stub("200 OK", torn)),
        ("garbage", stub("200 OK", b"not a push".to_vec())),
        ("refusing", stub("401 Unauthorized", b"{}".to_vec())),
    ] {
        let lines = peers(vec![url(addr)], TOKEN, mine.clone()).catch_up();
        assert_eq!(lines.len(), 1, "{name}: {lines:?}");
        assert!(lines[0].starts_with(&format!("peer {}:", url(addr))) && !lines[0].contains('\n'), "{name}: {lines:?}");
        assert_eq!(std::fs::read(&path).unwrap(), before, "{name}");
    }
    // The pass goes on to the next peer.
    let liar = stub("200 OK", b"junk".to_vec());
    let lines = peers(vec![url(liar), url(good_peer.local_addr())], TOKEN, mine.clone()).catch_up();
    assert_eq!(lines.len(), 2);
    assert!(mine.lock().unwrap().length() > before.len() as u64);
}

#[test]
fn the_token_is_what_a_peer_is_asked_with() {
    let (a, _, _) = peer("token", 1, Some(TOKEN));
    let (_path, mine) = empty_copy("token-mine");
    let lines = peers(vec![url(a.local_addr())], "wrong", mine.clone()).catch_up();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("401"), "{lines:?}");
    assert!(!lines[0].contains("wrong"));
    assert_eq!(mine.lock().unwrap().length(), FileCopy::empty().length);
}
