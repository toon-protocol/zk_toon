//! The evidence copy and its listener (ADR 0014): what a push does to the copy, over HTTP and
//! without it.
mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::{keypair, vault_key};
use mina_signer::{CompressedPubKey, Keypair, NetworkId};
use zk_evidence::{extend_running_hash, frame, scan_records, Checkpoint, Close, FileCopy, Push, Record};
use zk_note::Field;
use zk_toon_challenger_mina::{Listener, Receiver, Reply};

const NETWORK: NetworkId = NetworkId::TESTNET;

fn state_key() -> Keypair {
    keypair(4242)
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("zk-receiver-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn open(copy: &Path) -> Result<Receiver, String> {
    Receiver::open(copy, vault_key(), &state_key().public.into_compressed())
}

fn close(n: u64) -> Vec<u8> {
    frame(&Record::Close(Close { nullifier: Field::from(n), allowance_id: vec![n as u8], charge: n }).encode().unwrap())
}

/// A push of `bytes` onto `copy`, signed by `signer` for `vault`.
fn push(copy: &FileCopy, bytes: &[u8], vault: &CompressedPubKey, signer: &Keypair) -> Push {
    let scan = scan_records(bytes, 0).unwrap();
    let checkpoint = Checkpoint {
        vault: vault.clone(),
        length: copy.length + bytes.len() as u64,
        running_hash: scan.records.iter().fold(copy.running_hash, |h, r| extend_running_hash(&h, r.payload)),
    };
    Push { offset: copy.length, bytes: bytes.to_vec(), signature: checkpoint.sign(NETWORK, signer) }
}

fn good(copy: &FileCopy, n: u64) -> Push {
    push(copy, &close(n), &vault_key(), &state_key())
}

#[test]
fn a_new_copy_holds_the_header_and_grows_by_whole_records() {
    let d = dir("grow");
    let path = d.join("copy");
    let mut r = open(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), zk_evidence::write_header());
    let mut copy = FileCopy::empty();
    for n in 1..=3 {
        let p = good(&copy, n);
        let Reply::Accepted { length } = r.receive(&p.encode()) else { panic!() };
        let file = std::fs::read(&path).unwrap();
        assert_eq!(length, file.len() as u64);
        copy = FileCopy::of_file(&file).unwrap();
    }
    assert_eq!(copy.length, std::fs::read(&path).unwrap().len() as u64);
}

#[test]
fn forged_pushes_leave_the_copy_unchanged() {
    let d = dir("forged");
    let path = d.join("copy");
    let mut r = open(&path).unwrap();
    let mut copy = FileCopy::empty();
    assert!(matches!(r.receive(&good(&copy, 1).encode()), Reply::Accepted { .. }));
    copy = FileCopy::of_file(&std::fs::read(&path).unwrap()).unwrap();
    let before = (std::fs::read(&path).unwrap(), std::fs::read(d.join("copy.sig")).unwrap());

    let other_vault = CompressedPubKey { x: vault_key().x + Field::from(1u64), is_odd: vault_key().is_odd };
    let mut torn = close(2);
    torn.pop();
    let mut flipped = good(&copy, 2);
    flipped.bytes[6] ^= 1;
    let refused = [
        push(&copy, &close(2), &vault_key(), &keypair(1)),
        push(&copy, &close(2), &other_vault, &state_key()),
        push(&copy, &torn, &vault_key(), &state_key()),
        flipped,
        Push { offset: copy.length, bytes: Vec::new(), signature: good(&copy, 2).signature },
    ];
    for p in refused {
        assert!(matches!(r.receive(&p.encode()), Reply::Refused(_)), "{p:?}");
        assert_eq!((std::fs::read(&path).unwrap(), std::fs::read(d.join("copy.sig")).unwrap()), before);
    }
    assert!(matches!(r.receive(b"not a push"), Reply::Refused(_)));

    let mut stale = good(&copy, 2);
    stale.offset += 1;
    assert_eq!(r.receive(&stale.encode()), Reply::Behind { length: copy.length });
    let mut early = good(&copy, 2);
    early.offset = 0;
    assert_eq!(r.receive(&early.encode()), Reply::Behind { length: copy.length });
    assert_eq!(std::fs::read(&path).unwrap(), before.0);
}

#[test]
fn a_push_sent_twice_is_appended_once() {
    let d = dir("twice");
    let path = d.join("copy");
    let mut r = open(&path).unwrap();
    let p = good(&FileCopy::empty(), 1);
    let Reply::Accepted { length } = r.receive(&p.encode()) else { panic!() };
    let once = std::fs::read(&path).unwrap();
    assert_eq!(r.receive(&p.encode()), Reply::Behind { length });
    assert_eq!(std::fs::read(&path).unwrap(), once);
}

#[test]
fn a_restart_keeps_the_copy_and_the_signature_and_takes_the_next_push() {
    let d = dir("restart");
    let path = d.join("copy");
    let first = good(&FileCopy::empty(), 1);
    {
        let mut r = open(&path).unwrap();
        assert_eq!(r.signature(), None);
        r.receive(&first.encode());
        assert_eq!(r.signature(), Some(first.signature.clone()));
    }
    let mut r = open(&path).unwrap();
    assert_eq!(r.signature(), Some(first.signature.clone()));
    let copy = FileCopy::of_file(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(r.length(), copy.length);
    assert!(matches!(r.receive(&good(&copy, 2).encode()), Reply::Accepted { .. }));
}

#[test]
fn a_copy_that_fails_its_check_is_refused_at_start() {
    let d = dir("check");
    let path = d.join("copy");
    let first = good(&FileCopy::empty(), 1);
    open(&path).unwrap().receive(&first.encode());
    let intact = std::fs::read(&path).unwrap();

    // A flipped byte in a record.
    let mut bad = intact.clone();
    bad[14] ^= 1;
    std::fs::write(&path, &bad).unwrap();
    assert!(open(&path).unwrap_err().contains("evidence copy"));

    // A torn tail.
    let mut torn = intact.clone();
    torn.extend_from_slice(&[1, 2, 3]);
    std::fs::write(&path, &torn).unwrap();
    assert!(open(&path).is_err());

    // Records the saved signature doesn't cover.
    let mut longer = intact.clone();
    longer.extend(close(2));
    std::fs::write(&path, &longer).unwrap();
    assert!(open(&path).unwrap_err().contains("saved signature"));

    // No saved signature for a copy with records.
    std::fs::write(&path, &intact).unwrap();
    std::fs::remove_file(d.join("copy.sig")).unwrap();
    assert!(open(&path).unwrap_err().contains("saved signature"));

    // A signature from another key.
    std::fs::write(&path, &intact).unwrap();
    let forged = Push { offset: intact.len() as u64, bytes: Vec::new(), signature: push(&FileCopy::empty(), &close(1), &vault_key(), &keypair(1)).signature };
    std::fs::write(d.join("copy.sig"), forged.encode()).unwrap();
    assert!(open(&path).unwrap_err().contains("saved signature"));
}

fn post(addr: std::net::SocketAddr, body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "POST /evidence HTTP/1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    s.write_all(body).unwrap();
    let mut text = String::new();
    s.read_to_string(&mut text).unwrap();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, text.split("\r\n\r\n").nth(1).unwrap().to_string())
}

#[test]
fn the_listener_replies_with_the_length_and_logs_a_line_for_a_refusal() {
    let d = dir("http");
    let path = d.join("copy");
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let listener =
        Listener::start("127.0.0.1:0".parse().unwrap(), open(&path).unwrap(), move |l| sink.lock().unwrap().push(l.into()))
            .unwrap();
    let addr = listener.local_addr();

    let p = good(&FileCopy::empty(), 1);
    let (status, body) = post(addr, &p.encode());
    let length = std::fs::metadata(&path).unwrap().len();
    assert_eq!((status, body), (200, format!(r#"{{"length":{length}}}"#)));
    assert_eq!(post(addr, &p.encode()), (200, format!(r#"{{"length":{length}}}"#)));

    let forged = push(&FileCopy::of_file(&std::fs::read(&path).unwrap()).unwrap(), &close(2), &vault_key(), &keypair(1));
    let (status, body) = post(addr, &forged.encode());
    assert_eq!(status, 400);
    assert!(body.contains("BadSignature"), "{body}");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
    let refusals: Vec<_> = lines.lock().unwrap().iter().filter(|l| l.starts_with("push-refused")).cloned().collect();
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].contains("BadSignature"));
}

#[test]
fn each_forged_push_gets_its_reply_over_http() {
    let d = dir("http-forged");
    let path = d.join("copy");
    let listener = Listener::start("127.0.0.1:0".parse().unwrap(), open(&path).unwrap(), |_| {}).unwrap();
    let addr = listener.local_addr();
    assert_eq!(post(addr, &good(&FileCopy::empty(), 1).encode()).0, 200);
    let before = (std::fs::read(&path).unwrap(), std::fs::read(d.join("copy.sig")).unwrap());
    let copy = FileCopy::of_file(&before.0).unwrap();

    let other_vault = CompressedPubKey { x: vault_key().x + Field::from(1u64), is_odd: vault_key().is_odd };
    let mut torn = close(2);
    torn.pop();
    for p in [
        push(&copy, &close(2), &vault_key(), &keypair(1)),
        push(&copy, &close(2), &other_vault, &state_key()),
        push(&copy, &torn, &vault_key(), &state_key()),
    ] {
        assert_eq!(post(addr, &p.encode()).0, 400, "{p:?}");
        assert_eq!((std::fs::read(&path).unwrap(), std::fs::read(d.join("copy.sig")).unwrap()), before);
    }
    let mut stale = good(&copy, 2);
    stale.offset = 0;
    assert_eq!(post(addr, &stale.encode()), (200, format!(r#"{{"length":{}}}"#, copy.length)));
    assert_eq!((std::fs::read(&path).unwrap(), std::fs::read(d.join("copy.sig")).unwrap()), before);
}

#[test]
fn a_push_without_a_byte_count_is_refused() {
    let d = dir("http-length");
    let listener = Listener::start("127.0.0.1:0".parse().unwrap(), open(&d.join("copy")).unwrap(), |_| {}).unwrap();
    for headers in ["Content-Length: lots", "Transfer-Encoding: chunked"] {
        let mut s = TcpStream::connect(listener.local_addr()).unwrap();
        write!(s, "POST /evidence HTTP/1.1\r\n{headers}\r\nConnection: close\r\n\r\n").unwrap();
        let mut text = String::new();
        s.read_to_string(&mut text).unwrap();
        assert!(text.starts_with("HTTP/1.1 411"), "{text}");
    }
    assert_eq!(std::fs::read(d.join("copy")).unwrap(), zk_evidence::write_header());
}
