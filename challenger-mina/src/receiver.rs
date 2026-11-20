//! The challenger's evidence copy and the listener that grows it (ADR 0014). The zk edge `POST`s an
//! encoded [`Push`]; the copy is a prefix of the zk edge's evidence file, and `FileEvidence` reads
//! it as it reads the zk edge's own file. The latest accepted signature is kept next to the copy.
//! The framing and signature checks are `zk_evidence::check_push`'s. The listener also serves the copy
//! to peers on a `GET`, behind a bearer token, and [`Peers`] catches the copy up from them.
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mina_signer::{CompressedPubKey, NetworkId, PubKey, Signature};
use zk_evidence::{write_header, Checkpoint, FileCopy, Push, PushRefusal};

/// The state key signs checkpoints on the network the state messages use.
const NETWORK: NetworkId = NetworkId::TESTNET;
/// The most one push may carry.
const MAX_PUSH: usize = 16 << 20;
/// The longest request or header line read.
const MAX_LINE: u64 = 8 << 10;
/// How long a connection may sit idle before it is dropped.
const IDLE: Duration = Duration::from_secs(30);

/// How the receiver answered a push.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// The bytes were appended. The copy is now this long.
    Accepted { length: u64 },
    /// The offset isn't the copy's length: nothing was appended, and the zk edge resends from here.
    Behind { length: u64 },
    /// Refused with a client error, and why. Nothing was appended.
    Refused(String),
    /// The copy couldn't be written.
    Failed(String),
}

/// The evidence copy, grown one push at a time.
#[derive(Debug)]
pub struct Receiver {
    path: PathBuf,
    signature_path: PathBuf,
    vault: CompressedPubKey,
    state_key: PubKey,
    copy: FileCopy,
}

fn signature_path(copy: &Path) -> PathBuf {
    let mut name = copy.as_os_str().to_owned();
    name.push(".sig");
    name.into()
}

fn failed(what: &'static str) -> impl Fn(std::io::Error) -> String {
    move |e| format!("{what}: {e}")
}

fn sync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()
}

impl Receiver {
    /// Opens the copy at `path`, creating it with the evidence file's header if it is missing. A copy
    /// that exists must scan intact and its running hash must match the saved signature.
    pub fn open(path: &Path, vault: CompressedPubKey, state_key: &CompressedPubKey) -> Result<Receiver, String> {
        let signature_path = signature_path(path);
        let state_key = PubKey::from_address(&state_key.into_address()).map_err(|e| format!("state key: {e}"))?;
        let made = !path.exists();
        if made {
            if signature_path.exists() {
                return Err(format!("evidence copy {}: missing, but {} exists", path.display(), signature_path.display()));
            }
            let mut file = OpenOptions::new().write(true).create_new(true).open(path).map_err(|e| format!("evidence copy: {e}"))?;
            file.write_all(&write_header()).and_then(|_| file.sync_all()).and_then(|_| sync_dir(path)).map_err(|e| format!("evidence copy: {e}"))?;
        }
        let bytes = fs::read(path).map_err(|e| format!("evidence copy {}: {e}", path.display()))?;
        let copy = FileCopy::of_file(&bytes).map_err(|e| format!("evidence copy {}: {e:?}", path.display()))?;
        let receiver = Receiver { path: path.into(), signature_path, vault, state_key, copy };
        if copy != FileCopy::empty() || receiver.signature_path.exists() {
            receiver.check_saved_signature()?;
        }
        Ok(receiver)
    }

    fn check_saved_signature(&self) -> Result<(), String> {
        let at = self.signature_path.display();
        let saved = fs::read(&self.signature_path).map_err(|e| format!("saved signature {at}: {e}"))?;
        let saved = Push::decode(&saved).map_err(|e| format!("saved signature {at}: {e:?}"))?;
        if saved.offset != self.copy.length {
            return Err(format!("saved signature {at} is for a copy of {} bytes, the copy holds {}", saved.offset, self.copy.length));
        }
        let checkpoint = Checkpoint { vault: self.vault.clone(), length: self.copy.length, running_hash: self.copy.running_hash };
        if !checkpoint.verify(NETWORK, &self.state_key, &saved.signature) {
            return Err(format!("saved signature {at} does not match the copy's records"));
        }
        Ok(())
    }

    /// The copy's length in bytes.
    pub fn length(&self) -> u64 {
        self.copy.length
    }

    /// Checks `body`, an encoded push, against the copy and appends it if it holds.
    pub fn receive(&mut self, body: &[u8]) -> Reply {
        let push = match Push::decode(body) {
            Ok(p) => p,
            Err(e) => return Reply::Refused(format!("not a push: {e:?}")),
        };
        match zk_evidence::check_push(NETWORK, &self.state_key, &self.vault, &self.copy, &push) {
            Ok(extended) => match self.append(&push, extended) {
                Ok(()) => Reply::Accepted { length: self.copy.length },
                Err(e) => Reply::Failed(e),
            },
            Err(PushRefusal::WrongOffset { copy_length, .. }) => Reply::Behind { length: copy_length },
            Err(PushRefusal::BadCopy(e)) => Reply::Failed(format!("copy: {e:?}")),
            Err(e) => Reply::Refused(format!("{e:?}")),
        }
    }

    /// Appends the push and saves its signature. Until the signature is in place, a failure cuts the
    /// copy back to its old length, so it only ever grows by whole records its signature covers.
    fn append(&mut self, push: &Push, extended: FileCopy) -> Result<(), String> {
        let mut file = OpenOptions::new().write(true).open(&self.path).map_err(failed("copy"))?;
        if let Err(e) = self.write_push(&mut file, push, extended) {
            return Err(match file.set_len(self.copy.length).and_then(|_| file.sync_all()) {
                Ok(()) => e,
                Err(cut) => format!("{e}; cutting the copy back to {} bytes: {cut}", self.copy.length),
            });
        }
        self.copy = extended;
        sync_dir(&self.signature_path).map_err(failed("signature"))
    }

    /// Writes the push's bytes at the copy's length, then replaces the saved signature whole with the
    /// signature of the checkpoint at the new length.
    fn write_push(&self, file: &mut File, push: &Push, extended: FileCopy) -> Result<(), String> {
        file.seek(SeekFrom::Start(self.copy.length))
            .and_then(|_| file.write_all(&push.bytes))
            .and_then(|_| file.sync_all())
            .map_err(failed("copy"))?;
        let saved = Push { offset: extended.length, bytes: Vec::new(), signature: push.signature.clone() };
        let temp = self.signature_path.with_extension("sig.tmp");
        let mut sig = File::create(&temp).map_err(failed("signature"))?;
        sig.write_all(&saved.encode())
            .and_then(|_| sig.sync_all())
            .and_then(|_| fs::rename(&temp, &self.signature_path))
            .map_err(failed("signature"))
    }

    /// The copy's bytes from `offset`, with the latest signature, as the [`Push`] that brings a copy
    /// of `offset` bytes up to this one. `None` if there is no signature yet or `offset` is past the
    /// copy's end.
    pub fn since(&self, offset: u64) -> Option<Push> {
        if offset > self.copy.length {
            return None;
        }
        let signature = self.signature()?;
        let mut file = File::open(&self.path).ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut bytes = Vec::new();
        file.take(self.copy.length - offset).read_to_end(&mut bytes).ok()?;
        (bytes.len() as u64 == self.copy.length - offset).then_some(Push { offset, bytes, signature })
    }

    /// The signature saved with the copy, if a push was ever accepted.
    pub fn signature(&self) -> Option<Signature> {
        let saved = fs::read(&self.signature_path).ok()?;
        Push::decode(&saved).ok().map(|p| p.signature)
    }
}

/// A listener on its own thread, serving until the process ends.
pub struct Listener {
    addr: SocketAddr,
}

impl Listener {
    /// Binds `addr` and serves pushes to `receiver`, one at a time, logging a line for each through
    /// `log`. A `GET` serves the copy to a peer that sends `token` as its bearer token; with no
    /// `token`, reads are refused.
    pub fn start(
        addr: SocketAddr,
        receiver: Receiver,
        token: Option<String>,
        log: impl Fn(&str) + Send + Sync + 'static,
    ) -> std::io::Result<Listener> {
        Self::start_shared(addr, Arc::new(Mutex::new(receiver)), token, log)
    }

    /// As [`Listener::start`], over a copy that catching up from peers shares.
    pub fn start_shared(
        addr: SocketAddr,
        receiver: Arc<Mutex<Receiver>>,
        token: Option<String>,
        log: impl Fn(&str) + Send + Sync + 'static,
    ) -> std::io::Result<Listener> {
        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;
        let log = Arc::new(log);
        let token = Arc::new(token);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (receiver, log, token) = (receiver.clone(), log.clone(), token.clone());
                thread::spawn(move || {
                    let _ = serve(stream, &receiver, token.as_deref(), &*log);
                });
            }
        });
        Ok(Listener { addr })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

fn respond(out: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    write!(out, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())?;
    out.flush()
}

/// Whether `given` is `token`, taking as long for any two values of the same length.
fn same_token(given: &str, token: &str) -> bool {
    given.len() == token.len() && given.bytes().zip(token.bytes()).fold(0, |d, (a, b)| d | (a ^ b)) == 0
}

/// The `offset` of a `GET`'s request target, `/?offset=<n>`.
fn requested_offset(target: &str) -> Option<u64> {
    let query = target.split_once('?')?.1;
    query.split('&').find_map(|pair| pair.strip_prefix("offset=")).and_then(|n| n.parse().ok())
}

/// Answers a `GET`: the copy from the requested offset as an encoded push, to a peer with the token.
fn serve_copy(
    out: &mut TcpStream,
    receiver: &Mutex<Receiver>,
    target: &str,
    given: Option<&str>,
    token: Option<&str>,
    log: &dyn Fn(&str),
) -> std::io::Result<()> {
    let Some(token) = token else {
        log("read-refused: ZK_TOON_PEER_TOKEN is not set");
        return respond(out, "403 Forbidden", r#"{"error":"reads are off"}"#);
    };
    if !given.is_some_and(|g| same_token(g, token)) {
        log("read-refused: missing or wrong token");
        return respond(out, "401 Unauthorized", r#"{"error":"a bearer token is required"}"#);
    }
    let Some(offset) = requested_offset(target) else {
        return respond(out, "400 Bad Request", r#"{"error":"ask for ?offset=<bytes>"}"#);
    };
    let push = {
        let receiver = receiver.lock().unwrap_or_else(|p| p.into_inner());
        if offset > receiver.length() {
            return respond(out, "416 Range Not Satisfiable", &format!(r#"{{"length":{}}}"#, receiver.length()));
        }
        if offset == receiver.length() {
            return respond(out, "204 No Content", "");
        }
        receiver.since(offset)
    };
    let Some(push) = push else {
        log("read-failed: the copy or its signature couldn't be read");
        return respond(out, "500 Internal Server Error", r#"{"error":"copy unreadable"}"#);
    };
    let body = push.encode();
    log(&format!("read-served {} bytes from {offset}", push.bytes.len()));
    write!(out, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", body.len())?;
    out.write_all(&body)?;
    out.flush()
}

/// Reads one request or header line of at most [`MAX_LINE`] bytes. `Ok(0)` is the end of the stream.
fn read_line(reader: &mut BufReader<TcpStream>, line: &mut String) -> std::io::Result<usize> {
    let n = reader.by_ref().take(MAX_LINE).read_line(line)?;
    if n > 0 && !line.ends_with('\n') {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request line too long or cut short"));
    }
    Ok(n)
}

/// Answers the requests on one connection.
fn serve(stream: TcpStream, receiver: &Mutex<Receiver>, token: Option<&str>, log: &dyn Fn(&str)) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IDLE))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = stream;
    loop {
        let mut line = String::new();
        if read_line(&mut reader, &mut line)? == 0 {
            return Ok(());
        }
        let mut words = line.split_whitespace();
        let method = words.next().unwrap_or("").to_string();
        let target = words.next().unwrap_or("").to_string();
        let mut bearer: Option<String> = None;
        let mut length = Some(0usize);
        let mut chunked = false;
        let mut close = line.trim_end().ends_with("HTTP/1.0");
        loop {
            let mut header = String::new();
            if read_line(&mut reader, &mut header)? == 0 {
                return Ok(());
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().ok();
                }
                if name.eq_ignore_ascii_case("transfer-encoding") {
                    chunked = true;
                }
                if name.eq_ignore_ascii_case("authorization") {
                    bearer = value.trim().strip_prefix("Bearer ").map(|t| t.trim().to_string());
                }
                if name.eq_ignore_ascii_case("connection") && value.trim().eq_ignore_ascii_case("close") {
                    close = true;
                }
            }
        }
        if method == "GET" {
            serve_copy(&mut out, receiver, &target, bearer.as_deref(), token, log)?;
            if close {
                return Ok(());
            }
            continue;
        }
        if method != "POST" {
            respond(&mut out, "405 Method Not Allowed", r#"{"error":"POST an encoded push, or GET the copy"}"#)?;
            return Ok(());
        }
        let Some(length) = length.filter(|_| !chunked) else {
            respond(&mut out, "411 Length Required", r#"{"error":"send the push with a Content-Length"}"#)?;
            return Ok(());
        };
        if length > MAX_PUSH {
            log(&format!("push-refused: {length} bytes is over the {MAX_PUSH} byte limit"));
            respond(&mut out, "413 Payload Too Large", r#"{"error":"push too large"}"#)?;
            return Ok(());
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        let reply = receiver.lock().unwrap_or_else(|p| p.into_inner()).receive(&body);
        match reply {
            Reply::Accepted { length } => {
                log(&format!("push-accepted {} bytes, copy is {length} bytes", body.len()));
                respond(&mut out, "200 OK", &format!(r#"{{"length":{length}}}"#))?;
            }
            Reply::Behind { length } => {
                log(&format!("push-behind: copy is {length} bytes"));
                respond(&mut out, "200 OK", &format!(r#"{{"length":{length}}}"#))?;
            }
            Reply::Refused(why) => {
                log(&format!("push-refused: {why}"));
                respond(&mut out, "400 Bad Request", &format!(r#"{{"error":{:?}}}"#, why))?;
            }
            Reply::Failed(why) => {
                log(&format!("push-failed: {why}"));
                respond(&mut out, "500 Internal Server Error", &format!(r#"{{"error":{:?}}}"#, why))?;
            }
        }
        if close {
            return Ok(());
        }
    }
}

/// The most a peer's reply may carry.
const MAX_CATCH_UP: u64 = 256 << 20;

/// The peers a challenger catches its copy up from.
pub struct Peers {
    urls: Vec<String>,
    token: String,
    agent: ureq::Agent,
    receiver: Arc<Mutex<Receiver>>,
}

impl Peers {
    /// `urls` are asked in order, each with `token`, through `socks5` if it is given (and with no
    /// direct fallback), for at most `timeout` a request.
    pub fn new(
        urls: Vec<String>,
        token: String,
        socks5: Option<&str>,
        timeout: Duration,
        receiver: Arc<Mutex<Receiver>>,
    ) -> Result<Peers, String> {
        let mut agent = ureq::AgentBuilder::new().timeout(timeout);
        if let Some(proxy) = socks5 {
            agent = agent.proxy(ureq::Proxy::new(format!("socks5://{proxy}")).map_err(|e| format!("socks proxy: {e}"))?);
        }
        Ok(Peers { urls, token, agent: agent.build(), receiver })
    }

    /// Asks each peer in turn for bytes past the copy's length and appends what checks as a push. A
    /// peer that is down, answers badly or serves bytes that don't check costs one returned line and
    /// is skipped.
    pub fn catch_up(&self) -> Vec<String> {
        self.urls
            .iter()
            .filter_map(|url| match self.ask(url) {
                Ok(caught_up) => caught_up.map(|line| format!("peer {url}: {line}")),
                Err(why) => Some(format!("peer {url}: {why}")),
            })
            .collect()
    }

    /// `Ok` with a line if the copy grew; `Err` with why not if the peer couldn't be used.
    fn ask(&self, url: &str) -> Result<Option<String>, String> {
        let length = self.receiver.lock().unwrap_or_else(|p| p.into_inner()).length();
        let response = match self
            .agent
            .get(url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .query("offset", &length.to_string())
            .call()
        {
            Ok(r) => r,
            Err(ureq::Error::Status(code, _)) => return Err(format!("answered {code}")),
            Err(e) => return Err(format!("unreachable: {}", e.kind())),
        };
        if response.status() == 204 {
            return Ok(None);
        }
        let mut body = Vec::new();
        response.into_reader().take(MAX_CATCH_UP + 1).read_to_end(&mut body).map_err(|e| format!("cut short: {}", e.kind()))?;
        if body.len() as u64 > MAX_CATCH_UP {
            return Err("answered with too many bytes".into());
        }
        match self.receiver.lock().unwrap_or_else(|p| p.into_inner()).receive(&body) {
            Reply::Accepted { length: now } => Ok(Some(format!("caught up, copy is {now} bytes"))),
            Reply::Behind { length: now } => Err(format!("served bytes that don't extend the copy of {now} bytes")),
            Reply::Refused(why) => Err(format!("served bytes that don't check: {why}")),
            Reply::Failed(why) => Err(format!("the copy couldn't be written: {why}")),
        }
    }
}
