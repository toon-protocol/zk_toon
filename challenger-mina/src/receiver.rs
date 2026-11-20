//! The challenger's evidence copy and the listener that grows it (ADR 0014). The zk edge `POST`s an
//! encoded [`Push`]; the copy is a prefix of the zk edge's evidence file, and `FileEvidence` reads
//! it as it reads the zk edge's own file. The latest accepted signature is kept next to the copy.
//! The framing and signature checks are `zk_evidence::check_push`'s.
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
    /// `log`.
    pub fn start(
        addr: SocketAddr,
        receiver: Receiver,
        log: impl Fn(&str) + Send + Sync + 'static,
    ) -> std::io::Result<Listener> {
        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;
        let receiver = Arc::new(Mutex::new(receiver));
        let log = Arc::new(log);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (receiver, log) = (receiver.clone(), log.clone());
                thread::spawn(move || {
                    let _ = serve(stream, &receiver, &*log);
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

/// Reads one request or header line of at most [`MAX_LINE`] bytes. `Ok(0)` is the end of the stream.
fn read_line(reader: &mut BufReader<TcpStream>, line: &mut String) -> std::io::Result<usize> {
    let n = reader.by_ref().take(MAX_LINE).read_line(line)?;
    if n > 0 && !line.ends_with('\n') {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request line too long or cut short"));
    }
    Ok(n)
}

/// Answers the requests on one connection.
fn serve(stream: TcpStream, receiver: &Mutex<Receiver>, log: &dyn Fn(&str)) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IDLE))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = stream;
    loop {
        let mut line = String::new();
        if read_line(&mut reader, &mut line)? == 0 {
            return Ok(());
        }
        let method = line.split_whitespace().next().unwrap_or("").to_string();
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
                if name.eq_ignore_ascii_case("connection") && value.trim().eq_ignore_ascii_case("close") {
                    close = true;
                }
            }
        }
        if method != "POST" {
            respond(&mut out, "405 Method Not Allowed", r#"{"error":"POST an encoded push"}"#)?;
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
