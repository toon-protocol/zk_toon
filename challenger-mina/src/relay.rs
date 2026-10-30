//! A local GraphQL relay for the transaction builder. The builder reads the vault and the fee payer
//! from Mina GraphQL while it builds; started with `--mina <relay>/mina --archive <relay>/archive`, it
//! reaches them only through the adapter's own [`Graphql`], so the SOCKS opt-in covers it too and the
//! builder never connects to an endpoint directly.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use serde_json::{json, Value};

use crate::graphql::{Endpoint, Graphql};

/// A relay listening on a loopback port. It serves until the process ends.
pub struct Relay {
    addr: SocketAddr,
}

impl Relay {
    /// Starts relaying `POST /mina` and `POST /archive` to `graphql`.
    pub fn start(graphql: Arc<dyn Graphql + Send + Sync>) -> std::io::Result<Relay> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let graphql = graphql.clone();
                thread::spawn(move || {
                    let _ = serve(stream, &*graphql);
                });
            }
        });
        Ok(Relay { addr })
    }

    pub fn mina_url(&self) -> String {
        format!("http://{}/mina", self.addr)
    }

    pub fn archive_url(&self) -> String {
        format!("http://{}/archive", self.addr)
    }
}

/// Answers the requests on one connection, each with a JSON body.
fn serve(stream: TcpStream, graphql: &dyn Graphql) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = stream;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
        let mut length = 0usize;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header)?;
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        let endpoint = match path.as_str() {
            "/mina" => Some(Endpoint::Mina),
            "/archive" => Some(Endpoint::Archive),
            _ => None,
        };
        let (status, answer) = match (endpoint, serde_json::from_slice::<Value>(&body)) {
            (Some(endpoint), Ok(request)) => match graphql.post(endpoint, &request) {
                Ok(response) => ("200 OK", response),
                Err(e) => ("502 Bad Gateway", json!({ "errors": [{ "message": e }] })),
            },
            _ => ("400 Bad Request", json!({ "errors": [{ "message": "POST a JSON body to /mina or /archive" }] })),
        };
        let answer = answer.to_string();
        write!(
            out,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{answer}",
            answer.len()
        )?;
        out.flush()?;
    }
}
