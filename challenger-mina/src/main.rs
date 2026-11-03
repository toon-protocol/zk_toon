//! `zk-toon-challenger`: watches a vault's escapes and defeats or raises dishonest ones. See
//! `docs/challenger-mina.md`.
use zk_toon_challenger_mina::service::{run, Options, FEE_PAYER_KEY};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let started = Options::parse(&args, std::env::var(FEE_PAYER_KEY).ok()).and_then(run);
    if let Err(e) = started {
        eprintln!("zk-toon-challenger: {e}");
        std::process::exit(2);
    }
}
