//! A request the builder doesn't answer in time: the builder's process is killed and the request
//! fails as timed out, so a caller is never stuck on a builder that hangs. Stand-in processes play the
//! builder; no o1js runs.
use std::io::ErrorKind;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::json;
use zk_toon_tx_builder::{Error, TxBuilder};

#[test]
fn a_builder_that_never_answers_is_killed_and_the_request_times_out() {
    let mut sleep = Command::new("sleep");
    sleep.arg("60");
    let mut b = TxBuilder::spawn(sleep).unwrap();
    b.set_timeout(Some(Duration::from_millis(200)));
    let started = Instant::now();
    let error = b.call("anything", json!({})).unwrap_err();
    assert!(matches!(&error, Error::Io(e) if e.kind() == ErrorKind::TimedOut), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
    // Killed: the next request fails at once too, not after another wait.
    assert!(b.call("anything", json!({})).is_err());
}

#[test]
fn an_answer_within_the_timeout_is_returned() {
    let answer = r#"{"id":1,"ok":true,"result":{"done":true}}"#;
    let mut sh = Command::new("sh");
    sh.args(["-c", &format!("read line; echo '{answer}'; sleep 60")]);
    let mut b = TxBuilder::spawn(sh).unwrap();
    b.set_timeout(Some(Duration::from_secs(10)));
    assert_eq!(b.call("anything", json!({})).unwrap(), json!({ "done": true }));
}
