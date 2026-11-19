//! `test-vectors/zk-evidence.json`: generated here, checked in, and read back field by field.
//! Regenerate with `UPDATE_VECTORS=1 cargo test -p zk-evidence`.
//!
//! The proof is a dummy `JsonProof` around a real request sample's public input: the format does not
//! depend on the proof being valid. Nothing here is a secret.
use serde_json::{json, Value};
use std::str::FromStr;
use zk_evidence::*;
use mina_signer::{CompressedPubKey, Keypair, NetworkId, SecKey, Signature};
use zk_note::balance::Scalar;
use zk_note::{field_to_string, Field};

const ZK_NOTE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/zk-note.json");
const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/zk-evidence.json");

fn load(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn json_proof(public_input: &Value) -> String {
    json!({ "publicInput": public_input, "publicOutput": [], "maxProofsVerified": 0, "proof": "dummy-proof" })
        .to_string()
}

fn field(s: &str) -> Field {
    Field::from_str(s).unwrap()
}

fn grant(entry: &Value, id: &[u8], key_x: &str, odd: bool, expires_at: u64, granted_at: u64) -> Grant {
    Grant {
        proof: json_proof(&entry["publicInput"]).into_bytes(),
        allowance_id: id.to_vec(),
        session_key_x: field(key_x),
        session_key_is_odd: odd,
        expires_at,
        granted_at,
    }
}

fn record_json(record: &Record) -> Value {
    let payload = record.encode().unwrap();
    let mut v = match record {
        Record::Grant(g) => {
            let p = g.request_public().unwrap();
            json!({
                "kind": "grant",
                "proof": String::from_utf8(g.proof.clone()).unwrap(),
                "allowanceId": hex::encode(&g.allowance_id),
                "sessionKeyX": field_to_string(g.session_key_x),
                "sessionKeyIsOdd": g.session_key_is_odd,
                "expiresAt": g.expires_at.to_string(),
                "grantedAt": g.granted_at.to_string(),
                "requestPublic": {
                    "nullifier": field_to_string(p.nullifier),
                    "tier": p.tier.to_string(),
                    "subsidised": p.subsidised,
                },
            })
        }
        Record::Close(c) => json!({
            "kind": "close",
            "nullifier": field_to_string(c.nullifier),
            "allowanceId": hex::encode(&c.allowance_id),
            "charge": c.charge.to_string(),
        }),
    };
    v["payloadHex"] = hex::encode(&payload).into();
    v["framedHex"] = hex::encode(frame(&payload)).into();
    v["evidenceHash"] = hex::encode(evidence_hash(&payload)).into();
    v
}

fn file_bytes(records: &[&Record]) -> Vec<u8> {
    let mut out = write_header();
    for r in records {
        out.extend(frame(&r.encode().unwrap()));
    }
    out
}

const NETWORK: NetworkId = NetworkId::TESTNET;

/// Fixed test keys. The key numbers are not in the vector file, only the public halves.
fn keypair(n: u64) -> Keypair {
    Keypair::try_from(SecKey::new(Scalar::from(n))).unwrap()
}

fn key_json(k: &CompressedPubKey) -> Value {
    json!({ "x": field_to_string(k.x), "isOdd": k.is_odd, "address": k.into_address() })
}

fn key_from(v: &Value) -> CompressedPubKey {
    CompressedPubKey { x: field(v["x"].as_str().unwrap()), is_odd: v["isOdd"].as_bool().unwrap() }
}

fn sig_json(s: &Signature) -> Value {
    json!({ "r": field_to_string(s.rx), "s": s.s.to_string() })
}

fn sig_from(v: &Value) -> Signature {
    Signature::new(field(v["r"].as_str().unwrap()), Scalar::from_str(v["s"].as_str().unwrap()).unwrap())
}

fn copy_json(c: &FileCopy) -> Value {
    json!({ "length": c.length.to_string(), "runningHash": hex::encode(c.running_hash) })
}

fn copy_from(v: &Value) -> FileCopy {
    FileCopy {
        length: v["length"].as_str().unwrap().parse().unwrap(),
        running_hash: hx(&v["runningHash"]).try_into().unwrap(),
    }
}

/// A push of `bytes` onto `copy`, signed by `signer` for `vault`.
fn signed_push(copy: &FileCopy, bytes: &[u8], vault: &CompressedPubKey, signer: &Keypair) -> Push {
    let scan = scan_records(bytes, 0).unwrap();
    let cp = Checkpoint {
        vault: vault.clone(),
        length: copy.length + bytes.len() as u64,
        running_hash: scan.records.iter().fold(copy.running_hash, |h, r| extend_running_hash(&h, r.payload)),
    };
    Push { offset: copy.length, bytes: bytes.to_vec(), signature: cp.sign(NETWORK, signer) }
}

fn refusal_name(r: &PushRefusal) -> &'static str {
    match r {
        PushRefusal::BadCopy(_) => "badCopy",
        PushRefusal::WrongOffset { .. } => "wrongOffset",
        PushRefusal::Empty => "empty",
        PushRefusal::NotWholeRecords => "notWholeRecords",
        PushRefusal::BadRecord(_) => "badRecord",
        PushRefusal::BadSignature => "badSig",
    }
}

fn evidence_push_vectors(whole: &[u8], torn: &[u8]) -> Value {
    let state = keypair(1001);
    let other_state = keypair(1002);
    let vault = keypair(2001).public.into_compressed();
    let other_vault = keypair(2002).public.into_compressed();

    let scan = scan(whole).unwrap();
    let hash_after = |n: usize| running_hash(scan.records[..n].iter().map(|r| r.payload));
    let after_header = FileCopy::empty();
    let second_at = scan.records[2].offset;
    let first_two = &whole[after_header.length as usize..second_at];
    let last = &whole[second_at..];
    let after_two = FileCopy { length: second_at as u64, running_hash: hash_after(2) };

    let cp = Checkpoint { vault: vault.clone(), length: whole.len() as u64, running_hash: hash_after(3) };
    let cp_sig = cp.sign(NETWORK, &state);

    let push_a = signed_push(&after_header, first_two, &vault, &state);
    let push_b = signed_push(&after_two, last, &vault, &state);
    let push_json = |p: &Push, copy: &FileCopy| json!({ "copy": copy_json(copy), "pushHex": hex::encode(p.encode()) });

    let wrong_offset = Push { offset: after_two.length + 1, ..push_b.clone() };
    let torn_bytes = &torn[second_at..];
    let torn_push = signed_push_unchecked(&after_two, torn_bytes, &vault, &state);
    let bad_sig = Push { signature: cp.sign(NETWORK, &other_state), ..push_b.clone() };
    let other_vault_push = signed_push(&after_two, last, &other_vault, &state);

    let refused = |name: &str, p: &Push, copy: &FileCopy| {
        let mut v = push_json(p, copy);
        v["name"] = name.into();
        v["refusal"] = refusal_name(&check_push(NETWORK, &state.public, &vault, copy, p).unwrap_err()).into();
        v
    };

    json!({
        "runningHashes": {
            "empty": hex::encode(EMPTY_RUNNING_HASH),
            "afterEachRecord": (1..=3).map(|n| hex::encode(hash_after(n))).collect::<Vec<_>>(),
        },
        "checkpoint": {
            "networkId": "devnet",
            "stateKey": key_json(&state.public.into_compressed()),
            "vault": key_json(&vault),
            "length": cp.length.to_string(),
            "runningHash": hex::encode(cp.running_hash),
            "fields": cp.to_fields().into_iter().map(field_to_string).collect::<Vec<_>>(),
            "sig": sig_json(&cp_sig),
        },
        "stateKey": key_json(&state.public.into_compressed()),
        "vault": key_json(&vault),
        "otherVault": key_json(&other_vault),
        "pushes": [push_json(&push_a, &after_header), push_json(&push_b, &after_two)],
        "refusedPushes": [
            refused("wrongOffset", &wrong_offset, &after_two),
            refused("tornRecord", &torn_push, &after_two),
            refused("badSig", &bad_sig, &after_two),
            refused("otherVault", &other_vault_push, &after_two),
        ],
    })
}

/// Sign whatever `bytes` hold, as if its records were whole: what a faulty or hostile sender does.
fn signed_push_unchecked(copy: &FileCopy, bytes: &[u8], vault: &CompressedPubKey, signer: &Keypair) -> Push {
    let cp = Checkpoint { vault: vault.clone(), length: copy.length + bytes.len() as u64, running_hash: copy.running_hash };
    Push { offset: copy.length, bytes: bytes.to_vec(), signature: cp.sign(NETWORK, signer) }
}

fn build() -> Value {
    let zk_note = load(ZK_NOTE);
    let entries = zk_note["requestProofs"].as_array().unwrap();
    let a = Record::Grant(grant(&entries[0], b"allowance-a", "31337", true, 1_700_000_900_000, 1_700_000_100_000));
    let b = Record::Grant(grant(&entries[1], &[0xab; 64], "7", false, 1_700_000_950_000, 1_700_000_200_000));
    let nullifier_a = field(&record_json(&a)["requestPublic"]["nullifier"].as_str().unwrap().to_string());
    let close_a = Record::Close(Close { nullifier: nullifier_a, allowance_id: b"allowance-a".to_vec(), charge: 25_000_000 });

    let whole = file_bytes(&[&a, &b, &close_a]);
    // A torn tail: the file as above, then a close record cut off in its payload.
    let extra = frame(&Record::Close(Close { nullifier: Field::from(5u64), allowance_id: vec![], charge: 1 }).encode().unwrap());
    let mut torn = whole.clone();
    torn.extend_from_slice(&extra[..extra.len() - 6]);
    // Corruption mid-file: a payload byte of the first record flipped.
    let mut corrupt = whole.clone();
    let first_payload = 10 + 4;
    corrupt[first_payload + 1] ^= 0xff;

    let push_vectors = evidence_push_vectors(&whole, &torn);

    let mut v = json!({
        "description": "Evidence file test vectors, generated by Rust (`UPDATE_VECTORS=1 cargo test -p zk-evidence`). \
            Integers wider than 32 bits are decimal strings; field elements are decimal strings and encode as 32 bytes LE. \
            The proof is a dummy JsonProof around a real request sample's public input.",
        "magic": hex::encode(MAGIC),
        "version": VERSION,
        "headerHex": hex::encode(write_header()),
        "grant": record_json(&a),
        "grantMaxAllowanceId": record_json(&b),
        "close": record_json(&close_a),
        "file": {
            "hex": hex::encode(&whole),
            "records": [record_json(&a), record_json(&b), record_json(&close_a)],
        },
        "tornTail": {
            "hex": hex::encode(&torn),
            "records": [record_json(&a), record_json(&b), record_json(&close_a)],
            "validLen": whole.len(),
        },
        "corruptMidFile": { "hex": hex::encode(&corrupt), "error": { "corrupt": { "offset": 10 } } },
        "badMagic": { "hex": hex::encode(b"TOONZKEX\x01\x00") },
        "unknownVersion": { "hex": hex::encode([MAGIC.as_slice(), &2u16.to_le_bytes()].concat()), "version": 2 },
    });
    v["evidencePush"] = push_vectors;
    v
}

#[test]
fn vectors_are_current() {
    let built = build();
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        std::fs::write(VECTORS, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    assert_eq!(load(VECTORS), built, "test-vectors/zk-evidence.json is stale: UPDATE_VECTORS=1 cargo test -p zk-evidence");
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// A record rebuilt from a vector entry's fields.
fn record_from(e: &Value) -> Record {
    let u = |k: &str| e[k].as_str().unwrap().parse::<u64>().unwrap();
    match e["kind"].as_str().unwrap() {
        "grant" => Record::Grant(Grant {
            proof: e["proof"].as_str().unwrap().as_bytes().to_vec(),
            allowance_id: hx(&e["allowanceId"]),
            session_key_x: field(e["sessionKeyX"].as_str().unwrap()),
            session_key_is_odd: e["sessionKeyIsOdd"].as_bool().unwrap(),
            expires_at: u("expiresAt"),
            granted_at: u("grantedAt"),
        }),
        "close" => Record::Close(Close {
            nullifier: field(e["nullifier"].as_str().unwrap()),
            allowance_id: hx(&e["allowanceId"]),
            charge: u("charge"),
        }),
        k => panic!("unknown kind {k}"),
    }
}

fn check_record(e: &Value) {
    let record = record_from(e);
    let payload = hx(&e["payloadHex"]);
    assert_eq!(record.encode().unwrap(), payload);
    assert_eq!(Record::decode(&payload).unwrap(), record);
    assert_eq!(frame(&payload), hx(&e["framedHex"]));
    assert_eq!(evidence_hash(&payload), hx(&e["evidenceHash"])[..]);
    if let Record::Grant(g) = &record {
        let p = g.request_public().unwrap();
        let want = &e["requestPublic"];
        assert_eq!(field_to_string(p.nullifier), want["nullifier"].as_str().unwrap());
        assert_eq!(p.tier.to_string(), want["tier"].as_str().unwrap());
        assert_eq!(p.subsidised, want["subsidised"].as_bool().unwrap());
    }
}

#[test]
fn records_round_trip_and_hash() {
    let v = load(VECTORS);
    let mut n = 0;
    for k in ["grant", "grantMaxAllowanceId", "close"] {
        check_record(&v[k]);
        n += 1;
    }
    println!("vector cases run: {n}");
}

fn scan_records_of(file: &[u8]) -> Vec<Record> {
    scan(file).unwrap().records.iter().map(|f| Record::decode(f.payload).unwrap()).collect()
}

#[test]
fn reading_the_sample_file_yields_exactly_its_records() {
    let v = load(VECTORS);
    let want: Vec<Record> = v["file"]["records"].as_array().unwrap().iter().map(record_from).collect();
    let bytes = hx(&v["file"]["hex"]);
    let s = scan(&bytes).unwrap();
    assert!(!s.torn_tail);
    assert_eq!(s.valid_len, bytes.len());
    assert_eq!(scan_records_of(&bytes), want);
    for (e, f) in v["file"]["records"].as_array().unwrap().iter().zip(&s.records) {
        assert_eq!(f.payload, hx(&e["payloadHex"]));
        check_record(e);
    }
}

#[test]
fn a_torn_tail_yields_every_record_before_it() {
    let v = load(VECTORS);
    let want: Vec<Record> = v["tornTail"]["records"].as_array().unwrap().iter().map(record_from).collect();
    let bytes = hx(&v["tornTail"]["hex"]);
    let s = scan(&bytes).unwrap();
    assert!(s.torn_tail);
    assert_eq!(s.valid_len as u64, v["tornTail"]["validLen"].as_u64().unwrap());
    assert_eq!(scan_records_of(&bytes), want);

    // Every cut of the last record is a torn tail, and a CRC failure on the last record is too.
    let whole = hx(&v["file"]["hex"]);
    let last_at = scan(&whole).unwrap().records.last().unwrap().offset;
    for cut in last_at + 1..whole.len() {
        let s = scan(&whole[..cut]).unwrap();
        assert!(s.torn_tail && s.valid_len == last_at && s.records.len() == want.len() - 1, "cut {cut}");
    }
    let mut bad_crc = whole.clone();
    *bad_crc.last_mut().unwrap() ^= 1;
    let s = scan(&bad_crc).unwrap();
    assert!(s.torn_tail && s.valid_len == last_at);
}

#[test]
fn a_mid_file_crc_failure_is_corruption() {
    let v = load(VECTORS);
    let e = &v["corruptMidFile"];
    assert_eq!(scan(&hx(&e["hex"])).unwrap_err(), FileError::Corrupt { offset: e["error"]["corrupt"]["offset"].as_u64().unwrap() as usize });
}

#[test]
fn a_bad_magic_or_unknown_version_is_refused() {
    let v = load(VECTORS);
    assert_eq!(scan(&hx(&v["badMagic"]["hex"])).unwrap_err(), FileError::BadMagic);
    assert_eq!(scan(&hx(&v["unknownVersion"]["hex"])).unwrap_err(), FileError::UnsupportedVersion(2));
    assert_eq!(scan(&hx(&v["headerHex"])).unwrap().records.len(), 0);
    assert_eq!(scan(b"TOONZK").unwrap_err(), FileError::TruncatedHeader);
}

#[test]
fn a_non_canonical_field_element_is_refused() {
    let v = load(VECTORS);
    // The modulus itself, and all ones, are not canonical.
    let modulus: [u8; 32] = {
        let mut m = [0u8; 32];
        m.copy_from_slice(&field_to_bytes(-Field::from(1u64)));
        m[0] += 1; // p - 1 + 1 = p
        m
    };
    assert_eq!(field_from_bytes(&modulus), Err(DecodeError::NonCanonicalField));
    assert_eq!(field_from_bytes(&[0xff; 32]), Err(DecodeError::NonCanonicalField));
    assert!(field_from_bytes(&field_to_bytes(-Field::from(1u64))).is_ok());

    let mut close = hx(&v["close"]["payloadHex"]);
    close[1..33].copy_from_slice(&[0xff; 32]);
    assert_eq!(Record::decode(&close), Err(DecodeError::NonCanonicalField));

    let g = hx(&v["grant"]["payloadHex"]);
    let proof_len = u32::from_le_bytes(g[1..5].try_into().unwrap()) as usize;
    let id_len = g[5 + proof_len] as usize;
    let key_at = 5 + proof_len + 1 + id_len;
    let mut bad = g.clone();
    bad[key_at..key_at + 32].copy_from_slice(&[0xff; 32]);
    assert_eq!(Record::decode(&bad), Err(DecodeError::NonCanonicalField));
    let mut bad = g.clone();
    bad[key_at + 32] = 2;
    assert_eq!(Record::decode(&bad), Err(DecodeError::BadFlag));
}

#[test]
fn malformed_payloads_are_refused() {
    let v = load(VECTORS);
    let close = hx(&v["close"]["payloadHex"]);
    assert_eq!(Record::decode(&[]), Err(DecodeError::Truncated));
    assert_eq!(Record::decode(&[9]), Err(DecodeError::UnknownKind(9)));
    assert_eq!(Record::decode(&close[..close.len() - 1]), Err(DecodeError::Truncated));
    let mut long = close.clone();
    long.push(0);
    assert_eq!(Record::decode(&long), Err(DecodeError::TrailingBytes));
    let too_long = Record::Close(Close { nullifier: Field::from(1u64), allowance_id: vec![0; 65], charge: 0 });
    assert_eq!(too_long.encode(), Err(DecodeError::AllowanceIdTooLong(65)));
}

#[test]
fn nothing_in_the_vectors_is_a_secret() {
    let text = std::fs::read_to_string(VECTORS).unwrap().to_lowercase();
    for word in ["secret", "private", "blinding", "signature"] {
        assert!(!text.contains(word), "vectors mention {word}");
    }
}

// --- the running hash, the checkpoint and the push ---

fn whole_file(v: &Value) -> Vec<u8> {
    hx(&v["file"]["hex"])
}

#[test]
fn the_running_hash_matches_and_extends() {
    let v = load(VECTORS);
    let want = &v["evidencePush"]["runningHashes"];
    assert_eq!(EMPTY_RUNNING_HASH, [0u8; 32]);
    assert_eq!(hx(&want["empty"]), vec![0u8; 32]);
    let file = whole_file(&v);
    let s = scan(&file).unwrap();
    let mut h = EMPTY_RUNNING_HASH;
    for (i, r) in s.records.iter().enumerate() {
        h = extend_running_hash(&h, r.payload);
        assert_eq!(h[..], hx(&want["afterEachRecord"][i])[..]);
        assert_eq!(running_hash(s.records[..=i].iter().map(|r| r.payload)), h);
    }
    assert_eq!(FileCopy::of_file(&file).unwrap().running_hash, h);
    assert_eq!(FileCopy::of_file(&write_header()).unwrap(), FileCopy::empty());
}

#[test]
fn a_checkpoint_verifies_only_for_what_it_names() {
    let v = load(VECTORS);
    let c = &v["evidencePush"]["checkpoint"];
    let state = key_from(&c["stateKey"]);
    assert_eq!(state.x, key_from(&c["stateKey"]).x);
    let state_pub = mina_signer::PubKey::from_address(c["stateKey"]["address"].as_str().unwrap()).unwrap();
    let cp = Checkpoint {
        vault: key_from(&c["vault"]),
        length: c["length"].as_str().unwrap().parse().unwrap(),
        running_hash: hx(&c["runningHash"]).try_into().unwrap(),
    };
    let fields: Vec<String> = cp.to_fields().into_iter().map(field_to_string).collect();
    assert_eq!(fields, c["fields"].as_array().unwrap().iter().map(|f| f.as_str().unwrap().to_string()).collect::<Vec<_>>());
    assert_eq!(cp.to_fields()[0], zk_note::tag_to_field(zk_note::tags::EVIDENCE_CHECKPOINT));

    let sig = sig_from(&c["sig"]);
    assert_eq!(cp.sign(NETWORK, &keypair(1001)), sig);
    assert!(cp.verify(NETWORK, &state_pub, &sig));

    assert!(!cp.verify(NETWORK, &keypair(1002).public, &sig), "another key");
    let other_vault = Checkpoint { vault: key_from(&v["evidencePush"]["otherVault"]), ..cp.clone() };
    assert!(!other_vault.verify(NETWORK, &state_pub, &sig), "another vault");
    assert!(!Checkpoint { length: cp.length + 1, ..cp.clone() }.verify(NETWORK, &state_pub, &sig), "another length");
    let mut other_hash = cp.running_hash;
    other_hash[31] ^= 1;
    assert!(!Checkpoint { running_hash: other_hash, ..cp.clone() }.verify(NETWORK, &state_pub, &sig), "another hash");
    other_hash = cp.running_hash;
    other_hash[0] ^= 1;
    assert!(!Checkpoint { running_hash: other_hash, ..cp.clone() }.verify(NETWORK, &state_pub, &sig), "another hash, high half");
}

#[test]
fn a_checkpoint_is_not_a_state_message_or_a_clearance() {
    use zk_note::clearance::{sign_clearance, ClearanceMessage};
    let state = keypair(1001);
    let vault = keypair(2001).public.into_compressed();
    let cp = Checkpoint { vault: vault.clone(), length: 10, running_hash: [7; 32] };
    // A clearance with the same field values in its slots: the tags differ, so the signatures do.
    let clearance = ClearanceMessage::new(&vault, Field::from(10u64), &vault);
    assert!(!cp.verify(NETWORK, &state.public, &sign_clearance(&state, &clearance)));
    // A state message over the checkpoint's leading fields.
    let fields = cp.to_fields();
    let as_state = zk_note::state::sign_fields(NETWORK, &state, fields[1..].to_vec());
    assert!(!cp.verify(NETWORK, &state.public, &as_state));
    assert!(cp.verify(NETWORK, &state.public, &cp.sign(NETWORK, &state)));
}

#[test]
fn a_push_round_trips_and_refuses_truncated_and_trailing_input() {
    let v = load(VECTORS);
    for p in v["evidencePush"]["pushes"].as_array().unwrap() {
        let bytes = hx(&p["pushHex"]);
        let push = Push::decode(&bytes).unwrap();
        assert_eq!(push.encode(), bytes);
        for cut in 0..bytes.len() {
            assert_eq!(Push::decode(&bytes[..cut]), Err(PushDecodeError::Truncated), "cut {cut}");
        }
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(Push::decode(&long), Err(PushDecodeError::TrailingBytes));
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n - 1] = 0xff;
        assert_eq!(Push::decode(&bad), Err(PushDecodeError::NonCanonicalSignature));
    }
}

fn state_pub(v: &Value) -> mina_signer::PubKey {
    mina_signer::PubKey::from_address(v["evidencePush"]["stateKey"]["address"].as_str().unwrap()).unwrap()
}

#[test]
fn a_valid_push_is_accepted_and_extends_the_copy() {
    let v = load(VECTORS);
    let vault = key_from(&v["evidencePush"]["vault"]);
    let file = whole_file(&v);
    let mut copy = FileCopy::empty();
    for p in v["evidencePush"]["pushes"].as_array().unwrap() {
        assert_eq!(copy_from(&p["copy"]), copy);
        let push = Push::decode(&hx(&p["pushHex"])).unwrap();
        copy = check_push(NETWORK, &state_pub(&v), &vault, &copy, &push).unwrap();
    }
    assert_eq!(copy, FileCopy::of_file(&file).unwrap());
    let c = &v["evidencePush"]["checkpoint"];
    assert_eq!(copy.length.to_string(), c["length"].as_str().unwrap());
    assert_eq!(hex::encode(copy.running_hash), c["runningHash"].as_str().unwrap());
}

#[test]
fn a_bad_push_is_refused_for_the_reason_named() {
    let v = load(VECTORS);
    let vault = key_from(&v["evidencePush"]["vault"]);
    let refused = v["evidencePush"]["refusedPushes"].as_array().unwrap();
    assert_eq!(refused.len(), 4);
    for p in refused {
        let push = Push::decode(&hx(&p["pushHex"])).unwrap();
        let got = check_push(NETWORK, &state_pub(&v), &vault, &copy_from(&p["copy"]), &push).unwrap_err();
        assert_eq!(refusal_name(&got), p["refusal"].as_str().unwrap(), "{}", p["name"]);
    }
    let names: Vec<&str> = refused.iter().map(|p| p["refusal"].as_str().unwrap()).collect();
    assert_eq!(names, ["wrongOffset", "notWholeRecords", "badSig", "badSig"]);
    println!("vector cases run: {}", refused.len());
}
