//! The vault's pending escapes as the adapter rebuilds them: by replaying the vault's `escape` events
//! (`EscapeUpdate` in `o1js/src/vault.ts`) into an indexed Merkle map, as the reduce does, and checking
//! the result against the vault's `pendingEscapesRoot`. The root makes a lying, lagging or reordered
//! archive visible: the read fails rather than miss or invent an escape.
use std::collections::HashMap;

use zk_note::{field_to_bool, field_to_string, field_to_u64, poseidon, Field};

/// Fields in one `escape` event: `pending`, then a pending escape's eight.
pub const ESCAPE_EVENT_FIELDS: usize = 9;

/// Where `pendingEscapesRoot` sits in the vault's 32 app-state fields (`declareState` order in
/// `o1js/src/vault.ts`).
pub const PENDING_ESCAPES_ROOT_INDEX: usize = 24;

/// The height of the vault's `PendingEscapes` indexed Merkle map.
const HEIGHT: usize = 32;

/// A pending escape as the vault records it (`PendingEscape` in `o1js/src/vault.ts`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingEscape {
    /// The escaping state's nullifier: the escape's key.
    pub nullifier: Field,
    pub next_nullifier: Field,
    /// The escaping state's balance.
    pub amount: u64,
    pub conceded: u64,
    /// The note's deposit size.
    pub size: u64,
    pub destination_x: Field,
    pub destination_is_odd: bool,
    /// When the challenge window ends, in ms.
    pub deadline: u64,
}

impl PendingEscape {
    pub fn to_fields(&self) -> [Field; 8] {
        [
            self.nullifier,
            self.next_nullifier,
            Field::from(self.amount),
            Field::from(self.conceded),
            Field::from(self.size),
            self.destination_x,
            Field::from(self.destination_is_odd),
            Field::from(self.deadline),
        ]
    }

    /// The value the vault stores at the record's key while it is pending.
    pub fn hash(&self) -> Field {
        poseidon(&self.to_fields())
    }
}

/// One `escape` event: the record as recorded or raised (`pending`), or as finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub pending: bool,
    pub record: PendingEscape,
}

impl Update {
    pub fn to_fields(&self) -> Vec<Field> {
        let mut out = vec![Field::from(self.pending)];
        out.extend(self.record.to_fields());
        out
    }

    pub fn from_fields(f: &[Field]) -> Result<Self, String> {
        if f.len() != ESCAPE_EVENT_FIELDS {
            return Err(format!("an escape event has {ESCAPE_EVENT_FIELDS} fields, not {}", f.len()));
        }
        Ok(Update {
            pending: as_bool(f[0])?,
            record: PendingEscape {
                nullifier: f[1],
                next_nullifier: f[2],
                amount: as_u64(f[3])?,
                conceded: as_u64(f[4])?,
                size: as_u64(f[5])?,
                destination_x: f[6],
                destination_is_odd: as_bool(f[7])?,
                deadline: as_u64(f[8])?,
            },
        })
    }
}

fn as_u64(f: Field) -> Result<u64, String> {
    field_to_u64(f).ok_or_else(|| format!("{} does not fit in 64 bits", field_to_string(f)))
}

fn as_bool(f: Field) -> Result<bool, String> {
    field_to_bool(f).ok_or_else(|| format!("{} is not a boolean", field_to_string(f)))
}

/// The pending escapes `updates` rebuild, in order, and the root of the map they rebuild.
pub fn replay(updates: &[Update]) -> (Field, Vec<PendingEscape>) {
    let mut map = IndexedMap::new();
    let mut pending: Vec<PendingEscape> = Vec::new();
    for u in updates {
        let key = u.record.nullifier;
        map.set(key, if u.pending { u.record.hash() } else { Field::from(0u64) });
        pending.retain(|r| r.nullifier != key);
        if u.pending {
            pending.push(u.record.clone());
        }
    }
    (map.root(), pending)
}

/// o1js's `IndexedMerkleMap`, enough to compute its root. Leaves are a linked list sorted by key: leaf
/// `i` is `(key, value, nextKey)`, hashed as `Poseidon(key, value, nextKey)`, with `nextKey = 0` for the
/// largest key. Leaf 0 is `(0, 0, 0)`; a new key is appended at the next index and its predecessor's
/// `nextKey` is pointed at it. The root is `Poseidon(merkleRoot, length)`.
pub(crate) struct IndexedMap {
    leaves: Vec<(Field, Field, Field)>,
    index: HashMap<Field, usize>,
}

impl IndexedMap {
    pub(crate) fn new() -> Self {
        let zero = Field::from(0u64);
        IndexedMap { leaves: vec![(zero, zero, zero)], index: HashMap::from([(zero, 0)]) }
    }

    pub(crate) fn set(&mut self, key: Field, value: Field) {
        if let Some(&i) = self.index.get(&key) {
            self.leaves[i].1 = value;
            return;
        }
        // The predecessor: the largest key below `key`.
        let low = self
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, l)| l.0 < key)
            .max_by(|a, b| a.1 .0.cmp(&b.1 .0))
            .map(|(i, _)| i)
            .expect("leaf 0 holds key 0, below every other key");
        let next = self.leaves[low].2;
        self.leaves[low].2 = key;
        self.index.insert(key, self.leaves.len());
        self.leaves.push((key, value, next));
    }

    pub(crate) fn root(&self) -> Field {
        let mut level: Vec<Field> = self.leaves.iter().map(|(k, v, n)| poseidon(&[*k, *v, *n])).collect();
        let mut empty = Field::from(0u64);
        for _ in 0..HEIGHT - 1 {
            if level.len() % 2 == 1 {
                level.push(empty);
            }
            level = level.chunks(2).map(|p| poseidon(&[p[0], p[1]])).collect();
            empty = poseidon(&[empty, empty]);
        }
        poseidon(&[level[0], Field::from(self.leaves.len() as u64)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::str::FromStr;

    /// The `pendingEscapes` section of the shared vectors, which o1js computes for the vault's
    /// `PendingEscape` and `PendingEscapes`.
    fn vectors() -> Value {
        let v: Value = serde_json::from_str(zk_note::VECTORS_JSON).unwrap();
        v["pendingEscapes"].clone()
    }

    fn f(v: &Value) -> Field {
        Field::from_str(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn a_pending_escapes_hash_is_o1js_hash() {
        let records = vectors()["records"].as_array().unwrap().clone();
        assert!(!records.is_empty());
        println!("vector cases run: {}", records.len());
        for r in records {
            let fields: Vec<Field> = r["fields"].as_array().unwrap().iter().map(f).collect();
            // An `escape` event is `pending` followed by the record's fields.
            let event: Vec<Field> = std::iter::once(Field::from(1u64)).chain(fields.iter().copied()).collect();
            let record = Update::from_fields(&event).unwrap().record;
            assert_eq!(record.to_fields().to_vec(), fields);
            assert_eq!(record.hash(), f(&r["hash"]));
        }
    }

    #[test]
    fn the_map_root_is_o1js_root_after_each_insert_and_update() {
        let v = vectors();
        assert_eq!(v["height"].as_u64(), Some(HEIGHT as u64));
        let mut m = IndexedMap::new();
        assert_eq!(m.root(), f(&v["emptyRoot"]));
        let updates = v["updates"].as_array().unwrap();
        assert!(!updates.is_empty());
        println!("vector cases run: {}", updates.len());
        for u in updates {
            m.set(f(&u["key"]), f(&u["value"]));
            assert_eq!(m.root(), f(&u["root"]));
        }
    }
}
