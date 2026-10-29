//! The vault's pending escapes as the adapter rebuilds them: by replaying the vault's `escape` events
//! (`EscapeUpdate` in `o1js/src/vault.ts`) into an indexed Merkle map, as the reduce does, and checking
//! the result against the vault's `pendingEscapesRoot`. The root makes a lying, lagging or reordered
//! archive visible: the read fails rather than miss or invent an escape.
use std::collections::HashMap;

use ark_ff::PrimeField;
use zk_note::{poseidon, Field};

/// Fields in one `escape` event: `pending`, then a pending escape's eight.
pub const ESCAPE_EVENT_FIELDS: usize = 9;

/// Where `pendingEscapesRoot` sits in the vault's 32 app-state fields (`declareState` order in
/// `o1js/src/vault.ts`).
pub const PENDING_ESCAPES_ROOT_INDEX: usize = 24;

/// The height of the vault's `PendingEscapes` indexed Merkle map.
const HEIGHT: usize = 32;

/// A pending escape as the vault records it (`PendingEscape`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
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

impl Record {
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
    pub record: Record,
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
            record: Record {
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
    let big = f.into_bigint();
    let limbs = big.as_ref();
    if limbs[1..].iter().any(|l| *l != 0) {
        return Err(format!("{big} does not fit in 64 bits"));
    }
    Ok(limbs[0])
}

fn as_bool(f: Field) -> Result<bool, String> {
    match as_u64(f)? {
        0 => Ok(false),
        1 => Ok(true),
        n => Err(format!("{n} is not a boolean")),
    }
}

/// The pending escapes `updates` rebuild, in order, and the root of the map they rebuild.
pub fn replay(updates: &[Update]) -> (Field, Vec<Record>) {
    let mut map = IndexedMap::new();
    let mut pending: Vec<Record> = Vec::new();
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
    use std::str::FromStr;

    fn f(n: u64) -> Field {
        Field::from(n)
    }

    /// Roots o1js 3.1.0 computes for the vault's `PendingEscapes`.
    #[test]
    fn the_map_root_is_o1js_root() {
        let empty = "9137763517866771359044650373850135743137646204083611425983907660214991747507";
        assert_eq!(IndexedMap::new().root(), Field::from_str(empty).unwrap());

        // set(5, 7); set(3, 9); set(5, 0): an insert, an insert below it, and an update.
        let mut m = IndexedMap::new();
        m.set(f(5), f(7));
        m.set(f(3), f(9));
        m.set(f(5), f(0));
        let three = "18315625071029396185792180401267874511677914559847106317105467246156793966878";
        assert_eq!(m.root(), Field::from_str(three).unwrap());
    }
}
