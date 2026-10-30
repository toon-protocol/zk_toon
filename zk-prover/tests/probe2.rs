use std::io::Read;
use zk_prover::{StepCircuit, StepLand};
fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap()).read_to_end(&mut out).unwrap();
    out
}
#[test]
fn vk_shape() {
    for (name, file) in [("land","cs003"),("setup","cs004")] {
        let circuit = if name=="land" { StepCircuit::load::<StepLand>(&fixture("cs003_gates.json"), &fixture("cs003_internal_vars.bin"), &fixture("cs003_rows_rev.bin")).unwrap() } else { StepCircuit::load::<zk_prover::StepSetup>(&fixture("cs004_gates.json"), &fixture("cs004_internal_vars.bin"), &fixture("cs004_rows_rev.bin")).unwrap() };
        let vk = circuit.index().verifier_index();
        eprintln!("== {name} domain log2 {} zk_rows {} public {} prev_chal {}", vk.domain.log_size_of_group, vk.zk_rows, vk.public, vk.prev_challenges);
        eprintln!("rc0 {} rc1 {} ffadd {} ffmul {} xor {} rot {}", vk.range_check0_comm.is_some(), vk.range_check1_comm.is_some(), vk.foreign_field_add_comm.is_some(), vk.foreign_field_mul_comm.is_some(), vk.xor_comm.is_some(), vk.rot_comm.is_some());
        match &vk.lookup_index {
            None => eprintln!("no lookup index"),
            Some(l) => eprintln!("lookup: tables {} chunks {:?} ids {} runtime_sel {} sel xor {} lookup {} rc {} ffmul {} joint_used {:?} info {:?}", l.lookup_table.len(), l.lookup_table.iter().map(|c| c.chunks.len()).collect::<Vec<_>>(), l.table_ids.is_some(), l.runtime_tables_selector.is_some(), l.lookup_selectors.xor.is_some(), l.lookup_selectors.lookup.is_some(), l.lookup_selectors.range_check.is_some(), l.lookup_selectors.ffmul.is_some(), l.lookup_info.max_per_row, l.lookup_info),
        }
    }
}
