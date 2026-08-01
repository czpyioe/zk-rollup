use prover::types::fq_to_be_bytes;
use sequencer::{batch, fixtures};

// generates GENESIS_ROOT for the deploy script
fn main() {
    let root = batch::genesis_root(&fixtures::accounts());
    println!("0x{}", hex::encode(fq_to_be_bytes(root)));
}
