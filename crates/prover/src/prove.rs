use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use circuit::circuit::ZkRollup;
use ark_groth16::Groth16;
use rand::rngs::OsRng;
use ark_snark::SNARK;
use anyhow::Result;


use crate::types::{ProofInputs,PublicInputs,Proof};


pub fn generate_proof(inputs: ProofInputs, pk: &ProvingKey<Bn254>) -> Result<(Proof, PublicInputs)> {
    let mut rng = OsRng;

    let witness = ZkRollup { 
        txs: inputs.txs, 
        old_root: Some(inputs.old_root), 
        new_root: Some(inputs.new_root), 
        batch_hash: Some(inputs.batch_hash), 
    };

    let proof = Groth16::<Bn254>::prove(pk, witness, &mut rng)?;

    let proof = Proof { 
        a: proof.a, 
        b: proof.b, 
        c: proof.c 
    };

    let public_inputs = PublicInputs{
        old_root: inputs.old_root,
        new_root: inputs.new_root,
        batch_hash: inputs.batch_hash,
    };

    Ok((proof,public_inputs))
}