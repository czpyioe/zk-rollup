use ark_snark::CircuitSpecificSetupSNARK;
use rand::rngs::OsRng;
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_groth16::data_structures::VerifyingKey;
use circuit::circuit;
use ark_serialize::CanonicalSerialize;
use anyhow::Result;
use std::fs;



// in arkworks, in Fq2, the elements have the form: `c = c0 + c1 * X`
// in the solidity verifier contracts, elements have the form: a*i + b
// EIP-197: https://eips.ethereum.org/EIPS/eip-197
fn generate_verifier_contract(vk:VerifyingKey<Bn254>) -> Result<String> {
    let path_verifier_template = concat!(env!("CARGO_MANIFEST_DIR"), "/src/contract/Verifier_template.sol");
    let path_verifier_output   = concat!(env!("CARGO_MANIFEST_DIR"), "/src/contract/generated/Verifier.sol");

    let mut verifier_output = fs::read_to_string(path_verifier_template)?;
    fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/src/contract/generated"))?;


    // alpha1
    verifier_output = verifier_output.replace("{{ALFA1_X}}", &vk.alpha_g1.x.to_string());
    verifier_output = verifier_output.replace("{{ALFA1_Y}}", &vk.alpha_g1.y.to_string());



    // beta2
    verifier_output = verifier_output.replace("{{BETA2_X0}}", &vk.beta_g2.x.c1.to_string());
    verifier_output = verifier_output.replace("{{BETA2_X1}}", &vk.beta_g2.x.c0.to_string());
    verifier_output = verifier_output.replace("{{BETA2_Y0}}", &vk.beta_g2.y.c1.to_string());
    verifier_output = verifier_output.replace("{{BETA2_Y1}}", &vk.beta_g2.y.c0.to_string());



    // gamma2   
    verifier_output = verifier_output.replace("{{GAMMA2_X0}}", &vk.gamma_g2.x.c1.to_string());
    verifier_output = verifier_output.replace("{{GAMMA2_X1}}", &vk.gamma_g2.x.c0.to_string());
    verifier_output = verifier_output.replace("{{GAMMA2_Y0}}", &vk.gamma_g2.y.c1.to_string());
    verifier_output = verifier_output.replace("{{GAMMA2_Y1}}", &vk.gamma_g2.y.c0.to_string());



    // delta2
    verifier_output = verifier_output.replace("{{DELTA2_X0}}", &vk.delta_g2.x.c1.to_string());
    verifier_output = verifier_output.replace("{{DELTA2_X1}}", &vk.delta_g2.x.c0.to_string());
    verifier_output = verifier_output.replace("{{DELTA2_Y0}}", &vk.delta_g2.y.c1.to_string());
    verifier_output = verifier_output.replace("{{DELTA2_Y1}}", &vk.delta_g2.y.c0.to_string());




    // IC
    let ic_entries: String = vk.gamma_abc_g1.iter()
        .enumerate()
        .map(|(i, v)| {
            format!(
                "        vk.IC[{}] = Pairing.G1Point(uint256({}), uint256({}));\n",
                i,
                v.x.to_string(),
                v.y.to_string()
            )
        })
        .collect();
    verifier_output = verifier_output.replace("{{IC_ENTRIES}}", &ic_entries);



    // IC length
    verifier_output = verifier_output.replace("{{IC_LENGTH}}", &vk.gamma_abc_g1.len().to_string());

    // input size
    verifier_output = verifier_output.replace("{{INPUT_SIZE}}", &(vk.gamma_abc_g1.len()-1).to_string());


    fs::write(path_verifier_output, verifier_output)?;
    Ok(path_verifier_output.to_string())
}

fn main() {
    let mut rng = OsRng;
    let circuit = circuit::ZkRollup::default();
    let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng).unwrap();

    let mut pk_compressed_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_compressed_bytes).unwrap();

    let mut vk_compressed_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_compressed_bytes).unwrap();


    std::fs::create_dir_all("keys").unwrap();
    std::fs::write("keys/proving_key.bin", &pk_compressed_bytes).unwrap();
    std::fs::write("keys/verification_key.bin", &vk_compressed_bytes).unwrap();
    println!("pk: {} bytes", pk_compressed_bytes.len());
    println!("vk: {} bytes", vk_compressed_bytes.len());


    match generate_verifier_contract(vk) {
        Ok(path)=>println!("Verifier contract saved at: {}",path),
        Err(e)=>eprintln!("Error while genertaing the verifier contract: {}",e)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_snark::SNARK;
    use ark_bn254::Fr;
    use ark_groth16::data_structures::ProvingKey;
    use ark_serialize::CanonicalDeserialize;
    use crypto_primitives::hash::{compute_poseidon_hash_multi_input, hash_account,compute_poseidon_hash};
    use crypto_primitives::merkle::{MerkleTree, Side};
    use crypto_primitives::types::Account;
    use ::circuit::circuit::{ZkRollup, TREE_DEPTH, BATCH_SIZE, TxWitness};
    use ark_ff::Zero;

    fn load_keys() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
        let pk_bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../keys/proving_key.bin"))
            .expect("keys/proving_key.bin not found. run the setup binary first");
        let vk_bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../keys/verification_key.bin"))
            .expect("keys/verification_key.bin not found. run the setup binary first");
        let pk = ProvingKey::deserialize_compressed(pk_bytes.as_slice()).unwrap();
        let vk = VerifyingKey::deserialize_compressed(vk_bytes.as_slice()).unwrap();
        (pk, vk)
    }

    #[derive(Clone)]
    struct TxSpec {
        sender_idx: usize,
        sender_sk: Fr,
        amount: u64,
        receiver_idx: usize,
        receiver_public_key: Fr,
    }

    fn build_valid_batch(accounts: Vec<Account>, txs: Vec<TxSpec>) -> ZkRollup {
        assert_eq!(txs.len(), BATCH_SIZE);

        let mut tree = MerkleTree::new(TREE_DEPTH);
        let mut accounts = accounts;
        for account in &accounts {
            tree.insert(hash_account(account));
        }

        let old_root = tree.root();
        let mut running_hash = Fr::zero();
        let mut tx_witnesses = Vec::with_capacity(BATCH_SIZE);

        for tx in txs {
            let sender = accounts[tx.sender_idx];
            let receiver = accounts[tx.receiver_idx];

            let sender_proof = tree.generate_proof(tx.sender_idx);
            let sender_siblings: Vec<Fr> = sender_proof.siblings.iter().map(|(s, _)| *s).collect();
            let sender_sides: Vec<bool> = sender_proof.siblings.iter().map(|(_, side)| *side == Side::Right).collect();

            let updated_sender = Account {
                pub_key_hash: sender.pub_key_hash,
                balance: sender.balance - tx.amount,
                nonce: sender.nonce + 1,
            };
            tree.update(tx.sender_idx, hash_account(&updated_sender)).unwrap();
            let intermediate_root = tree.root();

            let receiver_proof = tree.generate_proof(tx.receiver_idx);
            let receiver_siblings: Vec<Fr> = receiver_proof.siblings.iter().map(|(s, _)| *s).collect();
            let receiver_sides: Vec<bool> = receiver_proof.siblings.iter().map(|(_, side)| *side == Side::Right).collect();

            let updated_receiver = Account {
                pub_key_hash: receiver.pub_key_hash,
                balance: receiver.balance + tx.amount,
                nonce: receiver.nonce,
            };
            tree.update(tx.receiver_idx, hash_account(&updated_receiver)).unwrap();
            let new_root = tree.root();

            let tx_commitment = compute_poseidon_hash_multi_input(vec![
                sender.pub_key_hash,
                receiver.pub_key_hash,
                Fr::from(tx.amount),
                Fr::from(sender.nonce),
            ]);
            running_hash = compute_poseidon_hash_multi_input(vec![running_hash, tx_commitment]);

            tx_witnesses.push(Some(TxWitness {
                sender_sk: Some(tx.sender_sk),
                sender_balance: Some(Fr::from(sender.balance)),
                sender_nonce: Some(Fr::from(sender.nonce)),
                sender_merkle_siblings: Some(sender_siblings),
                sender_merkle_siblings_side: Some(sender_sides),
                amount: Some(Fr::from(tx.amount)),
                intermediate_root: Some(intermediate_root),
                new_root: Some(new_root),
                receiver_balance: Some(Fr::from(receiver.balance)),
                receiver_merkle_siblings: Some(receiver_siblings),
                receiver_merkle_siblings_side: Some(receiver_sides),
                receiver_nonce: Some(Fr::from(receiver.nonce)),
                receiver_public_key: Some(tx.receiver_public_key),
            }));

            accounts[tx.sender_idx] = updated_sender;
            accounts[tx.receiver_idx] = updated_receiver;
        }

        ZkRollup {
            txs: tx_witnesses.try_into().unwrap(),
            old_root: Some(old_root),
            new_root: Some(tree.root()),
            batch_hash: Some(running_hash),
        }
    }


    fn default_batch() -> ZkRollup {
        let alice_sk = Fr::from(1u64);
        let bob_pk = Fr::from(777u64);
        let carol_sk = Fr::from(2u64);
        let dave_pk = Fr::from(888u64);

        let accounts = vec![
            Account { pub_key_hash: compute_poseidon_hash(alice_sk), balance: 1_000, nonce: 0 },
            Account { pub_key_hash: bob_pk, balance: 50, nonce: 0 },
            Account { pub_key_hash: compute_poseidon_hash(carol_sk), balance: 500, nonce: 0 },
            Account { pub_key_hash: dave_pk, balance: 20, nonce: 0 },
        ];


        let txs = vec![
            TxSpec { sender_idx: 0, sender_sk: alice_sk, amount: 100, receiver_idx: 1, receiver_public_key: bob_pk },
            TxSpec { sender_idx: 2, sender_sk: carol_sk, amount: 50, receiver_idx: 3, receiver_public_key: dave_pk },
            TxSpec { sender_idx: 0, sender_sk: alice_sk, amount: 100, receiver_idx: 2, receiver_public_key: compute_poseidon_hash(carol_sk) },
            TxSpec { sender_idx: 2, sender_sk: carol_sk, amount: 50, receiver_idx: 0, receiver_public_key: compute_poseidon_hash(alice_sk) },
        ];

        build_valid_batch(accounts, txs)
    }

    #[test]
    fn test_keys_load_from_disk() {
        let (_pk, _vk) = load_keys();
    }

    #[test]
    fn test_prove_verify_valid_witness() {
        let mut rng = OsRng;
        let (pk, vk) = load_keys();

        let witness = default_batch();
        let old_root = witness.old_root.unwrap();
        let new_root = witness.new_root.unwrap();
        let batch_hash = witness.batch_hash.unwrap();

        let proof = Groth16::<Bn254>::prove(&pk, witness, &mut rng).unwrap();
        let public_inputs = vec![old_root, new_root, batch_hash];

        assert!(Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap());
    }

    #[test]
    fn test_verify_fails_wrong_public_inputs() {
        let mut rng = OsRng;
        let (pk, vk) = load_keys();

        let witness = default_batch();
        let proof = Groth16::<Bn254>::prove(&pk, witness, &mut rng).unwrap();

        let fake_inputs = vec![Fr::from(999), Fr::from(888), Fr::from(777), Fr::from(666)];
        assert!(!Groth16::<Bn254>::verify(&vk, &fake_inputs, &proof).unwrap());
    }

    #[test]
    fn test_verify_fails_wrong_witness() {
        let (pk, vk) = load_keys();

        let mut witness = default_batch();
        witness.txs[0] = None;

        let old_root = witness.old_root.unwrap();
        let new_root = witness.new_root.unwrap();
        let batch_hash = witness.batch_hash.unwrap();

        let public_inputs = vec![old_root, new_root, batch_hash];

        let result = std::panic::catch_unwind(|| {
            Groth16::<Bn254>::prove(&pk, witness, &mut OsRng)
        });

        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(
                    !Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap(),
                    "a wrong witness must not produce a verifying proof"
                );
            }
        }
    }
}
