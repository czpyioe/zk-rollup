use ark_bn254::Fr;
use circuit::circuit::{ZkRollup, TxWitness, TREE_DEPTH, BATCH_SIZE};
use crypto_primitives::hash::{compute_poseidon_hash, compute_poseidon_hash_multi_input, hash_account};
use crypto_primitives::merkle::{MerkleTree, Side};
use crypto_primitives::types::Account;
use prover::keys;
use prover::prove::generate_proof;
use prover::types::{ProofInputs, fq_to_be_bytes};

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
    let mut running_hash = Fr::from(0u64);
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

fn main() {
    let pk = keys::load_pk();

    let witness = default_batch();
    let old_root = witness.old_root.unwrap();
    let new_root = witness.new_root.unwrap();
    let batch_hash = witness.batch_hash.unwrap();

    let inputs = ProofInputs {
        txs: witness.txs,
        old_root,
        new_root,
        batch_hash,
    };

    let (proof, pub_inputs) = generate_proof(inputs, &pk).unwrap();

    println!("proof = 0x{}", hex::encode(proof.to_solidity_call_data()));
    println!("genesisRoot = 0x{}", hex::encode(fq_to_be_bytes(pub_inputs.old_root)));
    println!("newRoot = 0x{}", hex::encode(fq_to_be_bytes(pub_inputs.new_root)));
    println!("batchHash = 0x{}", hex::encode(fq_to_be_bytes(pub_inputs.batch_hash)));
}
