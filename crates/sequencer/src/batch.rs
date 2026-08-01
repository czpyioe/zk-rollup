use ark_bn254::Fr;
use circuit::circuit::{TxWitness, ZkRollup, BATCH_SIZE, TREE_DEPTH};
use crypto_primitives::hash::{compute_poseidon_hash_multi_input, hash_account};
use crypto_primitives::merkle::{MerkleTree, Side};
use crypto_primitives::types::Account;

use crate::fixtures::TxSpec;

pub fn genesis_root(accounts: &[Account]) -> Fr {
    let mut tree = MerkleTree::new(TREE_DEPTH);
    for account in accounts {
        tree.insert(hash_account(account));
    }
    tree.root()
}


pub fn build_batch(accounts: Vec<Account>, txs: Vec<TxSpec>) -> ZkRollup {
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
