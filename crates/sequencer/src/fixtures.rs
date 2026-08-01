use ark_bn254::Fr;
use crypto_primitives::hash::compute_poseidon_hash;
use crypto_primitives::types::Account;

#[derive(Clone)]
pub struct TxSpec {
    pub sender_idx: usize,
    pub sender_sk: Fr,
    pub amount: u64,
    pub receiver_idx: usize,
    pub receiver_public_key: Fr,
}


pub fn accounts() -> Vec<Account> {
    let alice_sk = Fr::from(1u64);
    let bob_pk = Fr::from(777u64);
    let carol_sk = Fr::from(2u64);
    let dave_pk = Fr::from(888u64);

    vec![
        Account { pub_key_hash: compute_poseidon_hash(alice_sk), balance: 1_000, nonce: 0 },
        Account { pub_key_hash: bob_pk, balance: 50, nonce: 0 },
        Account { pub_key_hash: compute_poseidon_hash(carol_sk), balance: 500, nonce: 0 },
        Account { pub_key_hash: dave_pk, balance: 20, nonce: 0 },
    ]
}

pub fn txs() -> Vec<TxSpec> {
    let alice_sk = Fr::from(1u64);
    let bob_pk = Fr::from(777u64);
    let carol_sk = Fr::from(2u64);
    let dave_pk = Fr::from(888u64);

    vec![
        TxSpec { sender_idx: 0, sender_sk: alice_sk, amount: 100, receiver_idx: 1, receiver_public_key: bob_pk },
        TxSpec { sender_idx: 2, sender_sk: carol_sk, amount: 50, receiver_idx: 3, receiver_public_key: dave_pk },
        TxSpec { sender_idx: 0, sender_sk: alice_sk, amount: 100, receiver_idx: 2, receiver_public_key: compute_poseidon_hash(carol_sk) },
        TxSpec { sender_idx: 2, sender_sk: carol_sk, amount: 50, receiver_idx: 0, receiver_public_key: compute_poseidon_hash(alice_sk) },
    ]
}
