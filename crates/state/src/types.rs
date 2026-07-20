use ark_bn254::Fr;

pub struct Account {
    pub_key_hash: Fr,
    balance: u64,
    nonce: u64
}

pub struct Transaction{
    // index in the merkle tree

    sender_idx: usize,
    // not possible on real rollup
    // secret key is in the tx strcut to avoid ECDSA verification in the circuit

    sender_secret_key: Fr,

    // index in the merkle tree
    receiver_idx: usize,

    amount: u64,
    nonce: u64
}