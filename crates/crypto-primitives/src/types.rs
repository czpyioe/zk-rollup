use ark_bn254::Fr;

#[derive(Debug, Copy, Clone)]
pub struct Account {
    pub pub_key_hash: Fr,
    pub balance: u64,
    pub nonce: u64
}

pub struct Transaction{
    // index in the merkle tree
    pub sender_idx: usize,
    // not possible on real rollup
    // secret key is in the tx strcut to avoid ECDSA verification in the circuit
    pub sender_secret_key: Fr,


    // index in the merkle tree
    pub receiver_idx: usize,


    pub amount: u64,
    pub nonce: u64
}

#[derive(Debug)]
pub enum Error{
    InvalidSecretKey,
    InvalidNonce,
    InsufficientBalance,
    InvalidIndex,
    MerkleTreeFull
}
