use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig}
};
use crate::types::Account;

use ark_crypto_primitives::crh::{poseidon::CRH, CRHScheme};

pub fn poseidon_config() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        254,
        2,
        8,
        57,
        0,
    );
    PoseidonConfig {
        full_rounds: 8,
        partial_rounds: 57,
        alpha: 5,
        ark,
        mds,
        rate: 2,
        capacity: 1,
    }
}

pub fn compute_poseidon_hash(input: Fr) -> Fr {
    let cfg = poseidon_config();
    let crh_input = CRH::<Fr>::evaluate(&cfg, vec![input]).unwrap();
    crh_input
}

pub fn hash_left_right(left: Fr, right: Fr) -> Fr {
    let cfg = poseidon_config();
    CRH::<Fr>::evaluate(&cfg, vec![left, right]).unwrap()
}

pub fn hash_account(account: &Account) -> Fr{
    let cfg = poseidon_config();
    CRH::<Fr>::evaluate(&cfg, vec![account.pub_key_hash, Fr::from(account.balance), Fr::from(account.nonce)]).unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_poseidon_hash_deterministic() {
        let n = Fr::from(99);
        assert_eq!(compute_poseidon_hash(n), compute_poseidon_hash(n));
    }

    #[test]
    fn test_different_poseidon_hash_produce_different_hashes() {
        let n1 = Fr::from(1);
        let n2 = Fr::from(2);
        assert_ne!(compute_poseidon_hash(n1), compute_poseidon_hash(n2));
    }

    #[test]
    fn test_hash_left_right_deterministic() {
        let l = Fr::from(42);
        let r = Fr::from(99);
        assert_eq!(hash_left_right(l, r), hash_left_right(l, r));
    }

    #[test]
    fn test_hash_left_right_produce_different_hashes() {
        let l = Fr::from(42);
        let r = Fr::from(99);
        assert_ne!(hash_left_right(l, r), hash_left_right(r, r));
    }


    #[test]
    fn test_hash_account() {
        let acc = Account{
            pub_key_hash : Fr::from(1),
            balance: 1000,
            nonce: 0
        };

        assert_eq!(hash_account(&acc), hash_account(&acc));
    }

}
