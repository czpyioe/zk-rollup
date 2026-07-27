use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, boolean::Boolean};
use ark_ff::Zero;
use core::cmp::Ordering;

use crate::gadgets::hash;
use crate::gadgets::merkle;



pub const TREE_DEPTH: usize = 8;

pub const BATCH_SIZE: usize = 4;


#[derive(Clone,Debug)]
pub struct TxWitness {
    // private vars (witness)
    pub sender_sk: Option<Fr>,
    pub sender_balance: Option<Fr>,
    pub sender_nonce: Option<Fr>,
    pub sender_merkle_siblings: Option<Vec<Fr>>,
    pub sender_merkle_siblings_side: Option<Vec<bool>>,
    pub amount: Option<Fr>,

    pub intermediate_root: Option<Fr>,
    pub new_root: Option<Fr>,

    pub receiver_balance: Option<Fr>,
    pub receiver_merkle_siblings: Option<Vec<Fr>>,
    pub receiver_merkle_siblings_side: Option<Vec<bool>>,
    pub receiver_nonce: Option<Fr>,
    pub receiver_public_key: Option<Fr>,
}


#[derive(Clone,Debug)]
pub struct ZkRollup {
    // private vars (witness)
    pub txs: [Option<TxWitness>;BATCH_SIZE],

    // public vars (inputs)
    pub old_root: Option<Fr>,
    pub new_root: Option<Fr>,
    pub batch_hash : Option<Fr>
}

impl Default for ZkRollup {
    fn default() -> Self {
        let tx = TxWitness{
            sender_sk: Some(Fr::from(0)),
            sender_balance: Some(Fr::from(0)),
            sender_nonce: Some(Fr::from(0)),
            sender_merkle_siblings: Some(vec![Fr::zero(); TREE_DEPTH]),
            sender_merkle_siblings_side: Some(vec![false; TREE_DEPTH]),
            amount: Some(Fr::from(0)),
            intermediate_root: Some(Fr::from(0)),
            new_root: Some(Fr::from(0)),
            receiver_balance: Some(Fr::from(0)),
            receiver_merkle_siblings: Some(vec![Fr::zero(); TREE_DEPTH]),
            receiver_merkle_siblings_side: Some(vec![false; TREE_DEPTH]),
            receiver_nonce: Some(Fr::from(0)),
            receiver_public_key: Some(Fr::from(0)),
        };
        let txs = core::array::from_fn(|_| Some(tx.clone()));
        Self {
            txs,
            old_root: Some(Fr::from(0)),
            new_root: Some(Fr::from(0)),
            batch_hash: Some(Fr::from(0))
        }
    }
}


fn apply_tx_constraints(cs: ConstraintSystemRef<Fr>, tx: TxWitness, old_root: FpVar<Fr>) -> Result<(FpVar<Fr>, FpVar<Fr>),SynthesisError>{
    // witnesses
    let sender_sk = FpVar::new_witness(cs.clone(), || tx.sender_sk.ok_or(SynthesisError::AssignmentMissing))?;
    let sender_balance = FpVar::new_witness(cs.clone(), || tx.sender_balance.ok_or(SynthesisError::AssignmentMissing))?;
    let sender_nonce = FpVar::new_witness(cs.clone(), || tx.sender_nonce.ok_or(SynthesisError::AssignmentMissing))?;

    let sender_merkle_siblings: Vec<FpVar<Fr>> = tx.sender_merkle_siblings
        .ok_or(SynthesisError::AssignmentMissing)?
        .iter()
        .map(|sib| FpVar::new_witness(cs.clone(), || Ok(*sib)).unwrap())
        .collect();

    let sender_merkle_siblings_side: Vec<Boolean<Fr>> = tx.sender_merkle_siblings_side
        .ok_or(SynthesisError::AssignmentMissing)?
        .iter()
        .map(|side| Boolean::new_witness(cs.clone(), || Ok(*side)).unwrap())
        .collect();

    let amount = FpVar::new_witness(cs.clone(), || tx.amount.ok_or(SynthesisError::AssignmentMissing))?;
    let intermediate_root = FpVar::new_witness(cs.clone(), || tx.intermediate_root.ok_or(SynthesisError::AssignmentMissing))?;
    let new_root = FpVar::new_witness(cs.clone(), || tx.new_root.ok_or(SynthesisError::AssignmentMissing))?;
    let receiver_balance = FpVar::new_witness(cs.clone(), || tx.receiver_balance.ok_or(SynthesisError::AssignmentMissing))?;

    let receiver_merkle_siblings: Vec<FpVar<Fr>> = tx.receiver_merkle_siblings
        .ok_or(SynthesisError::AssignmentMissing)?
        .iter()
        .map(|sib| FpVar::new_witness(cs.clone(), || Ok(*sib)).unwrap())
        .collect();

    let receiver_merkle_siblings_side: Vec<Boolean<Fr>> = tx.receiver_merkle_siblings_side
        .ok_or(SynthesisError::AssignmentMissing)?
        .iter()
        .map(|side| Boolean::new_witness(cs.clone(), || Ok(*side)).unwrap())
        .collect();

    let receiver_nonce = FpVar::new_witness(cs.clone(), || tx.receiver_nonce.ok_or(SynthesisError::AssignmentMissing))?;
    let receiver_public_key = FpVar::new_witness(cs.clone(), || tx.receiver_public_key.ok_or(SynthesisError::AssignmentMissing))?;


    // derive public key from secret key, so the merkle proof is invalid if the secret key is incorrect
    let sender_public_key = hash::poseidon_gadget(cs.clone(), &[sender_sk])?;
    let sender_hash = hash::poseidon_gadget(cs.clone(), &[sender_public_key.clone(), sender_balance.clone(), sender_nonce.clone()])?;

    // check that sender is in the tree
    merkle::verify_merkle_proof_gadget(cs.clone(), sender_hash, &sender_merkle_siblings, &sender_merkle_siblings_side, old_root)?;

    // check that sender balance >= tx amount
    sender_balance.enforce_cmp(&amount, Ordering::Greater, true)?;

    // check intermediate root after updating the sender leaf
    // if nonce is incorrect, the merkle proof is going to be false
    let one = FpVar::constant(Fr::from(1));
    let intermediate_sender_hash = hash::poseidon_gadget(cs.clone(), &[sender_public_key.clone(), sender_balance.clone() - amount.clone(), sender_nonce.clone() + one])?;
    merkle::verify_merkle_proof_gadget(cs.clone(), intermediate_sender_hash, &sender_merkle_siblings, &sender_merkle_siblings_side, intermediate_root.clone())?;

    // check that the old receiver leaf is in the intermediate tree
    let receiver_hash = hash::poseidon_gadget(cs.clone(), &[receiver_public_key.clone(), receiver_balance.clone(), receiver_nonce.clone()])?;
    merkle::verify_merkle_proof_gadget(cs.clone(), receiver_hash, &receiver_merkle_siblings, &receiver_merkle_siblings_side, intermediate_root.clone())?;

    // check that the new receiver leaf is in the new merkle tree
    let new_receiver_leaf = hash::poseidon_gadget(cs.clone(), &[receiver_public_key.clone(), receiver_balance.clone() + amount.clone(), receiver_nonce.clone()])?;
    merkle::verify_merkle_proof_gadget(cs.clone(), new_receiver_leaf, &receiver_merkle_siblings, &receiver_merkle_siblings_side, new_root.clone())?;

    // commitment to this tx's public-facing data, chained into the batch hash by the caller.
    // sender_sk is deliberately excluded: it must never leak into a public input.
    let tx_commitment = hash::poseidon_gadget(cs.clone(), &[sender_public_key, receiver_public_key, amount, sender_nonce])?;

    Ok((new_root, tx_commitment))
}


impl ConstraintSynthesizer<Fr> for ZkRollup{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(),SynthesisError> {
        //public inputs
        let old_root = FpVar::new_input(cs.clone(), || self.old_root.ok_or(SynthesisError::AssignmentMissing))?;
        let new_root = FpVar::new_input(cs.clone(), || self.new_root.ok_or(SynthesisError::AssignmentMissing))?;
        let batch_hash = FpVar::new_input(cs.clone(), || self.batch_hash.ok_or(SynthesisError::AssignmentMissing))?;

        //constraints
        let mut current_root = old_root;
        let mut running_hash = FpVar::constant(Fr::zero());
        for tx in self.txs {
            let tx = tx.ok_or(SynthesisError::AssignmentMissing)?;
            let (next_root, tx_commitment) = apply_tx_constraints(cs.clone(), tx, current_root)?;
            current_root = next_root;
            running_hash = hash::poseidon_gadget(cs.clone(), &[running_hash, tx_commitment])?;
        }

        // the final chained root must match the publicly claimed new_root
        current_root.enforce_equal(&new_root)?;
        running_hash.enforce_equal(&batch_hash)?;

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_crypto_primitives::crh::{poseidon::CRH, CRHScheme};
    use crypto_primitives::hash::{compute_poseidon_hash, hash_account, poseidon_config};
    use crypto_primitives::merkle::{MerkleTree, Side};
    use crypto_primitives::types::Account;

    #[derive(Clone)]
    struct TxSpec {
        sender_idx: usize,
        sender_sk: Fr,
        amount: u64,
        receiver_idx: usize,
        receiver_public_key: Fr,
    }

    fn native_hash(inputs: Vec<Fr>) -> Fr {
        CRH::<Fr>::evaluate(&poseidon_config(), inputs).unwrap()
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

            let tx_commitment = native_hash(vec![
                sender.pub_key_hash,
                receiver.pub_key_hash,
                Fr::from(tx.amount),
                Fr::from(sender.nonce),
            ]);
            running_hash = native_hash(vec![running_hash, tx_commitment]);

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
    fn test_batch_circuit_satisfiable() {
        let circuit = default_batch();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_batch_circuit_wrong_secret_key_in_middle_tx() {
        let mut circuit = default_batch();
        circuit.txs[2].as_mut().unwrap().sender_sk = Some(Fr::from(999u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_batch_circuit_wrong_sender_nonce() {
        let mut circuit = default_batch();
        circuit.txs[0].as_mut().unwrap().sender_nonce = Some(Fr::from(41u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_batch_circuit_insufficient_balance() {
        let mut circuit = default_batch();
        circuit.txs[0].as_mut().unwrap().amount = Some(Fr::from(9_999u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_batch_circuit_broken_root_chain() {
        let mut circuit = default_batch();
        circuit.txs[0].as_mut().unwrap().new_root = Some(Fr::from(0u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_batch_circuit_wrong_old_root() {
        let mut circuit = default_batch();
        circuit.old_root = Some(Fr::from(0u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_batch_circuit_wrong_new_root() {
        let mut circuit = default_batch();
        circuit.new_root = Some(Fr::from(0u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_batch_circuit_tampered_batch_hash() {
        let mut circuit = default_batch();
        circuit.batch_hash = Some(Fr::from(0u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_batch_circuit_amount_mismatched_with_tree() {
        let mut circuit = default_batch();
        circuit.txs[0].as_mut().unwrap().amount = Some(Fr::from(1u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
