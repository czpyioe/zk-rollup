use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, boolean::Boolean};
use ark_ff::Zero;
use core::cmp::Ordering;

use crate::gadgets::hash;
use crate::gadgets::merkle;



pub const TREE_DEPTH: usize = 8;


#[derive(Clone,Debug)]
pub struct ZkRollup {
    // private vars (witness)
    pub sender_sk: Option<Fr>,
    pub sender_balance: Option<Fr>,
    pub sender_nonce: Option<Fr>,
    pub sender_merkle_siblings: Option<Vec<Fr>>,
    pub sender_merkle_siblings_side: Option<Vec<bool>>,
    pub amount: Option<Fr>,

    pub intermediate_root: Option<Fr>,

    pub receiver_balance: Option<Fr>,
    pub receiver_merkle_siblings: Option<Vec<Fr>>,
    pub receiver_merkle_siblings_side: Option<Vec<bool>>,
    pub receiver_nonce: Option<Fr>,
    pub receiver_public_key: Option<Fr>,

    // public vars (inputs)
    pub old_root: Option<Fr>,
    pub new_root: Option<Fr>,
}

impl Default for ZkRollup {
    fn default() -> Self {
        Self { 
            sender_sk: Some(Fr::from(0)), 
            sender_balance: Some(Fr::from(0)), 
            sender_nonce: Some(Fr::from(0)), 
            sender_merkle_siblings: Some(vec![Fr::zero(); TREE_DEPTH]), 
            sender_merkle_siblings_side: Some(vec![false; TREE_DEPTH]),
            amount: Some(Fr::from(0)), 
            intermediate_root: Some(Fr::from(0)), 
            receiver_balance: Some(Fr::from(0)), 
            receiver_merkle_siblings: Some(vec![Fr::zero(); TREE_DEPTH]), 
            receiver_merkle_siblings_side: Some(vec![false; TREE_DEPTH]),
            receiver_nonce: Some(Fr::from(0)), 
            receiver_public_key: Some(Fr::from(0)), 
            old_root: Some(Fr::from(0)), 
            new_root: Some(Fr::from(0))
        }
    }
}

impl ConstraintSynthesizer<Fr> for ZkRollup{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(),SynthesisError> {
        // witnesses
        let sender_sk = FpVar::new_witness(cs.clone(), || self.sender_sk.ok_or(SynthesisError::AssignmentMissing))?;
        let sender_balance = FpVar::new_witness(cs.clone(), || self.sender_balance.ok_or(SynthesisError::AssignmentMissing))?;
        let sender_nonce = FpVar::new_witness(cs.clone(), || self.sender_nonce.ok_or(SynthesisError::AssignmentMissing))?;

        let sender_merkle_siblings: Vec<FpVar<Fr>> = self.sender_merkle_siblings
            .ok_or(SynthesisError::AssignmentMissing)?
            .iter()
            .map(|sib| FpVar::new_witness(cs.clone(), || Ok(*sib)).unwrap())
            .collect();

        let sender_merkle_siblings_side: Vec<Boolean<Fr>> = self.sender_merkle_siblings_side
            .ok_or(SynthesisError::AssignmentMissing)?
            .iter()
            .map(|side| Boolean::new_witness(cs.clone(), || Ok(*side)).unwrap())
            .collect();

        let amount = FpVar::new_witness(cs.clone(), || self.amount.ok_or(SynthesisError::AssignmentMissing))?;
        let intermediate_root = FpVar::new_witness(cs.clone(), || self.intermediate_root.ok_or(SynthesisError::AssignmentMissing))?;
        let receiver_balance = FpVar::new_witness(cs.clone(), || self.receiver_balance.ok_or(SynthesisError::AssignmentMissing))?;

        let receiver_merkle_siblings: Vec<FpVar<Fr>> = self.receiver_merkle_siblings
            .ok_or(SynthesisError::AssignmentMissing)?
            .iter()
            .map(|sib| FpVar::new_witness(cs.clone(), || Ok(*sib)).unwrap())
            .collect();

        let receiver_merkle_siblings_side: Vec<Boolean<Fr>> = self.receiver_merkle_siblings_side
            .ok_or(SynthesisError::AssignmentMissing)?
            .iter()
            .map(|side| Boolean::new_witness(cs.clone(), || Ok(*side)).unwrap())
            .collect();

        let receiver_nonce = FpVar::new_witness(cs.clone(), || self.receiver_nonce.ok_or(SynthesisError::AssignmentMissing))?;
        let receiver_public_key = FpVar::new_witness(cs.clone(), || self.receiver_public_key.ok_or(SynthesisError::AssignmentMissing))?;


        //public inpputs
        let old_root = FpVar::new_input(cs.clone(), || self.old_root.ok_or(SynthesisError::AssignmentMissing))?;
        let new_root = FpVar::new_input(cs.clone(), || self.new_root.ok_or(SynthesisError::AssignmentMissing))?;




        //constraints

        // commpute public key from secret key, so proof merkle proof will be invalid if the secret key is incorrect
        let sender_public_key = hash::poseidon_gadget(cs.clone(), &[sender_sk])?;
        let sender_hash = hash::poseidon_gadget(cs.clone(), &[sender_public_key.clone(), sender_balance.clone(), sender_nonce.clone()])?;

        // check that sender is in the tree
        merkle::verify_merkle_proof_gadget(cs.clone(), sender_hash, &sender_merkle_siblings, &sender_merkle_siblings_side, old_root)?;

        // check that sender balance >= tx amount
        sender_balance.enforce_cmp(&amount, Ordering::Greater, true)?;

        // check intermediate root after updating the the sender leaf
        // if nonce is incorrect, the merkle proof is going to be false
        let one = FpVar::constant(Fr::from(1));
        let intermediate_sender_hash = hash::poseidon_gadget(cs.clone(), &[sender_public_key.clone(), sender_balance.clone() - amount.clone(), sender_nonce.clone() + one])?;
        merkle::verify_merkle_proof_gadget(cs.clone(), intermediate_sender_hash, &sender_merkle_siblings, &sender_merkle_siblings_side, intermediate_root.clone())?;

        // check that the old receiver leaf is in the intermmediate tree
        let receiver_hash = hash::poseidon_gadget(cs.clone(), &[receiver_public_key.clone(), receiver_balance.clone(), receiver_nonce.clone()])?;
        merkle::verify_merkle_proof_gadget(cs.clone(), receiver_hash, &receiver_merkle_siblings, &receiver_merkle_siblings_side, intermediate_root.clone())?;

        // check that the new receiver leaf is in the new merkle tree
        let new_receiver_leaf = hash::poseidon_gadget(cs.clone(), &[receiver_public_key.clone(), receiver_balance.clone() + amount.clone(), receiver_nonce.clone()])?;
        merkle::verify_merkle_proof_gadget(cs.clone(), new_receiver_leaf, &receiver_merkle_siblings, &receiver_merkle_siblings_side, new_root.clone())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::ConstraintSystem;
    use crypto_primitives::hash::{compute_poseidon_hash, hash_account};
    use crypto_primitives::merkle::{MerkleTree, Side};
    use crypto_primitives::types::Account;


    fn build_valid_circuit(
        sender_sk: Fr,
        sender_balance: u64,
        sender_nonce: u64,
        amount: u64,
        receiver_public_key: Fr,
        receiver_balance: u64,
        receiver_nonce: u64,
    ) -> ZkRollup {
        let sender_public_key = compute_poseidon_hash(sender_sk);

        let sender_leaf = hash_account(&Account {
            pub_key_hash: sender_public_key,
            balance: sender_balance,
            nonce: sender_nonce,
        });
        let receiver_leaf = hash_account(&Account {
            pub_key_hash: receiver_public_key,
            balance: receiver_balance,
            nonce: receiver_nonce,
        });

        let mut tree = MerkleTree::new(TREE_DEPTH);
        let sender_idx = tree.insert(sender_leaf);
        let receiver_idx = tree.insert(receiver_leaf);
        let old_root = tree.root();

        let sender_proof = tree.generate_proof(sender_idx);
        let sender_siblings: Vec<Fr> = sender_proof.siblings.iter().map(|(s, _)| *s).collect();
        let sender_sides: Vec<bool> = sender_proof
            .siblings
            .iter()
            .map(|(_, side)| *side == Side::Right)
            .collect();

        let new_sender_leaf = hash_account(&Account {
            pub_key_hash: sender_public_key,
            balance: sender_balance - amount,
            nonce: sender_nonce + 1,
        });
        tree.update(sender_idx, new_sender_leaf).unwrap();
        let intermediate_root = tree.root();

        let receiver_proof = tree.generate_proof(receiver_idx);
        let receiver_siblings: Vec<Fr> = receiver_proof.siblings.iter().map(|(s, _)| *s).collect();
        let receiver_sides: Vec<bool> = receiver_proof
            .siblings
            .iter()
            .map(|(_, side)| *side == Side::Right)
            .collect();

        let new_receiver_leaf = hash_account(&Account {
            pub_key_hash: receiver_public_key,
            balance: receiver_balance + amount,
            nonce: receiver_nonce,
        });
        tree.update(receiver_idx, new_receiver_leaf).unwrap();
        let new_root = tree.root();

        ZkRollup {
            sender_sk: Some(sender_sk),
            sender_balance: Some(Fr::from(sender_balance)),
            sender_nonce: Some(Fr::from(sender_nonce)),
            sender_merkle_siblings: Some(sender_siblings),
            sender_merkle_siblings_side: Some(sender_sides),
            amount: Some(Fr::from(amount)),
            intermediate_root: Some(intermediate_root),
            receiver_balance: Some(Fr::from(receiver_balance)),
            receiver_merkle_siblings: Some(receiver_siblings),
            receiver_merkle_siblings_side: Some(receiver_sides),
            receiver_nonce: Some(Fr::from(receiver_nonce)),
            receiver_public_key: Some(receiver_public_key),
            old_root: Some(old_root),
            new_root: Some(new_root),
        }
    }

    fn default_circuit() -> ZkRollup {
        build_valid_circuit(Fr::from(1u64), 1_000, 5, 100, Fr::from(777u64), 50, 2)
    }

    #[test]
    fn test_circuit_satisfiable() {
        let circuit = default_circuit();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_wrong_secret_key() {
        let mut circuit = default_circuit();
        circuit.sender_sk = Some(Fr::from(999u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_wrong_sender_nonce() {
        let mut circuit = default_circuit();
        circuit.sender_nonce = Some(Fr::from(0u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_insufficient_balance() {
        let mut circuit = default_circuit();
        circuit.amount = Some(Fr::from(2_000u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_amount_mismatched_with_tree() {
        let mut circuit = default_circuit();
        circuit.amount = Some(Fr::from(1u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_wrong_receiver_public_key() {
        let mut circuit = default_circuit();
        circuit.receiver_public_key = Some(Fr::from(0u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_wrong_receiver_balance() {
        let mut circuit = default_circuit();
        circuit.receiver_balance = Some(Fr::from(999u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_wrong_old_root() {
        let mut circuit = default_circuit();
        circuit.old_root = Some(Fr::from(0u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_wrong_intermediate_root() {
        let mut circuit = default_circuit();
        circuit.intermediate_root = Some(Fr::from(0u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_circuit_wrong_new_root() {
        let mut circuit = default_circuit();
        circuit.new_root = Some(Fr::from(0u64));

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}