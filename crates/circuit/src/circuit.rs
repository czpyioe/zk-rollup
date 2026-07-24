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