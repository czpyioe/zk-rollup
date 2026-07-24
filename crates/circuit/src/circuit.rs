use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, boolean::Boolean, eq::EqGadget};
use ark_ff::Zero;

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



        Ok(())
    }
}