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
