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
    pub sender_merkle_path: Option<Vec<(Fr,bool)>>,
    pub receiver_balance: Option<Fr>,
    pub receiver_markle_path: Option<Vec<(Fr,bool)>>,

    // public vars (inputs)
    pub old_root: Option<Fr>,
    pub now_root: Option<Fr>,
}

