use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_bn254::Fr;
use ark_r1cs_std::{
    fields::fp::FpVar,
    boolean::Boolean,
    select::CondSelectGadget,
    eq::EqGadget,
};
use crate::gadgets::hash::poseidon_gadget;

pub fn verify_merkle_proof_gadget(
    cs: ConstraintSystemRef<Fr>,
    leaf: FpVar<Fr>,
    siblings: &[FpVar<Fr>],
    sides: &[Boolean<Fr>],
    expected_root: FpVar<Fr>,
) -> Result<(), SynthesisError> {
    let mut current = leaf;

    for (sibling, side) in siblings.iter().zip(sides.iter()) {
        let left = FpVar::conditionally_select(side, sibling, &current)?;
        let right = FpVar::conditionally_select(side, &current, sibling)?;
        current = poseidon_gadget(cs.clone(), &[left, right])?;
    }

    current.enforce_equal(&expected_root)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_r1cs_std::alloc::AllocVar;
    use crypto_primitives::hash::hash_account;
    use crypto_primitives::merkle::MerkleTree;
    use crypto_primitives::types::Account;

    #[test]
    fn test_merkle_gadget_satisfiable() {
        let mut tree = MerkleTree::new(4);
        let acc = Account{
            pub_key_hash: Fr::from(1),
            balance: 100,
            nonce: 0
        };
        let leaf = hash_account(&acc);
        let idx = tree.insert(leaf);
        let proof = tree.generate_proof(idx);
        let root = tree.root();

        let cs = ConstraintSystem::<Fr>::new_ref();

        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

        let siblings_var: Vec<FpVar<Fr>> = proof.siblings.iter()
            .map(|(sib, _)| FpVar::new_witness(cs.clone(), || Ok(*sib)).unwrap())
            .collect();

        let sides_var: Vec<Boolean<Fr>> = proof.siblings.iter()
            .map(|(_, side)| {
                use crypto_primitives::merkle::Side;
                let is_right = *side == Side::Right;
                Boolean::new_witness(cs.clone(), || Ok(is_right)).unwrap()
            })
            .collect();

        verify_merkle_proof_gadget(cs.clone(), leaf_var, &siblings_var, &sides_var, root_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_merkle_gadget_unsatisfiable_wrong_root() {
        let mut tree = MerkleTree::new(4);
        let acc = Account{
            pub_key_hash: Fr::from(1),
            balance: 100,
            nonce: 0
        };
        let leaf = hash_account(&acc);
        let idx = tree.insert(leaf);
        let proof = tree.generate_proof(idx);

        let fake_root = Fr::from(0);

        let cs = ConstraintSystem::<Fr>::new_ref();

        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let fake_root_var = FpVar::new_input(cs.clone(), || Ok(fake_root)).unwrap();

        let siblings_var: Vec<FpVar<Fr>> = proof.siblings.iter()
            .map(|(sib, _)| FpVar::new_witness(cs.clone(), || Ok(*sib)).unwrap())
            .collect();

        let sides_var: Vec<Boolean<Fr>> = proof.siblings.iter()
            .map(|(_, side)| {
                use crypto_primitives::merkle::Side;
                let is_right = *side == Side::Right;
                Boolean::new_witness(cs.clone(), || Ok(is_right)).unwrap()
            })
            .collect();

        verify_merkle_proof_gadget(cs.clone(), leaf_var, &siblings_var, &sides_var, fake_root_var).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
