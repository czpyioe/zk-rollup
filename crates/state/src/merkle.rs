use ark_bn254::Fr;
use ark_ff::Zero;
use crate::primitives;
use crate::types::Error;

pub struct MerkleTree{
    pub depth: usize,
    nodes : Vec<Vec<Fr>>,
    next_index: usize
}

#[derive(PartialEq)]
pub enum Side{
    Left,
    Right
}

pub struct MerkleProof {
    pub siblings: Vec<(Fr,Side)>, // (hash, side)
    pub leaf: Fr
}


impl MerkleTree{
    pub fn new(depth: usize) -> Self {
        let mut zero_values = Vec::new();
        zero_values.push(primitives::hash_left_right(Fr::zero(), Fr::zero()));
        for i in 1..=depth {
            let z = zero_values[i - 1];
            zero_values.push(primitives::hash_left_right(z, z));
        }

        let nodes = (0..=depth)
            .map(|level| vec![zero_values[level]; 1 << (depth - level)])
            .collect();

        MerkleTree { depth, nodes, next_index: 0 }
    }

    pub fn insert(&mut self, leaf: Fr) -> usize {
        let index = self.next_index;
        self.nodes[0][index] = leaf;

        let mut parent_index = index / 2;
        for level in 1..=self.depth {
            self.nodes[level][parent_index] = primitives::hash_left_right(
                self.nodes[level - 1][parent_index * 2],
                self.nodes[level - 1][parent_index * 2 + 1],
            );
            parent_index /= 2;
        }

        self.next_index += 1;
        index
    }

    pub fn update(&mut self, index: usize, new_account_hash: Fr) -> Result<(),Error>{
        if index >= self.nodes[0].len(){
            return Err(Error::InvalidIndex);
        }

        self.nodes[0][index] = new_account_hash;

        let mut parent_index = index / 2;
        for level in 1..=self.depth {
            self.nodes[level][parent_index] = primitives::hash_left_right(
                self.nodes[level - 1][parent_index * 2],
                self.nodes[level - 1][parent_index * 2 + 1],
            );
            parent_index /= 2;
        }
        Ok(())
    }

    pub fn root(&self) -> Fr {
        self.nodes[self.depth][0]
    }

    pub fn generate_proof(&self, index: usize) -> MerkleProof {
        let leaf = self.nodes[0][index];
        let mut siblings = Vec::new();
        let mut current = index;
        for level in 0..self.depth {
            let side = if current % 2 == 0 { Side::Left } else { Side::Right };
            let sibling_index = current ^ 1; // XOR if even->current+1, if odd->current-1
            siblings.push((self.nodes[level][sibling_index], side));
            current /= 2;
        }
        MerkleProof { siblings, leaf }
    }

    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;
        for (sibling, side) in &proof.siblings {
            current = match side {
                Side::Left  => primitives::hash_left_right(current, *sibling),
                Side::Right => primitives::hash_left_right(*sibling, current),
            };
        }
        current == self.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_merkle_tree() {
        let tree = MerkleTree::new(4);
        let expected_leaf = primitives::hash_left_right(Fr::zero(), Fr::zero());
        assert_eq!(tree.nodes[0].len(), 1 << 4);
        assert_eq!(tree.nodes[4].len(), 1);
        assert_eq!(tree.nodes[0][0], expected_leaf);
        assert_eq!(tree.next_index, 0);
    }

    #[test]
    fn test_insert() {
        let mut tree = MerkleTree::new(4);
        let root_before = tree.root();

        let idx = tree.insert(Fr::from(5));

        assert_eq!(idx, 0);
        assert_eq!(tree.next_index, 1);
        assert_eq!(tree.nodes[0][0], Fr::from(5));
        assert_ne!(tree.root(), root_before);
    }

    #[test]
    fn test_two_inserts() {
        let mut tree = MerkleTree::new(4);

        let idx0 = tree.insert(Fr::from(1));
        let idx1 = tree.insert(Fr::from(2));

        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(tree.nodes[0][0], Fr::from(1));
        assert_eq!(tree.nodes[0][1], Fr::from(2));
        let expected_parent = primitives::hash_left_right(Fr::from(1), Fr::from(2));
        assert_eq!(tree.nodes[1][0], expected_parent);
    }


    #[test]
    fn test_root_empty() {
        let tree = MerkleTree::new(4);
        let z0 = primitives::hash_left_right(Fr::zero(), Fr::zero());
        let z1 = primitives::hash_left_right(z0, z0);
        let z2 = primitives::hash_left_right(z1, z1);
        let z3 = primitives::hash_left_right(z2, z2);
        let expected_root = primitives::hash_left_right(z3, z3);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_generate_and_verify_proof() {
        let mut tree = MerkleTree::new(4);
        let z = Fr::zero();
        let leaf = primitives::hash_left_right(z, primitives::hash_left_right(z, z));
        let idx = tree.insert(leaf);

        let proof = tree.generate_proof(idx);

        assert!(tree.verify_proof(&proof));
    }

    #[test]
    fn test_verify_proof_wrong_proof() {
        let mut tree = MerkleTree::new(4);
        let z = Fr::zero();
        let leaf = primitives::hash_left_right(z, primitives::hash_left_right(z, z));
        tree.insert(leaf);

        let other_leaf = primitives::hash_left_right(z, z);
        let mut other_tree = MerkleTree::new(4);
        let other_idx = other_tree.insert(other_leaf);
        let wrong_proof = other_tree.generate_proof(other_idx);

        assert!(!tree.verify_proof(&wrong_proof));
    }

    #[test]
    fn test_proof_after_multiple_inserts() {
        let mut tree = MerkleTree::new(4);
        let z = Fr::zero();
        let leaf0 = primitives::hash_left_right(z, z);
        let leaf1 = primitives::hash_left_right(leaf0, z);
        let leaf2 = primitives::hash_left_right(z, leaf0);

        let idx0 = tree.insert(leaf0);
        let idx1 = tree.insert(leaf1);
        let idx2 = tree.insert(leaf2);

        assert!(tree.verify_proof(&tree.generate_proof(idx0)));
        assert!(tree.verify_proof(&tree.generate_proof(idx1)));
        assert!(tree.verify_proof(&tree.generate_proof(idx2)));
    }

    #[test]
    fn test_update_changes_root_and_proof() {
        let mut tree = MerkleTree::new(4);
        let idx = tree.insert(Fr::from(1));
        let root_before = tree.root();

        let new_leaf = Fr::from(42);
        tree.update(idx, new_leaf).unwrap();

        assert_ne!(tree.root(), root_before);
        assert_eq!(tree.nodes[0][idx], new_leaf);
        assert!(tree.verify_proof(&tree.generate_proof(idx)));
    }

    #[test]
    fn test_update_out_of_bounds_returns_error() {
        let mut tree = MerkleTree::new(4);
        let out_of_bounds = 1 << 4;

        assert!(tree.update(out_of_bounds, Fr::from(1)).is_err());
    }
}