use crate::merkle::MerkleTree;
use crate::types::Account;

pub struct StateManager {
    merkle_tree: MerkleTree,
    accounts : Vec<Account> 
}