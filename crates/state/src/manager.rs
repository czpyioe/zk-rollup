use crate::merkle::MerkleTree;
use crate::types::{Account, Transaction};
use crate::primitives::compute_poseidon_hash;

enum Error{
    InvalidSecretKey,
    InvalidNonce,
    InsufficientBalance,
    InvalidIndex
}

pub struct StateManager {
    merkle_tree: MerkleTree,
    accounts : Vec<Account> 
}

impl StateManager {
    pub fn process_tx(&self, tx: &Transaction) -> Result<(),Error>{
        let sender = &self.accounts[tx.sender_idx];
        if compute_poseidon_hash(tx.sender_secret_key)!=sender.pub_key_hash{
            return Err(Error::InvalidSecretKey);
        }
        else if sender.nonce != tx.nonce {
            return Err(Error::InvalidNonce);
        }
        else if sender.balance<tx.amount{
            return Err(Error::InsufficientBalance);
        }

        Ok(())
    }

}