use crate::merkle::MerkleTree;
use crate::types::{Account, Transaction,Error};
use crate::primitives::{compute_poseidon_hash, hash_account};


pub struct StateManager {
    merkle_tree: MerkleTree,
    accounts : Vec<Account> 
}

impl StateManager {
    pub fn process_tx(&mut self, tx: &Transaction) -> Result<(),Error>{
        // check if tx is possible before processing
        if tx.sender_idx >= self.accounts.len() || tx.receiver_idx >= self.accounts.len(){
            return Err(Error::InvalidIndex);
        }

        let mut sender = self.accounts[tx.sender_idx];

        if compute_poseidon_hash(tx.sender_secret_key)!=sender.pub_key_hash{
            return Err(Error::InvalidSecretKey);
        }
        else if sender.nonce != tx.nonce {
            return Err(Error::InvalidNonce);
        }
        else if sender.balance<tx.amount{
            return Err(Error::InsufficientBalance);
        }

        let mut receiver = self.accounts[tx.receiver_idx];

        // update Accounts states
        sender.nonce += 1;
        sender.balance -= tx.amount;
        receiver.balance  += tx.amount;

        let sender_new_account_hash = hash_account(&sender);
        let receiver_new_account_hash = hash_account(&receiver);

        self.merkle_tree.update(tx.sender_idx, sender_new_account_hash)?;
        self.accounts[tx.sender_idx] = sender;
        self.merkle_tree.update(tx.receiver_idx, receiver_new_account_hash)?;
        self.accounts[tx.receiver_idx] = receiver;

        Ok(())
    }

}