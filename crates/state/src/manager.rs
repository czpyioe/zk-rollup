use crate::merkle::MerkleTree;
use crate::types::{Account, Transaction,Error};
use crate::primitives::{compute_poseidon_hash, hash_account};


pub struct StateManager {
    merkle_tree: MerkleTree,
    accounts : Vec<Account> 
}

impl StateManager {
    pub fn new(merkle_depth: usize) -> Self{
        Self {
            merkle_tree: MerkleTree::new(merkle_depth),
            accounts : Vec::new()
        }
    }

    pub fn add_account(&mut self, account: Account) -> Result<usize,Error>{
        if self.accounts.len()>= 1 << self.merkle_tree.depth{
            return Err(Error::MerkleTreeFull);
        }

        let idx = self.merkle_tree.insert(hash_account(&account));
        self.accounts.push(account);
        Ok(idx)
    }


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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use crate::primitives::compute_poseidon_hash;

    fn make_account(sk: u64, balance: u64) -> (Fr, Account) {
        let secret_key = Fr::from(sk);
        let account = Account {
            pub_key_hash: compute_poseidon_hash(secret_key),
            balance,
            nonce: 0,
        };
        (secret_key, account)
    }

    fn setup() -> (StateManager, Fr, Fr) {
        let mut state = StateManager::new(4);
        let (alice_sk, alice) = make_account(1, 1000);
        let (bob_sk, bob) = make_account(2, 500);
        state.add_account(alice).unwrap();
        state.add_account(bob).unwrap();
        (state, alice_sk, bob_sk)
    }

    #[test]
    fn test_valid_tx_updates_balances_and_root() {
        let (mut state, alice_sk, _) = setup();
        let root_before = state.merkle_tree.root();

        let tx = Transaction { sender_idx: 0, receiver_idx: 1, amount: 100, nonce: 0, sender_secret_key: alice_sk };
        state.process_tx(&tx).unwrap();

        assert_eq!(state.accounts[0].balance, 900);
        assert_eq!(state.accounts[1].balance, 600);
        assert_eq!(state.accounts[0].nonce, 1);
        assert_ne!(state.merkle_tree.root(), root_before);
    }

    #[test]
    fn test_invalid_secret_key_rejected() {
        let (mut state, _, _) = setup();

        let tx = Transaction { sender_idx: 0, receiver_idx: 1, amount: 100, nonce: 0, sender_secret_key: Fr::from(99) };
        let err = state.process_tx(&tx).unwrap_err();

        assert!(matches!(err, Error::InvalidSecretKey));
    }

    #[test]
    fn test_invalid_nonce_rejected() {
        let (mut state, alice_sk, _) = setup();

        let tx = Transaction { sender_idx: 0, receiver_idx: 1, amount: 100, nonce: 99, sender_secret_key: alice_sk };
        let err = state.process_tx(&tx).unwrap_err();

        assert!(matches!(err, Error::InvalidNonce));
    }

    #[test]
    fn test_insufficient_balance_rejected() {
        let (mut state, alice_sk, _) = setup();

        let tx = Transaction { sender_idx: 0, receiver_idx: 1, amount: 9999, nonce: 0, sender_secret_key: alice_sk };
        let err = state.process_tx(&tx).unwrap_err();

        assert!(matches!(err, Error::InsufficientBalance));
    }

    #[test]
    fn test_invalid_index_rejected() {
        let (mut state, alice_sk, _) = setup();

        let tx = Transaction { sender_idx: 0, receiver_idx: 99, amount: 100, nonce: 0, sender_secret_key: alice_sk };
        let err = state.process_tx(&tx).unwrap_err();

        assert!(matches!(err, Error::InvalidIndex));
    }

    #[test]
    fn test_nonce_increments_after_each_tx() {
        let (mut state, alice_sk, _) = setup();

        let tx1 = Transaction { sender_idx: 0, receiver_idx: 1, amount: 100, nonce: 0, sender_secret_key: alice_sk };
        state.process_tx(&tx1).unwrap();
        assert_eq!(state.accounts[0].nonce, 1);

        let tx2 = Transaction { sender_idx: 0, receiver_idx: 1, amount: 100, nonce: 1, sender_secret_key: alice_sk };
        state.process_tx(&tx2).unwrap();
        assert_eq!(state.accounts[0].nonce, 2);
    }

    #[test]
    fn test_add_account_beyond_capacity_rejected() {
        let mut state = StateManager::new(2); // depth 2 = 4 leaves max
        for i in 0..4 {
            let (_, account) = make_account(i, 100);
            state.add_account(account).unwrap();
        }
        let (_, extra) = make_account(99, 100);
        let err = state.add_account(extra).unwrap_err();

        assert!(matches!(err, Error::MerkleTreeFull));
    }
}