use alloy::primitives::{Address, B256, Bytes};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use prover::keys;
use prover::prove::generate_proof;
use prover::types::{ProofInputs, fq_to_be_bytes};
use sequencer::{batch, fixtures};



sol! {
    #[sol(rpc)]
    interface IRollup {
        function process_batch(bytes calldata proof, bytes32 old_root, bytes32 new_root, bytes32 batch_hash) external;
        function current_root() external view returns (bytes32);
        function index() external view returns (uint256);
    }
}

const ANVIL_SEQUENCER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_RPC_URL: &str = "http://localhost:8545";

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenvy::dotenv().ok();

    let rollup_address: Address = std::env::var("ROLLUP_ADDRESS")
        .expect("set ROLLUP_ADDRESS")
        .parse()?;

    let witness = batch::build_batch(fixtures::accounts(), fixtures::txs());
    let old_root = witness.old_root.unwrap();
    let new_root = witness.new_root.unwrap();
    let batch_hash = witness.batch_hash.unwrap();

    println!("old_root = 0x{}", hex::encode(fq_to_be_bytes(old_root)));
    println!("new_root = 0x{}", hex::encode(fq_to_be_bytes(new_root)));
    println!("batch_hash = 0x{}", hex::encode(fq_to_be_bytes(batch_hash)));

    let pk = keys::load_pk();
    let inputs = ProofInputs { txs: witness.txs, old_root, new_root, batch_hash };
    let (proof, _public_inputs) = generate_proof(inputs, &pk).map_err(|e| eyre::eyre!(e))?;

    let signer: PrivateKeySigner = ANVIL_SEQUENCER_KEY.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(ANVIL_RPC_URL.parse()?);

    let rollup = IRollup::new(rollup_address, provider);

    let old_root = B256::from(fq_to_be_bytes(old_root));
    let new_root = B256::from(fq_to_be_bytes(new_root));
    let batch_hash = B256::from(fq_to_be_bytes(batch_hash));
    let proof_bytes = Bytes::from(proof.to_solidity_call_data());

    println!("submitting batch to Rollup at {rollup_address}...");
    let pending = rollup
        .process_batch(proof_bytes, old_root, new_root, batch_hash)
        .send()
        .await?;
    let receipt = pending.get_receipt().await?;

    println!("tx hash = {:?}", receipt.transaction_hash);
    println!("status = {}", receipt.status());
    println!("on-chain current_root = {:?}", rollup.current_root().call().await?);
    println!("on-chain index = {}", rollup.index().call().await?);

    Ok(())
}
