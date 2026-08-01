# zk-rollup

A learning project to experiment with and improve ZK skills using [Arkworks](https://arkworks.rs/). This is not a production rollup.

The sequencer is intentionally hardcoded (fixed accounts, fixed transactions) rather than an interactive app (cli, server,..). the goal here is to learn and train on ZK circuits and proving, not to build a usable product.

## Not for production

The sequencer signs transactions with a well-known, public anvil private key, so anyone can call the contract as the sequencer. The circuit also has no ECDSA/signature verification, sender authorization is not cryptographically bound to a real key.

## Running locally

```
cargo run -p sequencer --bin genesis_root

anvil

forge script script/Deploy.s.sol:Deploy --rpc-url http://localhost:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --broadcast

cargo run -p sequencer
```

Example output:

```
❯ cargo run -p sequencer --bin sequencer
old_root = 0x0fae6368f7f3a04655da2c6de2d9962be2dea294bcae334da0f51316c218573a
new_root = 0x1df66c6e9c927e6d759c6f0225cb65cd44c92af530dda5d99410fd85c2bbf919
batch_hash = 0x27f9e58032bf504b3b41ce11dd50ed329e928ea486a3e85357730ca525c9290c
submitting batch to Rollup at 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9...
tx hash = 0xf5eb70c5aed6750dfd77d1cdff31bdce22daace2279544b1456b54d963007f2d
status = true
on-chain current_root = 0x1df66c6e9c927e6d759c6f0225cb65cd44c92af530dda5d99410fd85c2bbf919
on-chain index = 1
```

## References

- [Arkworks Groth16 Overview](https://deepwiki.com/arkworks-rs/groth16/1-groth16-overview)
- [arkworks.rs](https://arkworks.rs/)
- [alloy.rs](https://alloy.rs/)
- [The Rust Book](https://doc.rust-lang.org/stable/book/title-page.html)
