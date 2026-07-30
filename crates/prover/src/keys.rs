use ark_bn254::Bn254;
use ark_groth16::data_structures::ProvingKey;
use ark_serialize::CanonicalDeserialize;

pub fn load_pk() -> ProvingKey<Bn254> {
    let pk_bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../keys/proving_key.bin"))
        .expect("keys/proving_key.bin not found. run the setup binary first");
    let pk = ProvingKey::deserialize_compressed(pk_bytes.as_slice()).unwrap();
    pk
}