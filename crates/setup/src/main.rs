use ark_snark::CircuitSpecificSetupSNARK;
use rand::rngs::OsRng;
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_groth16::data_structures::VerifyingKey;
use circuit::circuit;
use ark_serialize::CanonicalSerialize;
use anyhow::Result;
use std::fs;



// in arkworks, in Fq2, the elements have the form: `c = c0 + c1 * X`
// in the solidity verifier contracts, elements have the form: a*i + b
// EIP-197: https://eips.ethereum.org/EIPS/eip-197
fn generate_verifier_contract(vk:VerifyingKey<Bn254>) -> Result<String> {
    let path_verifier_template = concat!(env!("CARGO_MANIFEST_DIR"), "/src/contract/Verifier_template.sol");
    let path_verifier_output   = concat!(env!("CARGO_MANIFEST_DIR"), "/src/contract/generated/Verifier.sol");

    let mut verifier_output = fs::read_to_string(path_verifier_template)?;
    fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/src/contract/generated"))?;


    // alpha1
    verifier_output = verifier_output.replace("{{ALFA1_X}}", &vk.alpha_g1.x.to_string());
    verifier_output = verifier_output.replace("{{ALFA1_Y}}", &vk.alpha_g1.y.to_string());



    // beta2
    verifier_output = verifier_output.replace("{{BETA2_X0}}", &vk.beta_g2.x.c1.to_string());
    verifier_output = verifier_output.replace("{{BETA2_X1}}", &vk.beta_g2.x.c0.to_string());
    verifier_output = verifier_output.replace("{{BETA2_Y0}}", &vk.beta_g2.y.c1.to_string());
    verifier_output = verifier_output.replace("{{BETA2_Y1}}", &vk.beta_g2.y.c0.to_string());



    // gamma2   
    verifier_output = verifier_output.replace("{{GAMMA2_X0}}", &vk.gamma_g2.x.c1.to_string());
    verifier_output = verifier_output.replace("{{GAMMA2_X1}}", &vk.gamma_g2.x.c0.to_string());
    verifier_output = verifier_output.replace("{{GAMMA2_Y0}}", &vk.gamma_g2.y.c1.to_string());
    verifier_output = verifier_output.replace("{{GAMMA2_Y1}}", &vk.gamma_g2.y.c0.to_string());



    // delta2
    verifier_output = verifier_output.replace("{{DELTA2_X0}}", &vk.delta_g2.x.c1.to_string());
    verifier_output = verifier_output.replace("{{DELTA2_X1}}", &vk.delta_g2.x.c0.to_string());
    verifier_output = verifier_output.replace("{{DELTA2_Y0}}", &vk.delta_g2.y.c1.to_string());
    verifier_output = verifier_output.replace("{{DELTA2_Y1}}", &vk.delta_g2.y.c0.to_string());




    // IC
    let ic_entries: String = vk.gamma_abc_g1.iter()
        .enumerate()
        .map(|(i, v)| {
            format!(
                "        vk.IC[{}] = Pairing.G1Point(uint256({}), uint256({}));\n",
                i,
                v.x.to_string(),
                v.y.to_string()
            )
        })
        .collect();
    verifier_output = verifier_output.replace("{{IC_ENTRIES}}", &ic_entries);



    // IC length
    verifier_output = verifier_output.replace("{{IC_LENGTH}}", &vk.gamma_abc_g1.len().to_string());

    // input size
    verifier_output = verifier_output.replace("{{INPUT_SIZE}}", &(vk.gamma_abc_g1.len()-1).to_string());


    fs::write(path_verifier_output, verifier_output)?;
    Ok(path_verifier_output.to_string())
}

fn main() {
    let mut rng = OsRng;
    let circuit = circuit::ZkRollup::default();
    let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng).unwrap();

    let mut pk_compressed_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_compressed_bytes).unwrap();

    let mut vk_compressed_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_compressed_bytes).unwrap();


    std::fs::create_dir_all("keys").unwrap();
    std::fs::write("keys/proving_key.bin", &pk_compressed_bytes).unwrap();
    std::fs::write("keys/verification_key.bin", &vk_compressed_bytes).unwrap();
    println!("pk: {} bytes", pk_compressed_bytes.len());
    println!("vk: {} bytes", vk_compressed_bytes.len());


    match generate_verifier_contract(vk) {
        Ok(path)=>println!("Verifier contract saved at: {}",path),
        Err(e)=>eprintln!("Error while genertaing the verifier contract: {}",e)
    }
}
