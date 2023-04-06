use anyhow::Result;
use log::LevelFilter;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ed25519::gadgets::eddsa::EDDSATargets;
use plonky2_sha256::circuit::Sha256Targets;
use plonky2_test_case4_2::data_type::{Block, BlockType, Data, EpochBlock};
use plonky2_test_case4_2::sig_hash_circuit::{
    aggregation_two, hash_circuit_proof, sig_circuit_proof,
};
use plonky2_test_case4_2::sig_hash_circuit::{decode_hex, verification};

use ed25519_compact::*;

use std::collections::HashMap;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub fn print(v: &[u8]) {
    for i in v.iter() {
        print!("{:x}", i);
    }
    println!();
}
pub fn print_data(b: Vec<BlockType>) {
    println!("Number of blocks: {}", b.len());
    for i in b.iter() {
        println!(
            "\nnonce: {}\nheight: {}\nprev_hash: {}\nhash: {}\nepock_id: {}",
            i.get_nonce(),
            i.get_height(),
            i.get_prev_hash(),
            i.get_hash(),
            i.get_epoch_id()
        );
        print!("sig: ");
        print(i.get_sig().as_slice());
        println!("v_sig: ");
        for j in i.get_v_sig().iter() {
            print(j.as_slice());
        }
        match i {
            BlockType::Block(_) => (),
            BlockType::EpochBlock(s) => {
                println!("v_pk: ");
                for j in s.get_v_pk().iter() {
                    print!("{}: ", j.0);
                    print(j.1.as_slice());
                }
            }
        }
    }
}

pub fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init()?;
    // generate keys for users
    let mut users: HashMap<u32, (PublicKey, SecretKey)> = HashMap::new();
    let mut keypair: KeyPair;
    for i in 0..3 {
        keypair = KeyPair::from_seed(Seed::generate());
        users.insert(i, (keypair.pk, keypair.sk));
    }
    let mut height = 2;
    let mut msg: String;
    let mut epoch_id: String;
    let mut prev_hash: String;
    let mut blockchain: Vec<BlockType> = Vec::new();
    let mut epoch_block: EpochBlock = EpochBlock::new();
    let mut block: Block = Block::new();
    for i in 0..10 {
        match height {
            2 => {
                match i {
                    // constant value for first two epochs
                    0 => {
                        epoch_id =
                            "EF3E2F087EE8CB7A457F346BBEBE552AB88BD476C880E979C964BA53F9CEFC92"
                                .to_string();
                        prev_hash = String::new()
                    }
                    3 => {
                        epoch_id =
                            "5C5F3CAB2EC995CFF8BD002F1B56E349E89B70DABEE1D3A554A3E536B7679175"
                                .to_string();
                        prev_hash = blockchain[i - 1].get_hash()
                    }
                    _ => {
                        epoch_id = blockchain[i - 1].get_epoch_id().clone();
                        prev_hash = blockchain[i - 1].get_hash()
                    }
                }
                epoch_block.set(i, height, prev_hash, epoch_id, users.clone());
                epoch_block.set_v_pk(users.clone());
                blockchain.push(BlockType::EpochBlock(epoch_block.clone()));
                height = 0;
            }
            _ => {
                if i == 1 || i == 2 {
                    epoch_id = "5C5F3CAB2EC995CFF8BD002F1B56E349E89B70DABEE1D3A554A3E536B7679175"
                        .to_string();
                } else if (i % 3) == 1 {
                    epoch_id = blockchain[i - 4].get_hash().clone();
                } else {
                    epoch_id = blockchain[i - 1].get_epoch_id().clone();
                }
                prev_hash = blockchain[i - 1].get_hash();
                block.set(i, height, prev_hash, epoch_id, users.clone());
                blockchain.push(BlockType::Block(block.clone()));
                height += 1;
            }
        }
    }
    print_data(blockchain.clone());

    let mut sha256_circuits: HashMap<usize, (CircuitData<F, C, D>, Sha256Targets)> = HashMap::new();
    let mut ed25519_circuits: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> = HashMap::new();
    // hash proof; final proof
    let mut proofchain: Vec<(
        (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
        (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
    )> = Vec::new();
    // circuit and proof for current hash
    let (mut circuit_hash, mut proof_hash): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    // circuit and proof for current signature
    let (mut circuit_sig, mut proof_sig): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    // circuit and proof for block validators
    let (mut validators_circuit, mut validators_proof): (
        CircuitData<F, C, D>,
        ProofWithPublicInputs<F, C, D>,
    );
    // final circuit and proof for each block
    let (mut aggregated_circuit, mut aggregated_proof): (
        CircuitData<F, C, D>,
        ProofWithPublicInputs<F, C, D>,
    );
    // a block to validate blocks #0, #01 and #1
    let mut const_block = EpochBlock::new();
    for i in 0..users.len() {
        const_block
            .validators_pk
            .insert(i, users.get(&(i as u32)).unwrap().0);
    }
    for i in 0..blockchain.len() {
        if i == 0 || i == 1 || i == 2 || i == 3 {
            epoch_block = const_block.clone();
        } else if (i % 3) == 1 {
            epoch_block = EpochBlock::new();
            epoch_block.validators_pk = blockchain[i - 4].get_v_pk().unwrap().clone();
        }
        msg = blockchain[i].get_prev_hash().clone() + &blockchain[i].get_nonce().to_string();
        println!("Msg: {}", msg);
        // prove current hash
        (circuit_hash, proof_hash) = hash_circuit_proof(
            msg.as_bytes(),
            &decode_hex(&blockchain[i].get_hash()).unwrap(),
            &mut sha256_circuits,
        );
        println!("Proof hash sz: {}", proof_hash.to_bytes().len());
        // prove current signature
        // i % (number of producers)
        (circuit_sig, proof_sig) = sig_circuit_proof(
            blockchain[i].get_nonce().to_string().as_bytes(),
            blockchain[i].get_sig().as_slice(),
            epoch_block
                .validators_pk
                .get(&(i % users.len()))
                .unwrap()
                .as_slice(),
            &mut ed25519_circuits,
        );
        println!("Proof signature sz: {}", proof_sig.to_bytes().len());
        (aggregated_circuit, aggregated_proof) = aggregation_two(
            (&circuit_hash, &proof_hash),
            Some((&circuit_sig, &proof_sig)),
        )
        .unwrap();
        // prove signatures of validators
        if i != blockchain.len() - 1 {
            for j in 0..blockchain[i].get_v_sig().len() {
                (validators_circuit, validators_proof) = sig_circuit_proof(
                    blockchain[i + 1].get_nonce().to_string().as_bytes(),
                    blockchain[i + 1].get_v_sig()[j].as_slice(),
                    epoch_block.validators_pk.get(&j).unwrap().as_slice(),
                    &mut ed25519_circuits,
                );
                println!(
                    "Validator's proof signature sz: {}",
                    validators_proof.to_bytes().len()
                );
                (aggregated_circuit, aggregated_proof) = aggregation_two(
                    (&validators_circuit, &validators_proof),
                    Some((&aggregated_circuit, &aggregated_proof)),
                )
                .unwrap();
            }
        }
        // add proofs for hashes of two previous epochs
        if blockchain[i].get_height() == 2 && i > 0 {
            (aggregated_circuit, aggregated_proof) = aggregation_two(
                (&proofchain[i - 3].0 .0, &proofchain[i - 3].0 .1),
                Some((&aggregated_circuit, &aggregated_proof)),
            )
            .unwrap();
            if i > 3 {
                (aggregated_circuit, aggregated_proof) = aggregation_two(
                    (&proofchain[i - 6].0 .0, &proofchain[i - 6].0 .1),
                    Some((&aggregated_circuit, &aggregated_proof)),
                )
                .unwrap();
            }
        }
        // add the final proof of the previous block
        if i != 0 {
            (aggregated_circuit, aggregated_proof) = aggregation_two(
                (&proofchain[i - 1].1 .0, &proofchain[i - 1].1 .1),
                Some((&aggregated_circuit, &aggregated_proof)),
            )
            .unwrap();
        }
        proofchain.push((
            (circuit_hash.clone(), proof_hash.clone()),
            (aggregated_circuit.clone(), aggregated_proof.clone()),
        ));
        println!("Final proof sz: {}", proofchain[i].1 .1.to_bytes().len());
    }
    verification((
        &proofchain[blockchain.len() - 1].1 .0,
        &proofchain[blockchain.len() - 1].1 .1,
    ))
}
