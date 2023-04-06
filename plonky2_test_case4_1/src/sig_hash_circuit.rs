use anyhow::Result;
use core::num::ParseIntError;
use log::Level;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use plonky2_ed25519::gadgets::eddsa::{ed25519_circuit, fill_ecdsa_targets, EDDSATargets};
use plonky2_sha256::circuit::{array_to_bits, sha256_circuit, Sha256Targets};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub fn decode_hex(s: &String) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn make_hash(msg: &[u8]) -> String {
    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(msg);
    // read hash digest and consume hasher
    let hash = hasher.finalize();
    format!("{:x}", hash)
}

pub fn get_sha256_circuit_targets(
    len: usize,
    cached_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, Sha256Targets)>,
) -> (CircuitData<F, C, D>, Sha256Targets) {
    match cached_circuits.get(&len) {
        Some(cache) => cache.clone(),
        None => {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let targets = sha256_circuit(&mut builder, len);

            let timing = TimingTree::new("build", Level::Debug);
            let circuit_data = builder.build::<C>();
            timing.print();

            cached_circuits.insert(len, (circuit_data.clone(), targets.clone()));

            (circuit_data, targets)
        }
    }
}

pub fn hash_circuit_proof(
    msg: &[u8],
    hash: &[u8],
    sha256_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, Sha256Targets)>,
) -> (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>) {
    let len = msg.len() * 8;
    println!("block count: {}", (len + 65 + 511) / 512);
    let (circuit_data, targets): (CircuitData<F, C, D>, Sha256Targets) =
        get_sha256_circuit_targets(len, sha256_circuits);
    let msg_bits = array_to_bits(msg);
    let hash_bits = array_to_bits(hash);
    let mut pw: PartialWitness<F> = PartialWitness::new();
    for i in 0..msg_bits.len() {
        pw.set_bool_target(targets.message[i], msg_bits[i]);
    }
    for i in 0..hash_bits.len() {
        pw.set_bool_target(targets.digest[i], hash_bits[i]);
    }
    let timing = TimingTree::new("prove", Level::Debug);
    let proof = circuit_data.prove(pw).unwrap();
    timing.print();
    (circuit_data, proof)
}

pub fn get_ed25519_circuit_targets(
    len: usize,
    cached_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)>,
) -> (CircuitData<F, C, D>, EDDSATargets) {
    match cached_circuits.get(&len) {
        Some(cache) => cache.clone(),
        None => {
            let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
            let targets = ed25519_circuit(&mut builder, len);

            let timing = TimingTree::new("build", Level::Debug);
            let circuit_data = builder.build::<C>();
            timing.print();

            cached_circuits.insert(len, (circuit_data.clone(), targets.clone()));

            (circuit_data, targets)
        }
    }
}

pub fn sig_circuit_proof(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    ed25519_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)>,
) -> (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>) {
    let len = msg.len() * 8;
    let (circuit_data, targets): (CircuitData<F, C, D>, EDDSATargets) =
        get_ed25519_circuit_targets(len, ed25519_circuits);
    let mut pw: PartialWitness<F> = PartialWitness::new();
    fill_ecdsa_targets::<F, D>(&mut pw, msg, sigv, pkv, &targets);
    let timing = TimingTree::new("prove", Level::Debug);
    let proof = circuit_data.prove(pw).unwrap();
    timing.print();
    (circuit_data, proof)
}

pub fn verification(
    (data, proof): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
) -> Result<()> {
    let timing = TimingTree::new("verify", Level::Debug);
    let res = data.verify(proof.to_owned());
    timing.print();
    res
}
pub fn verification_proofs(
    (data1, proof1): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
    (data2, proof2): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
) -> Result<()> {
    let timing = TimingTree::new("verify two proofs", Level::Debug);
    let res1 = verification((data1, proof1));
    let res2 = verification((data2, proof2));
    let res3 = res1.and(res2);
    timing.print();
    res3
}

pub fn aggregation_two(
    (data1, proof1): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
    data_proof_2: Option<(&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>)>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    verification((data1, proof1))?;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let proof_with_pis_target_1 = builder.add_virtual_proof_with_pis(&data1.common);
    // dynamic setup for verifier
    let verifier_circuit_target_1 = VerifierCircuitTarget {
        // data.common is static setup for verifier
        constants_sigmas_cap: builder.add_virtual_cap(data1.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_with_pis_target_1, proof1);
    pw.set_cap_target(
        &verifier_circuit_target_1.constants_sigmas_cap,
        &data1.verifier_only.constants_sigmas_cap,
    );
    pw.set_hash_target(
        verifier_circuit_target_1.circuit_digest,
        data1.verifier_only.circuit_digest,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_1,
        &verifier_circuit_target_1,
        &data1.common,
    );
    if data_proof_2.is_some() {
        verification((data_proof_2.unwrap().0, data_proof_2.unwrap().1))?;
        let proof_with_pis_target_2 =
            builder.add_virtual_proof_with_pis(&data_proof_2.unwrap().0.common);
        let verifier_circuit_target_2 = VerifierCircuitTarget {
            constants_sigmas_cap: builder
                .add_virtual_cap(data_proof_2.unwrap().0.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_proof_with_pis_target(&proof_with_pis_target_2, data_proof_2.unwrap().1);
        pw.set_cap_target(
            &verifier_circuit_target_2.constants_sigmas_cap,
            &data_proof_2.unwrap().0.verifier_only.constants_sigmas_cap,
        );
        pw.set_hash_target(
            verifier_circuit_target_2.circuit_digest,
            data_proof_2.unwrap().0.verifier_only.circuit_digest,
        );
        builder.verify_proof::<C>(
            &proof_with_pis_target_2,
            &verifier_circuit_target_2,
            &data_proof_2.unwrap().0.common,
        );
    }
    // create common circuit for two proofs
    let data_new = builder.build::<C>();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof_new = data_new.prove(pw)?;
    timing.print();
    Ok((data_new, proof_new))
}

pub fn aggregation_three(
    (data1, proof1): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
    (data2, proof2): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
    (data3, proof3): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    verification((data1, proof1))?;
    verification((data2, proof2))?;
    verification((data3, proof3))?;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let proof_with_pis_target_1 = builder.add_virtual_proof_with_pis(&data1.common);
    let proof_with_pis_target_2 = builder.add_virtual_proof_with_pis(&data2.common);
    let proof_with_pis_target_3 = builder.add_virtual_proof_with_pis(&data3.common);
    // dynamic setup for verifier
    let verifier_circuit_target_1 = VerifierCircuitTarget {
        // data.common is static setup for verifier
        constants_sigmas_cap: builder.add_virtual_cap(data1.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let verifier_circuit_target_2 = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data2.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let verifier_circuit_target_3 = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data3.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_with_pis_target_1, proof1);
    pw.set_proof_with_pis_target(&proof_with_pis_target_2, proof2);
    pw.set_proof_with_pis_target(&proof_with_pis_target_3, proof3);
    pw.set_cap_target(
        &verifier_circuit_target_1.constants_sigmas_cap,
        &data1.verifier_only.constants_sigmas_cap,
    );
    pw.set_cap_target(
        &verifier_circuit_target_2.constants_sigmas_cap,
        &data2.verifier_only.constants_sigmas_cap,
    );
    pw.set_cap_target(
        &verifier_circuit_target_3.constants_sigmas_cap,
        &data3.verifier_only.constants_sigmas_cap,
    );
    pw.set_hash_target(
        verifier_circuit_target_1.circuit_digest,
        data1.verifier_only.circuit_digest,
    );
    pw.set_hash_target(
        verifier_circuit_target_2.circuit_digest,
        data2.verifier_only.circuit_digest,
    );
    pw.set_hash_target(
        verifier_circuit_target_3.circuit_digest,
        data3.verifier_only.circuit_digest,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_1,
        &verifier_circuit_target_1,
        &data1.common,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_2,
        &verifier_circuit_target_2,
        &data2.common,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_3,
        &verifier_circuit_target_3,
        &data3.common,
    );
    // create common circuit for two proofs
    let data_new = builder.build::<C>();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof_new = data_new.prove(pw).unwrap();
    timing.print();
    Ok((data_new, proof_new))
}
