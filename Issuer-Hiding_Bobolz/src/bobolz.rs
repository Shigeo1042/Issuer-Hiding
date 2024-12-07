use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rang::rngs::StdRng, UniformRand};
use blake2::Blake2b512;
use schnorr_pok::compute_random_oracle_challenge;
use groth;
use groth1;
use groth2;

use crate::groth;
use crate::groth1;
use crate::groth2;

pub struct PublicParameters {
    group1: Bls12_381::G1,
    group2: Bls12_381::G2,
    groupt: Bls12_381::Gt,
    e: Pairing<Bls12_381>,
    p: Bls12_381::Fr,
    g1: Bls12_381::G1Affine::generators(),
    g2: Bls12_381::G2Affine::generators(),
    y1: Bls12_381::G1Affine::random_element(),
    y2: Bls12_381::G2Affine::random_element(),
    h: Vec<i32>
}

struct Credential{}

pub fn par_gen(len: i32) -> bobolz::PublicParameters{
    let pp_groth: groth::PublicParameters;
    let mut hvec = Vec::new();
    for i in 0..len{
        hvec.append(1)
    }
    let pp_bobolz = {
        group1 = Bls12_381::G1;
        group2 = Bls12_381::G2;
        groupt = Bls12_381::Gt;
        e = self.pairing;
        p = Bls12_381::Fr;
        g1 = Bls12_381::G1Affine::generators();
        g2 = Bls12_381::G2Affine::generators();
        y1 = Bls12_381::G1Affine::random_element();
        y2 = Bls12_381::G2Affine::random_element();
        h = hvec;
    };
    return pp
}

pub fn issuer_key_gen(pp: &groth::PublicParameters) -> groth1::KeyPair{
    let keypair = groth1::key_gen(pp);
    return keypair
}

pub fn issue(pp: &groth::PublicParameters, isk: &String, message:Vec<String>) -> groth1::Signature{
    let signature = groth1::sign(pp, isk, &message);
    return signature

}

pub fn verify(){}

pub fn issue_list(){}

pub fn verify_list(){}

pub fn present(){}

pub fn verify_present(){}
