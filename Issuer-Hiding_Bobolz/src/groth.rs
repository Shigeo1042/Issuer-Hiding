use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rang::rngs::StdRng, UniformRand};
use blake2::Blake2b512;
use schnorr_pok::compute_random_oracle_challenge;

struct PublicParameters {
    group1: Bls12_381::G1,
    group2: Bls12_381::G2,
    groupt: Bls12_381::Gt,
    e: Pairing<Bls12_381>,
    p: Bls12_381::Fr,
    g1: Bls12_381::G1Affine::generators(),
    g2: Bls12_381::G2Affine::generators(),
    y1: Bls12_381::G1Affine::random_element(),
    y2: Bls12_381::G2Affine::random_element(),
}