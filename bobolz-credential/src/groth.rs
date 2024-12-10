use ark_bls12_381::{G1Affine, G2Affine, Bls12_381};
// use bls12_381::Scalar;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use rand::RngCore;
// use ark_std::{rang::rngs::StdRng, UniformRand};
// use blake2::Blake2b512;
// use schnorr_pok::compute_random_oracle_challenge;
// use serde::{Deserialize, Serialize};

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

pub struct PublicParameters {
    //g1 \in G1, g2 \in G2, y1 \stackrel{\$}{\leftarrow} G1, y2 \stackrel{\$}{\leftarrow} G2
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub y1: G1Affine,
    pub y2: G2Affine,
}

pub fn par_gen<R: RngCore>(rng: &mut R) -> PublicParameters{
    // let mut rng = ark_std::rand::thread_rng();
    let pp = PublicParameters{
        g1: G1Affine::rand(rng),
        g2: G2Affine::rand(rng),
        y1: G1Affine::rand(rng),
        y2: G2Affine::rand(rng),
    };
    return pp
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecretKey(pub Fr);

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}