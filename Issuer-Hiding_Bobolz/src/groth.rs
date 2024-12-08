use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rang::rngs::StdRng, UniformRand};
use blake2::Blake2b512;
use schnorr_pok::compute_random_oracle_challenge;

pub struct PublicParameters {
    pub group1: Bls12_381::G1,
    pub group2: Bls12_381::G2,
    pub groupt: Bls12_381::Gt,
    pub e: Pairing<Bls12_381>,
    pub p: Bls12_381::Fr,
    pub g1: Bls12_381::G1Affine::generators(),
    pub g2: Bls12_381::G2Affine::generators(),
    pub y1: Bls12_381::G1Affine::random_element(),
    pub y2: Bls12_381::G2Affine::random_element(),
}

#[derive(Debug, Clone)]
pub struct SecretKey(pub Scalar);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(non_snake_case)]
pub struct KeyPair {
    pub secret_key: String,
    pub public_key: String,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}