use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective, g1::Config as G1Config, g2::Config as G2Config};
use ark_ec::{hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},pairing::Pairing};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use sha2::Sha256;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

use crate::issuer;
use crate::verifier;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicParameters {
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub h_seed: &'static str,
    pub h_dst: &'static [u8; 31],
    pub gbar1: G1Affine,  
    pub gbar2: G2Affine,

}

// g_1 = h'97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
// g_2 = h'93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'

pub fn par_gen() -> PublicParameters{
    let pp_issuer = issuer::par_gen();
    let pp_verifier = verifier::par_gen();
    let pp = PublicParameters{
        g1: pp_issuer.g1,
        g2: pp_issuer.g2,
        h_seed: pp_issuer.h_seed,
        h_dst: pp_issuer.h_dst,
        gbar1: pp_verifier.gbar1,
        gbar2: pp_verifier.gbar2,
    };
    return pp
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecretKey(pub Fr);

pub fn hash_to_fr(input: &[u8], dst: &[u8]) -> Fr {
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fr>>::new(dst);

    let scalars: [Fr; 1] = hasher.hash_to_field::<1>(input);
    let ans = scalars[0];
    return ans;
}

pub fn hash_to_g1(input: &[u8], dst: &[u8]) -> G1Affine {
    let hasher = MapToCurveBasedHasher::<G1Projective, DefaultFieldHasher<Sha256>,WBMap<G1Config>>::new(dst).unwrap();
    
    let hashpoint = hasher.hash(input).unwrap();
    return hashpoint;
}

pub fn hash_to_g2(input: &[u8], dst: &[u8]) -> G2Affine {
    // let dst = b"BLS12381G2_XMD:SHA-256_SSWU_RO_";
    let hasher = MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256>,WBMap<G2Config>>::new(dst).unwrap();
    
    let hashpoint = hasher.hash(input).unwrap();
    return hashpoint;
}

// #[cfg(test)]
// mod tests {
//     use super::par_gen;

//     #[test]
//     fn it_works() {
//         let pp = par_gen();
//         println!("{:?}", pp);
//     }
// }