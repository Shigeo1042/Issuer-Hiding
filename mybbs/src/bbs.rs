use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective, g1::Config as G1Config, g2::Config as G2Config};
use ark_ec::{hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},pairing::Pairing};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize)]
pub struct PublicParameters {
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub gbar1: G1Affine,
    pub gbar2: G2Affine,
    pub q1: G1Affine,
}

// g_1 = h'97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
// g_2 = h'93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'

pub fn par_gen() -> PublicParameters{
    let g1_hex = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    let g2_hex = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    let g1_bytes = hex::decode(g1_hex).unwrap();
    let g2_bytes = hex::decode(g2_hex).unwrap();
    let g1 = G1Affine::deserialize_compressed(&g1_bytes[..]).unwrap();
    let g2 = G2Affine::deserialize_compressed(&g2_bytes[..]).unwrap();
    
    let dst1 = b"BBS-SIG-GENERATOR-DST-V1";
    let dst2 = b"BBS-SIG-GENERATOR-DST-V2";
    let gbar1_bytes = "Issuer-Hiding BBS Make to gbar1".to_string().into_bytes();
    let gbar2_bytes = "Issuer-Hiding BBS Make to gbar2".to_string().into_bytes();
    let gbar1 = G1Affine::from(hash_to_g1(&gbar1_bytes[..], dst1));
    let gbar2 = G2Affine::from(hash_to_g2(&gbar2_bytes[..], dst2));

    let q1_hex = "a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be";
    let q1_bytes = hex::decode(q1_hex).unwrap();
    let q1 = G1Affine::deserialize_compressed(&q1_bytes[..]).unwrap();
    let pp = PublicParameters{
        g1,
        g2,
        gbar1,  
        gbar2,
        q1,
    };
    return pp
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize)]
pub struct SecretKey(pub Fr);

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

#[cfg(test)]
mod tests {
    use super::par_gen;

    #[test]
    fn it_works() {
        let pp = par_gen();
        println!("{:?}", pp);
    }
}