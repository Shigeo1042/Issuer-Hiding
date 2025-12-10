use ark_bls12_381::{G1Affine, G2Affine, Bls12_381, G1Projective, G2Projective, g1::Config as G1Config, g2::Config as G2Config};
use ark_ec::{pairing::Pairing, hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve}};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicParameters {
    //g1 \in G1, g2 \in G2, y1 \stackrel{\$}{\leftarrow} G1, y2 \stackrel{\$}{\leftarrow} G2
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub y1: G1Affine,
    pub y2: G2Affine,
}

pub fn par_gen() -> PublicParameters{
    let g1_hex = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    let g2_hex = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    let g1_bytes = hex::decode(g1_hex).unwrap();
    let g2_bytes = hex::decode(g2_hex).unwrap();
    let g1 = G1Affine::deserialize_compressed(&g1_bytes[..]).unwrap();
    let g2 = G2Affine::deserialize_compressed(&g2_bytes[..]).unwrap();

    let dst1 = b"GROTH-SIG-GENERATOR-DST-V1";
    let dst2 = b"GROTH-SIG-GENERATOR-DST-V2";
    let y1_bytes = "Jan Bobolz, Fabian Eidens, Stephan Krenn, Sebastian Ramacher, and Kai Samelin makes Y1".to_string().into_bytes();
    let y2_bytes = "Jan Bobolz, Fabian Eidens, Stephan Krenn, Sebastian Ramacher, and Kai Samelin makes Y2".to_string().into_bytes();
    let y1 = G1Affine::from(hash_to_g1(&y1_bytes[..], dst1));
    let y2 = G2Affine::from(hash_to_g2(&y2_bytes[..], dst2));
    let pp = PublicParameters{
        g1,
        g2,
        y1: G1Affine::from(y1),
        y2: G2Affine::from(y2),
    };
    return pp
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
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

#[cfg(test)]
mod tests {
    use super::par_gen;

    #[test]
    fn it_works() {
        let pp = par_gen();
        println!("{:?}", pp);
    }
}