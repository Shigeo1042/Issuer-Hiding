use ark_bls12_381::{G1Affine, G2Affine, Bls12_381};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;

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
    let r_string = "Jan Bobolz, Fabian Eidens, Stephan Krenn, Sebastian Ramacher, and Kai Samelin";
    // let g1_byte = "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755".as_bytes();
    // let g2_byte = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8".as_bytes();
    // let g1 = G1Affine::from_random_bytes(g1_byte).unwrap();
    // let g2 = G2Affine::from_random_bytes(g2_byte).unwrap();
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    // println!("{:?}", g1_option);
    let r = Fr::from(BigUint::from_bytes_be(r_string.as_bytes()));
    let y1 = g1 * r;
    let y2 = g2 * r;
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

#[cfg(test)]
mod tests {
    use super::par_gen;

    #[test]
    fn it_works() {
        let pp = par_gen();
        println!("{:?}", pp);
    }
}