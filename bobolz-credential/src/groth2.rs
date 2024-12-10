use ark_bls12_381::{G1Affine, G2Affine, Bls12_381};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_std::{fmt::Debug, UniformRand};
use rand;

use crate::groth;
// use schnorr_pok::compute_random_oracle_challenge;
pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey(pub G1Affine);

#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(non_snake_case)]
pub struct KeyPair {
    pub secret_key: groth::SecretKey,
    pub public_key: PublicKey,
}
#[derive(Debug, PartialEq, Eq,Clone)]
pub struct Signature {
    pub r1: G1Affine, //r2 = g2^r
    pub s2: G2Affine, // s1 = (y1 * g1^sk)^(1/r)
    pub t2: G2Affine // t1 = (y1^sk * message)^(1/r)
}

pub fn par_gen() -> groth::PublicParameters{
    let mut rng = rand::thread_rng();
    let pp = groth::par_gen(&mut rng);
    return pp
}

pub fn key_gen(pp: &groth::PublicParameters) -> KeyPair{
    // sk \stackrel{\$}{\leftarrow} Z_p^*
    // let sk_bytes = self.0.to_bytes();
    let mut rng = ark_std::rand::thread_rng();
    let sk_element = Fr::rand(&mut rng);
    let sk = groth::SecretKey(
        sk_element
    );

    // pk = g2^sk
    // let pk = G2Projective::generator() * sk.0;
    let pk_element = pp.g1 * sk.0;
    let pk_affine = G1Affine::from(pk_element);
    let pk = PublicKey(
        pk_affine
    );

    let keypair = KeyPair {
        secret_key: sk,
        public_key: pk,
    };

    return keypair
}

pub fn sign(pp: &groth::PublicParameters, sk: &groth::SecretKey, message: &G2Affine) -> Signature{
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let r_inverse = r.inverse().unwrap();

    let r1  = pp.g1 * r;
    let s2 = (pp.y2 + (pp.g2 * sk.0)) * (r_inverse);
    let t2 = (pp.y2 + *message * sk.0) * (r_inverse);
    let r1_affine = G1Affine::from(r1);
    let s2_affine = G2Affine::from(s2);
    let t2_affine = G2Affine::from(t2);
    let sig = Signature{
        r1: r1_affine,
        s2: s2_affine,
        t2: t2_affine
    };

    return sig
}

pub fn rand_sign(sig: &Signature) -> Signature{
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let r_inverse = r.inverse().unwrap();

    let newr1  = sig.r1 * r;
    let news2 = sig.s2 * (r_inverse);
    let newt2 = sig.t2 * (r_inverse);
    let newr1_affine = G1Affine::from(newr1);
    let news2_affine = G2Affine::from(news2);
    let newt2_affine = G2Affine::from(newt2);

    let newsig = Signature{
        r1: newr1_affine,
        s2: news2_affine,
        t2: newt2_affine
    };

    return newsig
}

pub fn verify(pp: &groth::PublicParameters, pk: &PublicKey, sig: &Signature, message: &G2Affine) -> bool{
    let mut boo1: bool = false;
    let mut bool2: bool = false;
    let r1 = sig.r1;
    let s2 = sig.s2;
    let t2 = sig.t2;
    let g1 = pp.g1;
    let g2 = pp.g2;
    let y2 = pp.y2;

    if Bls12_381::pairing(r1,s2) == Bls12_381::pairing(g1,y2) + Bls12_381::pairing(pk.0,g2){
        boo1 = true;
    }
    if Bls12_381::pairing(r1,t2) == Bls12_381::pairing(pk.0,y2) + Bls12_381::pairing(g1,message){
        bool2 = true;
    }

    return boo1 && bool2
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}