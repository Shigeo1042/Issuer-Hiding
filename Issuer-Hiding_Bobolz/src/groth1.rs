use ark_bls12_381::{G1Affine, G2Affine, Bls12_381};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_std::{fmt::Debug, UniformRand};
use rand;

use crate::groth;
// use schnorr_pok::compute_random_oracle_challenge;
pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey(pub G2Affine);

#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(non_snake_case)]
pub struct KeyPair {
    pub secret_key: groth::SecretKey,
    pub public_key: PublicKey,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature {
    pub r2: G2Affine, //r2 = g2^r
    pub s1: G1Affine, // s1 = (y1 * g1^sk)^(1/r)
    pub t1: G1Affine // t1 = (y1^sk * message)^(1/r)
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
    let pk_element = pp.g2 * sk.0;
    let pk_affine = G2Affine::from(pk_element);
    let pk = PublicKey(
        pk_affine
    );

    let keypair = KeyPair {
        secret_key: sk,
        public_key: pk,
    };

    return keypair
}

pub fn sign(pp: &groth::PublicParameters, sk: &groth::SecretKey, message: &G1Affine) -> Signature{
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let r_inverse = r.inverse().unwrap();

    let r2  = pp.g2 * r;
    let s1 = (pp.g1 + pp.g1 * sk.0) * (r_inverse);
    let t1 = (pp.y1 + *message * sk.0) * (r_inverse);
    let r2_affine = G2Affine::from(r2);
    let s1_affine = G1Affine::from(s1);
    let t1_affine = G1Affine::from(t1);
    let sig = Signature{
        r2: r2_affine,
        s1: s1_affine,
        t1: t1_affine
    };

    return sig
}

pub fn rand_sign(sig: &Signature) -> Signature{
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let r_inverse = r.inverse().unwrap();
    // let r = Fr::from(r_fq);
    let newr2  = sig.r2 * r;
    let news1 = sig.s1 * (r_inverse);
    let newt1 = sig.t1 * (r_inverse);
    let newr2_affine = G2Affine::from(newr2);
    let news1_affine = G1Affine::from(news1);
    let newt1_affine = G1Affine::from(newt1);

    let newsig = Signature{
        r2: newr2_affine,
        s1: news1_affine,
        t1: newt1_affine
    };

    return newsig
}

pub fn verify(pp: &groth::PublicParameters, pk: &PublicKey, sig: &Signature, message: &G1Affine) -> bool{
    let mut boo1: bool = false;
    let mut bool2: bool = false;
    let r2 = sig.r2;
    let s1 = sig.s1;
    let t1 = sig.t1;
    let g1 = pp.g1;
    let g2 = pp.g2;
    let y1 = pp.y1;
    
    if Bls12_381::pairing(s1,r2) == Bls12_381::pairing(y1,g2) + Bls12_381::pairing(g1,pk.0){
        boo1 = true;
    }
    if Bls12_381::pairing(t1,r2) == Bls12_381::pairing(y1,pk.0) + Bls12_381::pairing(message,g2){
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