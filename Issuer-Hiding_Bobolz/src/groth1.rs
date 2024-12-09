use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rang::rngs::StdRng, UniformRand};
use blake2::Blake2b512;
use groth;

use crate::groth;
// use schnorr_pok::compute_random_oracle_challenge;

pub fn par_gen() -> (groth::PublicParameters){
    let pp = groth::PublicParameters{
        group1: Bls12_381::G1,
        group2: Bls12_381::G2,
        groupt: Bls12_381::TargetField,
        e: Bls12_381::pairing(),
        p: Bls12_381::Fr,
        g1: Bls12_381::G1Prepared.get_element(),
        g2: Bls12_381::G2Prepared.get_element(),
        y1: Bls12_381::G1Prepared.get_element(),
        y2: Bls12_381::G2Prepared.get_element(),
    };
    return pp
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub r2: String, //r2 = g2^r
    pub s1: String, // s1 = (y1 * g1^sk)^(1/r)
    pub t1: String // t1 = (y1^sk * message)^(1/r)
}

pub fn key_gen(pp: groth::PublicParameters) -> (groth::KeyPair){
    let mut sk_bytes = self.0.to_bytes();
    sk_bytes.reverse();

    let sk = SecretKey(
        sk_bytes
    );

    // transform secret key from LE to BE
    let sk_bytes = sk.to_bytes();
    // let pk = G2Projective::generator() * sk.0;
    let pk = pp::g2 * sk.0;
    let pk_bytes = pk.to_affine().to_compressed();

    let keypair = groth::KeyPair {
        secret_key: hex::encode(sk_bytes),
        public_key: hex::encode(pk_bytes),
    };

    return keypair
}

pub fn sign(pp: groth::PublicParameters, sk: groth::SecretKey, message: String) -> Signature{
    let r: UniformRand::rand(rng);
    
    let message_bytes = message.to_bytes();
    let r2_bytes  = pp.g2 ^ r;
    let s1_bytes = (pp.y1 * pp.g1 ^ sk) ^ (1/r);
    let t1_bytes = (pp.y1 ^ sk * message_bytes) ^ (1/r);
    let mut r2_string = hex::encode(r2_bytes);
    let mut s1_string = hex::encode(s1_bytes);
    let mut t1_string = hex::encode(t1_bytes);
    let sig = Signature{
        r2: r2_string,
        s1: s1_string,
        t1: t1_string
    };

    return sig
}

pub fn rand(pp: groth::PublicParameters, sig: Signature) -> Signature{
    let r: UniformRand::rand(rng);
    
    let r2_bytes = sig.r2.to_bytes();
    let s1_bytes = sig.s1.to_bytes();
    let t1_bytes = sig.t1.to_bytes();
    let newr2_bytes  = r2_bytes ^ r;
    let news1_bytes = s1_bytes ^ (1/r);
    let newt1_bytes = t1_bytes ^ (1/r);
    let mut newr2_string = hex::encode(newr2_bytes);
    let mut news1_string = hex::encode(news1_bytes);
    let mut newt1_string = hex::encode(newt1_bytes);

    let newsig = Signature{
        r2: newr2_string,
        s1: news1_string,
        t1: newt1_string
    };

    return newsig
}

pub fn verify(pp: groth::PublicParameters, pk: String, sig: Signature, message: String) -> bool{
    let mut boo1: bool = false;
    let mut bool2: bool = false;
    let r2 = sig.r2.to_bytes();
    let s1 = sig.s1.to_bytes();
    let t1 = sig.t1.to_bytes();
    let g1 = pp.g1.to_bytes();
    let g2 = pp.g2.to_bytes();
    let y1 = pp.y1.to_bytes();
    let message_bytes = message.to_bytes();
    if e(s1,r2) == e(y1,g2) * e(g1,pk){
        boo1 = true;
    }
    if e(t1,r2) == e(y1,pk) * e(message_bytes,g2){
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