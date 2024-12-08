use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rang::rngs::StdRng, UniformRand};
use blake2::Blake2b512;
use schnorr_pok::compute_random_oracle_challenge;
use groth;

use crate::groth;

pub fn par_gen() -> (groth::PublicParameters){
    let pp: groth::PublicParameters;
    return pp
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub r1: String, //r1 = g1^r
    pub s2: String, // s2 = (y2 * g2^sk)^(1/r)
    pub t2: String // t2 = (y2^sk * message)^(1/r)
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
    let pk = pp.g1 * sk.0;
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
    let r1_bytes  = pp.g1 ^ r;
    let s2_bytes = (pp.y2 * pp.g2 ^ sk) ^ (1/r);
    let t2_bytes = (pp.y2 ^ sk * message_bytes) ^ (1/r);
    let mut r1_string = hex::encode(r1_bytes);
    let mut s2_string = hex::encode(s2_bytes);
    let mut t2_string = hex::encode(t2_bytes);
    let sig = Signature{
        r1: r1_string,
        s2: s2_string,
        t2: t2_string
    };

    return sig
}

pub fn rand(pp: groth::PublicParameters, sig: Signature) -> Signature{
    let r: UniformRand::rand(rng);
    
    let r1_bytes = sig.r1.to_bytes();
    let s2_bytes = sig.s2.to_bytes();
    let t2_bytes = sig.t2.to_bytes();
    let newr1_bytes  = r1_bytes ^ r;
    let news2_bytes = s2_bytes ^ (1/r);
    let newt2_bytes = t2_bytes ^ (1/r);
    let mut newr1_string = hex::encode(newr1_bytes);
    let mut news2_string = hex::encode(news2_bytes);
    let mut newt2_string = hex::encode(newt2_bytes);

    let newsig = Signature{
        r1: newr1_string,
        s2: news2_string,
        t2: newt2_string
    };

    return newsig
}

pub fn verify(pp: groth::PublicParameters, pk: String, sig: Signature, message: String) -> bool{
    let mut boo1: bool = false;
    let mut bool2: bool = false;
    let r1 = sig.r1.to_bytes();
    let s2 = sig.s2.to_bytes();
    let t2 = sig.t2.to_bytes();
    let g1 = pp.g1.to_bytes();
    let g2 = pp.g2.to_bytes();
    let y2 = pp.y2.to_bytes();
    let message_bytes = message.to_bytes();
    if e(r1,s2) == e(g1,y2) * e(pk,g2){
        boo1 = true;
    }
    if e(r1,t2) == e(pk,y2) * e(g1,message_bytes){
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