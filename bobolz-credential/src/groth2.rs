use ark_bls12_381::{G1Affine, G2Affine, Bls12_381};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, UniformRand};
use rand;
use crate::groth;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicParameters {
    //g1 \in G1, g2 \in G2, y1 \stackrel{\$}{\leftarrow} G1, y2 \stackrel{\$}{\leftarrow} G2
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub y2: G2Affine,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicKey(pub G1Affine);

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
#[allow(non_snake_case)]
pub struct KeyPair {
    pub secret_key: groth::SecretKey,
    pub public_key: PublicKey,
}
#[derive(Debug, PartialEq, Eq,Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct Signature {
    pub r1: G1Affine, //r2 = g2^r
    pub s2: G2Affine, // s1 = (y1 * g1^sk)^(1/r)
    pub t2: G2Affine // t1 = (y1^sk * message)^(1/r)
}

pub fn par_gen() -> PublicParameters{
    let g1_hex = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    let g2_hex = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    let g1_bytes = hex::decode(g1_hex).unwrap();
    let g2_bytes = hex::decode(g2_hex).unwrap();
    let g1 = G1Affine::deserialize_compressed(&g1_bytes[..]).unwrap();
    let g2 = G2Affine::deserialize_compressed(&g2_bytes[..]).unwrap();

    let dst2 = b"GROTH-SIG-GENERATOR-DST-V2";
    let y2_bytes = "Jan Bobolz, Fabian Eidens, Stephan Krenn, Sebastian Ramacher, and Kai Samelin makes Y2".to_string().into_bytes();
    let y2 = G2Affine::from(groth::hash_to_g2(&y2_bytes[..], dst2));
    let pp = PublicParameters{
        g1,
        g2,
        y2: G2Affine::from(y2),
    };
    return pp;
}

pub fn key_gen(pp: &PublicParameters) -> KeyPair{
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

pub fn sign(pp: &PublicParameters, sk: &groth::SecretKey, message: &G2Affine) -> Signature{
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let r_inverse = r.inverse().unwrap();

    let r1  = pp.g1 * r;
    let s2 = (pp.y2 + (pp.g2 * sk.0)) * (r_inverse);
    let t2 = (pp.y2 * sk.0 + *message) * (r_inverse);
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

pub fn verify(pp: &PublicParameters, pk: &PublicKey, sig: &Signature, message: &G2Affine) -> bool{
    let r1 = sig.r1;
    let s2 = sig.s2;
    let t2 = sig.t2;
    let g1 = pp.g1;
    let g2 = pp.g2;
    let y2 = pp.y2;

    if Bls12_381::pairing(r1,s2) != Bls12_381::pairing(g1,y2) + Bls12_381::pairing(pk.0,g2){
        println!("Groth2 First pairing check failed");
        return false;
    }
    if Bls12_381::pairing(r1,t2) != Bls12_381::pairing(pk.0,y2) + Bls12_381::pairing(g1,message){
        println!("Groth2 Second pairing check failed");
        return false;
    }

    return true;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let pp = super::par_gen();
        let keypair = super::key_gen(&pp);
        let message_string = "It's a Bobolz et.al. Issuer-Hiding";
        let message = groth::hash_to_g2(message_string.as_bytes(), b"TEST-DST");
        let sig = super::sign(&pp, &keypair.secret_key, &message);
        let newsig = super::rand_sign(&sig);
        let result = super::verify(&pp, &keypair.public_key, &newsig, &message);
        assert_eq!(result, true);
    }
}