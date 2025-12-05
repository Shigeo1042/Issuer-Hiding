use ark_bls12_381::{G1Affine, G2Affine, Bls12_381};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, UniformRand, vec::Vec};

use crate::bbs;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicParameters{
    pub gbar1: G1Affine,
    pub gbar2: G2Affine,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicKey(pub G1Affine, pub G2Affine);

#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(non_snake_case)]
pub struct KeyPair {
    pub secret_key: bbs::SecretKey,
    pub public_key: PublicKey,
}

#[derive(Debug, PartialEq, Eq, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct Signature {
    pub a: G2Affine, // A = (g2 * ipk)^{1/(sk + e)}
    pub e: Fr,       // e \stackrel{\$}{\leftarrow} Z_p^*
}

pub fn par_gen() -> PublicParameters{
    let dst1 = b"BBS-SIG-GENERATOR-DST-V1";
    let dst2 = b"BBS-SIG-GENERATOR-DST-V2";
    let gbar1_bytes = "Issuer-Hiding BBS Make to gbar1".to_string().into_bytes();
    let gbar2_bytes = "Issuer-Hiding BBS Make to gbar2".to_string().into_bytes();
    let gbar1 = G1Affine::from(bbs::hash_to_g1(&gbar1_bytes[..], dst1));
    let gbar2 = G2Affine::from(bbs::hash_to_g2(&gbar2_bytes[..], dst2));

    let pp = PublicParameters{
        gbar1,  
        gbar2,
    };
    return pp
}

pub fn key_gen(pp: &PublicParameters) -> KeyPair{
    // sk \stackrel{\$}{\leftarrow} Z_p^*
    let mut rng = ark_std::test_rng();
    let sk_element = Fr::rand(&mut rng);
    let sk = bbs::SecretKey(
        sk_element
    );

    // pk = g1^sk
    let pk_1_element = pp.gbar1 * sk.0;
    let pk_2_element = pp.gbar2 * sk.0;
    let pk_1_affine = G1Affine::from(pk_1_element);
    let pk_2_affine = G2Affine::from(pk_2_element);
    let pk = PublicKey(
        pk_1_affine,
        pk_2_affine
    );

    let keypair = KeyPair {
        secret_key: sk,
        public_key: pk,
    };

    return keypair
}

pub fn sign(pp: &PublicParameters, sk: &bbs::SecretKey, messages: &G2Affine) -> Signature{
    let mut rng = ark_std::test_rng();
    // e \stackrel{\$}{\leftarrow} Z_p^*
    let e = Fr::rand(&mut rng);

    // compute A = (g2 * ipk)^{1/(sk + e)}
    let sk_plus_e = sk.0 + e;
    let sk_plus_e_inv = sk_plus_e.inverse().unwrap();
    let a_element = (pp.gbar2 + messages) * sk_plus_e_inv;
    let a_affine = G2Affine::from(a_element);
    let signature = Signature{
        a: a_affine,
        e: e,
    };

    return signature
}

pub fn verify(pp: &PublicParameters, pk: &PublicKey, message: &G2Affine, signature: &Signature) -> bool{

    // verify e(gbar1^e * vpk, a) = e(gbar1, gbar2 * M)
    let pk_1: G1Affine = pk.0;
    let mut bool = false;
    let left_p = G1Affine::from(pp.gbar1 * signature.e + pk_1);
    let left_q = signature.a;
    let right_p = pp.gbar1;
    let right_q = G2Affine::from(pp.gbar2 + message);
    let left = Bls12_381::pairing(left_p, left_q);
    let right = Bls12_381::pairing(right_p, right_q);
    if left == right {
        bool = true;
        println!("Verification succeeded");
    } else {
        println!("Verification failed");
    }

    return bool
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works(){
        use crate::issuer;
        let pp = super::par_gen();
        let pp_issuer = issuer::par_gen();
        let issuerkeypair = issuer::key_gen(&pp_issuer);
        let verifierkeypair = super::key_gen(&pp);
        let signature = super::sign(&pp, &verifierkeypair.secret_key, &issuerkeypair.public_key.0);
        let verify_result = super::verify(&pp, &verifierkeypair.public_key, &issuerkeypair.public_key.0, &signature);
        assert_eq!(verify_result, true);
    }
}