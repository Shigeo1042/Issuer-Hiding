use ark_bls12_381::{G1Affine, G2Affine, Bls12_381, G1Projective};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, UniformRand, vec::Vec};

use crate::bbs;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicKey(pub G2Affine);

#[derive(Clone, PartialEq, Eq, Debug,  CanonicalSerialize)]
#[allow(non_snake_case)]
pub struct KeyPair {
    pub secret_key: bbs::SecretKey,
    pub public_key: PublicKey,
}

#[derive(Debug, PartialEq, Eq, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct Signature {
    pub a: G1Affine, // A = (g1 * \prod_{i=1}^{n} m_i)^{1/(sk + r)}
    pub e: Fr,       // e \stackrel{\$}{\leftarrow} Z_p^*
}

pub fn par_gen() -> bbs::PublicParameters{
    let pp = bbs::par_gen();
    return pp
}

pub fn key_gen(pp: &bbs::PublicParameters) -> KeyPair{
    // sk \stackrel{\$}{\leftarrow} Z_p^*
    let mut rng = ark_std::test_rng();
    let sk_element = Fr::rand(&mut rng);
    let sk = bbs::SecretKey(
        sk_element
    );

    // pk = g2^sk
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

pub fn sign(pp: &bbs::PublicParameters, sk: &bbs::SecretKey, messages: &Vec<Fr>) -> Signature{
    let mut rng = ark_std::test_rng();
    // e \stackrel{\$}{\leftarrow} Z_p^*
    let e = Fr::rand(&mut rng);

    let dst = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";

    let message_len = messages.len();
    // compute h_i
    let h_generators : Vec<G1Affine> = (0..message_len).map(|i| {
            let seed = format!("MESSAGE_GENERATOR_SEED_{}", i);
            bbs::hash_to_g1(seed.as_bytes(), dst)
        })
        .collect();

    // compute \prod_{i=1}^{n} h_i^m_i
    let mut m_product = G1Projective::from(pp.g1);
    for i in 0..message_len {
        let message = &messages[i];
        let h_element = h_generators[i];
        m_product += h_element * message;
    }

    // compute A = (g1 * \prod_{i=1}^{n} h_i^m_i)^{1/(sk + e)}
    let sk_plus_e = sk.0 + e;
    let sk_plus_e_inv = sk_plus_e.inverse().unwrap();
    let a_element = (m_product) * sk_plus_e_inv;
    let a_affine = G1Affine::from(a_element);

    let signature = Signature{
        a: a_affine,
        e: e,
    };

    return signature
}

pub fn verify(pp: &bbs::PublicParameters, pk: &PublicKey, messages: &Vec<Fr>, signature: &Signature) -> bool{
    let message_len = messages.len();

    let dst = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";

    let h_generators : Vec<G1Affine> = (0..message_len).map(|i| {
            let seed = format!("MESSAGE_GENERATOR_SEED_{}", i);
            bbs::hash_to_g1(seed.as_bytes(), dst)
        })
        .collect();

    // compute \prod_{i=1}^{n} h_i^m_i
    let mut m_product = G1Projective::from(pp.g1);
    for i in 0..message_len {
        let message = &messages[i];
        let h_element = h_generators[i];
        m_product += h_element * message;
    }
    // compute left side: e(A, pk + g2^e)
    let left_side = Bls12_381::pairing(signature.a, G2Affine::from(pk.0 + (pp.g2 * signature.e)));

    // compute right side: e(g1 * \prod_{i=1}^{n} h_i^m_i, g2)
    let right_side = Bls12_381::pairing(G1Affine::from(m_product), pp.g2);

    let mut bool = false;
    if left_side == right_side {
        bool = true;
        println!("Verification succeeded");
    } else {
        println!("Verification failed");
    }
    return bool
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use num_bigint::BigUint;

    #[test]
    fn it_works(){
        let pp = super::par_gen();
        let keypair = super::key_gen(&pp);
        let message_string = "Issuer-Hiding BBS Test Message";
        let message_fr = Fr::from(BigUint::from_bytes_be(message_string.as_bytes()));
        let messages = vec![message_fr];
        let signature = super::sign(&pp, &keypair.secret_key, &messages);
        let verify_result = super::verify(&pp, &keypair.public_key, &messages, &signature);
        assert_eq!(verify_result, true);
    }
}