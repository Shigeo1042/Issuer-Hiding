use ark_bls12_381::{G1Affine, G2Affine, Bls12_381, G1Projective};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, UniformRand, vec::Vec};
use rand::thread_rng;

use crate::bbs;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicParameters{
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub h_vec: Vec<G1Affine>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicKey(pub G2Affine);

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct KeyPair {
    pub secret_key: bbs::SecretKey,
    pub public_key: PublicKey,
}

#[derive(Debug, PartialEq, Eq, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct Signature {
    pub a: G1Affine, // A = (g1 * \prod_{i=1}^{n} m_i)^{1/(sk + r)}
    pub e: Fr,       // e \stackrel{\$}{\leftarrow} Z_p^*
}

pub fn par_gen() -> PublicParameters{
    let g1_hex = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    let g2_hex = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    let g1_bytes = hex::decode(g1_hex).unwrap();
    let g2_bytes = hex::decode(g2_hex).unwrap();
    let g1 = G1Affine::deserialize_compressed(&g1_bytes[..]).unwrap();
    let g2 = G2Affine::deserialize_compressed(&g2_bytes[..]).unwrap();
    
    let h_seed = "MESSAGE_GENERATOR_SEED_";
    let h_dst = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let h_vec:Vec<G1Affine> = (0..50).map(|i| {
            let seed = format!("{}{}", h_seed, i);
            bbs::hash_to_g1(seed.as_bytes(), h_dst)
        })
        .collect();
    let pp = PublicParameters{
        g1,
        g2,
        h_vec,
    };
    return pp
}

pub fn key_gen(pp: &PublicParameters) -> KeyPair{
    // sk \stackrel{\$}{\leftarrow} Z_p^*
    let mut rng = thread_rng();
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

pub fn sign(pp: &PublicParameters, sk: &bbs::SecretKey, messages: &Vec<Fr>) -> Signature{
    let mut rng = thread_rng();
    // e \stackrel{\$}{\leftarrow} Z_p^*
    let e = Fr::rand(&mut rng);

    let message_len = messages.len();
    // compute h_i
    let h_generators : Vec<G1Affine> = pp.h_vec[0..message_len].to_vec();

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

pub fn verify(pp: &PublicParameters, pk: &PublicKey, messages: &Vec<Fr>, signature: &Signature) -> bool{
    let message_len = messages.len();

    let h_generators : Vec<G1Affine> = pp.h_vec[0..message_len].to_vec();

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
    
    if left_side != right_side {
        println!("Verification Failed!");
        return false;
    } else {
    }
    return true
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use num_bigint::BigUint;

    #[test]
    fn it_works(){
        let pp = super::par_gen();
        let keypair = super::key_gen(&pp);
        println!("Secret Key: {}", keypair.secret_key.0);
        let message_string = "Issuer-Hiding BBS Test Message";
        let message_fr = Fr::from(BigUint::from_bytes_be(message_string.as_bytes()));
        let messages = vec![message_fr];
        let signature = super::sign(&pp, &keypair.secret_key, &messages);
        let verify_result = super::verify(&pp, &keypair.public_key, &messages, &signature);
        assert_eq!(verify_result, true);
    }
}