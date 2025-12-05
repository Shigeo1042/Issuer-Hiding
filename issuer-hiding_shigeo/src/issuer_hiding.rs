use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective};
// use ark_ff::{Field, PrimeField};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ec::{pairing::Pairing};
// use ark_std::{fmt::Debug, vec::Vec, UniformRand};
use ark_std::{fmt::Debug, vec::Vec};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Sha256};

use mybbs::bbs as bbs;
use mybbs::issuer;
use mybbs::verifier;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

// #[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
// pub struct PublicParameters {
//     pub g1: G1Affine,
//     pub g2: G2Affine,
//     pub gbar1: G1Affine,
//     pub gbar2: G2Affine,
//     pub q1: G1Affine,
//     pub h_seed: Vec<u8>,
//     pub h_dst: [u8; 31],
// }

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize)]
pub struct TrustedIssuerCredential{
    pub ipk: issuer::PublicKey,
    pub cred: verifier::Signature
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize)]
pub struct PiKP{
    pub a_bar1: G1Affine,
    pub b_bar1: G1Affine,
    pub d_1: G1Affine,
    pub u_1: G1Affine,
    pub u_2: G1Affine,
    pub a_bar2: G2Affine,
    pub b_bar2: G2Affine,
    pub d_2: G2Affine,
    pub u_3: G2Affine,
    pub u_4: G2Affine,
    pub open: Vec<usize>,
    pub len: usize,
    pub message_list: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize)]
pub struct PiZKP{
    pub s1: Fr,
    pub s2: Fr,
    pub t1: Fr,
    pub t2: Fr,
    pub z1: Fr,
    pub z2: Fr,
    pub v1: Vec<Fr>,
    pub v2: Fr
}

pub fn hash_to_fr(input: &[u8], dst: &[u8]) -> Fr {
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fr>>::new(dst);

    let scalars: [Fr; 1] = hasher.hash_to_field::<1>(input);
    let ans = scalars[0];
    return ans;
}

pub fn par_gen() -> bbs::PublicParameters{
    let pp = bbs::par_gen();
    return pp
}

pub fn issuer_key_gen(pp: &bbs::PublicParameters) -> issuer::KeyPair{
    let keypair = issuer::key_gen(pp);
    return keypair
}

pub fn issue(pp: &bbs::PublicParameters, isk: &bbs::SecretKey, messages: &Vec<Fr>) -> issuer::Signature{
    let signature = issuer::sign(pp, isk, messages);
    return signature
}

pub fn verify(pp: &bbs::PublicParameters, ipk: &issuer::PublicKey, messages: &Vec<Fr>, sig: &issuer::Signature) -> bool{
    let is_valid = issuer::verify(pp, ipk, messages, sig);
    return is_valid
}

pub fn verifier_key_gen(pp: &bbs::PublicParameters) -> verifier::KeyPair{
    let keypair = verifier::key_gen(pp);
    return keypair
}

pub fn issue_list(pp: &bbs::PublicParameters, key: &verifier::KeyPair, message_list: &Vec<issuer::PublicKey>) -> (verifier::PublicKey, Vec<TrustedIssuerCredential>){
    let vsk = &key.secret_key;
    let mut credential: Vec<TrustedIssuerCredential> = Vec::new();
    for i in 0..message_list.len(){
        let ipk = &message_list[i];
        let signature = verifier::sign(pp, vsk, &ipk.0);
        let cred = TrustedIssuerCredential{
            ipk: ipk.clone(),
            cred: signature,
        };
        credential.push(cred);
    }
    let vpk = key.public_key.clone();
    return (vpk, credential)
}

pub fn verify_list(pp: &bbs::PublicParameters, (vpk, list): &(verifier::PublicKey, Vec<TrustedIssuerCredential>)) -> bool{
    for i in 0..list.len(){
        let cred = &list[i];
        let ipk = &cred.ipk;
        let signature = &cred.cred;
        let is_valid = verifier::verify(pp, vpk, &ipk.0, signature);
        if is_valid == false{
            return false
        }
    }
    return true
}

