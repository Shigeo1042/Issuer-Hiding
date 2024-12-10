use ark_bls12_381::{G1Affine, G2Affine, Bls12_381, G1Projective, G2Projective};
use ark_ff::{Field, PrimeField};
use ark_ec::pairing::Pairing;
use ark_std::{fmt::Debug, vec::Vec, UniformRand};
use rand;
use sha2::{Digest, Sha256};
// use mulitbase::Base;
// use serde::{Deserialize, Serialize};

use crate::groth;
use crate::groth1;
use crate::groth2;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicParameters {
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub y1: G1Affine,
    pub y2: G2Affine,
    pub h: Vec<G1Affine>
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PiKP{
    pub p1: G2Affine,
    pub p2: G1Affine,
    pub p3: G1Affine,
    pub p4: G2Affine,
    pub p5: G1Affine,
    pub abar: G1Affine,
    pub open: Vec<usize>,
    pub len: usize,
    pub message_list: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PiZKP{
    pub u1: G2Projective,
    pub u2: G1Projective,
    pub u3: G1Projective,
    pub u4: G2Projective,
    pub u5: G1Projective,
    pub u6: G1Projective,
    pub challenge: Fr,
    pub randome_fr: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TrustedIssuerCredential{
    pub ipk: groth1::PublicKey,
    pub cred: groth2::Signature
}

fn hash_to_fr(input: &[u8]) -> Fr {
    // Step 1: Compute the hash (SHA-256 in this case)
    let hash_bytes = Sha256::digest(input);

    // Step 2: Convert the hash bytes to a field element in Fr
    // Fr::from_be_bytes_mod_order safely maps bytes to an Fr element
    Fr::from_be_bytes_mod_order(&hash_bytes)
}

pub fn par_gen(len: &i32) -> PublicParameters{
    let mut rng = rand::thread_rng();
    let pp_groth = groth::par_gen(&mut rng);
    let mut hvec: Vec<G1Affine> = Vec::new();
    for _ in 0..*len{
        hvec.push(G1Affine::rand(&mut rng));
    }
    let pp_bobolz = PublicParameters{
        g1 : pp_groth.g1,
        g2 : pp_groth.g2,
        y1 : pp_groth.y1,
        y2 : pp_groth.y2,
        h : hvec,
    };
    return pp_bobolz
}

pub fn issuer_key_gen(pp: &PublicParameters) -> groth1::KeyPair{
    let pp_groth = groth::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y1: pp.y1, 
        y2: pp.y2,
    };
    let keypair = groth1::key_gen(&pp_groth);
    return keypair
}

pub fn issue(pp: &PublicParameters, isk: &groth::SecretKey, message: &Fr) -> groth1::Signature{
    let pp_groth = groth::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y1: pp.y1, 
        y2: pp.y2,
    };
    let mut message_pro = pp.h[0] * message;
    for i in 1..pp.h.len(){
        message_pro += pp.h[i] * message;
    }
    let message_affine = G1Affine::from(message_pro);
    let signature = groth1::sign(&pp_groth, isk, &message_affine);
    return signature

}

pub fn verify(pp: &PublicParameters, cred: &groth1::Signature, message: &Vec<Fr>, ipk: &groth1::PublicKey) -> bool{
    let mut message_pro = pp.h[0] * message[0];
    for i in 1..message.len(){
        message_pro += pp.h[i] * message[i];
    }
    let pp_groth = groth::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y1: pp.y1, 
        y2: pp.y2,
    };
    let message_affine = G1Affine::from(message_pro);
    let result = groth1::verify(&pp_groth, ipk, cred, &message_affine);
    return result
}

pub fn verifier_key_gen(pp: &groth::PublicParameters) -> groth2::KeyPair{
    let keypair = groth2::key_gen(pp);
    return keypair
}

pub fn issue_list(pp: &groth::PublicParameters, message: &Vec<G2Affine>, keypair: &groth2::KeyPair) -> (groth2::PublicKey, Vec<TrustedIssuerCredential>){
    let mut result: Vec<TrustedIssuerCredential> = Vec::new();
    for i in 0..message.len(){
        let ipk_affine = message[i];
        let pp_groth = groth::PublicParameters {
            g1: pp.g1, 
            g2: pp.g2, 
            y1: pp.y1, 
            y2: pp.y2,
        };
        let signature = groth2::sign(&pp_groth, &keypair.secret_key, &ipk_affine);
        let ipk = groth1::PublicKey{
            0: ipk_affine
        };
        let cred = TrustedIssuerCredential{
            ipk,
            cred: signature
        };
        result.push(cred);
    }
    let pk = keypair.public_key.clone();
    return (pk, result);
}

pub fn verify_list(pp: &PublicParameters,(vpk, list): (&groth2::PublicKey, &Vec<TrustedIssuerCredential>)) -> bool{
    let pp_groth = groth::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y1: pp.y1, 
        y2: pp.y2,
    };
    let mut result = true;
    for trusted_cred in list{
        let ipk_i = &trusted_cred.ipk;
        let sig_i = &trusted_cred.cred;
        let res_i = groth2::verify(&pp_groth, vpk, &sig_i, &ipk_i.0);
        result = result && res_i;
    }
    return result
}

pub fn present(pp: &PublicParameters, cred: &groth1::Signature, ipk: &groth1::PublicKey, message: &Vec<Fr>, (_, list): (groth2::PublicKey, Vec<TrustedIssuerCredential>),open: &Vec<usize>) -> (groth1::Signature, groth1::PublicKey, groth2::Signature, PiKP, PiZKP){
    let newcred = groth1::rand_sign(cred);
    let mut issuer_list = list[0].clone();
    for i in 0..list.len(){
        if list[i].ipk == *ipk{
            issuer_list = list[i].clone();
        }
    }
    let mut message_pro = pp.h[0] * message[0];
    for i in 1..message.len(){
        message_pro += pp.h[i] * message[i];
    }
    let message_affine = G1Affine::from(message_pro);
    let new_issuer_sig = groth2::rand_sign( &issuer_list.cred);
    let mut rng = rand::thread_rng();
    let alpha = Fr::rand(&mut rng);
    let alpha_inverse = alpha.inverse().unwrap();
    let beta = Fr::rand(&mut rng);
    let beta_inverse = beta.inverse().unwrap();
    let gamma = Fr::rand(&mut rng);
    let gamma_inverse = gamma.inverse().unwrap();
    let delta = Fr::rand(&mut rng);
    let delta_inverse = delta.inverse().unwrap();
    let blind_cred = groth1::Signature{
        r2: cred.r2,
        s1: G1Affine::from(cred.s1 * (alpha_inverse)),
        t1: G1Affine::from(cred.t1 * (beta_inverse))
    };
    let blind_ipk = groth1::PublicKey(G2Affine::from(ipk.0 * (gamma_inverse)));
    let blind_issuer_sig = groth2::Signature{
        r1: issuer_list.cred.r1,
        s2: issuer_list.cred.s2,
        t2: G2Affine::from(issuer_list.cred.t2 * (delta_inverse))
    };
    let mut close = Vec::new();
    for i in 0..message.len(){
        if !open.contains(&i){
            close.push(i);
        }
    }
    // let close = close_mut.clone();
    let mut message_open_list: Vec<Fr> = Vec::new();
    for i in open{
        message_open_list.push(message[*i]);
    }
    let mut message_close_list: Vec<Fr> = Vec::new();
    for i in &close{
        message_close_list.push(message[*i]);
    }
    let mut open_pro = pp.h[open[0]] * message_open_list[0];
    for i in 1..open.len(){
        open_pro += pp.h[open[i]] * message_open_list[i];
    }
    let r = Fr::rand(&mut rng);
    let r_inverse = r.inverse().unwrap();
    let abar = message_affine * r;
    let p1 = G2Affine::from(blind_cred.r2 * alpha);
    let p2 = G1Affine::from(pp.g1 * (-gamma));
    let p3 = G1Affine::from(pp.y1 * (-gamma - r));
    let p4 = G2Affine::from(blind_cred.r2 * (beta + r));
    let p5 = G1Affine::from(blind_issuer_sig.r1 * delta);
    let pi_kp = PiKP{
        p1,
        p2,
        p3,
        p4,
        p5,
        abar: G1Affine::from(abar),
        open: open.clone(),
        len: message.len(),
        message_list: message_open_list,
    };
    let mut rprime : Vec<Fr> = Vec::new();
    for _ in 0..5{
        rprime.push(Fr::rand(&mut rng));
    }
    for _ in &close {
        rprime.push(Fr::rand(&mut rng));
    }
    let u1 = blind_cred.r2 * rprime[0];
    let u2 = pp.g1 * rprime[1];
    let u3 = pp.y1 * rprime[2];
    let u4 = blind_cred.r2 * rprime[3];
    let u5 = blind_issuer_sig.r1 * rprime[4];
    let mut u6_proj = abar * rprime[5];
    for i in 0..close.len(){
        u6_proj += pp.h[close[i]] * rprime[5+i];
    }
    let p1_string = p1.to_string();
    let p2_string = p2.to_string();
    let p3_string = p3.to_string();
    let p4_string = p4.to_string();
    let p5_string = p5.to_string();
    let abar_string = abar.to_string();
    let challange_string = p1_string + &p2_string + &p3_string + &p4_string + &p5_string + &abar_string;
    let challange_u8 = challange_string.as_bytes();
    let challange = hash_to_fr(&challange_u8);
    let mut rprime2 : Vec<Fr> = Vec::new();
    rprime2.push(rprime[0] + challange * alpha);
    rprime2.push(rprime[1] + challange * (-gamma));
    rprime2.push(rprime[2] + challange * (-gamma - r));
    rprime2.push(rprime[3] + challange * (beta + r));
    rprime2.push(rprime[4] + challange * delta);
    rprime2.push(rprime[5] + challange * r_inverse);
    for i in 0..close.len(){
        rprime2.push(rprime[i + 5] + challange * message_close_list[i]);
    }
    let pi_zkp = PiZKP{
        u1,
        u2,
        u3,
        u4,
        u5,
        u6: u6_proj,
        challenge: challange,
        randome_fr: rprime2,
    };
    return (newcred, blind_ipk, new_issuer_sig, pi_kp, pi_zkp)
}

pub fn verify_present(pp: &PublicParameters, (vpk, _): (&groth2::PublicKey, &Vec<TrustedIssuerCredential>), cred: &groth1::Signature, ipk: &groth1::PublicKey, issuer_sig: &groth2::Signature, pi_kp: &PiKP, pi_zkp: &PiZKP) -> bool{
    let mut result = true;
    if Bls12_381::pairing(pp.y1,pp.g2) != Bls12_381::pairing(cred.s1, pi_kp.p1) + Bls12_381::pairing(pi_kp.p2, ipk.0){
        result = false;
    }
    if Bls12_381::pairing(pi_kp.abar, pp.g2) != Bls12_381::pairing(pi_kp.p3, ipk.0) + Bls12_381::pairing(cred.t1, pi_kp.p4){
        result = false;
    }
    if Bls12_381::pairing(issuer_sig.r1, issuer_sig.s2) != Bls12_381::pairing(pp.g1, pp.y2) + Bls12_381::pairing(vpk.0, pp.g2){
        result = false;
    }
    if Bls12_381::pairing(vpk.0, pp.y2) != Bls12_381::pairing(pi_kp.p2, ipk.0) + Bls12_381::pairing(pi_kp.p5, issuer_sig.t2){
        result = false;
    }
    let p1_string = pi_kp.p1.to_string();
    let p2_string = pi_kp.p2.to_string();
    let p3_string = pi_kp.p3.to_string();
    let p4_string = pi_kp.p4.to_string();
    let p5_string = pi_kp.p5.to_string();
    let abar_string = pi_kp.abar.to_string();
    let challange_string = p1_string + &p2_string + &p3_string + &p4_string + &p5_string + &abar_string;
    let challange_u8 = challange_string.as_bytes();
    let challange = hash_to_fr(&challange_u8);
    if challange != pi_zkp.challenge{
        result = false;
    }
    let new_p1 = pi_zkp.u1 + pi_kp.p1 * pi_zkp.challenge;
    let new_p2 = pi_zkp.u2 + pi_kp.p2 * pi_zkp.challenge;
    let new_p3 = pi_zkp.u3 + pi_kp.p3 * pi_zkp.challenge;
    let new_p4 = pi_zkp.u4 + pi_kp.p4 * pi_zkp.challenge;
    let new_p5 = pi_zkp.u5 + pi_kp.p5 * pi_zkp.challenge; 
    let mut new_open_proj = pp.h[pi_kp.open[0]] * pi_kp.message_list[0];
    for i in 1..pi_kp.open.len(){
        new_open_proj += pp.h[pi_kp.open[i]] * pi_kp.message_list[i];
    }
    new_open_proj *= pi_zkp.challenge;
    new_open_proj += pi_zkp.u6;
    if new_p1 != cred.r2 * pi_zkp.randome_fr[0]{
        result = false;
    }
    if new_p2 != pp.g1 * pi_zkp.randome_fr[1]{
        result = false;
    }
    if new_p3 != pp.y1 * pi_zkp.randome_fr[2]{
        result = false;
    }
    if new_p4 != cred.r2 * pi_zkp.randome_fr[3]{
        result = false;
    }
    if new_p5 != issuer_sig.r1 * pi_zkp.randome_fr[4]{
        result = false;
    }
    let mut new_p6 = pi_kp.abar * pi_zkp.randome_fr[5];
    for i in 0..pi_zkp.randome_fr.len(){
        new_p6 += pp.h[i] * pi_zkp.randome_fr[5+i];
    }
    if new_open_proj != new_p6{
        result = false;
    }
    return result
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}