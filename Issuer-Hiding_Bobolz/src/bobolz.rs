use std::str::Bytes;
use std::string;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rang::rngs::StdRng, UniformRand};
use blake2::Blake2b512;
use schnorr_pok::compute_random_oracle_challenge;
use groth;
use groth1;
use groth2;

use crate::groth;
use crate::groth1;
use crate::groth2;

pub struct PublicParameters {
    pub pp_groth: groth::PublicParameters,
    pub h: Vec<i32>
}

pub struct PiZKP{
    pub pi: groth1::Signature,
    pub zkp: groth2::Signature
}
struct Credential{}

pub fn par_gen(len: i32) -> PublicParameters{
    let pp_groth: groth::PublicParameters;
    let mut hvec = Vec::new();
    for i in 0..len{
        hvec.append(1)
    }
    let pp_bobolz = PublicParameters{
        pp_groth : pp_groth,
        h : hvec,
    };
    return pp_bobolz
}

pub fn issuer_key_gen(pp: PublicParameters) -> groth1::KeyPair{
    let pp_groth = pp.pp_groth;
    let keypair = groth1::key_gen(pp_groth);
    return keypair
}

pub fn issue(pp: PublicParameters, isk: String, message:Vec<String>) -> groth1::Signature{
    let pp_groth = pp.pp_groth;
    let signature = groth1::sign(pp, isk, message);
    return signature

}

pub fn verify(pp: PublicParameters, cred: groth1::Signature, message: Vec<String>, ipk: String) -> bool{
    let mut message_byte: Bytes = 1;
    for i in 0..message.len(){
        message_byte *= pp.h[i].to_bytes() ^ message[i].to_bytes();
    }
    let pp_groth = pp.pp_groth;
    let result = groth1::verify(pp_groth, ipk, cred, message_bytes.to_string());
    return result
}

pub fn verifier_key_gen(pp: groth::PublicParameters) -> groth::KeyPair{
    let keypair = groth2::key_gen(pp);
    return keypair
}

pub fn issue_list(pp: groth::PublicParameters,message: Vec<String>, keypair: groth::KeyPair) -> Vec<String, (String, groth2::Signature)>{
    let mut result: Vec<(String, (String, groth2::Signature))> = Vec::new();
    for i in 0..message.len(){
        ipk = message[i];
        let signature = groth2::sign(pp_groth, keypair.secret_key, ipk);
        result.append((keypair.public_key, (ipk, signature)));
    }
    return result
}

pub fn verify_list(pp: PublicParameters,list: Vec<String, (String, groth2::Signature)>, message: Vec<String>) -> bool{
    let pp_groth = pp.pp_groth;
    let mut result = true;
    for i in 0..list.len(){
        let vpk = list[i].0;
        let ipk = list[i].1.0;
        let sig = list[i].1.1;
        let res = groth2::verify(pp_groth, vpk, sig, ipk);
        result = result && res;
    }
    return result
}

pub fn present(pp: PublicParameters, cred: groth1::Signature, ipk: String, message: Vec<String>, list: Vec<String, (String, groth2::Signature)>) -> (groth1::Signature, String, groth2::Signature, PiZKP){
    let newcred = groth1::rand(pp.pp_groth, cred);
    let mut issuer_list = list[0].1.1;
    for i in 0..list.len(){
        if list[i].1.0 == ipk{
            issuer_list = list[i].1.1;
        }
    }
    let new_issuer_sig = groth2::rand(pp.pp_groth, issuer_list);
    let alpha = UniformRand::rand(rng);
    let beta = UniformRand::rand(rng);
    let gamma = UniformRand::rand(rng);
    let delta = UniformRand::rand(rng);
    let blind_cred = groth1::Signature{
        r2: cred.r2,
        s1: cred.s1 ^ (1/alpha),
        t1: cred.t1 ^ (1/beta)
    };
    let blind_ipk = (ipk.to_bytes() ^ (1/gamma)).to_string();
    let blind_issuer_sig = groth2::Signature{
        r1: issuer_list.r1,
        s2: issuer_list.s2,
        t2: issuer_list.t2 ^ (1/delta)
    };
}

pub fn verify_present(){}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}