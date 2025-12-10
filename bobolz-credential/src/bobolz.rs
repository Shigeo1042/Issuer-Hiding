use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_std::{fmt::Debug, UniformRand, vec::Vec};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::groth;
use crate::groth1;
use crate::groth2;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicParameters {
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub y1: G1Affine,
    pub y2: G2Affine,
    pub h: Vec<G1Affine>
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
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

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PiZKP{
    pub u1: G2Affine,
    pub u2: G1Affine,
    pub u3: G1Affine,
    pub u4: G2Affine,
    pub u5: G1Affine,
    pub u6: G1Affine,
    pub challenge: Fr,
    pub randome_fr: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct TrustedIssuerCredential{
    pub ipk: groth1::PublicKey,
    pub cred: groth2::Signature
}

pub fn par_gen() -> PublicParameters{
    let pp_groth = groth::par_gen();
    
    let h_seed = "MESSAGE_GENERATOR_SEED_";
    let h_dst = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let h_vec:Vec<G1Affine> = (0..50).map(|i| {
            let seed = format!("{}{}", h_seed, i);
            groth::hash_to_g1(seed.as_bytes(), h_dst)
        })
        .collect();

    let pp_bobolz = PublicParameters{
        g1 : pp_groth.g1,
        g2 : pp_groth.g2,
        y1 : pp_groth.y1,
        y2 : pp_groth.y2,
        h : h_vec,
    };
    return pp_bobolz
}

pub fn issuer_key_gen(pp: &PublicParameters) -> groth1::KeyPair{
    let pp_groth1 = groth1::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y1: pp.y1, 
    };
    let keypair = groth1::key_gen(&pp_groth1);
    return keypair
}

pub fn issue(pp: &PublicParameters, isk: &groth::SecretKey, message: &Vec<Fr>) -> groth1::Signature{
    let pp_groth1 = groth1::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y1: pp.y1,
    };
    let message_len = message.len();
    let mut message_pro = pp.h[0] * message[0];
    for i in 1..message_len{
        message_pro += pp.h[i] * message[i];
    }
    let message_affine = G1Affine::from(message_pro);
    let signature = groth1::sign(&pp_groth1, isk, &message_affine);
    return signature

}

pub fn verify(pp: &PublicParameters, cred: &groth1::Signature, message: &Vec<Fr>, ipk: &groth1::PublicKey) -> bool{
    let mut message_pro = pp.h[0] * message[0];
    for i in 1..message.len(){
        message_pro += pp.h[i] * message[i];
    }
    let pp_groth1 = groth1::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y1: pp.y1,
    };
    let message_affine = G1Affine::from(message_pro);
    let result = groth1::verify(&pp_groth1, ipk, cred, &message_affine);
    return result
}

pub fn verifier_key_gen(pp: &PublicParameters) -> groth2::KeyPair{
    let pp_groth2 = groth2::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y2: pp.y2,
    };
    let keypair = groth2::key_gen(&pp_groth2);
    return keypair
}

pub fn issue_list(pp: &PublicParameters, message: &Vec<groth1::PublicKey>, keypair: &groth2::KeyPair) -> (groth2::PublicKey, Vec<TrustedIssuerCredential>){
    let pp_groth2 = groth2::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y2: pp.y2,
    };
    let mut result: Vec<TrustedIssuerCredential> = Vec::new();
    for i in 0..message.len(){
        let ipk = &message[i];
        let signature = groth2::sign(&pp_groth2, &keypair.secret_key, &ipk.0);
        let cred = TrustedIssuerCredential{
            ipk: ipk.clone(),
            cred: signature
        };
        result.push(cred);
    }
    let pk = keypair.public_key.clone();
    return (pk, result);
}

pub fn verify_list(pp: &PublicParameters,(vpk, list): &(groth2::PublicKey, Vec<TrustedIssuerCredential>)) -> bool{
    let pp_groth2 = groth2::PublicParameters {
        g1: pp.g1, 
        g2: pp.g2, 
        y2: pp.y2,
    };
    for trusted_cred in list{
        let ipk_i = &trusted_cred.ipk;
        let sig_i = &trusted_cred.cred;
        let is_valid = groth2::verify(&pp_groth2, vpk, &sig_i, &ipk_i.0);
        if is_valid == false{
            println!("Groth2 list verification failed");
            return false
        }
    }
    return true
}

pub fn present(pp: &PublicParameters, cred: &groth1::Signature, ipk: &groth1::PublicKey, message: &Vec<Fr>, (_, list): &(groth2::PublicKey, Vec<TrustedIssuerCredential>),open: &Vec<usize>) -> (groth1::Signature, groth1::PublicKey, groth2::Signature, PiKP, PiZKP){
    //make random holder signature
    let new_cred = groth1::rand_sign(cred);
    let mut issuer_list = list[0].clone();
    for i in 0..list.len(){
        if list[i].ipk == *ipk{
            issuer_list = list[i].clone();
        }
    }
    //make message affine
    let mut message_pro = pp.h[0] * message[0];
    for i in 1..message.len(){
        message_pro += pp.h[i] * message[i];
    }
    let message_affine = G1Affine::from(message_pro);

    //make random issuer public key signature
    let new_issuer_sig = groth2::rand_sign( &issuer_list.cred);

    //make random blind values
    let mut rng = rand::thread_rng();
    let alpha = Fr::rand(&mut rng);
    let alpha_inverse = alpha.inverse().unwrap();
    let beta = Fr::rand(&mut rng);
    let beta_inverse = beta.inverse().unwrap();
    let gamma = Fr::rand(&mut rng);
    let gamma_inverse = gamma.inverse().unwrap();
    let delta = Fr::rand(&mut rng);
    let delta_inverse = delta.inverse().unwrap();

    //make blind holder signature
    let blind_cred = groth1::Signature{
        r2: new_cred.r2,
        s1: G1Affine::from(new_cred.s1 * (alpha_inverse)),
        t1: G1Affine::from(new_cred.t1 * (beta_inverse))
    };

    //make blind issuer public key
    let blind_ipk = groth1::PublicKey(G2Affine::from(ipk.0 * (gamma_inverse)));
    //make blind issuer public key signature
    let blind_issuer_sig = groth2::Signature{
        r1: new_issuer_sig.r1,
        s2: new_issuer_sig.s2,
        t2: G2Affine::from(new_issuer_sig.t2 * (delta_inverse))
    };

    //make close message number list
    let mut close = Vec::new();
    for i in 0..message.len(){
        if !open.contains(&i){
            close.push(i);
        }
    }
    //make open message list
    let mut message_open_list: Vec<Fr> = Vec::new();
    for i in open{
        message_open_list.push(message[*i]);
    }
    //make close message list
    let mut message_close_list: Vec<Fr> = Vec::new();
    for i in &close{
        message_close_list.push(message[*i]);
    }
    
    //make proof of knowledge
    let r = Fr::rand(&mut rng);
    let r_inverse = r.inverse().unwrap();
    let r1 = gamma * r;
    let r2 = beta * r;

    let abar = G1Affine::from(message_affine * r);
    let p1 = G2Affine::from(blind_cred.r2 * alpha);
    let p2 = G1Affine::from(pp.g1 * (-gamma));
    let p3 = G1Affine::from(pp.y1 * (-r1));
    let p4 = G2Affine::from(blind_cred.r2 * r2);
    let p5 = G1Affine::from(blind_issuer_sig.r1 * delta);

    let pi_kp = PiKP{
        p1,
        p2,
        p3,
        p4,
        p5,
        abar,
        open: open.clone(),
        len: message.len(),
        message_list: message_open_list,
    };

    let mut rprime : Vec<Fr> = Vec::new();
    for _ in 0..6{
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
        u6_proj += pp.h[close[i]] * rprime[6+i];
    }

    let p1_string = p1.to_string();
    let p2_string = p2.to_string();
    let p3_string = p3.to_string();
    let p4_string = p4.to_string();
    let p5_string = p5.to_string();
    let abar_string = abar.to_string();

    let challange_string = p1_string + &p2_string + &p3_string + &p4_string + &p5_string + &abar_string;
    let challange_u8 = challange_string.as_bytes();
    let dst = b"MY_CHALLENGE_GENERATOR_DST_Issuer_Hiding_V1";
    let challange = groth::hash_to_fr(&challange_u8, dst);
    let mut rprime2 : Vec<Fr> = Vec::new();
    rprime2.push(rprime[0] + challange * alpha);
    rprime2.push(rprime[1] + challange * (-gamma));
    rprime2.push(rprime[2] + challange * (-r1));
    rprime2.push(rprime[3] + challange * r2);
    rprime2.push(rprime[4] + challange * delta);
    rprime2.push(rprime[5] + challange * r_inverse);
    for i in 0..close.len(){
        rprime2.push(rprime[i + 6] + challange * (-message_close_list[i]));
    }
    let pi_zkp = PiZKP{
        u1: G2Affine::from(u1),
        u2: G1Affine::from(u2),
        u3: G1Affine::from(u3),
        u4: G2Affine::from(u4),
        u5: G1Affine::from(u5),
        u6: G1Affine::from(u6_proj),
        challenge: challange,
        randome_fr: rprime2,
    };
    return (blind_cred, blind_ipk, blind_issuer_sig, pi_kp, pi_zkp)
}

pub fn verify_present(pp: &PublicParameters, (vpk, _): &(groth2::PublicKey, Vec<TrustedIssuerCredential>), (cred, ipk, issuer_sig, pi_kp, pi_zkp): &(groth1::Signature, groth1::PublicKey, groth2::Signature, PiKP, PiZKP)) -> bool{
    if Bls12_381::pairing(pp.y1,pp.g2) != Bls12_381::pairing(cred.s1, pi_kp.p1) + Bls12_381::pairing(pi_kp.p2, ipk.0){
        println!("Pairing check 1 failed");
        return false
    }
    if Bls12_381::pairing(pi_kp.abar, pp.g2) != Bls12_381::pairing(pi_kp.p3, ipk.0) + Bls12_381::pairing(cred.t1, pi_kp.p4){
        println!("Pairing check 2 failed");
        return false
    }
    if Bls12_381::pairing(issuer_sig.r1, issuer_sig.s2) != Bls12_381::pairing(pp.g1, pp.y2) + Bls12_381::pairing(vpk.0, pp.g2){
        println!("Pairing check 3 failed");
        return false
    }
    if Bls12_381::pairing(vpk.0, pp.y2) != Bls12_381::pairing(pi_kp.p2, ipk.0) + Bls12_381::pairing(pi_kp.p5, issuer_sig.t2){
        println!("Pairing check 4 failed");
        return false
    }
    let p1_string = pi_kp.p1.to_string();
    let p2_string = pi_kp.p2.to_string();
    let p3_string = pi_kp.p3.to_string();
    let p4_string = pi_kp.p4.to_string();
    let p5_string = pi_kp.p5.to_string();
    let abar_string = pi_kp.abar.to_string();
    let challange_string = p1_string + &p2_string + &p3_string + &p4_string + &p5_string + &abar_string;
    let challange_u8 = challange_string.as_bytes();
    let dst = b"MY_CHALLENGE_GENERATOR_DST_Issuer_Hiding_V1";
    let challange = groth::hash_to_fr(&challange_u8, dst);
    if challange != pi_zkp.challenge{
        println!("Challenge check failed");
        return false
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
    new_open_proj = G1Affine::from(new_open_proj) * pi_zkp.challenge;
    new_open_proj += pi_zkp.u6;
    if new_p1 != cred.r2 * pi_zkp.randome_fr[0]{
        println!("p1 check failed");
        return false
    }
    if new_p2 != pp.g1 * pi_zkp.randome_fr[1]{
        println!("p2 check failed");
        return false
    }
    if new_p3 != pp.y1 * pi_zkp.randome_fr[2]{
        println!("p3 check failed");
        return false
    }
    if new_p4 != cred.r2 * pi_zkp.randome_fr[3]{
        println!("p4 check failed");
        return false
    }
    if new_p5 != issuer_sig.r1 * pi_zkp.randome_fr[4]{
        println!("p5 check failed");
        return false
    }
    let mut close = Vec::new();
    for i in 0..pi_kp.len{
        if !pi_kp.open.contains(&i){
            close.push(i);
        }
    }
    let mut new_p6 = pi_kp.abar * pi_zkp.randome_fr[5];
    for i in 6..pi_zkp.randome_fr.len(){
        new_p6 += pp.h[close[i - 6]] * pi_zkp.randome_fr[i];
    }
    if new_open_proj != new_p6{
        println!("p6 check failed");
        return false
    }
    return true
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use super::*;
    #[test]
    // fn test(){
    //     for _ in 0..10{
    //         it_works();
    //     }
    // }
    fn it_works() {
        let message_len = 10;
        let issuer_num = 5;
        let mut rng = thread_rng();
        let pp = par_gen();
        let issuer_keypair = issuer_key_gen(&pp);
        let ipk = &issuer_keypair.public_key;
        let mut message_fr = Vec::new();
        for _ in 0..message_len{
            message_fr.push(Fr::rand(&mut rng));
        }
        let cred = issue(&pp, &issuer_keypair.secret_key, &message_fr);
        let result1 = verify(&pp, &cred, &message_fr, &issuer_keypair.public_key);
        assert_eq!(result1, true);

        let verifier_keypair = verifier_key_gen(&pp);
        let mut issuer_list = Vec::new();
        for _ in 0..issuer_num{
            let issuer_keypair_i = issuer_key_gen(&pp);
            let ipk_i = issuer_keypair_i.public_key;
            issuer_list.push(ipk_i);
        }

        let r = rng.gen_range(1..issuer_num);
        issuer_list[r] = ipk.clone();
        let trusted_issuer_credential = issue_list(&pp, &issuer_list, &verifier_keypair);
        let result2 = verify_list(&pp, &trusted_issuer_credential);
        assert_eq!(result2, true);
        let open_num = rng.gen_range(1..(message_len / 2));
        let mut open = Vec::new();
        for j in 0..open_num{
            let mut flg = true;
            let mut x = rng.gen_range(0..message_len) as usize;
            while flg {
                flg = false;
                for i in 0..j{
                    if x == open[i as usize]{
                        flg = true;
                        x = rng.gen_range(0..message_len) as usize;
                        break;
                    }
                }
            }
            open.push(x);
        }
        open.sort();
        let pt = present(&pp, &cred, &ipk, &message_fr, &trusted_issuer_credential, &open);
        let result3 = verify_present(&pp, &trusted_issuer_credential, &pt);
        assert_eq!(result3, true);
    }
}