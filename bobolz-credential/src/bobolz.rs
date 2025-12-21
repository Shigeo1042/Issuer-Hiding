use ark_bls12_381::{Bls12_381, G1Affine, G2Affine, G1Projective};
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
    pub blind_cred: groth1::Signature, 
    pub blind_ipk: groth1::PublicKey,
    pub blind_issuer_sig: groth2::Signature,
    pub open: Vec<usize>,
    pub len: usize,
    pub message_list: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PiZKP{
    pub c: Fr,
    pub z1: Fr,
    pub z2: Fr,
    pub z3: Fr,
    pub z4: Fr,
    pub z5: Vec<Fr>,
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

pub fn present(pp: &PublicParameters, cred: &groth1::Signature, ipk: &groth1::PublicKey, message: &Vec<Fr>, (_, list): &(groth2::PublicKey, Vec<TrustedIssuerCredential>),open: &Vec<usize>) -> (PiKP, PiZKP){
    //make random holder signature
    let new_cred = groth1::rand_sign(cred);
    let mut issuer_list = list[0].clone();
    for i in 0..list.len(){
        if list[i].ipk == *ipk{
            issuer_list = list[i].clone();
        }
    }
    let h_generators : Vec<G1Affine> = pp.h[0..message.len()].to_vec();

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
    let r1 = Fr::rand(&mut rng);
    let r2 = Fr::rand(&mut rng);
    let r3 = Fr::rand(&mut rng);
    let r4 = Fr::rand(&mut rng);
    let mut r5 = Vec::new();
    for _ in 0..close.len(){
        r5.push(Fr::rand(&mut rng));
    }

    let pi_kp = PiKP{
        blind_cred: blind_cred.clone(),
        blind_ipk: blind_ipk.clone(),
        blind_issuer_sig: blind_issuer_sig.clone(),
        open: open.clone(),
        len: message.len(),
        message_list: message_open_list.clone(),
    };
    
    let k_ipk = G2Affine::from(blind_ipk.0 * (-r3));
    let mut message_close_proj_rand = pp.h[close[0]] * -r5[0];
    for i in 1..close.len(){
        message_close_proj_rand += pp.h[close[i]] * -r5[i];
    }
    let message_close_affine_rand = G1Affine::from(message_close_proj_rand);
    let u1 = Bls12_381::pairing(G1Affine::from(blind_cred.s1 * r1), blind_cred.r2) + Bls12_381::pairing(pp.g1, k_ipk);
    let u2 = Bls12_381::pairing(G1Affine::from(blind_cred.t1 * r2), blind_cred.r2) + Bls12_381::pairing(pp.y1, k_ipk) + Bls12_381::pairing(message_close_affine_rand, pp.g2);
    let u3 = Bls12_381::pairing(blind_issuer_sig.r1, blind_issuer_sig.t2 * r4) + Bls12_381::pairing(pp.g1, k_ipk);

    let dst = b"CHALLENGE_GENERATOR_DST_Bobolz_Issuer_Hiding_V1";
    let mut c_inputs_buffer = Vec::new();
    blind_cred.serialize_compressed(&mut c_inputs_buffer).unwrap();
    blind_ipk.serialize_compressed(&mut c_inputs_buffer).unwrap();
    blind_issuer_sig.serialize_compressed(&mut c_inputs_buffer).unwrap();

    h_generators.serialize_compressed(&mut c_inputs_buffer).unwrap();
    message_open_list.serialize_compressed(&mut c_inputs_buffer).unwrap();
    u1.serialize_compressed(&mut c_inputs_buffer).unwrap();
    u2.serialize_compressed(&mut c_inputs_buffer).unwrap();
    u3.serialize_compressed(&mut c_inputs_buffer).unwrap();
    list.serialize_compressed(&mut c_inputs_buffer).unwrap();

    let c = groth::hash_to_fr(&c_inputs_buffer[..], dst);

    let z1 = r1 + c * alpha;
    let z2 = r2 + c * beta;
    let z3 = r3 + c * gamma;
    let z4 = r4 + c * delta;
    let mut z5 = Vec::new();
    for i in 0..r5.len(){
        z5.push(r5[i] + c * message_close_list[i]);
    }
    let pi_zkp = PiZKP{
        c,
        z1,
        z2,
        z3,
        z4,
        z5,
    };
    return (pi_kp, pi_zkp)
}

pub fn verify_present(pp: &PublicParameters, (vpk, list): &(groth2::PublicKey, Vec<TrustedIssuerCredential>), (pi_kp, pi_zkp): &(PiKP, PiZKP)) -> bool{
    let blind_cred = &pi_kp.blind_cred;
    let blind_ipk = &pi_kp.blind_ipk;
    let blind_issuer_sig = &pi_kp.blind_issuer_sig;
    let h_generators : Vec<G1Affine> = pp.h[0..pi_kp.len].to_vec();
    let mut close_index: Vec<usize> = Vec::new();
    for i in 0..pi_kp.len{
        if !pi_kp.open.contains(&i){
            close_index.push(i);
        }
    }
    let close_len = close_index.len();

    let mut k2_element = G1Projective::from(G1Affine::identity());
    for i in 0..pi_kp.open.len(){
        let h_i = h_generators[pi_kp.open[i]];
        k2_element += (h_i * (pi_kp.message_list[i])) * (-pi_zkp.c);
    }
    for i in 0..close_len{
        let h_i = h_generators[close_index[i]];
        k2_element += h_i * (-pi_zkp.z5[i]);
    }

    let k1 = Bls12_381::pairing(G1Affine::from(blind_cred.s1 * pi_zkp.z1), blind_cred.r2) + Bls12_381::pairing(pp.g1, G2Affine::from(blind_ipk.0 * (-pi_zkp.z3))) + Bls12_381::pairing(pp.y1, pp.g2 * (-pi_zkp.c));
    let k2 = Bls12_381::pairing(G1Affine::from(blind_cred.t1 * pi_zkp.z2), blind_cred.r2) + Bls12_381::pairing(pp.y1, G2Affine::from(blind_ipk.0 * (-pi_zkp.z3))) + Bls12_381::pairing(G1Affine::from(k2_element), pp.g2);
    let k3 = Bls12_381::pairing(blind_issuer_sig.r1, blind_issuer_sig.t2 * pi_zkp.z4) + Bls12_381::pairing(pp.g1, G2Affine::from(blind_ipk.0 * (-pi_zkp.z3))) + Bls12_381::pairing(vpk.0.clone(), pp.y2 * (-pi_zkp.c));

    let dst = b"CHALLENGE_GENERATOR_DST_Bobolz_Issuer_Hiding_V1";
    let mut c_inputs_buffer = Vec::new();
    blind_cred.serialize_compressed(&mut c_inputs_buffer).unwrap();
    blind_ipk.serialize_compressed(&mut c_inputs_buffer).unwrap();
    blind_issuer_sig.serialize_compressed(&mut c_inputs_buffer).unwrap();
    h_generators.serialize_compressed(&mut c_inputs_buffer).unwrap();
    pi_kp.message_list.serialize_compressed(&mut c_inputs_buffer).unwrap();
    k1.serialize_compressed(&mut c_inputs_buffer).unwrap();
    k2.serialize_compressed(&mut c_inputs_buffer).unwrap();
    k3.serialize_compressed(&mut c_inputs_buffer).unwrap();
    list.serialize_compressed(&mut c_inputs_buffer).unwrap();
    let c_calculated = groth::hash_to_fr(&c_inputs_buffer[..], dst);
    if c_calculated != pi_zkp.c{
        println!("ZKP verification failed");
        return false
    }
    if Bls12_381::pairing(blind_issuer_sig.r1, blind_issuer_sig.s2) != Bls12_381::pairing(pp.g1, pp.y2) + Bls12_381::pairing(vpk.0, pp.g2){
        println!("ZKP verification failed at equation 1");
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