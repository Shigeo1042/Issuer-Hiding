use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine};
// use ark_ff::{Field, PrimeField};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
// use ark_std::{fmt::Debug, vec::Vec, UniformRand};
use ark_std::{fmt::Debug, UniformRand, vec::Vec};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::thread_rng;

use mybbs::bbs as bbs;
use mybbs::issuer;
use mybbs::verifier;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TrustedIssuerCredential{
    pub ipk: issuer::PublicKey,
    pub cred: verifier::Signature
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PiKP{
    pub a_bar1: G1Affine,
    pub b_bar1: G1Affine,
    pub d_1: G1Affine,
    pub u_1: G1Affine,
    pub u_2: G1Affine,
    pub ipk_rand: G2Affine,
    pub a_bar2: G2Affine,
    pub b_bar2: G2Affine,
    pub d_2: G2Affine,
    pub u_3: G2Affine,
    pub u_4: G2Affine,
    pub c: Fr,
    pub open: Vec<usize>,
    pub len: usize,
    pub message_list: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
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

pub fn par_gen() -> bbs::PublicParameters{
    let pp = bbs::par_gen();
    return pp
}

pub fn issuer_key_gen(pp: &bbs::PublicParameters) -> issuer::KeyPair{
    let pp_issuer = issuer::PublicParameters{
        g1: pp.g1,
        g2: pp.g2,
        h_seed: pp.h_seed,
        h_dst: pp.h_dst,
    };
    let keypair = issuer::key_gen(&pp_issuer);
    return keypair
}

pub fn issue(pp: &bbs::PublicParameters, isk: &bbs::SecretKey, messages: &Vec<Fr>) -> issuer::Signature{
    let pp_issuer = issuer::PublicParameters{
        g1: pp.g1,
        g2: pp.g2,
        h_seed: pp.h_seed,
        h_dst: pp.h_dst,
    };
    let signature = issuer::sign(&pp_issuer, isk, messages);
    return signature
}

pub fn verify(pp: &bbs::PublicParameters, ipk: &issuer::PublicKey, messages: &Vec<Fr>, sig: &issuer::Signature) -> bool{
    let pp_issuer = issuer::PublicParameters{
        g1: pp.g1,
        g2: pp.g2,
        h_seed: pp.h_seed,
        h_dst: pp.h_dst,
    };
    let is_valid = issuer::verify(&pp_issuer, ipk, messages, sig);
    return is_valid
}

pub fn verifier_key_gen(pp: &bbs::PublicParameters) -> verifier::KeyPair{
    let pp_verifier = verifier::PublicParameters{
        gbar1: pp.gbar1,
        gbar2: pp.gbar2,
    };
    let keypair = verifier::key_gen(&pp_verifier);
    return keypair
}

pub fn issue_list(pp: &bbs::PublicParameters, key: &verifier::KeyPair, message_list: &Vec<issuer::PublicKey>) -> (verifier::PublicKey, Vec<TrustedIssuerCredential>){
    let pp_verifier = verifier::PublicParameters{
        gbar1: pp.gbar1,
        gbar2: pp.gbar2,
    };
    let vsk = &key.secret_key;
    let mut credential: Vec<TrustedIssuerCredential> = Vec::new();
    for i in 0..message_list.len(){
        let ipk = &message_list[i];
        let signature = verifier::sign(&pp_verifier, vsk, &ipk.0);
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
    let pp_verifier = verifier::PublicParameters{
        gbar1: pp.gbar1,
        gbar2: pp.gbar2,
    };
    for i in 0..list.len(){
        let cred = &list[i];
        let ipk = &cred.ipk;
        let signature = &cred.cred;
        let is_valid = verifier::verify(&pp_verifier, vpk, &ipk.0, signature);
        if is_valid == false{
            return false
        }
    }
    return true
}

pub fn present(
    pp: &bbs::PublicParameters, 
    cred: &issuer::Signature, 
    ipk: &issuer::PublicKey, 
    message_list: &Vec<Fr>, 
    reveal_index: &Vec<usize>,
    (_, list): &(verifier::PublicKey, Vec<TrustedIssuerCredential>)
) -> (PiKP, PiZKP){
    let message_len = message_list.len();

    let mut rng = thread_rng();
    let h_generators : Vec<G1Affine> = (0..message_len).map(|i| {
            let seed = format!("{}{}", pp.h_seed, i);
            bbs::hash_to_g1(seed.as_bytes(), pp.h_dst)
        })
        .collect();
    
    let list_len = list.len();
    let mut verifier_sig = list[0].cred.clone();
    for i in 0..list_len{
        if list[i].ipk == *ipk{
            verifier_sig = list[i].cred.clone();
        }
    }

    let r = Fr::rand(&mut rng);
    let r_inv = r.inverse().unwrap();
    let r_1 = Fr::rand(&mut rng);
    let r_2 = Fr::rand(&mut rng);
    let r_2_inv = r_2.inverse().unwrap();
    let r_3 = Fr::rand(&mut rng);
    let r_3_inv = r_3.inverse().unwrap();

    let mut d_element = G1Projective::from(pp.g1);
    let mut open_messages: Vec<Fr> = Vec::new();
    let mut close_index: Vec<usize> = Vec::new();
    for i in 0..message_len{
        d_element += h_generators[i] * message_list[i];
        if reveal_index.contains(&i){
            open_messages.push(message_list[i]);
        } else {
            close_index.push(i);
        }
    }
    let d_affine = G1Affine::from(d_element * r_2_inv);
    let close_len = close_index.len();
    let ipk_rand = G2Affine::from(ipk.0 * r);
    let abar = G1Affine::from(cred.a * (r_1 * r_2_inv * r_inv));
    let bbar = G1Affine::from((d_affine * r_1) + (abar * (-cred.e * r)));

    if Bls12_381::pairing(abar, ipk_rand) != Bls12_381::pairing(bbar, pp.g2) {
        println!("Credential signature verification failed during presentation");
    }

    let d2_affine = G2Affine::from((pp.gbar2 + ipk.0) * r_3_inv);
    let abar2 = G2Affine::from(verifier_sig.a * (r * r_3_inv));
    let bbar2 = G2Affine::from((d2_affine * r) + (abar2 * (-verifier_sig.e)));

    let alpha1 = Fr::rand(&mut rng);
    let alpha2 = Fr::rand(&mut rng);
    let beta1 = Fr::rand(&mut rng);
    let beta2 = Fr::rand(&mut rng); 
    let gamma1 = Fr::rand(&mut rng);
    let gamma2 = Fr::rand(&mut rng);
    let delta1_vec = (0..close_len).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();
    let delta2 = Fr::rand(&mut rng);

    let u1 = G1Affine::from((d_affine * alpha1) + (abar * beta1));
    let mut u2_element = d_affine * gamma1;
    for i in 0..close_len{
        u2_element += h_generators[close_index[i]] * delta1_vec[i];
    }
    let u2 = G1Affine::from(u2_element);
    let u3 = G2Affine::from((d2_affine * alpha2) + (abar2 * beta2));
    let u4 = G2Affine::from((d2_affine * gamma2) + (pp.gbar2 * delta2));
    let dst = b"MY_CHALLENGE_GENERATOR_DST_Issuer_Hiding_V1";
    let c_inputs1 = vec![
        abar,
        bbar,
        d_affine,
        u1,
        u2,
    ];
    let c_input2 = vec![
        ipk_rand,
        abar2,
        bbar2,
        d2_affine,
        u3,
        u4,
    ];
    let mut c_inputs_buffer = Vec::new();
    for c_input in &c_inputs1{
        c_input.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for c_input in &c_input2{
        c_input.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for open_msg in &open_messages{
        open_msg.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }

    let c = bbs::hash_to_fr(&c_inputs_buffer[..], dst);
    let pikp = PiKP{
        a_bar1: abar,
        b_bar1: bbar,
        d_1: d_affine,
        u_1: u1,
        u_2: u2,
        ipk_rand: ipk_rand,
        a_bar2: abar2,
        b_bar2: bbar2,
        d_2: d2_affine,
        u_3: u3,
        u_4: u4,
        c: c,
        open: reveal_index.clone(),
        len: message_len,
        message_list: open_messages,
    };

    let s1 = alpha1 + c * r_1;
    let s2 = alpha2 + c * r;
    let t1 = beta1 - c * (cred.e * r);
    let t2 = beta2 - c * (verifier_sig.e);
    let z1 = gamma1 + c * r_2;
    let z2 = gamma2 + c * r * r_3;
    let mut v1_vec: Vec<Fr> = Vec::new();
    for i in 0..close_len{
        let v1 = delta1_vec[i] - c * message_list[close_index[i]];
        v1_vec.push(v1);
    }
    let v2 = delta2 - c * r;
    let pizkp = PiZKP{
        s1: s1,
        s2: s2,
        t1: t1,
        t2: t2,
        z1: z1,
        z2: z2,
        v1: v1_vec,
        v2: v2,
    };
    return (pikp, pizkp)
}

pub fn verify_presentation(
    pp: &bbs::PublicParameters, 
    (vpk, _): &(verifier::PublicKey, Vec<TrustedIssuerCredential>), 
    pikp: &PiKP, 
    pizkp: &PiZKP
) -> bool{
    let message_len = pikp.len;

    let h_generators : Vec<G1Affine> = (0..message_len).map(|i| {
            let seed = format!("{}{}", pp.h_seed, i);
            bbs::hash_to_g1(seed.as_bytes(), pp.h_dst)
        })
        .collect();
    let mut close_index: Vec<usize> = Vec::new();
    for i in 0..message_len{
        if !pikp.open.contains(&i){
            close_index.push(i);
        }
    }
    let close_len = close_index.len();

    let dst = b"MY_CHALLENGE_GENERATOR_DST_Issuer_Hiding_V1";
    let c_inputs1 = vec![
        pikp.a_bar1,
        pikp.b_bar1,
        pikp.d_1,
        pikp.u_1,
        pikp.u_2,
    ];
    let c_input2 = vec![
        pikp.ipk_rand,
        pikp.a_bar2,
        pikp.b_bar2,
        pikp.d_2,
        pikp.u_3,
        pikp.u_4,
    ];
    let mut c_inputs_buffer = Vec::new();
    for c_input in &c_inputs1{
        c_input.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for c_input in &c_input2{
        c_input.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for open_msg in &pikp.message_list{
        open_msg.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    let c = bbs::hash_to_fr(&c_inputs_buffer[..], dst);

    if c != pikp.c{
        println!("Challenge hash check failed");
        println!("Computed c: {:?}", c);
        println!("Presented c: {:?}", pikp.c);
        return false
    }

    let lhs_u1 = G1Affine::from((pikp.d_1 * pizkp.s1) + (pikp.a_bar1 * pizkp.t1) + (pikp.b_bar1 * (-pikp.c)));
    let rhs_u1 = pikp.u_1;
    let mut lhs_u2_element = pikp.d_1 * pizkp.z1 + pp.g1 * (-pikp.c);
    for i in 0..pikp.open.len(){
        let h_i = h_generators[pikp.open[i]];
        lhs_u2_element += (h_i * (pikp.message_list[i])) * (-pikp.c);
    }
    for i in 0..close_len{
        let h_i = h_generators[close_index[i]];
        lhs_u2_element += h_i * (pizkp.v1[i]);
    }
    let lhs_u2 = G1Affine::from(lhs_u2_element);
    let rhs_u2 = pikp.u_2;
    let lhs_u3 = G2Affine::from((pikp.d_2 * pizkp.s2) + (pikp.a_bar2 * pizkp.t2) + (pikp.b_bar2 * (-pikp.c)));
    let rhs_u3 = pikp.u_3;
    let lhs_u4 = G2Affine::from(pikp.d_2 * pizkp.z2 + pp.gbar2 * pizkp.v2 + pikp.ipk_rand * (-pikp.c));
    let rhs_u4 = pikp.u_4;

    if lhs_u1 != rhs_u1 {
        println!("U1 check failed");
        return false
    }
    if lhs_u2 != rhs_u2 {
        println!("U2 check failed");
        return false
    }
    if lhs_u3 != rhs_u3 {
        println!("U3 check failed");
        return false
    }
    if lhs_u4 != rhs_u4 {
        println!("U4 check failed");
        return false
    }
    if Bls12_381::pairing(pikp.a_bar1, pikp.ipk_rand) != Bls12_381::pairing(pikp.b_bar1, pp.g2) {
        println!("Pairing check 1 failed");
        return false
    }
    if Bls12_381::pairing(vpk.0, pikp.a_bar2) != Bls12_381::pairing(pp.gbar1, pikp.b_bar2) {
        println!("Pairing check 2 failed");
        return false
    }
    return true;
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn test_issuer_hiding() {
        let message_len = 10;
        let issuer_num = 10;
        let mut rng = thread_rng();
        let messages: Vec<Fr> = (0..message_len).map(|_| Fr::rand(&mut rng)).collect();

        let pp = par_gen();
        let issuer_keypair = issuer_key_gen(&pp);
        let issuer_pk = &issuer_keypair.public_key;

        let signature = issue(&pp, &issuer_keypair.secret_key, &messages);

        let is_valid_cred = verify(&pp, &issuer_pk, &messages, &signature);
        assert_eq!(is_valid_cred, true);

        let mut issuer_keypairs: Vec<issuer::KeyPair> = Vec::new();
        let mut issuer_pubkeys: Vec<issuer::PublicKey> = Vec::new();

        for _ in 0..issuer_num{
            let keypair = issuer_key_gen(&pp);
            issuer_pubkeys.push(keypair.public_key.clone());
            issuer_keypairs.push(keypair.clone());
        }

        let r = rng.gen_range(1..issuer_num);
        issuer_keypairs[r] = issuer_keypair.clone();
        issuer_pubkeys[r] = issuer_pk.clone();

        let verifier_keypair = verifier_key_gen(&pp);

        let list = issue_list(&pp, &verifier_keypair, &issuer_pubkeys);

        let is_valid_list = verify_list(&pp, &list);
        assert_eq!(is_valid_list, true);

        let reveal_index = vec![0, 3, 5, 6];
        let (pikp, pizkp) = present(&pp, &signature, &issuer_pk, &messages, &reveal_index, &list);

        let is_valid_presentation = verify_presentation(&pp, &list, &pikp, &pizkp);
        assert_eq!(is_valid_presentation, true);
    }
}