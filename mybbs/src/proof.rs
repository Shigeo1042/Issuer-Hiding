use ark_bls12_381::{G1Affine, Bls12_381, G1Projective};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, UniformRand, vec::Vec};
use rand::thread_rng;

use crate::bbs;
use crate::issuer;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PiKP{
    pub a_bar: G1Affine,
    pub b_bar: G1Affine,
    pub d: G1Affine,
    pub u_1: G1Affine,
    pub u_2: G1Affine,
    pub c: Fr,
    pub open: Vec<usize>,
    pub len: usize,
    pub message_list: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PiZKP{
    pub s: Fr,
    pub t: Fr,
    pub z: Fr,
    pub v: Vec<Fr>,
}

pub fn prove(
    pp: &issuer::PublicParameters,
    cred: &issuer::Signature,
    message_list: &Vec<Fr>,
    reveal_index: &Vec<usize>,
) -> (PiKP, PiZKP){
    let mut rng = thread_rng();
    let r1 = Fr::rand(&mut rng);
    let r2 = Fr::rand(&mut rng);
    let r2_inv = r2.inverse().unwrap();

    let message_len = message_list.len();

    let h_generators : Vec<G1Affine> = (0..message_len).map(|i| {
            let seed = format!("{}{}", pp.h_seed, i);
            bbs::hash_to_g1(seed.as_bytes(), pp.h_dst)
        })
        .collect();

    let mut d_element = G1Projective::from(pp.g1);
    let mut open_messages = Vec::new();
    let mut close_index = Vec::new();
    for i in 0..message_len{
        d_element += h_generators[i] * message_list[i];
        if reveal_index.contains(&i){
            open_messages.push(message_list[i]);
        }else{
            close_index.push(i);
        }
    }
    let d_affine = G1Affine::from(d_element * r2_inv);
    let abar = G1Affine::from((cred.a * r1) * r2_inv);
    let bbar = G1Affine::from((d_affine * r1) + (abar * (-cred.e)));

    let close_len = close_index.len();

    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let delta_vec : Vec<Fr> = (0..close_len).map(|_| Fr::rand(&mut rng)).collect();

    let u1 = G1Affine::from((d_affine * alpha) + (abar * beta));
    let mut u2_element = d_affine * gamma;
    for i in 0..close_len{
        u2_element += h_generators[close_index[i]] * delta_vec[i];
    }
    let u2 = G1Affine::from(u2_element);
    let dst = b"MY_CHALLENGE_GENERATOR_DST_V1";
    let c_inputs = vec![
        abar,
        bbar,
        d_affine,
        u1,
        u2,
    ];
    let mut buffer = Vec::new();
    for c_input in &c_inputs{
        c_input.serialize_compressed(&mut buffer).unwrap();
    }
    for open_msg in &open_messages{
        open_msg.serialize_compressed(&mut buffer).unwrap();
    }
    let c = bbs::hash_to_fr(&buffer[..], dst);
    let pikp = PiKP{
        a_bar: abar,
        b_bar: bbar,
        d: d_affine,
        u_1: u1,
        u_2: u2,
        c: c,
        open: reveal_index.clone(),
        len: message_len,
        message_list: open_messages,
    };
    let s = alpha + c * r1;
    let t = beta - c * cred.e;
    let z = gamma + c * r2;
    let mut v_vec = Vec::new();
    for i in 0..close_len{
        let v_i = delta_vec[i] - c * message_list[close_index[i]];
        v_vec.push(v_i);
    }
    let pizkp = PiZKP{
        s,
        t,
        z,
        v: v_vec,
    };
    (pikp, pizkp)
}

pub fn verify_proof(
    pp: &issuer::PublicParameters,
    pk: &issuer::PublicKey,
    pikp: &PiKP,
    pizkp: &PiZKP,
) -> bool{
    let dst = b"MY_CHALLENGE_GENERATOR_DST_V1";
    let c_inputs = vec![
        pikp.a_bar,
        pikp.b_bar,
        pikp.d,
        pikp.u_1,
        pikp.u_2,
    ];
    let mut buffer = Vec::new();
    for c_input in &c_inputs{
        c_input.serialize_compressed(&mut buffer).unwrap();
    }
    for open_msg in &pikp.message_list{
        open_msg.serialize_compressed(&mut buffer).unwrap();
    }
    let c_calculated = bbs::hash_to_fr(&buffer[..], dst);

    if c_calculated != pikp.c{
        println!("Challenge hash check failed");
        return false
    }

    let h_generators : Vec<G1Affine> = (0..pikp.len).map(|i| {
            let seed = format!("{}{}", pp.h_seed, i);
            bbs::hash_to_g1(seed.as_bytes(), pp.h_dst)
        })
        .collect();

    let lhs_u1 = G1Affine::from((pikp.d * pizkp.s) + (pikp.a_bar * pizkp.t) + (pikp.b_bar * (-pikp.c)));
    let rhs_u1 = pikp.u_1;

    let mut lhs_u2_element = pikp.d * pizkp.z + pp.g1 * (-pikp.c);
    let close_len = pikp.len - pikp.open.len();
    let mut close_idx = Vec::new();
    for i in 0..pikp.len{
        if !pikp.open.contains(&i){
            close_idx.push(i);
        }
    }
    for i in 0..pikp.open.len(){
        let h_i = h_generators[pikp.open[i]];
        lhs_u2_element += (h_i * (pikp.message_list[i])) * (-pikp.c);
    }
    for i in 0..close_len{
        let h_i = h_generators[close_idx[i]];
        lhs_u2_element += h_i * (pizkp.v[i]);
    }
    let lhs_u2 = G1Affine::from(lhs_u2_element);
    let rhs_u2 = pikp.u_2;

    if lhs_u1 != rhs_u1 {
        println!("U1 check failed");
        return false
    }
    if lhs_u2 != rhs_u2 {
        println!("U2 check failed");
        return false
    }
    if Bls12_381::pairing(pikp.a_bar, pk.0) != Bls12_381::pairing(pikp.b_bar, pp.g2) {
        println!("Pairing check failed");
        return false
    }

    return true
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{UniformRand, vec::Vec};
    use rand::thread_rng;
    use crate::issuer;

    pub type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn it_works() {
        // Test code can be added here
        let message_len = 10;
        let mut rng = thread_rng();
        let messages: Vec<Fr> = (0..message_len).map(|_| Fr::rand(&mut rng)).collect();
        let pp = issuer::par_gen();
        let keypair = issuer::key_gen(&pp);
        let signature = issuer::sign(&pp, &keypair.secret_key, &messages);
        let reveal_index = vec![0, 3, 5];
        let (pikp, pizkp) = super::prove(&pp, &signature, &messages, &reveal_index);
        let bool = super::verify_proof(&pp, &keypair.public_key, &pikp, &pizkp);
        assert_eq!(bool,true);
    }
}