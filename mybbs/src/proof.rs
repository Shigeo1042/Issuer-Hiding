use ark_bls12_381::{G1Affine, Bls12_381, G1Projective};
use ark_ff::Field;
use ark_ec::{pairing::Pairing, CurveGroup};
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
    pub c: Fr,
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

    let h_generators : Vec<G1Affine> = pp.h_vec[0..message_len].to_vec();

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
    d_element *= r2_inv;
    let abar_pro = (cred.a * r1) * r2_inv;
    let bbar_pro = (d_element * r1) + (abar_pro * (-cred.e));

    let close_len = close_index.len();

    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let delta_vec : Vec<Fr> = (0..close_len).map(|_| Fr::rand(&mut rng)).collect();

    let u1_pro = (d_element * alpha) + (abar_pro * beta);
    let mut u2_element = d_element * gamma;
    for i in 0..close_len{
        u2_element += h_generators[close_index[i]] * delta_vec[i];
    }
    let dst = b"MY_CHALLENGE_GENERATOR_DST_V1";
    let c_inputs_pro = vec![
        abar_pro,
        bbar_pro,
        d_element,
        u1_pro,
        u2_element,
    ];
    let c_inputs = G1Projective::normalize_batch(&c_inputs_pro);
    let mut buffer = Vec::new();
    for h_i in &h_generators{
        h_i.serialize_compressed(&mut buffer).unwrap();
    }
    for c_input in &c_inputs{
        c_input.serialize_compressed(&mut buffer).unwrap();
    }
    for open_msg in &open_messages{
        open_msg.serialize_compressed(&mut buffer).unwrap();
    }
    let c = bbs::hash_to_fr(&buffer[..], dst);
    let pikp = PiKP{
        a_bar: c_inputs[0],
        b_bar: c_inputs[1],
        d: c_inputs[2],
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
        c
    };
    (pikp, pizkp)
}

pub fn verify_proof(
    pp: &issuer::PublicParameters,
    pk: &issuer::PublicKey,
    pikp: &PiKP,
    pizkp: &PiZKP,
) -> bool{
    let h_generators : Vec<G1Affine> = pp.h_vec[0..pikp.len].to_vec();
    let dst = b"MY_CHALLENGE_GENERATOR_DST_V1";

    let mut lhs_u2_element = pikp.d * pizkp.z + pp.g1 * (-pizkp.c);
    let close_len = pikp.len - pikp.open.len();
    let mut close_idx = Vec::new();
    for i in 0..pikp.len{
        if !pikp.open.contains(&i){
            close_idx.push(i);
        }
    }
    for i in 0..pikp.open.len(){
        let h_i = h_generators[pikp.open[i]];
        lhs_u2_element += (h_i * (pikp.message_list[i])) * (-pizkp.c);
    }
    for i in 0..close_len{
        let h_i = h_generators[close_idx[i]];
        lhs_u2_element += h_i * (pizkp.v[i]);
    }
    let u_12_pro = vec![
        (pikp.d * pizkp.s) + (pikp.a_bar * pizkp.t) + (pikp.b_bar * (-pizkp.c)),
        lhs_u2_element
    ];
    let u_12_affine = G1Projective::normalize_batch(&u_12_pro);

    let c_inputs = vec![
        pikp.a_bar,
        pikp.b_bar,
        pikp.d
    ];
    let mut buffer = Vec::new();
    for h_i in &h_generators{
        h_i.serialize_compressed(&mut buffer).unwrap();
    }
    for c_input in &c_inputs{
        c_input.serialize_compressed(&mut buffer).unwrap();
    }
    for u_i in &u_12_affine{
        u_i.serialize_compressed(&mut buffer).unwrap();
    }
    for open_msg in &pikp.message_list{
        open_msg.serialize_compressed(&mut buffer).unwrap();
    }
    let c_calculated = bbs::hash_to_fr(&buffer[..], dst);

    if c_calculated != pizkp.c{
        println!("Challenge hash check failed");
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