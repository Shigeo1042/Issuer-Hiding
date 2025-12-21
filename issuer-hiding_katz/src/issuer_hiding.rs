use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_std::{fmt::Debug, UniformRand, vec::Vec};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::thread_rng;

use mybbs::bbs;
use mybbs::issuer;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PiPolicy{
    pub c: Fr,
    pub s: Fr,
    pub t: Fr,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PolicySecretKey{
    pub a: Fr,
    pub b: Fr,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PolicyPublicKey{
    pub ipks: Vec<issuer::PublicKey>,
    pub s: G2Affine,
    pub t: Vec<G2Affine>,
    pub pi: PiPolicy,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PolicyKeyPair{
    pub secret_key: PolicySecretKey,
    pub public_key: PolicyPublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PiKP{
    pub a_bar: G1Affine,
    pub b_bar: G1Affine,
    pub d: G1Affine,
    pub sigma_tilde: G2Affine,
    pub open: Vec<usize>,
    pub len: usize,
    pub message_list: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PiZKP{
    pub c: Fr,
    pub s: Fr,
    pub t: Fr,
    pub z: Fr,
    pub v: Vec<Fr>,
}

pub fn par_gen() -> issuer::PublicParameters{
    let pp = issuer::par_gen();
    return pp
}

pub fn issuer_key_gen(pp: &issuer::PublicParameters) -> issuer::KeyPair{
    let keypair = issuer::key_gen(&pp);
    return keypair
}

pub fn issue(pp: &issuer::PublicParameters, isk: &bbs::SecretKey, messages: &Vec<Fr>) -> issuer::Signature{
    let signature = issuer::sign(&pp, isk, messages);
    return signature
}

pub fn verify(pp: &issuer::PublicParameters, ipk: &issuer::PublicKey, messages: &Vec<Fr>, sig: &issuer::Signature) -> bool{
    let is_valid = issuer::verify(&pp, ipk, messages, sig);
    return is_valid
}

pub fn set_policy(pp: &issuer::PublicParameters, ipk_list: &Vec<issuer::PublicKey>) -> PolicyKeyPair{
    let ipk_len = ipk_list.len();
    let mut rng = thread_rng();
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let sk = PolicySecretKey{
        a: a,
        b: b,
    };

    let s_pro = pp.g2 * a;
    let mut t_pro  = Vec::new();
    for i in 0..ipk_len{
        let t_i = (ipk_list[i].0 + pp.g2 * b) * a;
        t_pro.push(t_i);
    }

    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let u_1_pro = s_pro * alpha;
    let mut u_2_vec = Vec::new();
    for i in 0..ipk_len{
        let u_2_i = t_pro[i] * alpha + pp.g2 * beta;
        u_2_vec.push(u_2_i);
    }

    let dst = b"MY_CHALLENGE_GENERATOR_DST_Set_Policy_V1";
    let mut c_input_pro = vec![s_pro];
    c_input_pro.extend(t_pro.clone());
    c_input_pro.push(u_1_pro);
    c_input_pro.extend(u_2_vec.clone());
    // s, t_i, u1, u2_i
    let c_input = G2Projective::normalize_batch(&c_input_pro);

    let mut c_input_buffer = Vec::new();
    for issuer_pk in ipk_list{
        issuer_pk.0.serialize_compressed(&mut c_input_buffer).unwrap();
    }
    for c_input in &c_input{
        c_input.serialize_compressed(&mut c_input_buffer).unwrap();
    }
    let c = bbs::hash_to_fr(&c_input_buffer[..], dst);

    let a_inv = a.inverse().unwrap();

    let pi = PiPolicy{
        c: c,
        s: alpha + c * a_inv,
        t: beta - c * b,
    };
    let pk = PolicyPublicKey{
        ipks: ipk_list.clone(),
        s: c_input[0],
        t: c_input[1..=ipk_len].to_vec(),
        pi: pi,
    };
    let keypair = PolicyKeyPair{
        secret_key: sk,
        public_key: pk,
    };
    return keypair
}

pub fn audit_policy(pp: &issuer::PublicParameters, ppk: &PolicyPublicKey) -> bool{
    let (ipk_list, s,t,c,pi_s,pi_t) = (ppk.ipks.clone(), ppk.s, ppk.t.clone(), ppk.pi.c, ppk.pi.s, ppk.pi.t);
    let ipk_len = ipk_list.len();
    if ipk_len != t.len(){
        println!("Issuer public key list length and t vector length mismatch");
        return false
    }
    if s.is_zero() {
        println!("s is identity element");
        return false
    }
    let mut c_input = vec![s];
    c_input.extend(t.clone());
    let mut u_pro = vec![s * pi_s + pp.g2 * (-c)];
    for i in 0..ipk_len{
        let ipk = &ipk_list[i];
        u_pro.push((t[i] * pi_s) + (pp.g2 * pi_t) + (ipk.0 * (-c)));
    }
    c_input.extend(G2Projective::normalize_batch(&u_pro));
    
    let dst = b"MY_CHALLENGE_GENERATOR_DST_Set_Policy_V1";
    let mut c_input_buffer = Vec::new();
    for issuer_pk in ipk_list{
        issuer_pk.0.serialize_compressed(&mut c_input_buffer).unwrap();
    }
    for c_input in &c_input{
        c_input.serialize_compressed(&mut c_input_buffer).unwrap();
    }
    let c_check = bbs::hash_to_fr(&c_input_buffer[..], dst);
    if c != c_check{
        println!("Policy challenge hash check failed");
        println!("Computed c: {:?}", c_check);
        println!("Presented c: {:?}", c);
        return false
    }
    return true
}

pub fn present(
    pp: &issuer::PublicParameters, 
    cred: &issuer::Signature, 
    ipk: &issuer::PublicKey, 
    message_list: &Vec<Fr>, 
    reveal_index: &Vec<usize>,
    ppk: &PolicyPublicKey
) -> (PiKP, PiZKP){
    let message_len = message_list.len();
    let (ipks, s,t_vec) = (ppk.ipks.clone(), ppk.s, ppk.t.clone());

    let mut rng = thread_rng();
    let h_generators : Vec<G1Affine> = pp.h_vec[0..message_len].to_vec();
    let r = Fr::rand(&mut rng);
    
    let ipks_len = ipks.len();
    let mut sigma_tilde_element = s * r;
    for i in 0..ipks_len{
        if ipks[i] != *ipk{
            sigma_tilde_element += t_vec[i];
        }
    }
    let sigma_tilde = G2Affine::from(sigma_tilde_element);

    let r_1 = Fr::rand(&mut rng);
    let r_2 = Fr::rand(&mut rng);
    let r_2_inv = r_2.inverse().unwrap();

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
    d_element *= r_2_inv;
    // let d_affine = G1Affine::from(d_element * r_2_inv);
    let close_len = close_index.len();
    // let abar = G1Affine::from(cred.a * (r_1 * r_2_inv));
    // let bbar = G1Affine::from((d_affine * r_1) + (abar * (-cred.e - r)));
    let abar_pro = cred.a * (r_1 * r_2_inv);
    let bbar_pro = (d_element * r_1) + (abar_pro * (-cred.e - r));

    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let delta_vec = (0..close_len).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();

    let u1_pro = (d_element * alpha) + (abar_pro * beta);
    let mut u2_element = d_element * gamma;
    for i in 0..close_len{
        u2_element += h_generators[close_index[i]] * delta_vec[i];
    }
    let dst = b"MY_CHALLENGE_GENERATOR_DST_Issuer_Hiding_V1";
    let c_inputs1_pro =vec![
        abar_pro,
        bbar_pro,
        d_element,
        u1_pro,
        u2_element,
    ];
    let c_inputs1 = G1Projective::normalize_batch(&c_inputs1_pro);
    let mut c_inputs_buffer = Vec::new();
    h_generators.serialize_compressed(&mut c_inputs_buffer).unwrap();
    open_messages.serialize_compressed(&mut c_inputs_buffer).unwrap();
    for c_input in &c_inputs1{
        c_input.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }

    let c = bbs::hash_to_fr(&c_inputs_buffer[..], dst);
    let pikp = PiKP{
        a_bar: c_inputs1[0],
        b_bar: c_inputs1[1],
        d: c_inputs1[2],
        sigma_tilde: sigma_tilde,
        open: reveal_index.clone(),
        len: message_len,
        message_list: open_messages,
    };

    let s = alpha + c * r_1;
    let t = beta - c * (cred.e + r);
    let z = gamma + c * r_2;
    let mut v_vec: Vec<Fr> = Vec::new();
    for i in 0..close_len{
        let v1 = delta_vec[i] - c * message_list[close_index[i]];
        v_vec.push(v1);
    }
    let pizkp = PiZKP{
        c: c,
        s: s,
        t: t,
        z: z,
        v: v_vec,
    };
    return (pikp, pizkp)
}

pub fn verify_present(
    pp: &issuer::PublicParameters, 
    keypair: &PolicyKeyPair, 
    pikp: &PiKP, 
    pizkp: &PiZKP
) -> bool{
    let message_len = pikp.len;
    let  ipks_num = keypair.public_key.ipks.len();

    let h_generators : Vec<G1Affine> = pp.h_vec[0..message_len].to_vec();
    let mut close_index: Vec<usize> = Vec::new();
    for i in 0..message_len{
        if !pikp.open.contains(&i){
            close_index.push(i);
        }
    }
    let close_len = close_index.len();

    let dst = b"MY_CHALLENGE_GENERATOR_DST_Issuer_Hiding_V1";
    let mut u2_element = pikp.d * pizkp.z + pp.g1 * (-pizkp.c);
    for i in 0..pikp.open.len(){
        let h_i = h_generators[pikp.open[i]];
        u2_element += (h_i * (pikp.message_list[i])) * (-pizkp.c);
    }
    for i in 0..close_len{
        let h_i = h_generators[close_index[i]];
        u2_element += h_i * (pizkp.v[i]);
    }
    let mut u_pro = vec![(pikp.d * pizkp.s) + (pikp.a_bar * pizkp.t) + (pikp.b_bar * (-pizkp.c))];
    u_pro.push(u2_element);
    let u = G1Projective::normalize_batch(&u_pro);
    let c_inputs1 =vec![
        pikp.a_bar,
        pikp.b_bar,
        pikp.d,
    ];
    let mut c_inputs_buffer = Vec::new();
    h_generators.serialize_compressed(&mut c_inputs_buffer).unwrap();
    pikp.message_list.serialize_compressed(&mut c_inputs_buffer).unwrap();
    for c_input in &c_inputs1{
        c_input.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for u_i in &u{
        u_i.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    let c = bbs::hash_to_fr(&c_inputs_buffer[..], dst);

    if c != pizkp.c{
        println!("Challenge hash check failed");
        println!("Computed c: {:?}", c);
        println!("Presented c: {:?}", pizkp.c);
        return false
    }
    let a_inv = keypair.secret_key.a.inverse().unwrap();
    let mut pairing_right = pikp.sigma_tilde * (-a_inv) + pp.g2 * (Fr::from((ipks_num - 1) as u64) * keypair.secret_key.b);
    for i in 0..ipks_num{
        pairing_right += keypair.public_key.ipks[i].0;
    }

    if Bls12_381::pairing(pikp.a_bar, pairing_right) != Bls12_381::pairing(pikp.b_bar, pp.g2) {
        println!("Pairing check 1 failed");
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

        let policy_key_pair = set_policy(&pp, &issuer_pubkeys);
        let policy_pk = &policy_key_pair.public_key;

        let is_valid_list = audit_policy(&pp, &policy_pk);
        assert_eq!(is_valid_list, true);

        let reveal_index = vec![0, 3, 5, 6];
        let (pikp, pizkp) = present(&pp, &signature, &issuer_pk, &messages, &reveal_index, &policy_pk);

        let is_valid_present = verify_present(&pp, &policy_key_pair, &pikp, &pizkp);
        assert_eq!(is_valid_present, true);
    }
}