use std::vec;

use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective, g1::Config as G1Config, g2::Config as G2Config};
use ark_ec::{hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},pairing::Pairing, CurveGroup};
use ark_ff::{field_hashers::{DefaultFieldHasher, HashToField}, Field};
use ark_std::{fmt::Debug, UniformRand, vec::Vec};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;
use rand::thread_rng;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicParameters {
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub x1: G1Affine,
    pub x2: G2Affine,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SecretKey {
    pub y: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicKey {
    pub pk_y: Vec<G2Affine>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Signature {
    pub sigma1: G1Affine,
    pub sigma2: G1Affine,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PolicySecretKey {
    pub a: Fr,
    pub b: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PolicyPublicKey {
    pub ipks: Vec<PublicKey>,
    pub s: G2Affine,
    pub vec_b: Vec<G2Affine>,
    pub t: Vec<Vec<G2Affine>>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PolicyKeyPair {
    pub psk: PolicySecretKey,
    pub ppk: PolicyPublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PolicyProof{
    pub vec_z: Vec<Fr>,
    pub c: Fr,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof{
    pub z_i: Vec<Fr>,
    pub c: Fr,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PresentationToken{
    pub sigma1: G1Affine,
    pub sigma2: G1Affine,
    pub sigma_tilde: G2Affine,
    pub proof: Proof,
    pub len: usize,
    pub open_messages: Vec<Fr>,
    pub reveal_index: Vec<usize>,
}

pub fn hash_to_fr(input: &[u8], dst: &[u8]) -> Fr {
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fr>>::new(dst);

    let scalars: [Fr; 1] = hasher.hash_to_field::<1>(input);
    let ans = scalars[0];
    return ans;
}

pub fn hash_to_g1(input: &[u8], dst: &[u8]) -> G1Affine {
    let hasher = MapToCurveBasedHasher::<G1Projective, DefaultFieldHasher<Sha256>,WBMap<G1Config>>::new(dst).unwrap();
    
    let hashpoint = hasher.hash(input).unwrap();
    return hashpoint;
}

pub fn hash_to_g2(input: &[u8], dst: &[u8]) -> G2Affine {
    let hasher = MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256>,WBMap<G2Config>>::new(dst).unwrap();
    
    let hashpoint = hasher.hash(input).unwrap();
    return hashpoint;
}

pub fn par_gen() -> PublicParameters{
    let g1_hex = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    let g2_hex = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    let g1_bytes = hex::decode(g1_hex).unwrap();
    let g2_bytes = hex::decode(g2_hex).unwrap();
    let g1 = G1Affine::deserialize_compressed(&g1_bytes[..]).unwrap();
    let g2 = G2Affine::deserialize_compressed(&g2_bytes[..]).unwrap();
    let x = Fr::from(123456789u64);
    let x1 = G1Affine::from(g1 * x);
    let x2 = G2Affine::from(g2 * x);
    let pp = PublicParameters{
        g1,
        g2,
        x1,
        x2,
    };
    return pp
}

pub fn key_gen(pp: &PublicParameters) -> KeyPair{
    let mut rng = thread_rng();
    let y_vec : Vec<Fr> = (0..50).map(|_| Fr::rand(&mut rng)).collect();

    let mut pk_y_pro : Vec<G2Projective> = Vec::new();
    for i in 0..50{
        let pk_y_i = pp.g2 * y_vec[i];
        pk_y_pro.push(pk_y_i);
    }

    let pk_y = G2Projective::normalize_batch(&pk_y_pro);

    let sk = SecretKey{
        y: y_vec,
    };
    let pk = PublicKey{
        pk_y,
    };
    let keypair = KeyPair{
        sk,
        pk,
    };
    return keypair
}

pub fn sign(pp: &PublicParameters, sk: &SecretKey, messages: &Vec<Fr>) -> Signature{
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);

    let message_len = messages.len();

    let sigma1 = G1Affine::from(pp.g1 * r);
    let mut temp_element = sk.y[0] * messages[0];
    for i in 1..message_len{
        temp_element += sk.y[i] * messages[i];
    }
    let sigma2 = G1Affine::from(pp.x1 * r + pp.g1 * (r * temp_element));

    let signature = Signature{
        sigma1,
        sigma2,
    };
    return signature
}

pub fn verify_sign(pp: &PublicParameters, pk: &PublicKey, signature: &Signature, messages: &Vec<Fr>) -> bool{
    let message_len = messages.len();

    let mut temp_element = pk.pk_y[0] * messages[0];
    for i in 1..message_len{
        temp_element += pk.pk_y[i] * messages[i];
    }
    let left = Bls12_381::pairing(signature.sigma2, pp.g2);
    let right = Bls12_381::pairing(signature.sigma1, G2Affine::from(pp.x2 + temp_element));

    if left != right{
        println!("Signature verification failed: pairing mismatch");
        return false
    }

    return true
}

pub fn set_policy(
    pp: &PublicParameters,
    ipks: &Vec<PublicKey>,
)-> (PolicyKeyPair, PolicyProof){
    let ipks_len = ipks.len();
    let ipks_len_1 = Fr::from(ipks_len as u64 - 1);
    let mut rng = thread_rng();
    let a = Fr::rand(&mut rng);
    let a_inv = a.inverse().unwrap();
    let mut b : Vec<Fr> = Vec::new();
    let mut vec_b : Vec<G2Affine> = Vec::new();
    for _ in 0..ipks[0].pk_y.len(){
        let b_i = Fr::rand(&mut rng);
        let vec_b_i = G2Affine::from(pp.g2 * (b_i * ipks_len_1));
        b.push(b_i);
        vec_b.push(vec_b_i);
    }

    let s = G2Affine::from(pp.g2 * a.clone());
    let mut t : Vec<Vec<G2Affine>> = Vec::new();
    for i in 0..ipks.len(){
        let mut t_i : Vec<G2Affine> = Vec::new();
        for j in 0..ipks[i].pk_y.len(){
            let t_ij = G2Affine::from((ipks[i].pk_y[j] + pp.g2 * b[j]) * a);
            t_i.push(t_ij);
        }
        t.push(t_i);
    }

    let psk = PolicySecretKey{
        a,
        b,
    };
    let ppk = PolicyPublicKey{
        ipks: ipks.clone(),
        s,
        vec_b: vec_b.clone(),
        t: t.clone(),
    };
    let policy_keypair = PolicyKeyPair{
        psk: psk.clone(),
        ppk: ppk.clone(),
    };

    let mut r: Vec<Fr> = vec![
        Fr::rand(&mut rng),
    ];
    for _ in 0..ipks[0].pk_y.len(){
        let r_i = Fr::rand(&mut rng);
        r.push(r_i);
    }

    let k_s = s * r[0];
    let mut k_vec_b: Vec<G2Projective> = Vec::new();
    for i in 0..vec_b.len(){
        let k_vec_b_i = pp.g2 * (r[i+1] * ipks_len_1);
        k_vec_b.push(k_vec_b_i);
    }
    let mut k_t: Vec<Vec<G2Projective>> = Vec::new();
    for i in 0..ipks.len(){
        let mut k_t_i : Vec<G2Projective> = Vec::new();
        for j in 0..ipks[i].pk_y.len(){
            let k_t_ij = t[i][j] * r[0] + pp.g2 * r[j+1];
            k_t_i.push(k_t_ij);
        }
        k_t.push(k_t_i);
    }

    let dst = b"MY_POLICY_CHALLENGE_GENERATOR_DST_V1";
    let mut buffer = Vec::new();
    ppk.serialize_compressed(&mut buffer).unwrap();
    k_s.serialize_compressed(&mut buffer).unwrap();
    k_vec_b.serialize_compressed(&mut buffer).unwrap();
    k_t.serialize_compressed(&mut buffer).unwrap();
    let c = hash_to_fr(&buffer, dst);

    let mut vec_z : Vec<Fr> = vec![
        r[0] + c * a_inv,
    ];
    for i in 0..ipks[0].pk_y.len(){
        let z_i = r[i+1] - c * psk.b[i];
        vec_z.push(z_i);
    }
    let policy_proof = PolicyProof{
        vec_z,
        c,
    };
    return (policy_keypair, policy_proof);
}

pub fn audit_policy(
    pp: &PublicParameters,
    ppk: &PolicyPublicKey,
    proof: &PolicyProof,
) -> bool{
    let ipks_len_1 = Fr::from(ppk.ipks.len() as u64 - 1);

    let k_s = ppk.s * proof.vec_z[0] + pp.g2 * (-proof.c);
    let mut k_vec_b: Vec<G2Projective> = Vec::new();
    for i in 0..ppk.vec_b.len(){
        let k_vec_b_i = ppk.vec_b[i] * proof.c + pp.g2 * (proof.vec_z[i+1] * ipks_len_1);
        k_vec_b.push(k_vec_b_i);
    }
    let mut k_t: Vec<Vec<G2Projective>> = Vec::new();
    for i in 0..ppk.ipks.len(){
        let mut k_t_i : Vec<G2Projective> = Vec::new();
        for j in 0..ppk.ipks[i].pk_y.len(){
            let k_t_ij = ppk.t[i][j] * proof.vec_z[0] + pp.g2 * proof.vec_z[j+1] + ppk.ipks[i].pk_y[j] * (-proof.c);
            k_t_i.push(k_t_ij);
        }
        k_t.push(k_t_i);
    }

    let dst = b"MY_POLICY_CHALLENGE_GENERATOR_DST_V1";
    let mut buffer = Vec::new();
    ppk.serialize_compressed(&mut buffer).unwrap();
    k_s.serialize_compressed(&mut buffer).unwrap();
    k_vec_b.serialize_compressed(&mut buffer).unwrap();
    k_t.serialize_compressed(&mut buffer).unwrap();
    let c_calculated = hash_to_fr(&buffer, dst);

    if c_calculated != proof.c{
        println!("Policy proof verification failed: challenge mismatch");
        return false
    }

    return true
}

pub fn create_proof(
    _: &PublicParameters,
    pk: &PublicKey,
    cred: &Signature,
    ppk: &PolicyPublicKey,
    message_list: &Vec<Fr>,
    reveal_index: &Vec<usize>,
) -> PresentationToken{
    let mut match_flag = false;
    let (ipks, s, vec_b, t) = (&ppk.ipks, &ppk.s, &ppk.vec_b, &ppk.t);
    for ipk in &ipks.clone(){
        if pk == ipk{
            match_flag = true;
        }
    }
    if !match_flag{
        panic!("The provided public key does not match any in the policy public key.");
    }

    let mut rng = thread_rng();
    let message_len = message_list.len();
    let close_len = message_len - reveal_index.len();

    let mut close_index : Vec<usize> = Vec::new();
    let mut open_messages : Vec<Fr> = Vec::new();
    for i in 0..message_len{
        if reveal_index.contains(&i){
            open_messages.push(message_list[i]);
        }else{
            close_index.push(i);
        }
    }

    let r_1 = Fr::rand(&mut rng);
    let r_2 = Fr::rand(&mut rng);
    let mut k_i = Vec::new();
    for _ in 0..close_len{
        let k_i_i = Fr::rand(&mut rng);
        k_i.push(k_i_i);
    }

    let new_sigma1 = G1Affine::from(cred.sigma1 * r_1);
    let new_sigma2 = G1Affine::from(cred.sigma2 * r_1 + new_sigma1 * (-r_2));
    let mut sigma_tilde_pro = s.clone() * r_2;
    for i in 0..message_len{
        let mut sigma_tilde_i = G2Projective::from(G2Affine::identity());
        for j in 0..ipks.len(){
            if &ipks[j] != pk{
                sigma_tilde_i += t[j][i];
            }
        }
        sigma_tilde_pro += sigma_tilde_i * message_list[i];
    }
    let sigma_tilde = G2Affine::from(sigma_tilde_pro);

    let mut k_input = G2Projective::from(G2Affine::identity());
    for i in 0..close_len{
        let mut k_input_ij = G2Projective::from(vec_b[close_index[i].clone()]);
        for j in 0..ipks.len(){
            k_input_ij += ipks[j].pk_y[close_index[i].clone()] ;
        }
        k_input += k_input_ij * k_i[i];
    }
    let k = Bls12_381::pairing(new_sigma1, G2Affine::from(k_input));

    let dst = b"MY_CHALLENGE_GENERATOR_DST_V1";
    let c_inputs = vec![
        new_sigma1,
        new_sigma2,
    ];
    let mut buffer = Vec::new();
    k.serialize_compressed(&mut buffer).unwrap();
    ppk.serialize_compressed(&mut buffer).unwrap();
    for c_input in &c_inputs{
        c_input.serialize_compressed(&mut buffer).unwrap();
    }
    sigma_tilde.serialize_compressed(&mut buffer).unwrap();
    for open_msg in &open_messages{
        open_msg.serialize_compressed(&mut buffer).unwrap();
    }
    let c = hash_to_fr(&buffer, dst);

    let mut z_i : Vec<Fr> = Vec::new();
    for i in 0..close_len{
        let z_i_i = k_i[i] + c * message_list[close_index[i]];
        z_i.push(z_i_i);
    }
    let proof = Proof{
        z_i,
        c,
    };
    let pt = PresentationToken{
        sigma1: new_sigma1,
        sigma2: new_sigma2,
        sigma_tilde,
        proof,
        len: message_len,
        open_messages,
        reveal_index: reveal_index.clone(),
    };
    return pt
}

pub fn verify_proof(
    pp: &PublicParameters,
    pt: &PresentationToken,
    pkp: &PolicyKeyPair,
) -> bool{
    if pt.sigma1 == G1Affine::identity(){
        println!("Proof verification failed: sigma1 is identity");
        return false
    }
    let (ppk, psk) = (&pkp.ppk, &pkp.psk);
    let message_len = pt.len;
    let close_len = message_len - pt.reveal_index.len();
    let ipks_len_1 = Fr::from(ppk.ipks.len() as u64 - 1);

    let mut close_index : Vec<usize> = Vec::new();
    for i in 0..message_len{
        if !pt.reveal_index.contains(&i){
            close_index.push(i);
        }
    }

    let a_inv = psk.a.clone().inverse().unwrap();
    let mut t_input = pp.x2 * (-Fr::from(1u64)) + pt.sigma_tilde * (a_inv);
    for i in 0..pt.reveal_index.len(){
        let idx = pt.reveal_index[i].clone();
        let mut t_input_i = pp.g2 * (psk.b[idx] * ipks_len_1);
        for j in 0..ppk.ipks.len(){
            t_input_i += ppk.ipks[j].pk_y[idx];
        }
        t_input += t_input_i * (-pt.open_messages[i]);
    }
    t_input *= -pt.proof.c;

    let t = Bls12_381::pairing(pt.sigma2, pp.g2 * (-pt.proof.c)) + Bls12_381::pairing(pt.sigma1, G2Affine::from(t_input));
    let mut k_input = G2Projective::from(G2Affine::identity());
    for i in 0..close_len{
        let idx = close_index[i].clone();
        let mut k_input_i = pp.g2 * (psk.b[idx] * ipks_len_1);
        for j in 0..ppk.ipks.len(){
            k_input_i += ppk.ipks[j].pk_y[idx];
        }
        k_input += k_input_i * pt.proof.z_i[i];
    }
    let k = t + Bls12_381::pairing(pt.sigma1, G2Affine::from(k_input));

    let dst = b"MY_CHALLENGE_GENERATOR_DST_V1";
    let c_inputs = vec![
        pt.sigma1,
        pt.sigma2,
    ];
    let mut buffer = Vec::new();
    k.serialize_compressed(&mut buffer).unwrap();
    ppk.serialize_compressed(&mut buffer).unwrap();
    for c_input in &c_inputs{
        c_input.serialize_compressed(&mut buffer).unwrap();
    }
    pt.sigma_tilde.serialize_compressed(&mut buffer).unwrap();
    for open_msg in &pt.open_messages{
        open_msg.serialize_compressed(&mut buffer).unwrap();
    }
    let c_calculated = hash_to_fr(&buffer, dst);

    if c_calculated != pt.proof.c{
        println!("Proof verification failed: challenge mismatch");
        return false
    }

    return true
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use super::*;

    pub type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn it_works() {
        // Test code can be added here
        let message_len = 10;
        let ipks_len = 3;
        let mut rng = thread_rng();
        let messages: Vec<Fr> = (0..message_len).map(|_| Fr::rand(&mut rng)).collect();

        let pp = par_gen();

        let keypair = key_gen(&pp);

        let signature = sign(&pp, &keypair.sk, &messages);
        let bool1 = verify_sign(&pp, &keypair.pk, &signature, &messages);
        assert_eq!(bool1,true);

        let mut ipks = Vec::new();
        for _ in 0..ipks_len{
            let ipk = key_gen(&pp).pk;
            ipks.push(ipk);
        }
        let r = rng.gen_range(0..ipks_len);
        ipks[r] = keypair.pk.clone();
        let (policy_keypair, policy_proof) = set_policy(&pp, &ipks);
        let bool_policy = audit_policy(&pp, &policy_keypair.ppk, &policy_proof);
        assert_eq!(bool_policy,true);

        let reveal_index = vec![0, 3, 5];
        let pt = create_proof(&pp, &keypair.pk, &signature, &policy_keypair.ppk, &messages, &reveal_index);
        let bool2 = verify_proof(&pp, &pt, &policy_keypair);
        assert_eq!(bool2,true);
    }
}