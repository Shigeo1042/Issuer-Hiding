use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective, g1::Config as G1Config, g2::Config as G2Config};
use ark_ec::{hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},pairing::Pairing, CurveGroup};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_std::{fmt::Debug, UniformRand, vec::Vec};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;
use rand::thread_rng;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicParameters {
    pub g1: G1Affine,
    pub g2: G2Affine,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SecretKey {
    pub x: Fr,
    pub y: Vec<Fr>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PublicKey {
    pub pk_x: G2Affine,
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
pub struct Proof{
    pub z_i: Vec<Fr>,
    pub z_t: Fr,
    pub c: Fr,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct PresentationToken{
    pub sigma1: G1Affine,
    pub sigma2: G1Affine,
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
    let pp = PublicParameters{
        g1,
        g2,
    };
    return pp
}

pub fn key_gen(pp: &PublicParameters) -> KeyPair{
    let mut rng = thread_rng();
    let x = Fr::rand(&mut rng);
    let y_vec : Vec<Fr> = (0..50).map(|_| Fr::rand(&mut rng)).collect();

    let pk_x = G2Affine::from(pp.g2 * x);
    let mut pk_y_pro : Vec<G2Projective> = Vec::new();
    for i in 0..50{
        let pk_y_i = pp.g2 * y_vec[i];
        pk_y_pro.push(pk_y_i);
    }

    let pk_y = G2Projective::normalize_batch(&pk_y_pro);

    let sk = SecretKey{
        x,
        y: y_vec,
    };
    let pk = PublicKey{
        pk_x,
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
    let sigma2 = G1Affine::from(pp.g1 * (r * (sk.x + temp_element)));

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
    let left = Bls12_381::pairing(signature.sigma2, G2Affine::from(pp.g2));
    let right = Bls12_381::pairing(signature.sigma1, G2Affine::from(pk.pk_x + temp_element));

    return left == right
}

pub fn create_proof(
    pp: &PublicParameters,
    pk: &PublicKey,
    cred: &Signature,
    message_list: &Vec<Fr>,
    reveal_index: &Vec<usize>,
) -> PresentationToken{
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

    let r = Fr::rand(&mut rng);
    let t = Fr::rand(&mut rng);
    let mut k_i = Vec::new();
    for _ in 0..close_len{
        let k_i_i = Fr::rand(&mut rng);
        k_i.push(k_i_i);
    }
    let k_t = Fr::rand(&mut rng);

    let new_sigma1 = G1Affine::from(cred.sigma1 * r);
    let new_sigma2 = G1Affine::from((cred.sigma2 + (cred.sigma1 * t)) * r);

    let mut k_input = pp.g2 * k_t;
    for i in 0..close_len{
        k_input += pk.pk_y[close_index[i]] * k_i[i];
    }
    let k = Bls12_381::pairing(new_sigma1, G2Affine::from(k_input));

    let dst = b"MY_CHALLENGE_GENERATOR_DST_V1";
    let c_inputs = vec![
        new_sigma1,
        new_sigma2,
    ];
    let mut buffer = Vec::new();
    for c_input in &c_inputs{
        c_input.serialize_compressed(&mut buffer).unwrap();
    }
    for open_msg in &open_messages{
        open_msg.serialize_compressed(&mut buffer).unwrap();
    }
    k.serialize_compressed(&mut buffer).unwrap();
    let c = hash_to_fr(&buffer, dst);

    let mut z_i : Vec<Fr> = Vec::new();
    for i in 0..close_len{
        let z_i_i = k_i[i] + c * message_list[close_index[i]];
        z_i.push(z_i_i);
    }
    let z_t = k_t + c * t;
    let proof = Proof{
        z_i,
        z_t,
        c,
    };
    let pt = PresentationToken{
        sigma1: new_sigma1,
        sigma2: new_sigma2,
        proof,
        len: message_len,
        open_messages,
        reveal_index: reveal_index.clone(),
    };
    return pt
}

pub fn verify_proof(
    pp: &PublicParameters,
    pk: &PublicKey,
    pt: &PresentationToken,
) -> bool{
    let message_len = pt.len;
    let close_len = message_len - pt.reveal_index.len();

    let mut close_index : Vec<usize> = Vec::new();
    for i in 0..message_len{
        if !pt.reveal_index.contains(&i){
            close_index.push(i);
        }
    }

    let mut t_input = -G2Projective::from(pk.pk_x);
    for i in 0..pt.reveal_index.len(){
        let idx = pt.reveal_index[i];
        t_input += pk.pk_y[idx] * (-pt.open_messages[i]);
    }
    t_input *= -pt.proof.c;

    let t = Bls12_381::pairing(pt.sigma2, pp.g2 * (-pt.proof.c)) + Bls12_381::pairing(pt.sigma1, G2Affine::from(t_input));
    let mut k_input = pp.g2 * pt.proof.z_t;
    for i in 0..close_len{
        k_input += pk.pk_y[close_index[i]] * pt.proof.z_i[i];
    }
    let k = t + Bls12_381::pairing(pt.sigma1, G2Affine::from(k_input));

    let dst = b"MY_CHALLENGE_GENERATOR_DST_V1";
    let c_inputs = vec![
        pt.sigma1,
        pt.sigma2,
    ];
    let mut buffer = Vec::new();
    for c_input in &c_inputs{
        c_input.serialize_compressed(&mut buffer).unwrap();
    }
    for open_msg in &pt.open_messages{
        open_msg.serialize_compressed(&mut buffer).unwrap();
    }
    k.serialize_compressed(&mut buffer).unwrap();
    let c_calculated = hash_to_fr(&buffer, dst);

    if c_calculated != pt.proof.c{
        println!("Proof verification failed: challenge mismatch");
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
    use super::*;

    pub type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn it_works() {
        // Test code can be added here
        let message_len = 10;
        let mut rng = thread_rng();
        let messages: Vec<Fr> = (0..message_len).map(|_| Fr::rand(&mut rng)).collect();
        let pp = par_gen();
        let keypair = key_gen(&pp);
        let signature = sign(&pp, &keypair.sk, &messages);
        let bool1 = verify_sign(&pp, &keypair.pk, &signature, &messages);
        assert_eq!(bool1,true);
        let reveal_index = vec![0, 3, 5];
        let pt = super::create_proof(&pp, &keypair.pk, &signature, &messages, &reveal_index);
        let bool2 = super::verify_proof(&pp, &keypair.pk, &pt);
        assert_eq!(bool2,true);
    }
}