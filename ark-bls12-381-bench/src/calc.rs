use ark_bls12_381::{Bls12_381, G1Affine, G2Affine, Config};
use ark_ec::{bls12::Bls12, pairing::{Pairing, PairingOutput}};
use ark_std::{UniformRand, vec::Vec};
use rand::thread_rng;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

pub fn fr_rand() -> () {
    let mut rng = thread_rng();
    for _ in 0..1000{
        let _r = Fr::rand(&mut rng);
    }
}

pub fn fr_rand_return() -> Vec<Fr> {
    let mut rng = thread_rng();
    let mut response = Vec::new();
    for _ in 0..1000{
        let r: Fr = Fr::rand(&mut rng);
        response.push(r);
    }
    return response;
}

pub fn g1_rand() -> () {
    let mut rng = thread_rng();
    for _ in 0..1000{
        let _r = G1Affine::rand(&mut rng);
    }
}

pub fn g1_rand_return() -> Vec<G1Affine> {
    let mut rng = thread_rng();
    let mut response = Vec::new();
    for _ in 0..1000{
        let r = G1Affine::rand(&mut rng);
        response.push(r);
    }
    return response;
}

pub fn g2_rand() -> () {
    let mut rng = thread_rng();
    for _ in 0..1000{
        let _r = G2Affine::rand(&mut rng);
    }
}

pub fn g2_rand_return() -> Vec<G2Affine> {
    let mut rng = thread_rng();
    let mut response = Vec::new();
    for _ in 0..1000{
        let r = G2Affine::rand(&mut rng);
        response.push(r);
    }
    return response;
}

pub fn add_fr(a: &Vec<Fr>, b: &Vec<Fr>) -> () {
    for i in 0..a.len() {
        let _c = a[i] + b[i];
    }
}

pub fn mul_fr(a: &Vec<Fr>, b: &Vec<Fr>) -> () {
    for i in 0..a.len() {
        let _c = a[i] * b[i];
    }
}

pub fn add_g1(a: &Vec<G1Affine>, b: &Vec<G1Affine>) -> () {
    for i in 0..a.len() {
        let _c = a[i] + b[i];
    }
}

pub fn add_g2(a: &Vec<G2Affine>, b: &Vec<G2Affine>) -> () {
    for i in 0..a.len() {
        let _c = a[i] + b[i];
    }
}

pub fn mul_g1(a: &Vec<G1Affine>, b: &Vec<Fr>) -> () {
    for i in 0..a.len() {
        let _c = a[i] * b[i];
    }
}

pub fn mul_g2(a: &Vec<G2Affine>, b: &Vec<Fr>) -> () {
    for i in 0..a.len() {
        let _c = a[i] * b[i];
    }
}

pub fn pairing_op(a: &Vec<G1Affine>, b: &Vec<G2Affine>) -> () {
    for i in 0..a.len() {
        let _c = Bls12_381::pairing(a[i], b[i]);
    }
}

pub fn pairing_op_return(a: &Vec<G1Affine>, b: &Vec<G2Affine>) -> Vec<PairingOutput<Bls12<Config>>> {
    let mut response = Vec::new();
    for i in 0..a.len() {
        let c = Bls12_381::pairing(a[i], b[i]);
        response.push(c);
    }
    return response;
}

pub fn add_pairing(a: &Vec<PairingOutput<Bls12<Config>>>, b: &Vec<PairingOutput<Bls12<Config>>>) -> () {
    for i in 0..a.len() {
        let _c = a[i] + b[i];
    }
}

pub fn mul_pairing(a: &Vec<PairingOutput<Bls12<Config>>>, b: &Vec<Fr>) -> () {
    for i in 0..a.len() {
        let _c = a[i] * b[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let vec_fr = fr_rand_return();
        assert_eq!(vec_fr.len(), 1000);
        let vec_g1 = g1_rand_return();
        assert_eq!(vec_g1.len(), 1000);
        let vec_g2 = g2_rand_return();
        assert_eq!(vec_g2.len(), 1000);
        let vec_pairing = pairing_op_return(&vec_g1, &vec_g2);
        assert_eq!(vec_pairing.len(), 1000);
    }
}