use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use ark_bls12_381::{Bls12_381, G2Affine};
use ark_ec::pairing::Pairing;
use ark_std::{vec::Vec, UniformRand};
use ark_ec::AffineRepr;
use rand::{self, Rng};
pub type Fr = <Bls12_381 as Pairing>::ScalarField;

fn bobolz_benchmark(c: &mut Criterion) {
    let mut rng = OsRng;
    let pp_groth = bobolz_rs_lib::groth::par_gen();

    c.bench_function("Issuer Key Gen", |b| {
        b.iter(|| {
            let issuer_key_pair = bobolz_rs_lib::bobolz::issuer_key_gen(&pp_groth);
            black_box(issuer_key_pair);
        });
    });

    c.bench_function("Verifier Key Gen", |b| {
        b.iter(|| {
            let verifier_key_pair = bobolz_rs_lib::bobolz::verifier_key_gen(&pp_groth);
            black_box(verifier_key_pair);
        });
    });

    let issuer_key_pair = bobolz_rs_lib::bobolz::issuer_key_gen(&pp_groth);
    let verifier_key_pair = bobolz_rs_lib::bobolz::verifier_key_gen(&pp_groth);
    for message_len_temp in [5, 10, 15, 20].iter(){
        let pp_temp = bobolz_rs_lib::bobolz::par_gen(&message_len_temp);
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        c.bench_function("Issuer Sign", |b|{
            b.iter(|| {
                let signature = bobolz_rs_lib::bobolz::issue(&pp_temp, &issuer_key_pair.secret_key,&message_fr_temp);
                black_box(signature);
            });
        });
    }

    for message_len_temp in [5, 10, 15, 20].iter(){
        let pp_temp = bobolz_rs_lib::bobolz::par_gen(&message_len_temp);
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        let cred_temp = bobolz_rs_lib::bobolz::issue(&pp_temp, &issuer_key_pair.secret_key,&message_fr_temp);
        c.bench_function("Verify Credential", |b|{
            b.iter(|| {
                let result = bobolz_rs_lib::bobolz::verify(&pp_temp, &cred_temp, &message_fr_temp, &issuer_key_pair.public_key);
                black_box(result);
            });
        });
    }

    for issuer_num_temp in [5, 10, 50, 100].iter(){
        let mut issuer_list_temp = Vec::new();
        for _ in 0..*issuer_num_temp{
            issuer_list_temp.push(G2Affine::generator());
        }
        c.bench_function("verifier's trusted issuer list", |b|{
            let r = rng.gen_range(1..*issuer_num_temp);
            issuer_list_temp[r] = issuer_key_pair.public_key.0;
            b.iter(|| {
                let trusted_issuer_credential = bobolz_rs_lib::bobolz::issue_list(&pp_groth, &issuer_list_temp, &verifier_key_pair);
                black_box(trusted_issuer_credential);
            });
        });
    }

    for issuer_num_temp in [5, 10, 50, 100].iter(){
        let mut issuer_list_temp = Vec::new();
        for _ in 0..*issuer_num_temp{
            issuer_list_temp.push(G2Affine::generator());
        }
        let r = rng.gen_range(1..*issuer_num_temp);
        issuer_list_temp[r] = issuer_key_pair.public_key.0;
        let trusted_issuer_credential = bobolz_rs_lib::bobolz::issue_list(&pp_groth, &issuer_list_temp, &verifier_key_pair);
        c.bench_function("verify verifier's trusted issuer list", |b|{
            b.iter(|| {
                let result = bobolz_rs_lib::bobolz::verify_list(&pp_groth, &trusted_issuer_credential);
                black_box(result);
            });
        });
    }

    for message_len_temp in [5, 10, 15, 20].iter(){
        let pp_temp = bobolz_rs_lib::bobolz::par_gen(&message_len_temp);
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        let cred_temp = bobolz_rs_lib::bobolz::issue(&pp_temp, &issuer_key_pair.secret_key,&message_fr_temp);
        let open_message_6 = message_len_temp * 3 / 5;
        let mut open_message_len_temp: Vec<i32> = Vec::new();
        if open_message_6 == 3{
            open_message_len_temp.append(&mut [3, message_len_temp - 3].to_vec());
        }else{
            open_message_len_temp.append(&mut [3, open_message_6, message_len_temp - 3].to_vec());
        }
        open_message_len_temp.sort();
        for open_message_len_i in open_message_len_temp.iter(){
            let mut open_temp = Vec::new();
            for j in 0..*open_message_len_i{
                let mut flg = true;
                let mut x = rng.gen_range(0..*message_len_temp) as usize;
                while flg {
                    flg = false;
                    for i in 0..j{
                        if x == open_temp[i as usize]{
                            flg = true;
                            x = rng.gen_range(0..*message_len_temp) as usize;
                            break;
                        }
                    }
                }
                open_temp.push(x);
            }
            open_temp.sort();
            for issuer_num_temp in [5, 10, 50, 100].iter(){
                let mut issuer_list_temp = Vec::new();
                for _ in 0..*issuer_num_temp{
                    issuer_list_temp.push(G2Affine::generator());
                }
                let r = rng.gen_range(1..*issuer_num_temp);
                issuer_list_temp[r] = issuer_key_pair.public_key.0;
                let trusted_issuer_credential_temp = bobolz_rs_lib::bobolz::issue_list(&pp_groth, &issuer_list_temp, &verifier_key_pair);
                c.bench_function("present", |b|{
                    b.iter(|| {
                        let pt = bobolz_rs_lib::bobolz::present(&pp_temp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &trusted_issuer_credential_temp, &open_temp);
                        black_box(pt);
                    });
                });
            }
        }
    }

    for message_len_temp in [5, 10, 15, 20].iter(){
        let pp_temp = bobolz_rs_lib::bobolz::par_gen(&message_len_temp);
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        let cred_temp = bobolz_rs_lib::bobolz::issue(&pp_temp, &issuer_key_pair.secret_key,&message_fr_temp);
        let open_message_6 = message_len_temp * 3 / 5;
        let mut open_message_len_temp: Vec<i32> = Vec::new();
        if open_message_6 == 3{
            open_message_len_temp.append(&mut [3, message_len_temp - 3].to_vec());
        }else{
            open_message_len_temp.append(&mut [3, open_message_6, message_len_temp - 3].to_vec());
        }
        open_message_len_temp.sort();
        for open_message_len_i in open_message_len_temp.iter(){
            let mut open_temp = Vec::new();
            for j in 0..*open_message_len_i{
                let mut flg = true;
                let mut x = rng.gen_range(0..*message_len_temp) as usize;
                while flg {
                    flg = false;
                    for i in 0..j{
                        if x == open_temp[i as usize]{
                            flg = true;
                            x = rng.gen_range(0..*message_len_temp) as usize;
                            break;
                        }
                    }
                }
                open_temp.push(x);
            }
            open_temp.sort();
            for issuer_num_temp in [5, 10, 50, 100].iter(){
                let mut issuer_list_temp = Vec::new();
                for _ in 0..*issuer_num_temp{
                    issuer_list_temp.push(G2Affine::generator());
                }
                let r = rng.gen_range(1..*issuer_num_temp);
                issuer_list_temp[r] = issuer_key_pair.public_key.0;
                let trusted_issuer_credential_temp = bobolz_rs_lib::bobolz::issue_list(&pp_groth, &issuer_list_temp, &verifier_key_pair);
                let pt_temp = bobolz_rs_lib::bobolz::present(&pp_temp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &trusted_issuer_credential_temp, &open_temp);

                c.bench_function("verify_present", |b|{
                    b.iter(|| {
                        let result = bobolz_rs_lib::bobolz::verify_present(&pp_temp, &trusted_issuer_credential_temp, &pt_temp);
                        black_box(result);
                    });
                });
            }
        }
    }



}

criterion_group!(benches, bobolz_benchmark);
criterion_main!(benches);