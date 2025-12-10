use bobolz_rs_lib::bobolz as bobolz;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{vec::Vec, UniformRand};
use rand::{thread_rng, Rng};

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

fn bobolz_benchmark(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 40, 50];
    let issuer_num = [5, 10, 50, 100, 500, 1000];
    let mut rng = thread_rng();
    let pp = bobolz::par_gen();

    c.bench_function("Issuer Key Gen", |b| {
        b.iter(|| {
            let issuer_key_pair = bobolz::issuer_key_gen(&pp);
            black_box(issuer_key_pair);
        });
    });

    c.bench_function("Verifier Key Gen", |b| {
        b.iter(|| {
            let verifier_key_pair = bobolz::verifier_key_gen(&pp);
            black_box(verifier_key_pair);
        });
    });

    let issuer_key_pair = bobolz::issuer_key_gen(&pp);
    let verifier_key_pair = bobolz::verifier_key_gen(&pp);
    for message_len_temp in message_len.iter(){
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }

        let bench_name = format!(
            "Issuer_Sign_messagelen{}",
            message_len_temp
        );
        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let signature = bobolz::issue(&pp, &issuer_key_pair.secret_key,&message_fr_temp);
                black_box(signature);
            });
        });
    }

    for message_len_temp in message_len.iter(){
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        let cred_temp = bobolz::issue(&pp, &issuer_key_pair.secret_key,&message_fr_temp);

        let bench_name = format!(
            "Verify_Credential_messagelen{}",
            message_len_temp
        );
        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let result = bobolz::verify(&pp, &cred_temp, &message_fr_temp, &issuer_key_pair.public_key);
                black_box(result);
            });
        });
    }

    for issuer_num_temp in issuer_num.iter(){
        let mut issuer_list_temp = Vec::new();
        for _ in 0..*issuer_num_temp{
            let issuer_key_pair_temp = bobolz::issuer_key_gen(&pp);
            let ipk_temp = issuer_key_pair_temp.public_key;
            issuer_list_temp.push(ipk_temp);
        }

        let bench_name = format!(
            "Issue_Verifier's_trusted_issuer_list_issuernum{}",
            issuer_num_temp
        );
        let r = rng.gen_range(1..*issuer_num_temp);
        issuer_list_temp[r] = issuer_key_pair.public_key.clone();
        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let trusted_issuer_credential = bobolz::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);
                black_box(trusted_issuer_credential);
            });
        });
    }

    for issuer_num_temp in issuer_num.iter(){
        let mut issuer_list_temp = Vec::new();
        for _ in 0..*issuer_num_temp{
            let issuer_key_pair_temp = bobolz::issuer_key_gen(&pp);
            let ipk_temp = issuer_key_pair_temp.public_key;
            issuer_list_temp.push(ipk_temp);
        }
        let r = rng.gen_range(1..*issuer_num_temp);
        issuer_list_temp[r] = issuer_key_pair.public_key.clone();
        let trusted_issuer_credential = bobolz::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);

        let bench_name = format!(
            "Verify_Verifier's_trusted_issuer_list_issuernum{}",
            issuer_num_temp
        );
        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let result = bobolz::verify_list(&pp, &trusted_issuer_credential);
                black_box(result);
            });
        });
    }

    for message_len_temp in message_len.iter(){
        let pp_temp = bobolz::par_gen();
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        let cred_temp = bobolz::issue(&pp_temp, &issuer_key_pair.secret_key,&message_fr_temp);
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
            for issuer_num_temp in issuer_num.iter(){
                let mut issuer_list_temp = Vec::new();
                for _ in 0..*issuer_num_temp{
                    let issuer_key_pair_temp = bobolz::issuer_key_gen(&pp);
                    let ipk_temp = issuer_key_pair_temp.public_key;
                    issuer_list_temp.push(ipk_temp);
                }
                let r = rng.gen_range(1..*issuer_num_temp);
                issuer_list_temp[r] = issuer_key_pair.public_key.clone();
                let trusted_issuer_credential_temp = bobolz::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);

                let bench_name = format!(
                    "Present_mlen{}_olen{}_issuernum{}",
                    message_len_temp, open_message_len_i, issuer_num_temp
                );
                c.bench_function(&bench_name, |b|{
                    b.iter(|| {
                        let pt = bobolz::present(&pp_temp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &trusted_issuer_credential_temp, &open_temp);
                        black_box(pt);
                    });
                });
            }
        }
    }

    for message_len_temp in message_len.iter(){
        let pp_temp = bobolz::par_gen();
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        let cred_temp = bobolz::issue(&pp_temp, &issuer_key_pair.secret_key,&message_fr_temp);
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
            for issuer_num_temp in issuer_num.iter(){
                let mut issuer_list_temp = Vec::new();
                for _ in 0..*issuer_num_temp{
                    let issuer_key_pair_temp = bobolz::issuer_key_gen(&pp);
                    let ipk_temp = issuer_key_pair_temp.public_key;
                    issuer_list_temp.push(ipk_temp);
                }
                let r = rng.gen_range(1..*issuer_num_temp);
                issuer_list_temp[r] = issuer_key_pair.public_key.clone();
                let trusted_issuer_credential_temp = bobolz::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);
                let pt_temp = bobolz::present(&pp_temp, &cred_temp, &issuer_key_pair.public_key.clone(), &message_fr_temp, &trusted_issuer_credential_temp, &open_temp);

                let bench_name = format!(
                    "Verify_present_mlen{}_olen{}_issuernum{}",
                    message_len_temp, open_message_len_i, issuer_num_temp
                );

                c.bench_function(&bench_name, |b|{
                    b.iter(|| {
                        let result = bobolz::verify_present(&pp_temp, &trusted_issuer_credential_temp, &pt_temp);
                        black_box(result);
                    });
                });
            }
        }
    }



}

criterion_group!(benches, bobolz_benchmark);
criterion_main!(benches);