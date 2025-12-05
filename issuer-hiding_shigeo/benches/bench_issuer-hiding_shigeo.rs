use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{vec::Vec, UniformRand};
use rand::{self, Rng, thread_rng};
pub type Fr = <Bls12_381 as Pairing>::ScalarField;
use issuer_hiding_shigeo::issuer_hiding as ih;

fn myih_benchmark(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20];
    let issuer_num = [5, 10, 50];
    let mut rng = thread_rng();
    let pp = ih::par_gen();

    // c.bench_function("Issuer Key Gen", |b| {
    //     b.iter(|| {
    //         let issuer_key_pair = ih::issuer_key_gen(&pp_groth);
    //         black_box(issuer_key_pair);
    //     });
    // });

    // c.bench_function("Verifier Key Gen", |b| {
    //     b.iter(|| {
    //         let verifier_key_pair = ih::verifier_key_gen(&pp_groth);
    //         black_box(verifier_key_pair);
    //     });
    // });

    let issuer_key_pair = ih::issuer_key_gen(&pp);
    let verifier_key_pair = ih::verifier_key_gen(&pp);
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
                let signature = ih::issue(&pp, &issuer_key_pair.secret_key,&message_fr_temp);
                black_box(signature);
            });
        });
    }

    for message_len_temp in message_len.iter(){
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key,&message_fr_temp);

        let bench_name = format!(
            "Verify_Credential_messagelen{}",
            message_len_temp
        );
        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let result = ih::verify(&pp, &issuer_key_pair.public_key, &message_fr_temp, &cred_temp);
                black_box(result);
            });
        });
    }

    for issuer_num_temp in issuer_num.iter(){
        let mut issuer_list_temp = Vec::new();
        for _ in 0..*issuer_num_temp{
            let keypair = ih::issuer_key_gen(&pp);
            issuer_list_temp.push(keypair.public_key.clone());
        }

        let bench_name = format!(
            "Issue_Verifier's_trusted_issuer_list_issuernum{}",
            issuer_num_temp
        );
        let r = rng.gen_range(1..*issuer_num_temp);
        issuer_list_temp[r] = issuer_key_pair.public_key.clone();
        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let trusted_issuer_credential = ih::issue_list(&pp, &verifier_key_pair, &issuer_list_temp);
                black_box(trusted_issuer_credential);
            });
        });
    }

    for issuer_num_temp in issuer_num.iter(){
        let mut issuer_list_temp = Vec::new();
        for _ in 0..*issuer_num_temp{
            let keypair = ih::issuer_key_gen(&pp);
            issuer_list_temp.push(keypair.public_key.clone());
        }
        let r = rng.gen_range(1..*issuer_num_temp);
        issuer_list_temp[r] = issuer_key_pair.public_key.clone();
        let trusted_issuer_credential = ih::issue_list(&pp, &verifier_key_pair, &issuer_list_temp);

        let bench_name = format!(
            "Verify_Verifier's_trusted_issuer_list_issuernum{}",
            issuer_num_temp
        );
        c.bench_function(&bench_name, |b|{
            b.iter(|| {
                let result = ih::verify_list(&pp, &trusted_issuer_credential);
                black_box(result);
            });
        });
    }

    for message_len_temp in message_len.iter(){
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key,&message_fr_temp);
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
                    let keypair = ih::issuer_key_gen(&pp);
                    issuer_list_temp.push(keypair.public_key.clone());
                }
                let r = rng.gen_range(1..*issuer_num_temp);
                issuer_list_temp[r] = issuer_key_pair.public_key.clone();
                let trusted_issuer_credential_temp = ih::issue_list(&pp, &verifier_key_pair, &issuer_list_temp);
                let bench_name = format!(
                    "Present_mlen{}_olen{}_issuernum{}",
                    message_len_temp, open_message_len_i, issuer_num_temp
                );
                c.bench_function(&bench_name, |b|{
                    b.iter(|| {
                        let pt = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &open_temp, &trusted_issuer_credential_temp);
                        black_box(pt);
                    });
                });
            }
        }
    }

    for message_len_temp in message_len.iter(){
        let mut message_fr_temp = Vec::new();
        for _ in 0..*message_len_temp{
            message_fr_temp.push(Fr::rand(&mut rng));
        }
        let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key,&message_fr_temp);
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
                    let keypair = ih::issuer_key_gen(&pp);
                    issuer_list_temp.push(keypair.public_key.clone());
                }
                let r = rng.gen_range(1..*issuer_num_temp);
                issuer_list_temp[r] = issuer_key_pair.public_key.clone();
                let trusted_issuer_credential_temp = ih::issue_list(&pp, &verifier_key_pair, &issuer_list_temp);
                let (pikp, pizkp) = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &open_temp, &trusted_issuer_credential_temp);

                let bench_name = format!(
                    "Verify_present_mlen{}_olen{}_issuernum{}",
                    message_len_temp, open_message_len_i, issuer_num_temp
                );

                c.bench_function(&bench_name, |b|{
                    b.iter(|| {
                        let result = ih::verify_present(&pp, &trusted_issuer_credential_temp, &pikp, &pizkp);
                        black_box(result);
                    });
                });
            }
        }
    }

    // let message_len_temp = 1000;
}

criterion_group!(benches, myih_benchmark);
criterion_main!(benches);