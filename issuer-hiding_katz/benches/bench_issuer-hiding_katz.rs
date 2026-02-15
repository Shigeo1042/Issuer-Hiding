use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::hint::black_box;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{vec::Vec, UniformRand};
use rand::{self, Rng, thread_rng};
pub type Fr = <Bls12_381 as Pairing>::ScalarField;
use issuer_hiding_katz::issuer_hiding as ih;

fn katz_ih_benchmark(c: &mut Criterion){
    let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    let issuer_num = [5, 10, 50, 100, 500, 1000];
    let mut rng = thread_rng();

    c.bench_function("Setup", |b| {
        b.iter(|| {
            let pp = ih::par_gen();
            black_box(pp);
        });
    });

    let pp = ih::par_gen();

    c.bench_function("Issuer_Key_Gen", |b| {
        b.iter(|| {
            let issuer_key_pair = ih::issuer_key_gen(&pp);
            black_box(issuer_key_pair);
        });
    });

    let issuer_key_pair = ih::issuer_key_gen(&pp);

    // ------------------------------------------------------------------
    // Group 1: Basic Signature Generation and Verification (Variation Based on Message Length)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Basic_Credential_Ops");
        
        for &len in message_len.iter() {
            // Preparing the input data
            let mut message_fr_temp = Vec::new();
            for _ in 0..len {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            
            // Issuer Sign
            group.bench_with_input(BenchmarkId::new("Sign", len), &len, |b, &_| {
                b.iter(|| {
                    let signature = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);
                    black_box(signature);
                });
            });

            // Verify Credential (Generated Data Required)
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);
            group.bench_with_input(BenchmarkId::new("Verify", len), &len, |b, &_| {
                b.iter(|| {
                    let result = ih::verify(&pp, &issuer_key_pair.public_key, &message_fr_temp, &cred_temp);
                    black_box(result);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 2: Policy Issuance and Verification (Variation Based on Number of Issuers)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Policy_Ops");

        for &num in issuer_num.iter() {
            // Preparing the list
            let mut issuer_list_temp = Vec::new();
            for _ in 0..num {
                let keypair = ih::issuer_key_gen(&pp);
                issuer_list_temp.push(keypair.public_key.clone());
            }
            // Inserting the target at a random position
            let r = rng.gen_range(0..num);
            if r < issuer_list_temp.len() {
                 issuer_list_temp[r] = issuer_key_pair.public_key.clone();
            }

            // Set Policy
            group.bench_with_input(BenchmarkId::new("Set_Policy", num), &num, |b, &_| {
                b.iter(|| {
                    let pkp = ih::set_policy(&pp, &issuer_list_temp);
                black_box(pkp);
                });
            });

            // Policy (Generated Data Required)
            let policy_key_pair = ih::set_policy(&pp, &issuer_list_temp);
            let policy_pk = &policy_key_pair.public_key;
            group.bench_with_input(BenchmarkId::new("Verify_List", num), &num, |b, &_| {
                b.iter(|| {
                    let result = ih::audit_policy(&pp, &policy_pk);
                    black_box(result);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 3: Presentation Generation (Complex Parameters: Message Length, Open Attribute Count, Issuer Count)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Presentation_Ops");
        // If you need to extend the sample time for more complex operations, you can set it here (e.g., 10 seconds).
        // group.measurement_time(std::time::Duration::from_secs(10));

        for &mlen in message_len.iter() {
            // Preparing the Message
            let mut message_fr_temp = Vec::new();
            for _ in 0..mlen {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);

            // Determining the number of attributes to open
            let open_message_6 = mlen * 3 / 5;
            let mut open_message_len_temp: Vec<i32> = Vec::new();
            if open_message_6 == 3 {
                open_message_len_temp.extend_from_slice(&[3, (mlen as i32) - 3]);
            } else {
                open_message_len_temp.extend_from_slice(&[3, open_message_6 as i32, (mlen as i32) - 3]);
            }
            open_message_len_temp.sort();
            open_message_len_temp.dedup(); // Remove duplicates (just in case)

            for &olen in open_message_len_temp.iter() {
                // Selecting indices to open
                let mut open_temp = Vec::new();
                while open_temp.len() < olen as usize {
                    let x = rng.gen_range(0..mlen);
                    if !open_temp.contains(&x) {
                        open_temp.push(x);
                    }
                }
                open_temp.sort();

                for &inum in issuer_num.iter() {
                    // Preparing the Issuer List
                    let mut issuer_list_temp = Vec::new();
                    for _ in 0..inum {
                        let kp = ih::issuer_key_gen(&pp);
                        issuer_list_temp.push(kp.public_key.clone());
                    }
                    let r = rng.gen_range(0..inum);
                    issuer_list_temp[r] = issuer_key_pair.public_key.clone();
                    
                    let policy_key_pair = ih::set_policy(&pp, &issuer_list_temp);
                    let policy_pk = &policy_key_pair.public_key;

                    // Creating a parameter identification string (e.g., "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &open_temp, &policy_pk);
                            black_box(pt);
                        });
                    });
                    // Verify Present Benchmark
                    let (pikp, pizkp) = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &open_temp, &policy_pk);
                    
                    group.bench_with_input(BenchmarkId::new("Verify_Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let result = ih::verify_present(&pp, &policy_key_pair, &pikp, &pizkp);
                            black_box(result);
                        });
                    });
                }
            }
        }
        group.finish();
    }
}

fn katz_ih_benchmark_pc(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    let issuer_num = [5, 10, 50, 100, 500, 1000];
    let mut rng = thread_rng();

    c.bench_function("Setup", |b| {
        b.iter(|| {
            let pp = ih::par_gen();
            black_box(pp);
        });
    });
    let pp = ih::par_gen();

    c.bench_function("Issuer_Key_Gen", |b| {
        b.iter(|| {
            let ikp = ih::issuer_key_gen(&pp);
            black_box(ikp);
        });
    });

    let issuer_key_pair = ih::issuer_key_gen(&pp);

    // ------------------------------------------------------------------
    // Group 1: Basic Signature Generation (Variation Based on Message Length)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Basic_Credential_Ops");
        
        for &len in message_len.iter() {
            // Preparing the input data
            let mut message_fr_temp = Vec::new();
            for _ in 0..len {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            
            // Issuer Sign
            group.bench_with_input(BenchmarkId::new("Sign", len), &len, |b, &_| {
                b.iter(|| {
                    let signature = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);
                    black_box(signature);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 2: Policy Issuance (Variation Based on Number of Issuers)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Policy_Ops");

        for &num in issuer_num.iter() {
            // Preparing the list
            let mut issuer_list_temp = Vec::new();
            for _ in 0..num {
                let keypair = ih::issuer_key_gen(&pp);
                issuer_list_temp.push(keypair.public_key.clone());
            }
            // Inserting the target at a random position
            let r = rng.gen_range(0..num);
            if r < issuer_list_temp.len() {
                 issuer_list_temp[r] = issuer_key_pair.public_key.clone();
            }

            // Set Policy
            group.bench_with_input(BenchmarkId::new("Set_Policy", num), &num, |b, &_| {
                b.iter(|| {
                    let pkp = ih::set_policy(&pp, &issuer_list_temp);
                black_box(pkp);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 3: Presentation Verification (Complex Parameters: Message Length, Open Attribute Count, Issuer Count)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Presentation_Ops");
        // If you need to extend the sample time for more complex operations, you can set it here (e.g., 10 seconds).
        // group.measurement_time(std::time::Duration::from_secs(10));

        for &mlen in message_len.iter() {
            // Preparing the Message
            let mut message_fr_temp = Vec::new();
            for _ in 0..mlen {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);

            // Determining the number of attributes to open
            let open_message_6 = mlen * 3 / 5;
            let mut open_message_len_temp: Vec<i32> = Vec::new();
            if open_message_6 == 3 {
                open_message_len_temp.extend_from_slice(&[3, (mlen as i32) - 3]);
            } else {
                open_message_len_temp.extend_from_slice(&[3, open_message_6 as i32, (mlen as i32) - 3]);
            }
            open_message_len_temp.sort();
            open_message_len_temp.dedup(); // 重複排除（念の為）

            for &olen in open_message_len_temp.iter() {
                // Selecting indices to open
                let mut open_temp = Vec::new();
                while open_temp.len() < olen as usize {
                    let x = rng.gen_range(0..mlen);
                    if !open_temp.contains(&x) {
                        open_temp.push(x);
                    }
                }
                open_temp.sort();

                for &inum in issuer_num.iter() {
                    // Preparing the Issuer List
                    let mut issuer_list_temp = Vec::new();
                    for _ in 0..inum {
                        let kp = ih::issuer_key_gen(&pp);
                        issuer_list_temp.push(kp.public_key.clone());
                    }
                    let r = rng.gen_range(0..inum);
                    issuer_list_temp[r] = issuer_key_pair.public_key.clone();

                    let policy_key_pair = ih::set_policy(&pp, &issuer_list_temp);
                    let policy_pk = &policy_key_pair.public_key;

                    // Creating a parameter identification string (e.g., "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Verify Present Benchmark
                    // Verify Present Benchmark (Generated Data Required)
                    let (pikp, pizkp) = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &open_temp, &policy_pk);
                    
                    group.bench_with_input(BenchmarkId::new("Verify_Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let result = ih::verify_present(&pp, &policy_key_pair, &pikp, &pizkp);
                            black_box(result);
                        });
                    });
                }
            }
        }
        group.finish();
    }
}

fn katz_ih_benchmark_android(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    let issuer_num = [5, 10, 50, 100, 500, 1000];
    let mut rng = thread_rng();
    let pp = ih::par_gen();

    let issuer_key_pair = ih::issuer_key_gen(&pp);

    // ------------------------------------------------------------------
    // Group 1: Basic Signature Verification (Variation Based on Message Length)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Basic_Credential_Ops");
        
        for &len in message_len.iter() {
            // Preparing the input data
            let mut message_fr_temp = Vec::new();
            for _ in 0..len {
                message_fr_temp.push(Fr::rand(&mut rng));
            }

            // Verify Credential (Generated Data Required)
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);
            group.bench_with_input(BenchmarkId::new("Verify", len), &len, |b, &_| {
                b.iter(|| {
                    let result = ih::verify(&pp, &issuer_key_pair.public_key, &message_fr_temp, &cred_temp);
                    black_box(result);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 2: Policy Verification (Variation Based on Number of Issuers)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Policy_Ops");

        for &num in issuer_num.iter() {
            // Preparing the list
            let mut issuer_list_temp = Vec::new();
            for _ in 0..num {
                let keypair = ih::issuer_key_gen(&pp);
                issuer_list_temp.push(keypair.public_key.clone());
            }
            // Inserting the target at a random position
            let r = rng.gen_range(0..num);
            if r < issuer_list_temp.len() {
                 issuer_list_temp[r] = issuer_key_pair.public_key.clone();
            }

            // Policy (Generated Data Required)
            let policy_key_pair = ih::set_policy(&pp, &issuer_list_temp);
            let policy_pk = &policy_key_pair.public_key;
            group.bench_with_input(BenchmarkId::new("Verify_List", num), &num, |b, &_| {
                b.iter(|| {
                    let result = ih::audit_policy(&pp, &policy_pk);
                    black_box(result);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 3: Presentation Generation (Complex Parameters: Message Length, Open Attribute Count, Issuer Count)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Presentation_Ops");
        // If you need to extend the sample time for more complex operations, you can set it here (e.g., 10 seconds).
        // group.measurement_time(std::time::Duration::from_secs(10));

        for &mlen in message_len.iter() {
            // Preparing the Message
            let mut message_fr_temp = Vec::new();
            for _ in 0..mlen {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);

            // Determining the number of attributes to open
            let open_message_6 = mlen * 3 / 5;
            let mut open_message_len_temp: Vec<i32> = Vec::new();
            if open_message_6 == 3 {
                open_message_len_temp.extend_from_slice(&[3, (mlen as i32) - 3]);
            } else {
                open_message_len_temp.extend_from_slice(&[3, open_message_6 as i32, (mlen as i32) - 3]);
            }
            open_message_len_temp.sort();
            open_message_len_temp.dedup(); // Remove duplicates (just in case)

            for &olen in open_message_len_temp.iter() {
                // Selecting indices to open
                let mut open_temp = Vec::new();
                while open_temp.len() < olen as usize {
                    let x = rng.gen_range(0..mlen);
                    if !open_temp.contains(&x) {
                        open_temp.push(x);
                    }
                }
                open_temp.sort();

                for &inum in issuer_num.iter() {
                    // Preparing the Issuer List
                    let mut issuer_list_temp = Vec::new();
                    for _ in 0..inum {
                        let kp = ih::issuer_key_gen(&pp);
                        issuer_list_temp.push(kp.public_key.clone());
                    }
                    let r = rng.gen_range(0..inum);
                    issuer_list_temp[r] = issuer_key_pair.public_key.clone();
                    
                    let policy_key_pair = ih::set_policy(&pp, &issuer_list_temp);
                    let policy_pk = &policy_key_pair.public_key;

                    // Creating a parameter identification string (e.g., "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &open_temp, &policy_pk);
                            black_box(pt);
                        });
                    });
                }
            }
        }
        group.finish();
    }
}

criterion_group!(benches, katz_ih_benchmark);
criterion_group!(bench_pc, katz_ih_benchmark_pc);
criterion_group!(bench_android, katz_ih_benchmark_android);
criterion_main!(benches);