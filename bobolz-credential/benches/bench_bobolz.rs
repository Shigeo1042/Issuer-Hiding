use bobolz_rs_lib::bobolz as ih;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::hint::black_box;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{vec::Vec, UniformRand};
use rand::{thread_rng, Rng};

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

fn bobolz_benchmark(c: &mut Criterion) {
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

    c.bench_function("Verifier_Key_Gen", |b| {
        b.iter(|| {
            let verifier_key_pair = ih::verifier_key_gen(&pp);
            black_box(verifier_key_pair);
        });
    });

    let issuer_key_pair = ih::issuer_key_gen(&pp);
    let verifier_key_pair = ih::verifier_key_gen(&pp);

    // ------------------------------------------------------------------
    // Group 1: Basic Signature Generation and Verification (Variation Based on Message Length)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Basic_Credential_Ops");
        
        for &len in message_len.iter() {
            // Preparing Input Data
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
                    let result = ih::verify(&pp, &cred_temp, &message_fr_temp, &issuer_key_pair.public_key);
                    black_box(result);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 2: Trusted List Issuance and Verification (Variation Based on Number of Issuers)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Policy_Ops");

        for &num in issuer_num.iter() {
            // Preparing the List
            let mut issuer_list_temp = Vec::new();
            for _ in 0..num {
                let keypair = ih::issuer_key_gen(&pp);
                issuer_list_temp.push(keypair.public_key.clone());
            }
            // Inserting the Target at a Random Position
            let r = rng.gen_range(0..num);
            if r < issuer_list_temp.len() {
                 issuer_list_temp[r] = issuer_key_pair.public_key.clone();
            }

            // Set Policy
            group.bench_with_input(BenchmarkId::new("Set_Policy", num), &num, |b, &_| {
                b.iter(|| {
                    let pkp = ih::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);
                black_box(pkp);
                });
            });

            // Policy (Generated Data Required)
            let trusted_list = ih::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);
            group.bench_with_input(BenchmarkId::new("Verify_List", num), &num, |b, &_| {
                b.iter(|| {
                    let result = ih::verify_list(&pp, &trusted_list);
                    black_box(result);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 3: Presentation Generation and Verification (Complex Parameters: Message Length, Open Attribute Count, Number of Issuers)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Presentation_Ops");
        // If you need to extend the sample time for more complex operations, you can set it here (e.g., 10 seconds).
        // group.measurement_time(std::time::Duration::from_secs(10));

        for &mlen in message_len.iter() {
            // Preparing Messages
            let mut message_fr_temp = Vec::new();
            for _ in 0..mlen {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);

            // Determining the Number of Attributes to Open
            let open_message_6 = mlen * 3 / 5;
            let mut open_message_len_temp: Vec<i32> = Vec::new();
            if open_message_6 == 3 {
                open_message_len_temp.extend_from_slice(&[3, (mlen as i32) - 3]);
            } else {
                open_message_len_temp.extend_from_slice(&[3, open_message_6 as i32, (mlen as i32) - 3]);
            }
            open_message_len_temp.sort();
            open_message_len_temp.dedup(); // Removing Duplicates (Just in Case)

            for &olen in open_message_len_temp.iter() {
                // Selecting Public Indices
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
                    
                    let trusted_list = ih::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);

                    // Creating a Parameter Identification String (e.g., "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &trusted_list, &open_temp);
                            black_box(pt);
                        });
                    });

                    // Verify Present Benchmark
                    // Generating this every time in the benchmark would be slow, so we generate it once outside the measurement.
                    let pt = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &trusted_list, &open_temp);
                    
                    group.bench_with_input(BenchmarkId::new("Verify_Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let result = ih::verify_present(&pp, &trusted_list, &pt);
                            black_box(result);
                        });
                    });
                }
            }
        }
        group.finish();
    }
}

fn bobolz_mobile_benchmark(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    let issuer_num = [5, 10, 50, 100, 500, 1000];
    let mut rng = thread_rng();
    let pp = ih::par_gen();
    let issuer_key_pair = ih::issuer_key_gen(&pp);
    let verifier_key_pair = ih::verifier_key_gen(&pp);

    // ------------------------------------------------------------------
    // Group 1: Basic Signature Generation (Variation Based on Message Length)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Basic_Credential_Ops");
        
        for &len in message_len.iter() {
            // Preparing Input Data
            let mut message_fr_temp = Vec::new();
            for _ in 0..len {
                message_fr_temp.push(Fr::rand(&mut rng));
            }

            // Verify Credential (Generated Data Required)
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);
            group.bench_with_input(BenchmarkId::new("Verify", len), &len, |b, &_| {
                b.iter(|| {
                    let result = ih::verify(&pp, &cred_temp, &message_fr_temp, &issuer_key_pair.public_key);
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
            // Preparing the List
            let mut issuer_list_temp = Vec::new();
            for _ in 0..num {
                let keypair = ih::issuer_key_gen(&pp);
                issuer_list_temp.push(keypair.public_key.clone());
            }
            // Inserting the Target at a Random Position
            let r = rng.gen_range(0..num);
            if r < issuer_list_temp.len() {
                 issuer_list_temp[r] = issuer_key_pair.public_key.clone();
            }

            // Policy (Generated Data Required)
            let trusted_list = ih::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);
            group.bench_with_input(BenchmarkId::new("Verify_List", num), &num, |b, &_| {
                b.iter(|| {
                    let result = ih::verify_list(&pp, &trusted_list);
                    black_box(result);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 3: Presentation Generattion (Variation Based on Message Length, Open Attribute Count, Number of Issuers)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Presentation_Ops");
        // If you need to extend the sample time for more complex operations, you can set it here (e.g., 10 seconds).
        // group.measurement_time(std::time::Duration::from_secs(10));

        for &mlen in message_len.iter() {
            // Preparing Messages
            let mut message_fr_temp = Vec::new();
            for _ in 0..mlen {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);

            // Determining the Number of Attributes to Open
            let open_message_6 = mlen * 3 / 5;
            let mut open_message_len_temp: Vec<i32> = Vec::new();
            if open_message_6 == 3 {
                open_message_len_temp.extend_from_slice(&[3, (mlen as i32) - 3]);
            } else {
                open_message_len_temp.extend_from_slice(&[3, open_message_6 as i32, (mlen as i32) - 3]);
            }
            open_message_len_temp.sort();
            open_message_len_temp.dedup(); // Removing Duplicates (Just in Case)

            for &olen in open_message_len_temp.iter() {
                // Selecting Public Indices
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
                    
                    let trusted_list = ih::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);

                    // Creating a Parameter Identification String (e.g., "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &trusted_list, &open_temp);
                            black_box(pt);
                        });
                    });
                }
            }
        }
        group.finish();
    }
}

fn bobolz_pc_benchmark(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    let issuer_num = [5, 10, 50, 100, 500, 1000];
    let mut rng = thread_rng();
    let pp = ih::par_gen();

    c.bench_function("Issuer_Key_Gen", |b| {
        b.iter(|| {
            let issuer_key_pair = ih::issuer_key_gen(&pp);
            black_box(issuer_key_pair);
        });
    });

    c.bench_function("Verifier_Key_Gen", |b| {
        b.iter(|| {
            let verifier_key_pair = ih::verifier_key_gen(&pp);
            black_box(verifier_key_pair);
        });
    });

    let issuer_key_pair = ih::issuer_key_gen(&pp);
    let verifier_key_pair = ih::verifier_key_gen(&pp);

    // ------------------------------------------------------------------
    // Group 1: Basic Signature Generation (Variation Based on Message Length)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Basic_Credential_Ops");
        
        for &len in message_len.iter() {
            // Preparing Input Data
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
    // Group 2: Policy Generation (Variation Based on Number of Issuers)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Policy_Ops");

        for &num in issuer_num.iter() {
            // Preparing the List
            let mut issuer_list_temp = Vec::new();
            for _ in 0..num {
                let keypair = ih::issuer_key_gen(&pp);
                issuer_list_temp.push(keypair.public_key.clone());
            }
            // Inserting the Target at a Random Position
            let r = rng.gen_range(0..num);
            if r < issuer_list_temp.len() {
                 issuer_list_temp[r] = issuer_key_pair.public_key.clone();
            }

            // Set Policy
            group.bench_with_input(BenchmarkId::new("Set_Policy", num), &num, |b, &_| {
                b.iter(|| {
                    let pkp = ih::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);
                black_box(pkp);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 3: Presentation Verification (Variation Based on Message Length, Open Attribute Count, Number of Issuers)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Presentation_Ops");
        // If you need to extend the sample time for more complex operations, you can set it here (e.g., 10 seconds).
        // group.measurement_time(std::time::Duration::from_secs(10));

        for &mlen in message_len.iter() {
            // Preparing Messages
            let mut message_fr_temp = Vec::new();
            for _ in 0..mlen {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);

            // Determining the Number of Attributes to Open
            let open_message_6 = mlen * 3 / 5;
            let mut open_message_len_temp: Vec<i32> = Vec::new();
            if open_message_6 == 3 {
                open_message_len_temp.extend_from_slice(&[3, (mlen as i32) - 3]);
            } else {
                open_message_len_temp.extend_from_slice(&[3, open_message_6 as i32, (mlen as i32) - 3]);
            }
            open_message_len_temp.sort();
            open_message_len_temp.dedup(); // Removing Duplicates (Just in Case)

            for &olen in open_message_len_temp.iter() {
                // Selecting Public Indices
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

                    let trusted_list = ih::issue_list(&pp, &issuer_list_temp, &verifier_key_pair);

                    // Creating a Parameter Identification String (e.g., "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Verify Present Benchmark
                    // Generating this every time in the benchmark would be slow, so we generate it once outside the measurement.
                    let pt = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &trusted_list, &open_temp);
                    
                    group.bench_with_input(BenchmarkId::new("Verify_Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let result = ih::verify_present(&pp, &trusted_list, &pt);
                            black_box(result);
                        });
                    });
                }
            }
        }
        group.finish();
    }
}

criterion_group!(benches, bobolz_benchmark);
criterion_group!(mobile_benches, bobolz_mobile_benchmark);
criterion_group!(pc_benches, bobolz_pc_benchmark);
criterion_main!(benches);