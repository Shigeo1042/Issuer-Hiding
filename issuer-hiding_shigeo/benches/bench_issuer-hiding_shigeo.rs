use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId}; // BenchmarkIdを追加
use std::hint::black_box;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{vec::Vec, UniformRand};
use rand::{self, Rng, thread_rng};
pub type Fr = <Bls12_381 as Pairing>::ScalarField;
use issuer_hiding_shigeo::issuer_hiding as ih;

fn myih_benchmark_pc(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    let issuer_num = [5, 10, 50, 100, 500, 1000];
    let mut rng = thread_rng();
    let pp = ih::par_gen();

    let issuer_key_pair = ih::issuer_key_gen(&pp);
    let verifier_key_pair = ih::verifier_key_gen(&pp);

    // ------------------------------------------------------------------
    // Group 1: 基本的な署名の生成 (メッセージ長による変化)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Basic_Credential_Ops");
        
        for &len in message_len.iter() {
            // 入力データの準備
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
    // Group 2: Trusted List の発行 (Issuer数による変化)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Trusted_List_Ops");

        for &num in issuer_num.iter() {
            // リストの準備
            let mut issuer_list_temp = Vec::new();
            for _ in 0..num {
                let keypair = ih::issuer_key_gen(&pp);
                issuer_list_temp.push(keypair.public_key.clone());
            }
            // ランダムな位置にターゲットを挿入
            let r = rng.gen_range(0..num);
            if r < issuer_list_temp.len() {
                 issuer_list_temp[r] = issuer_key_pair.public_key.clone();
            }

            // Issue List
            group.bench_with_input(BenchmarkId::new("Issue_List", num), &num, |b, &_| {
                b.iter(|| {
                    let trusted_issuer_credential = ih::issue_list(&pp, &verifier_key_pair, &issuer_list_temp);
                    black_box(trusted_issuer_credential);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 3: Presentation検証 (複雑なパラメータ)
    // ------------------------------------------------------------------
    // ここはパラメータが3つ(mlen, olen, inum)あるため、BenchmarkIdの表示を工夫します。
    // まとめて1つのグループに入れることでディレクトリ構造を整理します。
    {
        let mut group = c.benchmark_group("Presentation_Ops");
        // サンプル時間を少し伸ばす必要がある場合はここで設定（例: 10秒）
        // group.measurement_time(std::time::Duration::from_secs(10));

        for &mlen in message_len.iter() {
            // メッセージ準備
            let mut message_fr_temp = Vec::new();
            for _ in 0..mlen {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);

            // 公開する属性の数を決定
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
                // 公開インデックスの選択
                let mut open_temp = Vec::new();
                while open_temp.len() < olen as usize {
                    let x = rng.gen_range(0..mlen);
                    if !open_temp.contains(&x) {
                        open_temp.push(x);
                    }
                }
                open_temp.sort();

                for &inum in issuer_num.iter() {
                    // Issuerリスト準備
                    let mut issuer_list_temp = Vec::new();
                    for _ in 0..inum {
                        let kp = ih::issuer_key_gen(&pp);
                        issuer_list_temp.push(kp.public_key.clone());
                    }
                    let r = rng.gen_range(0..inum);
                    issuer_list_temp[r] = issuer_key_pair.public_key.clone();
                    
                    let trusted_cred = ih::issue_list(&pp, &verifier_key_pair, &issuer_list_temp);

                    // パラメータ識別文字列を作成 (例: "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Verify Present Benchmark
                    // ベンチマーク内で毎回生成すると遅いので、計測外で一度生成
                    let (pikp, pizkp) = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &open_temp, &trusted_cred);
                    
                    group.bench_with_input(BenchmarkId::new("Verify_Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let result = ih::verify_present(&pp, &trusted_cred, &pikp, &pizkp);
                            black_box(result);
                        });
                    });
                }
            }
        }
        group.finish();
    }
}

fn myih_benchmark_android(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    let issuer_num = [5, 10, 50, 100, 500, 1000];
    let mut rng = thread_rng();
    let pp = ih::par_gen();

    let issuer_key_pair = ih::issuer_key_gen(&pp);
    let verifier_key_pair = ih::verifier_key_gen(&pp);

    // ------------------------------------------------------------------
    // Group 1: 基本的な署名の検証 (メッセージ長による変化)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Basic_Credential_Ops");
        
        for &len in message_len.iter() {
            // 入力データの準備
            let mut message_fr_temp = Vec::new();
            for _ in 0..len {
                message_fr_temp.push(Fr::rand(&mut rng));
            }

            // Verify Credential (署名生成済みデータが必要)
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
    // Group 2: Trusted List の検証 (Issuer数による変化)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Trusted_List_Ops");

        for &num in issuer_num.iter() {
            // リストの準備
            let mut issuer_list_temp = Vec::new();
            for _ in 0..num {
                let keypair = ih::issuer_key_gen(&pp);
                issuer_list_temp.push(keypair.public_key.clone());
            }
            // ランダムな位置にターゲットを挿入
            let r = rng.gen_range(0..num); // gen_range(1..num)だとnum=5のときindex 0が選ばれない可能性があるため修正考慮(元ロジック尊重なら戻してください)
            if r < issuer_list_temp.len() {
                 issuer_list_temp[r] = issuer_key_pair.public_key.clone();
            }

            // Verify List (生成済みデータが必要)
            let trusted_issuer_credential = ih::issue_list(&pp, &verifier_key_pair, &issuer_list_temp);
            group.bench_with_input(BenchmarkId::new("Verify_List", num), &num, |b, &_| {
                b.iter(|| {
                    let result = ih::verify_list(&pp, &trusted_issuer_credential);
                    black_box(result);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 3: Presentation 生成 (複雑なパラメータ)
    // ------------------------------------------------------------------
    // ここはパラメータが3つ(mlen, olen, inum)あるため、BenchmarkIdの表示を工夫します。
    // まとめて1つのグループに入れることでディレクトリ構造を整理します。
    {
        let mut group = c.benchmark_group("Presentation_Ops");
        // サンプル時間を少し伸ばす必要がある場合はここで設定（例: 10秒）
        // group.measurement_time(std::time::Duration::from_secs(10));

        for &mlen in message_len.iter() {
            // メッセージ準備
            let mut message_fr_temp = Vec::new();
            for _ in 0..mlen {
                message_fr_temp.push(Fr::rand(&mut rng));
            }
            let cred_temp = ih::issue(&pp, &issuer_key_pair.secret_key, &message_fr_temp);

            // 公開する属性の数を決定
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
                // 公開インデックスの選択
                let mut open_temp = Vec::new();
                while open_temp.len() < olen as usize {
                    let x = rng.gen_range(0..mlen);
                    if !open_temp.contains(&x) {
                        open_temp.push(x);
                    }
                }
                open_temp.sort();

                for &inum in issuer_num.iter() {
                    // Issuerリスト準備
                    let mut issuer_list_temp = Vec::new();
                    for _ in 0..inum {
                        let kp = ih::issuer_key_gen(&pp);
                        issuer_list_temp.push(kp.public_key.clone());
                    }
                    let r = rng.gen_range(0..inum);
                    issuer_list_temp[r] = issuer_key_pair.public_key.clone();
                    
                    let trusted_cred = ih::issue_list(&pp, &verifier_key_pair, &issuer_list_temp);

                    // パラメータ識別文字列を作成 (例: "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("Present", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = ih::present(&pp, &cred_temp, &issuer_key_pair.public_key, &message_fr_temp, &open_temp, &trusted_cred);
                            black_box(pt);
                        });
                    });
                }
            }
        }
        group.finish();
    }
}

criterion_group!(benches, myih_benchmark_pc, myih_benchmark_android);
criterion_main!(benches);