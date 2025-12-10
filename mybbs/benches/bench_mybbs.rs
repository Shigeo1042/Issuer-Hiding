use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId}; // BenchmarkIdを追加
use std::hint::black_box;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{vec::Vec, UniformRand};
use rand::{self, Rng, thread_rng};
pub type Fr = <Bls12_381 as Pairing>::ScalarField;
use mybbs::issuer as issuer;
use mybbs::proof as proof;

fn mybbs_benchmark_pc(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    let mut rng = thread_rng();
    let pp = issuer::par_gen();
    let issuer_key_pair = issuer::key_gen(&pp);
    let isk = &issuer_key_pair.secret_key;
    let ipk = &issuer_key_pair.public_key;

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
                    let signature = issuer::sign(&pp, isk, &message_fr_temp);
                    black_box(signature);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 2: Proof検証 (複雑なパラメータ)
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
            let cred_temp = issuer::sign(&pp, &issuer_key_pair.secret_key, &message_fr_temp);

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

                // パラメータ識別文字列を作成 (例: "m10_o3")
                let param_str = format!("m{}_o{}", mlen, olen);

                // Verify Proof Benchmark
                // ベンチマーク内で毎回生成すると遅いので、計測外で一度生成
                let (pikp, pizkp) = proof::prove(&pp, &cred_temp,  &message_fr_temp, &open_temp);
                    
                group.bench_with_input(BenchmarkId::new("Verify_Proof", &param_str), &param_str, |b, _| {
                    b.iter(|| {
                        let result = proof::verify_proof(&pp, &ipk, &pikp, &pizkp);
                        black_box(result);
                    });
                });
            }
        }
        group.finish();
    }
}

fn mybbs_benchmark_android(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 40, 50];
    let mut rng = thread_rng();
    let pp = issuer::par_gen();
    let issuer_key_pair = issuer::key_gen(&pp);
    let isk = &issuer_key_pair.secret_key;
    let ipk = &issuer_key_pair.public_key;

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
            let cred_temp = issuer::sign(&pp, isk, &message_fr_temp);
            group.bench_with_input(BenchmarkId::new("Verify", len), &len, |b, &_| {
                b.iter(|| {
                    let result = issuer::verify(&pp, ipk, &message_fr_temp, &cred_temp);
                    black_box(result);
                });
            });
        }
        group.finish();
    }

    // ------------------------------------------------------------------
    // Group 3: Proof 生成 (複雑なパラメータ)
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
            let cred_temp = issuer::sign(&pp, isk, &message_fr_temp);

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

                // パラメータ識別文字列を作成 (例: "m10_o3")
                let param_str = format!("m{}_o{}", mlen, olen);

                // Present Benchmark
                group.bench_with_input(BenchmarkId::new("Proof", &param_str), &param_str, |b, _| {
                    b.iter(|| {
                        let pt = proof::prove(&pp, &cred_temp, &message_fr_temp, &open_temp);
                        black_box(pt);
                    });
                });
            }
        }
        group.finish();
    }
}

criterion_group!(benches, mybbs_benchmark_pc, mybbs_benchmark_android);
criterion_main!(benches);