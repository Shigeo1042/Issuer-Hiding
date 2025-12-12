use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::hint::black_box;
use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Field;
use ark_std::{vec::Vec, UniformRand};
use ark_serialize::CanonicalSerialize;
use rand::{self, Rng, thread_rng};
pub type Fr = <Bls12_381 as Pairing>::ScalarField;
use issuer_hiding_katz::issuer_hiding as ih;
use mybbs::{bbs, issuer};

fn katz_ih_benchmark_pc(c: &mut Criterion) {
    let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    let issuer_num = [5, 10, 50, 100, 500, 1000];
    let mut rng = thread_rng();
    let pp = ih::par_gen();

    let issuer_key_pair = ih::issuer_key_gen(&pp);

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
    // Group 2: Policy の発行 (Issuer数による変化)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Policy_Ops");

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

                    let policy_key_pair = ih::set_policy(&pp, &issuer_list_temp);
                    let policy_pk = &policy_key_pair.public_key;

                    // パラメータ識別文字列を作成 (例: "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Verify Present Benchmark
                    // ベンチマーク内で毎回生成すると遅いので、計測外で一度生成
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
    // Group 2: Policy の検証 (Issuer数による変化)
    // ------------------------------------------------------------------
    {
        let mut group = c.benchmark_group("Policy_Ops");

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

            // Policy (生成済みデータが必要)
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
                    
                    let policy_key_pair = ih::set_policy(&pp, &issuer_list_temp);
                    let policy_pk = &policy_key_pair.public_key;

                    // パラメータ識別文字列を作成 (例: "m10_o3_i50")
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



fn katz_test(c: &mut Criterion) {
    // let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    // let issuer_num = [5, 10, 50, 100, 500, 1000];
    let message_len = [50];
    let issuer_num = [5];
    let mut rng = thread_rng();
    let pp = ih::par_gen();

    let issuer_key_pair = ih::issuer_key_gen(&pp);

    {
        let mut group = c.benchmark_group("Test");
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
            open_message_len_temp.extend_from_slice(&[3, open_message_6 as i32, (mlen as i32) - 3]);
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
                    
                    let policy_key_pair = ih::set_policy(&pp, &issuer_list_temp);
                    let policy_pk = &policy_key_pair.public_key;

                    // パラメータ識別文字列を作成 (例: "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("Present_setup", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = present_setup(&pp, &issuer_key_pair.public_key, &message_fr_temp, &policy_pk);
                            let _ = black_box(pt);
                        });
                    });
                    let (h_generators, _, r_1, r_2, r_2_inv, r) = present_setup(&pp, &issuer_key_pair.public_key, &message_fr_temp, &policy_pk);
                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("make_pikp1", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = make_pikp1(&pp, &cred_temp, &message_fr_temp, &open_temp, (h_generators.clone(), mlen, r, r_1, r_2_inv));
                            let _ = black_box(pt);
                        });
                    });
                    let (open_messages, close_index, close_len, d_element, abar_pro, bbar_pro) = make_pikp1(&pp, &cred_temp, &message_fr_temp, &open_temp, (h_generators.clone(), mlen, r, r_1, r_2_inv));
                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("make_u1u2", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = make_u1u2(d_element, abar_pro, &close_index, close_len, &h_generators.clone());
                            let _ = black_box(pt);
                        });
                    });
                    let (u1_pro, u2_element, alpha, beta, gamma, delta_vec) = make_u1u2(d_element, abar_pro, &close_index, close_len, &h_generators.clone());

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("calc_c", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = calc_c(h_generators.clone(), (abar_pro, bbar_pro, d_element, u1_pro, u2_element), open_messages.clone());
                            black_box(pt);
                        });
                    });
                    let c = calc_c(h_generators.clone(), (abar_pro, bbar_pro, d_element, u1_pro, u2_element), open_messages.clone());

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("make_pizkp", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = make_pizkp((c, alpha, beta, gamma, delta_vec.clone(), r, r_1, r_2), &cred_temp, &open_messages.clone(), &close_index, close_len);
                            black_box(pt);
                        });
                    });
                }
            }
        }
        group.finish();
    }
}

fn present_setup(
    pp: &issuer::PublicParameters, 
    ipk: &issuer::PublicKey, 
    message_list: &Vec<Fr>, 
    ppk: &ih::PolicyPublicKey
) -> (Vec<G1Affine>, G2Affine, Fr, Fr, Fr, Fr){
    let message_len = message_list.len();
    let (ipks, s,t_vec) = (ppk.ipks.clone(), ppk.s, ppk.t.clone());

    let mut rng = thread_rng();
    let h_generators : Vec<G1Affine> = pp.h_vec[0..message_len].to_vec();
    let r = Fr::rand(&mut rng);
    
    let ipks_len = ipks.len();
    let mut sigma_tilde_element = s * r;
    for i in 0..ipks_len{
        if ipks[i] != *ipk{
            sigma_tilde_element += t_vec[i];
        }
    }
    let sigma_tilde = G2Affine::from(sigma_tilde_element);

    let r_1 = Fr::rand(&mut rng);
    let r_2 = Fr::rand(&mut rng);
    let r_2_inv = r_2.inverse().unwrap();
    return (h_generators, sigma_tilde, r_1, r_2, r_2_inv, r);
}

fn make_pikp1(
    pp: &issuer::PublicParameters, 
    cred: &issuer::Signature, 
    message_list: &Vec<Fr>, 
    reveal_index: &Vec<usize>,
    (h_generators, message_len, r, r_1, r_2_inv): (Vec<G1Affine>, usize, Fr, Fr, Fr)
) -> (Vec<Fr>, Vec<usize>, usize, G1Projective, G1Projective, G1Projective){
    let mut d_element = G1Projective::from(pp.g1);
    let mut open_messages: Vec<Fr> = Vec::new();
    let mut close_index: Vec<usize> = Vec::new();
    for i in 0..message_len{
        d_element += h_generators[i] * message_list[i];
        if reveal_index.contains(&i){
            open_messages.push(message_list[i]);
        } else {
            close_index.push(i);
        }
    }
    d_element *= r_2_inv;
    let close_len = close_index.len();
    let abar_pro = cred.a * (r_1 * r_2_inv);
    let bbar_pro = (d_element * r_1) + (abar_pro * (-cred.e - r));
    return (open_messages, close_index, close_len, d_element, abar_pro, bbar_pro);
}

fn make_u1u2(
    d_element: G1Projective,
    abar_pro: G1Projective,
    close_index: &Vec<usize>,
    close_len: usize,
    h_generators: &Vec<G1Affine>
) -> (G1Projective, G1Projective, Fr, Fr, Fr, Vec<Fr>){
    let mut rng = thread_rng();

    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let delta_vec = (0..close_len).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();

    let u1_pro = (d_element * alpha) + (abar_pro * beta);
    let mut u2_element = d_element * gamma;
    for i in 0..close_len{
        u2_element += h_generators[close_index[i]] * delta_vec[i];
    }
    return (u1_pro, u2_element, alpha, beta, gamma, delta_vec);
}

fn calc_c(
    h_generators: Vec<G1Affine>,
    (abar_pro, bbar_pro, d_element, u1_pro, u2_element): (G1Projective, G1Projective, G1Projective, G1Projective, G1Projective),
    open_messages: Vec<Fr>,
) -> Fr{
    let dst = b"MY_CHALLENGE_GENERATOR_DST_Issuer_Hiding_V1";
    let c_inputs1_pro =vec![
        abar_pro,
        bbar_pro,
        d_element,
        u1_pro,
        u2_element,
    ];
    let c_inputs1 = G1Projective::normalize_batch(&c_inputs1_pro);
    let mut c_inputs_buffer = Vec::new();
    for h in h_generators{
        h.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for m in &open_messages{
        m.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for c_input in &c_inputs1{
        c_input.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }

    let c = bbs::hash_to_fr(&c_inputs_buffer[..], dst);
    return c;
}

fn make_pizkp(
    (c, alpha, beta, gamma, delta_vec, r, r_1, r_2): (Fr, Fr, Fr, Fr, Vec<Fr>, Fr, Fr, Fr),
    cred: &issuer::Signature,
    message_list: &Vec<Fr>,
    close_index: &Vec<usize>,
    close_len: usize,
) -> ih::PiZKP{
    let s = alpha + c * r_1;
    let t = beta - c * (cred.e + r);
    let z = gamma + c * r_2;
    let mut v_vec: Vec<Fr> = Vec::new();
    for i in 0..close_len{
        let v1 = delta_vec[i] - c * message_list[close_index[i]];
        v_vec.push(v1);
    }
    let pizkp = ih::PiZKP{
        c: c,
        s: s,
        t: t,
        z: z,
        v: v_vec,
    };
    return pizkp;
}

criterion_group!(benches, katz_ih_benchmark_pc, katz_ih_benchmark_android);
criterion_group!(test_bench, katz_test);
criterion_main!(benches);