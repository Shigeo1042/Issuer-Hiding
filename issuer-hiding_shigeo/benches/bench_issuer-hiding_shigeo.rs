use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId}; // BenchmarkIdを追加
use std::hint::black_box;
use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Field;
use ark_std::{vec::Vec, UniformRand};
use ark_serialize::CanonicalSerialize;
use rand::{self, Rng, thread_rng};
pub type Fr = <Bls12_381 as Pairing>::ScalarField;
use issuer_hiding_shigeo::issuer_hiding as ih;
use mybbs::{bbs, issuer, verifier};

fn myih_benchmark_pc(c: &mut Criterion) {
    // let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    // let issuer_num = [5, 10, 50, 100, 500, 1000];
    let message_len = [50];
    let issuer_num = [5];
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
    // let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    // let issuer_num = [5, 10, 50, 100, 500, 1000];
    let message_len = [50];
    let issuer_num = [5];
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

fn my_benchmark_test(c: &mut Criterion) {
    // let message_len = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50];
    // let issuer_num = [5, 10, 50, 100, 500, 1000];
    let message_len = [50];
    let issuer_num = [5];
    let mut rng = thread_rng();
    let pp = ih::par_gen();

    let issuer_key_pair = ih::issuer_key_gen(&pp);
    let verifier_key_pair = ih::verifier_key_gen(&pp);

    // ------------------------------------------------------------------
    // Group 3: Presentation 生成 (複雑なパラメータ)
    // ------------------------------------------------------------------
    // ここはパラメータが3つ(mlen, olen, inum)あるため、BenchmarkIdの表示を工夫します。
    // まとめて1つのグループに入れることでディレクトリ構造を整理します。
    {
        let mut group = c.benchmark_group(" Test");
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
                    
                    let trusted_cred = ih::issue_list(&pp, &verifier_key_pair, &issuer_list_temp);

                    // パラメータ識別文字列を作成 (例: "m10_o3_i50")
                    let param_str = format!("m{}_o{}_i{}", mlen, olen, inum);

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("Present_setup", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = present_setup(&pp, &issuer_key_pair.public_key, &message_fr_temp, &trusted_cred);
                            black_box(pt);
                        });
                    });
                    let (h_generators, verifier_sig, message_len, r, r_inv, r_1, r_2, r_2_inv, r_3, r_3_inv) = present_setup(&pp, &issuer_key_pair.public_key, &message_fr_temp, &trusted_cred);

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("make_pikp1", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = make_pikp1(&pp, &cred_temp, &message_fr_temp, &open_temp, (h_generators.clone(), message_len, r, r_inv, r_1, r_2_inv));
                            let _ = black_box(pt);
                        });
                    });
                    let (open_messages, close_index, close_len, d_element, abar_pro, bbar_pro) = make_pikp1(&pp, &cred_temp, &message_fr_temp, &open_temp, (h_generators.clone(), message_len, r, r_inv, r_1, r_2_inv));

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("make_pikp2", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = make_pikp2(&pp, &issuer_key_pair.public_key, (verifier_sig.clone(), r, r_3_inv));
                            let _ = black_box(pt);
                        });
                    });
                    let (ipk_rand_pro, d2_pro, abar2_pro, bbar2_pro) = make_pikp2(&pp, &issuer_key_pair.public_key, (verifier_sig.clone(), r, r_3_inv));

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("make_u1u2", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = make_u1u2(d_element, abar_pro, &close_index, close_len, &h_generators.clone());
                            let _ = black_box(pt);
                        });
                    });
                    let (u1_pro, u2_element, alpha1, beta1, gamma1, delta1_vec) = make_u1u2(d_element, abar_pro, &close_index, close_len, &h_generators.clone());

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("make_u3u4", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = make_u3u4(&pp, d2_pro, abar2_pro);
                            let _ = black_box(pt);
                        });
                    });
                    let (u3_pro, u4_pro, alpha2, beta2, gamma2) = make_u3u4(&pp, d2_pro, abar2_pro, );

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("calc_c", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = calc_c(h_generators.clone(), (abar_pro, bbar_pro, d_element, u1_pro, u2_element), (ipk_rand_pro, abar2_pro, bbar2_pro, d2_pro, u3_pro, u4_pro), open_messages.clone());
                            black_box(pt);
                        });
                    });
                    let c = calc_c(h_generators.clone(), (abar_pro, bbar_pro, d_element, u1_pro, u2_element), (ipk_rand_pro, abar2_pro, bbar2_pro, d2_pro, u3_pro, u4_pro), open_messages.clone());

                    // Present Benchmark
                    group.bench_with_input(BenchmarkId::new("make_pizkp", &param_str), &param_str, |b, _| {
                        b.iter(|| {
                            let pt = make_pizkp((c, alpha1, alpha2, beta1, beta2, gamma1, gamma2, delta1_vec.clone(), r, r_1, r_2, r_3), &cred_temp, &verifier_sig, &open_messages.clone(), &close_index, close_len);
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
    pp: &bbs::PublicParameters, 
    ipk: &issuer::PublicKey, 
    message_list: &Vec<Fr>, 
    (_, list): &(verifier::PublicKey, Vec<ih::TrustedIssuerCredential>)
) -> (Vec<G1Affine>, verifier::Signature, usize, Fr, Fr, Fr, Fr, Fr, Fr, Fr){
    let message_len = message_list.len();

    let mut rng = thread_rng();
    let h_generators : Vec<G1Affine> = pp.h_vec[0..message_len].to_vec();
    
    let list_len = list.len();
    let mut verifier_sig = list[0].cred.clone();
    for i in 0..list_len{
        if list[i].ipk == *ipk{
            verifier_sig = list[i].cred.clone();
        }
    }

    let r = Fr::rand(&mut rng);
    let r_inv = r.inverse().unwrap();
    let r_1 = Fr::rand(&mut rng);
    let r_2 = Fr::rand(&mut rng);
    let r_2_inv = r_2.inverse().unwrap();
    let r_3 = Fr::rand(&mut rng);
    let r_3_inv = r_3.inverse().unwrap();
    return (h_generators, verifier_sig, message_len, r, r_inv, r_1, r_2, r_2_inv, r_3, r_3_inv);
}

fn make_pikp1(
    pp: &bbs::PublicParameters, 
    cred: &issuer::Signature, 
    message_list: &Vec<Fr>, 
    reveal_index: &Vec<usize>,
    (h_generators, message_len, r, r_inv, r_1, r_2_inv): (Vec<G1Affine>, usize, Fr, Fr, Fr, Fr)
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
    let abar_pro = cred.a * (r_1 * r_2_inv * r_inv);
    let bbar_pro = (d_element * r_1) + (abar_pro * (-cred.e * r));
    return (open_messages, close_index, close_len, d_element, abar_pro, bbar_pro);
}

fn make_pikp2(
    pp: &bbs::PublicParameters, 
    ipk: &issuer::PublicKey, 
    (verifier_sig, r, r_3_inv): (verifier::Signature, Fr, Fr)
) -> (G2Projective, G2Projective, G2Projective, G2Projective){
    let ipk_rand_pro = ipk.0 * r;
    let d2_pro = (pp.gbar2 + ipk.0) * r_3_inv;
    let abar2_pro = verifier_sig.a * (r * r_3_inv);
    let bbar2_pro = (d2_pro * r) + (abar2_pro * (-verifier_sig.e));
    return (ipk_rand_pro, d2_pro, abar2_pro, bbar2_pro);
}

fn make_u1u2(
    d_element: G1Projective,
    abar_pro: G1Projective,
    close_index: &Vec<usize>,
    close_len: usize,
    h_generators: &Vec<G1Affine>
) -> (G1Projective, G1Projective, Fr, Fr, Fr, Vec<Fr>){
    let mut rng = thread_rng();

    let alpha1 = Fr::rand(&mut rng);
    let beta1 = Fr::rand(&mut rng);
    let gamma1 = Fr::rand(&mut rng);
    let delta1_vec = (0..close_len).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();
    let u1 = (d_element * alpha1) + (abar_pro * beta1);
    let mut u2_element = d_element * gamma1;
    for i in 0..close_len{
        u2_element += h_generators[close_index[i]] * delta1_vec[i];
    }
    return (u1, u2_element, alpha1, beta1, gamma1, delta1_vec);
}

fn make_u3u4(
    pp: &bbs::PublicParameters, 
    d2_pro: G2Projective,
    abar2_pro: G2Projective,
) -> (G2Projective, G2Projective, Fr, Fr, Fr){
    let mut rng = thread_rng();

    let alpha2 = Fr::rand(&mut rng);
    let beta2 = Fr::rand(&mut rng);
    let gamma2 = Fr::rand(&mut rng);
    let u3 = (d2_pro * alpha2) + (abar2_pro * beta2);
    let u4 = (d2_pro * gamma2) + (pp.gbar2 * (-alpha2));
    return (u3, u4, alpha2, beta2, gamma2);
}

fn calc_c(
    h_generators: Vec<G1Affine>,
    (abar_pro, bbar_pro, d_element, u1_pro, u2_element): (G1Projective, G1Projective, G1Projective, G1Projective, G1Projective),
    (ipk_rand, abar2_pro, bbar2_pro, d2_pro, u3_pro, u4_pro): (G2Projective, G2Projective, G2Projective, G2Projective, G2Projective, G2Projective),
    open_messages: Vec<Fr>,
) -> Fr{
    let dst = b"MY_CHALLENGE_GENERATOR_DST_Issuer_Hiding_V1";
    let c_inputs1_pro = vec![
        abar_pro,
        bbar_pro,//bbar1
        d_element,
        u1_pro,//u1
        u2_element,
    ];
    let c_inputs1 = G1Projective::normalize_batch(&c_inputs1_pro);
    let c_input2_pro = vec![
        ipk_rand,//ipk_rand
        abar2_pro,
        bbar2_pro,//bbar2
        d2_pro,
        u3_pro,//u3
        u4_pro,//u4
    ];
    let c_input2 = G2Projective::normalize_batch(&c_input2_pro);
    let mut c_inputs_buffer = Vec::new();
    for h_i in &h_generators{
        h_i.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for c_input in &c_inputs1{
        c_input.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for c_input in &c_input2{
        c_input.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }
    for open_msg in &open_messages{
        open_msg.serialize_compressed(&mut c_inputs_buffer).unwrap();
    }

    let c = bbs::hash_to_fr(&c_inputs_buffer[..], dst);
    return c;
}

fn make_pizkp(
    (c, alpha1, alpha2, beta1, beta2, gamma1, gamma2, delta1_vec, r, r_1, r_2, r_3): (Fr, Fr, Fr, Fr, Fr, Fr, Fr, Vec<Fr>, Fr, Fr, Fr, Fr),
    cred: &issuer::Signature,
    verifier_sig: &verifier::Signature,
    message_list: &Vec<Fr>,
    close_index: &Vec<usize>,
    close_len: usize,
) -> ih::PiZKP{
    let s1 = alpha1 + c * r_1;
    let s2 = alpha2 + c * r;
    let t1 = beta1 - c * (cred.e * r);
    let t2 = beta2 - c * (verifier_sig.e);
    let z1 = gamma1 + c * r_2;
    let z2 = gamma2 + c * r * r_3;
    let mut v1_vec: Vec<Fr> = Vec::new();
    for i in 0..close_len{
        let v1 = delta1_vec[i] - c * message_list[close_index[i]];
        v1_vec.push(v1);
    }
    let pizkp = ih::PiZKP{
        s1: s1,
        s2: s2,
        t1: t1,
        t2: t2,
        z1: z1,
        z2: z2,
        v1: v1_vec,
        c: c,
    };
    return pizkp;
}

criterion_group!(benches, myih_benchmark_pc, myih_benchmark_android);
criterion_group!(test_bench, my_benchmark_test);
criterion_main!(benches);