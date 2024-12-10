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
    let message_len = 5;
    let open_message_len = 3;
    let issuer_num = 5;
    let pp = bobolz_rs_lib::bobolz::par_gen(&message_len);
    let pp_groth = bobolz_rs_lib::groth::par_gen();

    c.bench_function("Issuer Key Gen", |b| {
        b.iter(|| {
            let issuer_key_pair = bobolz_rs_lib::bobolz::issuer_key_gen(&pp);
            black_box(issuer_key_pair);
        });
    });

    c.bench_function("Verifier Key Gen", |b| {
        b.iter(|| {
            let verifier_key_pair = bobolz_rs_lib::bobolz::verifier_key_gen(&pp_groth);
            black_box(verifier_key_pair);
        });
    });

    let issuer_key_pair = bobolz_rs_lib::bobolz::issuer_key_gen(&pp);
    let mut message_fr = Vec::new();
    for _ in 0..message_len{
        message_fr.push(Fr::rand(&mut rng));
    }
    let verifier_key_pair = bobolz_rs_lib::bobolz::verifier_key_gen(&pp_groth);

    c.bench_function("Issuer Sign", |b|{
        b.iter(|| {
            let signature = bobolz_rs_lib::bobolz::issue(&pp, &issuer_key_pair.secret_key,&message_fr);
            black_box(signature);
        });
    });

    let cred = bobolz_rs_lib::bobolz::issue(&pp, &issuer_key_pair.secret_key,&message_fr);

    c.bench_function("Verify Credential", |b|{
        b.iter(|| {
            let result = bobolz_rs_lib::bobolz::verify(&pp, &cred, &message_fr, &issuer_key_pair.public_key);
            black_box(result);
        });
    });

    let mut issuer_list = Vec::new();
    for _ in 0..issuer_num{
        issuer_list.push(G2Affine::generator());
    }

    c.bench_function("verifier's trusted issuer list", |b|{
        let mut issuer_list_temp = issuer_list.clone();
        let r = rng.gen_range(1..issuer_num);
        issuer_list_temp[r] = issuer_key_pair.public_key.0;
        b.iter(|| {
            let trusted_issuer_credential = bobolz_rs_lib::bobolz::issue_list(&pp_groth, &issuer_list, &verifier_key_pair);
            black_box(trusted_issuer_credential);
        });
    });

    let r = rng.gen_range(1..issuer_num);
    issuer_list[r] = issuer_key_pair.public_key.0;let trusted_issuer_credential = bobolz_rs_lib::bobolz::issue_list(&pp_groth, &issuer_list, &verifier_key_pair);

    c.bench_function("verify verifier's trusted issuer list", |b|{
        b.iter(|| {
            let result = bobolz_rs_lib::bobolz::verify_list(&pp_groth, &trusted_issuer_credential);
            black_box(result);
        });
    });

    let mut open = Vec::new();
    for j in 0..open_message_len{
        let mut flg = true;
        let mut x = rng.gen_range(0..message_len) as usize;
        while flg {
            flg = false;
            for i in 0..j{
                if x == open[i as usize]{
                    flg = true;
                    x = rng.gen_range(0..message_len) as usize;
                    break;
                }
            }
        }
        open.push(x);
    }
    open.sort();

    c.bench_function("present", |b|{
        b.iter(|| {
            let pt = bobolz_rs_lib::bobolz::present(&pp, &cred, &issuer_key_pair.public_key, &message_fr, &trusted_issuer_credential, &open);
            black_box(pt);
        });
    });

    let pt = bobolz_rs_lib::bobolz::present(&pp, &cred, &issuer_key_pair.public_key, &message_fr, &trusted_issuer_credential, &open);

    c.bench_function("verify_present", |b|{
        b.iter(|| {
            let result = bobolz_rs_lib::bobolz::verify_present(&pp, &trusted_issuer_credential, &pt);
            black_box(result);
        });
    });



}

criterion_group!(benches, bobolz_benchmark);
criterion_main!(benches);