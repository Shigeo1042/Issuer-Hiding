use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::hint::black_box;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;

use ark_bls12_381_bench::calc as calc;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

fn ark_bls12_381_bench(c: &mut Criterion){
    let mut group = c.benchmark_group("ark_bls12_381_bench");

    group.bench_function(BenchmarkId::new("fr_rand", ""), |b| {
        b.iter(|| {
            calc::fr_rand();
        })
    });

    group.bench_function(BenchmarkId::new("g1_rand", ""), |b| {
        b.iter(|| {
            calc::g1_rand();
        })
    });

    group.bench_function(BenchmarkId::new("g2_rand", ""), |b| {
        b.iter(|| {
            calc::g2_rand();
        })
    });

    let vec_fr = calc::fr_rand_return();
    let vec_g1 = calc::g1_rand_return();
    let vec_g2 = calc::g2_rand_return();

    group.bench_function(BenchmarkId::new("add_fr", ""), |b| {
        b.iter(|| {
            calc::add_fr(black_box(&vec_fr), black_box(&vec_fr));
        })
    });

    group.bench_function(BenchmarkId::new("add_g1", ""), |b| {
        b.iter(|| {
            calc::add_g1(black_box(&vec_g1), black_box(&vec_g1));
        })
    });

    group.bench_function(BenchmarkId::new("add_g2", ""), |b| {
        b.iter(|| {
            calc::add_g2(black_box(&vec_g2), black_box(&vec_g2));
        })
    });

    group.bench_function(BenchmarkId::new("mul_fr", ""), |b| {
        b.iter(|| {
            calc::mul_fr(black_box(&vec_fr), black_box(&vec_fr));
        })
    });

    group.bench_function(BenchmarkId::new("mul_g1", ""), |b| {
        b.iter(|| {
            calc::mul_g1(black_box(&vec_g1), black_box(&vec_fr));
        })
    });

    group.bench_function(BenchmarkId::new("mul_g2", ""), |b| {
        b.iter(|| {
            calc::mul_g2(black_box(&vec_g2), black_box(&vec_fr));
        })
    });

    group.bench_function(BenchmarkId::new("pairing_op", ""), |b| {
        b.iter(|| {
            calc::pairing_op_return(black_box(&vec_g1), black_box(&vec_g2));
        })
    });

    let vec_pairing = calc::pairing_op_return(&vec_g1, &vec_g2);

    group.bench_function(BenchmarkId::new("add_pairing", ""), |b| {
        b.iter(|| {
            calc::add_pairing(black_box(&vec_pairing), black_box(&vec_pairing));
        })
    });

    group.bench_function(BenchmarkId::new("mul_pairing", ""), |b| {
        b.iter(|| {
            calc::mul_pairing(black_box(&vec_pairing), black_box(&vec_fr));
        })
    });

    group.finish();
}

criterion_group!(benches, ark_bls12_381_bench);
criterion_main!(benches);