//! p256 `ProjectivePoint` benchmarks

use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::Measurement,
};
use hex_literal::hex;
use p256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{
        Group, PrimeField,
        ops::{LinearCombination, MulByGeneratorVartime, MulVartime},
    },
};
use primefield::subtle::ConstantTimeEq;
use std::hint::black_box;

fn test_scalar() -> Scalar {
    Scalar::from_repr(
        hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464").into(),
    )
    .unwrap()
}

fn bench_point_lincomb<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let s = test_scalar();

    group.bench_function("point-scalar lincomb", |b| {
        b.iter(|| ProjectivePoint::lincomb(&[(p, s), (p, s), (p, s)]))
    });
    group.bench_function("point-scalar lincomb (variable-time)", |b| {
        b.iter(|| ProjectivePoint::lincomb_vartime(&[(p, s), (p, s), (p, s)]))
    });
}

fn bench_point_mul<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let s = test_scalar();
    group.bench_function("point-scalar mul", |b| {
        b.iter(|| black_box(p) * black_box(s))
    });
    group.bench_function("point-scalar mul (variable-time)", |b| {
        b.iter(|| black_box(p).mul_vartime(&black_box(s)))
    });
}

fn bench_point_mul_by_generator<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let m = test_scalar();
    let s = Scalar::from_repr(m.into()).unwrap();
    group.bench_function("generator-scalar mul", |b| {
        b.iter(|| ProjectivePoint::mul_by_generator(&black_box(s)))
    });
    group.bench_function("generator-scalar mul (variable-time)", |b| {
        b.iter(|| ProjectivePoint::mul_by_generator_vartime(&black_box(s)))
    });
}

fn bench_point(c: &mut Criterion) {
    let mut group = c.benchmark_group("ProjectivePoint operations");

    bench_point_lincomb(&mut group);
    bench_point_mul(&mut group);
    bench_point_mul_by_generator(&mut group);

    group.bench_function("ct_eq", |b| {
        b.iter(|| ProjectivePoint::GENERATOR.ct_eq(&ProjectivePoint::GENERATOR))
    });

    group.finish();
}

criterion_group!(benches, bench_point);
criterion_main!(benches);
