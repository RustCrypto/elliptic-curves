//! p256 `ProjectivePoint` benchmarks

#![allow(missing_docs, clippy::unwrap_used, reason = "benchmark")]

use core::hint::black_box;
use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::Measurement,
};
use hex_literal::hex;
use p256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        BatchNormalize, Group, PrimeField,
        ops::{LinearCombination, MulByGeneratorVartime, MulVartime},
        subtle::ConstantTimeEq,
    },
};

fn test_scalar_x() -> Scalar {
    Scalar::from_repr(
        hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464").into(),
    )
    .unwrap()
}

fn test_scalar_y() -> Scalar {
    Scalar::from_repr(
        hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464").into(),
    )
    .unwrap()
}

fn bench_point_add<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let a = AffinePoint::GENERATOR;
    group.bench_function("add", |b| b.iter(|| black_box(p) + black_box(p)));
    group.bench_function("add_mixed", |b| b.iter(|| black_box(p) + black_box(a)));
}

fn bench_point_lincomb<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let s = test_scalar_x();

    group.bench_function("lincomb (2-term, naive)", |b| b.iter(|| (p * s) + (p * s)));
    group.bench_function("lincomb (2-term)", |b| {
        b.iter(|| ProjectivePoint::lincomb(&[(p, s), (p, s)]));
    });
    group.bench_function("lincomb_vartime (2-term)", |b| {
        b.iter(|| ProjectivePoint::lincomb_vartime(&[(p, s), (p, s)]));
    });
}

fn bench_point_mul<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let s = test_scalar_x();
    group.bench_function("mul", |b| b.iter(|| black_box(p) * black_box(s)));
    group.bench_function("mul_vartime", |b| {
        b.iter(|| black_box(p).mul_vartime(&black_box(s)));
    });
}

fn bench_point_mul_by_generator<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("ProjectivePoint::GENERATOR * scalar", |b| {
        b.iter(|| ProjectivePoint::GENERATOR * black_box(x));
    });
    group.bench_function("mul_by_generator", |b| {
        b.iter(|| ProjectivePoint::mul_by_generator(&black_box(x)));
    });
    group.bench_function("mul_by_generator_vartime", |b| {
        b.iter(|| ProjectivePoint::mul_by_generator_vartime(&black_box(x)));
    });
    group.bench_function("mul_by_generator_and_mul_add_vartime", |b| {
        b.iter(|| {
            ProjectivePoint::mul_by_generator_and_mul_add_vartime(
                &black_box(x),
                &black_box(y),
                &black_box(ProjectivePoint::GENERATOR),
            )
        });
    });
}

fn bench_point_normalize<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let points = [p, p];
    group.bench_function("batch_normalize (2p)", |b| {
        b.iter(|| ProjectivePoint::batch_normalize(&black_box(points)));
    });
    group.bench_function("batch_normalize_vartime (2p)", |b| {
        b.iter(|| ProjectivePoint::batch_normalize_vartime(&black_box(points)));
    });
    group.bench_function("normalize (1p)", |b| b.iter(|| black_box(p).to_affine()));
}

fn bench_point(c: &mut Criterion) {
    let mut group = c.benchmark_group("ProjectivePoint operations");

    bench_point_add(&mut group);
    bench_point_lincomb(&mut group);
    bench_point_mul(&mut group);
    bench_point_mul_by_generator(&mut group);
    bench_point_normalize(&mut group);

    group.bench_function("ct_eq", |b| {
        b.iter(|| ProjectivePoint::GENERATOR.ct_eq(&ProjectivePoint::GENERATOR));
    });

    group.finish();
}

criterion_group!(benches, bench_point);
criterion_main!(benches);
