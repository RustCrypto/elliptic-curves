//! k256 `ProjectivePoint` benchmarks

use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::Measurement,
};
use k256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        BatchNormalize, PrimeField,
        ops::{LinearCombination, MulByGeneratorVartime, MulVartime},
        subtle::ConstantTimeEq,
    },
};
use std::hint::black_box;

fn test_scalar_x() -> Scalar {
    Scalar::from_repr(
        [
            0xbb, 0x48, 0x8a, 0xef, 0x41, 0x6a, 0x41, 0xd7, 0x68, 0x0d, 0x1c, 0xf0, 0x1d, 0x70,
            0xf5, 0x9b, 0x60, 0xd7, 0xf5, 0xf7, 0x7e, 0x30, 0xe7, 0x8b, 0x8b, 0xf9, 0xd2, 0xd8,
            0x82, 0xf1, 0x56, 0xa6,
        ]
        .into(),
    )
    .unwrap()
}

fn test_scalar_y() -> Scalar {
    Scalar::from_repr(
        [
            0x67, 0xe2, 0xf6, 0x80, 0x71, 0xed, 0x82, 0x81, 0xe8, 0xae, 0xd6, 0xbc, 0xf1, 0xc5,
            0x20, 0x7c, 0x5e, 0x63, 0x37, 0x22, 0xd9, 0x20, 0xaf, 0xd6, 0xae, 0x22, 0xd0, 0x6e,
            0xeb, 0x80, 0x35, 0xe3,
        ]
        .into(),
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
        b.iter(|| ProjectivePoint::lincomb(&[(p, s), (p, s)]))
    });
    group.bench_function("lincomb_vartime (2-term)", |b| {
        b.iter(|| ProjectivePoint::lincomb_vartime(&[(p, s), (p, s)]))
    });
}

fn bench_point_mul<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let s = test_scalar_x();
    group.bench_function("mul", |b| b.iter(|| black_box(p) * black_box(s)));
    group.bench_function("mul_vartime", |b| {
        b.iter(|| black_box(p).mul_vartime(&black_box(s)))
    });
}

fn bench_point_mul_by_generator<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("ProjectivePoint::GENERATOR * scalar", |b| {
        b.iter(|| ProjectivePoint::GENERATOR * &black_box(x))
    });
    group.bench_function("mul_by_generator", |b| {
        b.iter(|| ProjectivePoint::mul_by_generator(&black_box(x)))
    });
    group.bench_function("mul_by_generator_vartime", |b| {
        b.iter(|| ProjectivePoint::mul_by_generator_vartime(&black_box(x)))
    });
    group.bench_function("mul_by_generator_and_mul_add_vartime", |b| {
        b.iter(|| {
            ProjectivePoint::mul_by_generator_and_mul_add_vartime(
                &black_box(x),
                &black_box(y),
                &black_box(ProjectivePoint::GENERATOR),
            )
        })
    });
}

fn bench_point_normalize<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let points = [p, p];
    group.bench_function("batch_normalize (2p)", |b| {
        b.iter(|| ProjectivePoint::batch_normalize(&black_box(points)))
    });
    group.bench_function("batch_normalize_vartime (2p)", |b| {
        b.iter(|| ProjectivePoint::batch_normalize_vartime(&black_box(points)))
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
        b.iter(|| ProjectivePoint::GENERATOR.ct_eq(&ProjectivePoint::GENERATOR))
    });

    group.finish();
}

criterion_group!(benches, bench_point);
criterion_main!(benches);
