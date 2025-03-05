//! secp256k1 scalar arithmetic benchmarks

use criterion::{
    BenchmarkGroup, Criterion, black_box, criterion_group, criterion_main, measurement::Measurement,
};
use hex_literal::hex;
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{group::ff::PrimeField, ops::LinearCombination, ops::MulByGenerator},
};

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

fn bench_point_mul<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let m = hex!("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522");
    let s = Scalar::from_repr(m.into()).unwrap();
    group.bench_function("point-scalar mul", |b| {
        b.iter(|| black_box(p) * black_box(s))
    });
}

fn bench_point_lincomb<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let m = hex!("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522");
    let s = Scalar::from_repr(m.into()).unwrap();
    group.bench_function("lincomb via mul+add", |b| {
        b.iter(|| black_box(p) * black_box(s) + black_box(p) * black_box(s))
    });
    group.bench_function("lincomb()", |b| {
        b.iter(|| {
            ProjectivePoint::lincomb(&[(black_box(p), black_box(s)), (black_box(p), black_box(s))])
        })
    });
}

fn bench_point_mul_by_generator<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let p = ProjectivePoint::GENERATOR;
    let x = test_scalar_x();

    group.bench_function("mul_by_generator naive", |b| {
        b.iter(|| black_box(p) * black_box(x))
    });

    group.bench_function("mul_by_generator precomputed", |b| {
        b.iter(|| ProjectivePoint::mul_by_generator(&black_box(x)))
    });
}

fn bench_high_level(c: &mut Criterion) {
    let mut group = c.benchmark_group("high-level operations");
    bench_point_mul(&mut group);
    bench_point_mul_by_generator(&mut group);
    bench_point_lincomb(&mut group);
    group.finish();
}

fn bench_scalar_sub<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("sub", |b| b.iter(|| black_box(x) - black_box(y)));
}

fn bench_scalar_add<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("add", |b| b.iter(|| black_box(x) + black_box(y)));
}

fn bench_scalar_mul<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("mul", |b| b.iter(|| black_box(x) * black_box(y)));
}

fn bench_scalar_negate<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let x = test_scalar_x();
    group.bench_function("negate", |b| b.iter(|| -black_box(x)));
}

fn bench_scalar_invert<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let x = test_scalar_x();
    group.bench_function("invert", |b| b.iter(|| black_box(x).invert()));
}

fn bench_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar operations");
    bench_scalar_sub(&mut group);
    bench_scalar_add(&mut group);
    bench_scalar_mul(&mut group);
    bench_scalar_negate(&mut group);
    bench_scalar_invert(&mut group);
    group.finish();
}

criterion_group!(benches, bench_high_level, bench_scalar);
criterion_main!(benches);
