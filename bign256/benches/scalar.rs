//! bign-curve256v1 scalar arithmetic benchmarks

use bign256::{ProjectivePoint, Scalar, elliptic_curve::group::ff::PrimeField};
use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::Measurement,
};
use hex_literal::hex;

fn test_scalar_x() -> Scalar {
    Scalar::from_repr(
        hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464").into(),
    )
    .unwrap()
}

fn test_scalar_y() -> Scalar {
    Scalar::from_repr(
        hex!("0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813").into(),
    )
    .unwrap()
}

fn bench_point_mul<M: Measurement>(group: &mut BenchmarkGroup<M>) {
    let p = ProjectivePoint::GENERATOR;
    let m = test_scalar_x();
    let s = Scalar::from_repr(m.into()).unwrap();
    group.bench_function("point-scalar mul", |b| b.iter(|| p * s));
}

fn bench_scalar_sub<M: Measurement>(group: &mut BenchmarkGroup<M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("sub", |b| b.iter(|| x - y));
}

fn bench_scalar_add<M: Measurement>(group: &mut BenchmarkGroup<M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("add", |b| b.iter(|| x + y));
}

fn bench_scalar_mul<M: Measurement>(group: &mut BenchmarkGroup<M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("mul", |b| b.iter(|| x * y));
}

fn bench_scalar_negate<M: Measurement>(group: &mut BenchmarkGroup<M>) {
    let x = test_scalar_x();
    group.bench_function("negate", |b| b.iter(|| -x));
}

fn bench_scalar_invert<M: Measurement>(group: &mut BenchmarkGroup<M>) {
    let x = test_scalar_x();
    group.bench_function("invert", |b| b.iter(|| x.invert()));
}

fn bench_point(c: &mut Criterion) {
    let mut group = c.benchmark_group("point operations");
    bench_point_mul(&mut group);
    group.finish();
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

criterion_group!(benches, bench_point, bench_scalar);
criterion_main!(benches);
