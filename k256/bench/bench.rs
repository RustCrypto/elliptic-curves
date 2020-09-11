//! secp256k1 benchmarks

use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use hex_literal::hex;
use k256::elliptic_curve::{ff::PrimeField, generic_array::arr};
use k256::{FieldElement, ProjectivePoint, Scalar};

fn test_scalar_x() -> Scalar {
    Scalar::from_repr(arr![u8;
        0xbb, 0x48, 0x8a, 0xef, 0x41, 0x6a, 0x41, 0xd7, 0x68, 0x0d, 0x1c, 0xf0, 0x1d, 0x70,
        0xf5, 0x9b, 0x60, 0xd7, 0xf5, 0xf7, 0x7e, 0x30, 0xe7, 0x8b, 0x8b, 0xf9, 0xd2, 0xd8,
        0x82, 0xf1, 0x56, 0xa6,
    ])
    .unwrap()
}

fn test_scalar_y() -> Scalar {
    Scalar::from_repr(arr![u8;
        0x67, 0xe2, 0xf6, 0x80, 0x71, 0xed, 0x82, 0x81, 0xe8, 0xae, 0xd6, 0xbc, 0xf1, 0xc5,
        0x20, 0x7c, 0x5e, 0x63, 0x37, 0x22, 0xd9, 0x20, 0xaf, 0xd6, 0xae, 0x22, 0xd0, 0x6e,
        0xeb, 0x80, 0x35, 0xe3,
    ])
    .unwrap()
}

fn bench_point_mul<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let p = ProjectivePoint::generator();
    let m = hex!("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522");
    let s = Scalar::from_repr(m.into()).unwrap();
    group.bench_function("point-scalar mul", |b| b.iter(|| &p * &s));
}

fn bench_high_level(c: &mut Criterion) {
    let mut group = c.benchmark_group("high-level operations");
    bench_point_mul(&mut group);
    group.finish();
}

fn bench_scalar_sub<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("sub", |b| b.iter(|| &x - &y));
}

fn bench_scalar_add<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("add", |b| b.iter(|| &x + &y));
}

fn bench_scalar_mul<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_scalar_x();
    let y = test_scalar_y();
    group.bench_function("mul", |b| b.iter(|| &x * &y));
}

fn bench_scalar_negate<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_scalar_x();
    group.bench_function("negate", |b| b.iter(|| -x));
}

fn bench_scalar_invert<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_scalar_x();
    group.bench_function("invert", |b| b.iter(|| x.invert()));
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

fn test_field_element_x() -> FieldElement {
    FieldElement::from_bytes(
        &[
            0xbb, 0x48, 0x8a, 0xef, 0x41, 0x6a, 0x41, 0xd7, 0x68, 0x0d, 0x1c, 0xf0, 0x1d, 0x70,
            0xf5, 0x9b, 0x60, 0xd7, 0xf5, 0xf7, 0x7e, 0x30, 0xe7, 0x8b, 0x8b, 0xf9, 0xd2, 0xd8,
            0x82, 0xf1, 0x56, 0xa6,
        ]
        .into(),
    )
    .unwrap()
}

fn test_field_element_y() -> FieldElement {
    FieldElement::from_bytes(
        &[
            0x67, 0xe2, 0xf6, 0x80, 0x71, 0xed, 0x82, 0x81, 0xe8, 0xae, 0xd6, 0xbc, 0xf1, 0xc5,
            0x20, 0x7c, 0x5e, 0x63, 0x37, 0x22, 0xd9, 0x20, 0xaf, 0xd6, 0xae, 0x22, 0xd0, 0x6e,
            0xeb, 0x80, 0x35, 0xe3,
        ]
        .into(),
    )
    .unwrap()
}

fn bench_field_element_normalize_weak<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_field_element_x();
    group.bench_function("normalize_weak", |b| b.iter(|| x.normalize_weak()));
}

fn bench_field_element_normalize<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_field_element_x();
    group.bench_function("normalize", |b| b.iter(|| x.normalize()));
}

fn bench_field_element_mul<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_field_element_x();
    let y = test_field_element_y();
    group.bench_function("mul", |b| b.iter(|| &x * &y));
}

fn bench_field_element_square<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_field_element_x();
    group.bench_function("square", |b| b.iter(|| x.square()));
}

fn bench_field_element_sqrt<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_field_element_x();
    group.bench_function("sqrt", |b| b.iter(|| x.sqrt()));
}

fn bench_field_element_invert<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let x = test_field_element_x();
    group.bench_function("invert", |b| b.iter(|| x.invert()));
}

fn bench_field_element(c: &mut Criterion) {
    let mut group = c.benchmark_group("field element operations");
    bench_field_element_normalize_weak(&mut group);
    bench_field_element_normalize(&mut group);
    bench_field_element_mul(&mut group);
    bench_field_element_square(&mut group);
    bench_field_element_invert(&mut group);
    bench_field_element_sqrt(&mut group);
    group.finish();
}

criterion_group!(benches, bench_high_level, bench_scalar, bench_field_element);
criterion_main!(benches);
