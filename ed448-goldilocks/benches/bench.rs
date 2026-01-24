use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ed448_goldilocks::{
    Decaf448, DecafPoint, DecafScalar, Ed448, EdwardsPoint, EdwardsScalar, MontgomeryPoint,
    elliptic_curve::{Generate, group::GroupEncoding},
};
use getrandom::{SysRng, rand_core::TryRng};
use hash2curve::GroupDigest;

pub fn ed448(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed448");

    group.bench_function("scalar multiplication", |b| {
        b.iter_batched(
            || {
                let point = EdwardsPoint::generate();
                let scalar = EdwardsScalar::generate();
                (point, scalar)
            },
            |(point, scalar)| point * scalar,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("point addition", |b| {
        b.iter_batched(
            || {
                let p1 = EdwardsPoint::generate();
                let p2 = EdwardsPoint::generate();
                (p1, p2)
            },
            |(p1, p2)| p1 + p2,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("encode_to_curve", |b| {
        b.iter_batched(
            || {
                let mut msg = [0; 64];
                SysRng.try_fill_bytes(&mut msg).unwrap();
                msg
            },
            |msg| Ed448::encode_from_bytes(&msg, b"test DST"),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("compress", |b| {
        b.iter_batched(
            || EdwardsPoint::generate(),
            |point| point.to_bytes(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("decompress", |b| {
        b.iter_batched(
            || EdwardsPoint::generate().to_bytes(),
            |bytes| EdwardsPoint::from_bytes(&bytes).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

pub fn decaf448(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decaf448");

    group.bench_function("scalar multiplication", |b| {
        b.iter_batched(
            || {
                let point = DecafPoint::generate();
                let scalar = DecafScalar::generate();
                (point, scalar)
            },
            |(point, scalar)| point * scalar,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("point addition", |b| {
        b.iter_batched(
            || {
                let p1 = DecafPoint::generate();
                let p2 = DecafPoint::generate();
                (p1, p2)
            },
            |(p1, p2)| p1 + p2,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("encode_to_curve", |b| {
        b.iter_batched(
            || {
                let mut msg = [0; 64];
                SysRng.try_fill_bytes(&mut msg).unwrap();
                msg
            },
            |msg| Decaf448::encode_from_bytes(&msg, b"test DST"),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("encode", |b| {
        b.iter_batched(
            || DecafPoint::generate(),
            |point| point.to_bytes(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("decode", |b| {
        b.iter_batched(
            || DecafPoint::generate().to_bytes(),
            |bytes| DecafPoint::from_bytes(&bytes).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

pub fn x448(c: &mut Criterion) {
    let mut group = c.benchmark_group("X448");

    group.bench_function("scalar multiplication", |b| {
        b.iter_batched(
            || {
                let mut point = MontgomeryPoint::default();
                SysRng.try_fill_bytes(&mut point.0).unwrap();
                let scalar = EdwardsScalar::generate();
                (point, scalar)
            },
            |(point, scalar)| &point * &scalar,
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, ed448, decaf448, x448);
criterion_main!(benches);
