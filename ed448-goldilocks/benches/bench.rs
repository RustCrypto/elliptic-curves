use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ed448_goldilocks::{
    CompressedDecaf, CompressedEdwardsY, Decaf448, DecafPoint, DecafScalar, EdwardsPoint,
    EdwardsScalar, MontgomeryPoint,
};
use elliptic_curve::{Field, Group};
use hash2curve::{ExpandMsgXof, GroupDigest};
use rand_core::{OsRng, TryRngCore};
use sha3::Shake256;

pub fn ed448(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed448");

    group.bench_function("scalar multiplication", |b| {
        b.iter_batched(
            || {
                let point = EdwardsPoint::try_from_rng(&mut OsRng).unwrap();
                let scalar = EdwardsScalar::try_from_rng(&mut OsRng).unwrap();
                (point, scalar)
            },
            |(point, scalar)| point * scalar,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("point addition", |b| {
        b.iter_batched(
            || {
                let p1 = EdwardsPoint::try_from_rng(&mut OsRng).unwrap();
                let p2 = EdwardsPoint::try_from_rng(&mut OsRng).unwrap();
                (p1, p2)
            },
            |(p1, p2)| p1 + p2,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("hash_to_curve", |b| {
        b.iter_batched(
            || {
                let mut msg = [0; 64];
                OsRng.try_fill_bytes(&mut msg).unwrap();
                msg
            },
            |msg| EdwardsPoint::hash_with_defaults(&msg),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("encode_to_curve", |b| {
        b.iter_batched(
            || {
                let mut msg = [0; 64];
                OsRng.try_fill_bytes(&mut msg).unwrap();
                msg
            },
            |msg| EdwardsPoint::encode_with_defaults(&msg),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("compress", |b| {
        b.iter_batched(
            || EdwardsPoint::try_from_rng(&mut OsRng).unwrap(),
            |point| point.compress().0,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("decompress", |b| {
        b.iter_batched(
            || EdwardsPoint::try_from_rng(&mut OsRng).unwrap().compress().0,
            |bytes| CompressedEdwardsY(bytes).decompress().unwrap(),
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
                let point = DecafPoint::try_from_rng(&mut OsRng).unwrap();
                let scalar = DecafScalar::try_from_rng(&mut OsRng).unwrap();
                (point, scalar)
            },
            |(point, scalar)| point * scalar,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("point addition", |b| {
        b.iter_batched(
            || {
                let p1 = DecafPoint::try_from_rng(&mut OsRng).unwrap();
                let p2 = DecafPoint::try_from_rng(&mut OsRng).unwrap();
                (p1, p2)
            },
            |(p1, p2)| p1 + p2,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("hash_to_curve", |b| {
        b.iter_batched(
            || {
                let mut msg = [0; 64];
                OsRng.try_fill_bytes(&mut msg).unwrap();
                msg
            },
            |msg| {
                Decaf448::hash_from_bytes::<ExpandMsgXof<Shake256>>(
                    &[&msg],
                    &[b"decaf448_XOF:SHAKE256_D448MAP_RO_"],
                )
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("encode_to_curve", |b| {
        b.iter_batched(
            || {
                let mut msg = [0; 64];
                OsRng.try_fill_bytes(&mut msg).unwrap();
                msg
            },
            |msg| {
                Decaf448::encode_from_bytes::<ExpandMsgXof<Shake256>>(
                    &[&msg],
                    &[b"decaf448_XOF:SHAKE256_D448MAP_NU_"],
                )
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("compress", |b| {
        b.iter_batched(
            || DecafPoint::try_from_rng(&mut OsRng).unwrap(),
            |point| point.compress().0,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("decompress", |b| {
        b.iter_batched(
            || DecafPoint::try_from_rng(&mut OsRng).unwrap().compress().0,
            |bytes| CompressedDecaf(bytes).decompress().unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

pub fn curve448(c: &mut Criterion) {
    let mut group = c.benchmark_group("Curve448");

    group.bench_function("scalar multiplication", |b| {
        b.iter_batched(
            || {
                let mut point = MontgomeryPoint::default();
                OsRng.try_fill_bytes(&mut point.0).unwrap();
                let scalar = EdwardsScalar::try_from_rng(&mut OsRng).unwrap();
                (point, scalar)
            },
            |(point, scalar)| &point * &scalar,
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, ed448, decaf448, curve448);
criterion_main!(benches);
