//! secp256k1 scalar arithmetic benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use k256::{
    ecdsa::{
        signature::hazmat::{PrehashSigner, PrehashVerifier},
        Signature, SigningKey,
    },
    elliptic_curve::group::ff::PrimeField,
    FieldBytes, NonZeroScalar, Scalar,
};

fn test_scalar_d() -> NonZeroScalar {
    NonZeroScalar::new(
        Scalar::from_repr(
            [
                0xbb, 0x48, 0x8a, 0xef, 0x41, 0x6a, 0x41, 0xd7, 0x68, 0x0d, 0x1c, 0xf0, 0x1d, 0x70,
                0xf5, 0x9b, 0x60, 0xd7, 0xf5, 0xf7, 0x7e, 0x30, 0xe7, 0x8b, 0x8b, 0xf9, 0xd2, 0xd8,
                0x82, 0xf1, 0x56, 0xa6,
            ]
            .into(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn test_scalar_z() -> FieldBytes {
    [
        0xe3, 0x35, 0x80, 0xeb, 0x6e, 0xd0, 0x22, 0xae, 0xd6, 0xaf, 0x20, 0xd9, 0x22, 0x37, 0x63,
        0x5e, 0x7c, 0x20, 0xc5, 0xf1, 0xbc, 0xd6, 0xae, 0xe8, 0x81, 0x82, 0xed, 0x71, 0x80, 0xf6,
        0xe2, 0x67,
    ]
    .into()
}

fn bench_ecdsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa");

    let d = SigningKey::from(test_scalar_d());
    let z = test_scalar_z();

    group.bench_function("try_sign_prehashed", |b| {
        b.iter(|| {
            let _: Signature = black_box(&d).sign_prehash(&black_box(z)).unwrap();
        })
    });

    let q = d.verifying_key();
    let s: Signature = d.sign_prehash(&z).unwrap();

    group.bench_function("verify_prehashed", |b| {
        b.iter(|| {
            black_box(q)
                .verify_prehash(&black_box(z), &black_box(s))
                .unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_ecdsa);
criterion_main!(benches);
