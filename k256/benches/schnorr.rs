//! Taproot Schnorr signature benchmarks

use criterion::{Criterion, criterion_group, criterion_main};
use k256::{
    elliptic_curve::Generate,
    schnorr::{
        SigningKey,
        signature::{Signer, Verifier},
    },
};
use std::hint::black_box;

fn bench_schnorr(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr");

    // Key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _sk = SigningKey::generate();
        })
    });

    let sk = SigningKey::generate();
    let vk = sk.verifying_key().clone();
    let message = b"Schnorr benchmark message for performance testing";

    // Signing (deterministic)
    group.bench_function("sign", |b| {
        b.iter(|| {
            let _sig = black_box(&sk).sign(black_box(&message[..]));
        })
    });

    // Signing (randomized) - removed, needs rng plumbing

    let sig = sk.sign(&message[..]);

    // Verification
    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(&vk)
                .verify(black_box(&message[..]), black_box(&sig))
                .unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_schnorr);
criterion_main!(benches);
