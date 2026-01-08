//! SM2DSA benchmarks

use core::hint::black_box;
use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::Measurement,
};
use hex_literal::hex;
use signature::{Signer, Verifier};
use sm2::dsa::{Signature, SigningKey};

const SIGNING_KEY_BYTES: [u8; 32] =
    hex!("1cf6bc6c7f642a84994119e206c9f0753ff100709f4fd12f2338c1be60bf4175");

fn signing_key() -> SigningKey {
    SigningKey::from_bytes("", &SIGNING_KEY_BYTES.into()).unwrap()
}

fn bench_sign<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let sk = black_box(signing_key());
    let msg = black_box(b"example message");
    group.bench_function("sign", |b| {
        b.iter(|| {
            let sig: Signature = sk.sign(msg);
            black_box(sig)
        })
    });
}

fn bench_verify<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let sk = black_box(signing_key());
    let vk = black_box(sk.verifying_key());
    let msg = black_box(b"example message");
    let sig: Signature = black_box(sk.sign(msg));
    group.bench_function("verify", |b| b.iter(|| vk.verify(msg, &sig)));
}

fn bench_dsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("SM2DSA");
    bench_sign(&mut group);
    bench_verify(&mut group);
    group.finish();
}

criterion_group!(benches, bench_dsa);
criterion_main!(benches);
