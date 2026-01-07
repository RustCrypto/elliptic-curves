//! p256 ECDSA benchmarks

use criterion::{criterion_group, criterion_main};
use hex_literal::hex;
use p256::ecdsa::{Signature, SigningKey};

const SIGNING_KEY_BYTES: [u8; 32] =
    hex!("1cf6bc6c7f642a84994119e206c9f0753ff100709f4fd12f2338c1be60bf4175");

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_KEY_BYTES.into()).unwrap()
}

ecdsa_core::bench_ecdsa!(
    bench_ecdsa,
    "ECDSA/P-256 (SHA-256)",
    signing_key(),
    Signature
);
criterion_group!(benches, bench_ecdsa);
criterion_main!(benches);
