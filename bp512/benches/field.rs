//! bp512 `FieldElement` benchmarks

use bp512::BrainpoolP512r1;
use criterion::{criterion_group, criterion_main};
use elliptic_curve::hazmat::FieldArithmetic;

type FieldElement = <BrainpoolP512r1 as FieldArithmetic>::FieldElement;

const FE_A: FieldElement = FieldElement::from_hex_vartime(
    "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
);
const FE_B: FieldElement = FieldElement::from_hex_vartime(
    "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
);

primefield::bench_field!(bench_field_element, "FieldElement", FE_A, FE_B);
criterion_group!(benches, bench_field_element);
criterion_main!(benches);
