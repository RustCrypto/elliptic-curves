//! bp384 `Scalar` benchmarks

use bp384::Scalar;
use criterion::{criterion_group, criterion_main};

const SCALAR_A: Scalar = Scalar::from_hex_vartime(
    "15f50e6c168cec3af4a81b946b7d25e07253ac13eb22b3b0aa28bb4a4eb2996324f5d5579829a25a0a17108bb1f2cc05",
);
const SCALAR_B: Scalar = Scalar::from_hex_vartime(
    "4b798823f02af50afddfdba4a0ac7b7eb70ad811ff6327f77d16f7d6069ea956bd68c7eabee8f7e959393630ae276fba",
);

primefield::bench_field!(bench_scalar, "Scalar", SCALAR_A, SCALAR_B);
criterion_group!(benches, bench_scalar);
criterion_main!(benches);
