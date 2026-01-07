//! bp256 `Scalar` benchmarks

use bp256::Scalar;
use criterion::{criterion_group, criterion_main};

const SCALAR_A: Scalar =
    Scalar::from_hex_vartime("9bb0d8b72602b70dd5cfed99607a2e2c021dd0fe3b3af842df02c06f8c1a0f4e");
const SCALAR_B: Scalar =
    Scalar::from_hex_vartime("6494152e2b6c34768296d2ea0e984f89a77f0d7399b70f2e29789128423a9bea");

primefield::bench_field!(bench_scalar, "Scalar", SCALAR_A, SCALAR_B);
criterion_group!(benches, bench_scalar);
criterion_main!(benches);
