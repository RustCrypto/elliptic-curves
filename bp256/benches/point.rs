//! bp256r1 `ProjectivePoint` benchmarks

use bp256::r1::{ProjectivePoint, Scalar};
use criterion::{criterion_group, criterion_main};

const SCALAR_A: Scalar =
    Scalar::from_hex_vartime("9bb0d8b72602b70dd5cfed99607a2e2c021dd0fe3b3af842df02c06f8c1a0f4e");
const SCALAR_B: Scalar =
    Scalar::from_hex_vartime("6494152e2b6c34768296d2ea0e984f89a77f0d7399b70f2e29789128423a9bea");
const SCALAR_C: Scalar =
    Scalar::from_hex_vartime("a316f6a92d2f8359218cf9f68900d9f791ad2ad77aee07686adeb5ec7c7b8cb3");

elliptic_curve::bench_projective!(
    bench_projective,
    "ProjectivePoint",
    ProjectivePoint::GENERATOR * SCALAR_A,
    ProjectivePoint::GENERATOR * SCALAR_B,
    SCALAR_C
);

criterion_group!(benches, bench_projective);
criterion_main!(benches);
