//! bp256r1 `ProjectivePoint` benchmarks

use bp256::r1::{ProjectivePoint, Scalar};
use criterion::{criterion_group, criterion_main};

const POINT_A: ProjectivePoint = ProjectivePoint::GENERATOR;
const POINT_B: ProjectivePoint = ProjectivePoint::GENERATOR;

const SCALAR: Scalar =
    Scalar::from_hex_vartime("9bb0d8b72602b70dd5cfed99607a2e2c021dd0fe3b3af842df02c06f8c1a0f4e");

elliptic_curve::bench_projective!(
    bench_projective,
    "ProjectivePoint",
    POINT_A,
    POINT_B,
    SCALAR
);

criterion_group!(benches, bench_projective);
criterion_main!(benches);
