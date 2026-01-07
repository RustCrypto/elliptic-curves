//! bp384r1 `ProjectivePoint` benchmarks

use bp384::r1::{ProjectivePoint, Scalar};
use criterion::{criterion_group, criterion_main};

const SCALAR_A: Scalar = Scalar::from_hex_vartime(
    "15f50e6c168cec3af4a81b946b7d25e07253ac13eb22b3b0aa28bb4a4eb2996324f5d5579829a25a0a17108bb1f2cc05",
);
const SCALAR_B: Scalar = Scalar::from_hex_vartime(
    "4b798823f02af50afddfdba4a0ac7b7eb70ad811ff6327f77d16f7d6069ea956bd68c7eabee8f7e959393630ae276fba",
);
const SCALAR_C: Scalar = Scalar::from_hex_vartime(
    "8b5ede2fb64cacce9e951b66aab631c900328924a5cd73f69f0f5bbf9a4b2db560679cbe98ee4c6038c8cbdbe170cbe7",
);

elliptic_curve::bench_projective!(
    bench_projective,
    "ProjectivePoint",
    ProjectivePoint::GENERATOR * SCALAR_A,
    ProjectivePoint::GENERATOR * SCALAR_B,
    SCALAR_C
);

criterion_group!(benches, bench_projective);
criterion_main!(benches);
