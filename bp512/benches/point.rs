//! bp512r1 `ProjectivePoint` benchmarks

use bp512::r1::{ProjectivePoint, Scalar};
use criterion::{criterion_group, criterion_main};

const SCALAR_A: Scalar = Scalar::from_hex_vartime(
    "16302ff0dbbb5a8d733dab7141c1b45acbc8715939677f6a56850a38bd87bd59b09e80279609ff333eb9d4c061231fb26f92eeb04982a5f1d1764cad57665422",
);
const SCALAR_B: Scalar = Scalar::from_hex_vartime(
    "230e18e1bcc88a362fa54e4ea3902009292f7f8033624fd471b5d8ace49d12cfabbc19963dab8e2f1eba00bffb29e4d72d13f2224562f405cb80503666b25429",
);
const SCALAR_C: Scalar = Scalar::from_hex_vartime(
    "1f3d5b79a7c5e30123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
);

elliptic_curve::bench_projective!(
    bench_projective,
    ProjectivePoint,
    ProjectivePoint::GENERATOR * SCALAR_A,
    ProjectivePoint::GENERATOR * SCALAR_B,
    SCALAR_C
);

criterion_group!(benches, bench_projective);
criterion_main!(benches);
