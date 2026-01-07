//! bign-curve256v1 `Scalar` benchmarks

use bignp256::Scalar;
use criterion::{criterion_group, criterion_main};

const SCALAR_A: Scalar =
    Scalar::from_hex_vartime("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464");
const SCALAR_B: Scalar =
    Scalar::from_hex_vartime("0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813");

primefield::bench_field!(bench_scalar, "Scalar", SCALAR_A, SCALAR_B);
criterion_group!(benches, bench_scalar);
criterion_main!(benches);
