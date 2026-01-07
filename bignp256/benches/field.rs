//! bign-curve256v1 `FieldElement` benchmarks

use bignp256::arithmetic::FieldElement;
use criterion::{criterion_group, criterion_main};

const FE_A: FieldElement = FieldElement::from_hex_vartime(
    "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83",
);
const FE_B: FieldElement = FieldElement::from_hex_vartime(
    "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9",
);

primefield::bench_field!(bench_field_element, "FieldElement", FE_A, FE_B);
criterion_group!(benches, bench_field_element);
criterion_main!(benches);
