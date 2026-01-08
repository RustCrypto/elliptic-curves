//! sm2 `FieldElement` benchmarks

use criterion::{criterion_group, criterion_main};
use primeorder::PrimeCurveParams;
use sm2::Sm2;

type FieldElement = <Sm2 as PrimeCurveParams>::FieldElement;

const FE_A: FieldElement = FieldElement::from_hex_vartime(
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
);
const FE_B: FieldElement = FieldElement::from_hex_vartime(
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
);

primefield::bench_field!(bench_field, "FieldElement", FE_A, FE_B);
criterion_group!(benches, bench_field);
criterion_main!(benches);
