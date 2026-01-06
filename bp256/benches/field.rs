//! bp256 `FieldElement` benchmarks

use bp256::BrainpoolP256r1;
use criterion::{Criterion, criterion_group, criterion_main};
use primeorder::PrimeCurveParams;

type FieldElement = <BrainpoolP256r1 as PrimeCurveParams>::FieldElement;

const FE_A: FieldElement = FieldElement::from_hex_vartime(
    "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
);
const FE_B: FieldElement = FieldElement::from_hex_vartime(
    "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
);

primefield::bench_field!(bench_field_element, "FieldElement", FE_A, FE_B);
criterion_group!(benches, bench_field_element);
criterion_main!(benches);
