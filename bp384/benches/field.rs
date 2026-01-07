//! bp384 `FieldElement` benchmarks

use bp384::BrainpoolP384r1;
use criterion::{criterion_group, criterion_main};
use primeorder::PrimeCurveParams;

type FieldElement = <BrainpoolP384r1 as PrimeCurveParams>::FieldElement;

const FE_A: FieldElement = FieldElement::from_hex_vartime(
    "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
);
const FE_B: FieldElement = FieldElement::from_hex_vartime(
    "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
);

primefield::bench_field!(bench_field_element, "FieldElement", FE_A, FE_B);
criterion_group!(benches, bench_field_element);
criterion_main!(benches);
