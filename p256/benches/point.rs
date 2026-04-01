//! p256 `ProjectivePoint` benchmarks

use criterion::{Criterion, criterion_group, criterion_main};
use p256::ProjectivePoint;
use primefield::subtle::ConstantTimeEq;

fn bench_projective(c: &mut Criterion) {
    let mut group = c.benchmark_group("ProjectivePoint constant time operations");

    group.bench_function("point_generator_ct_eq", |b| {
        b.iter(|| ProjectivePoint::GENERATOR.ct_eq(&ProjectivePoint::GENERATOR))
    });

    group.finish();
}

criterion_group!(benches, bench_projective);
criterion_main!(benches);
