//! p256 `ProjectivePoint` benchmarks

use criterion::{Criterion, criterion_group, criterion_main};
use p256::ProjectivePoint;
use primefield::subtle::ConstantTimeEq;

fn bench_projective(c: &mut Criterion) {
    let mut group = c.benchmark_group("Projective point operations");

    group.bench_function("generator_vs_generator", |b| {
        b.iter(|| ProjectivePoint::GENERATOR.ct_eq(&ProjectivePoint::GENERATOR))
    });
    group.bench_function("identity_vs_identity", |b| {
        b.iter(|| ProjectivePoint::IDENTITY.ct_eq(&ProjectivePoint::IDENTITY))
    });
    group.bench_function("generator_vs_identity", |b| {
        b.iter(|| ProjectivePoint::GENERATOR.ct_eq(&ProjectivePoint::IDENTITY))
    });

    group.finish();
}

criterion_group!(benches, bench_projective);
criterion_main!(benches);
