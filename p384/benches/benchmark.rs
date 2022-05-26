use benchmark_simple::*;
use elliptic_curve::ops::Reduce;
use p384::*;
use rand_core::*;

fn main() {
    let mut rng = OsRng;
    let mut s = [0u8; 48];
    rng.fill_bytes(&mut s);
    let s = Scalar::from_le_bytes_reduced(s.into());
    let mut p = ProjectivePoint::GENERATOR;

    let bench = Bench::new();
    let options = &Options {
        iterations: 10_000,
        warmup_iterations: 100,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        verbose: true,
        ..Default::default()
    };
    let res = bench.run(options, || {
        p *= s;
        black_box(p);
    });
    println!("scalar multiplication: {}", res);
}
