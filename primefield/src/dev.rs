/// Write a series of `criterion`-based benchmarks for a field implementation.
#[macro_export]
macro_rules! bench_field {
    { $name:ident, $desc:expr, $fe_a:expr, $fe_b:expr } => {
        fn bench_add<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let x = core::hint::black_box($fe_a);
            let y = core::hint::black_box($fe_b);
            group.bench_function("add", |b| b.iter(|| x + y));
        }

        fn bench_sub<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let x = core::hint::black_box($fe_a);
            let y = core::hint::black_box($fe_b);
            group.bench_function("sub", |b| b.iter(|| x - y));
        }

        fn bench_mul<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let x = core::hint::black_box($fe_a);
            let y = core::hint::black_box($fe_b);
            group.bench_function("mul", |b| b.iter(|| x * y));
        }

        fn bench_neg<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let x = core::hint::black_box($fe_a);
            group.bench_function("neg", |b| b.iter(|| -x));
        }

        fn bench_invert<M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'_, M>,
        ) {
            let x = core::hint::black_box($fe_a);
            group.bench_function("invert", |b| b.iter(|| x.invert()));
        }

        fn bench_square<'a, M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'a, M>,
        ) {
            let x = core::hint::black_box($fe_a);
            group.bench_function("square", |b| b.iter(|| x.square()));
        }

        fn bench_sqrt<'a, M: ::criterion::measurement::Measurement>(
            group: &mut ::criterion::BenchmarkGroup<'a, M>,
        ) {
            use ::primefield::ff::Field;
            let x = core::hint::black_box($fe_a);
            group.bench_function("sqrt", |b| b.iter(|| x.sqrt()));
        }

        fn $name(c: &mut ::criterion::Criterion) {
            let mut group = c.benchmark_group($desc);
            bench_add(&mut group);
            bench_sub(&mut group);
            bench_mul(&mut group);
            bench_neg(&mut group);
            bench_invert(&mut group);
            bench_square(&mut group);
            bench_sqrt(&mut group);
            group.finish();
        }
    };
}

/// Implement all tests for a type which impls the `PrimeField` trait.
#[macro_export]
macro_rules! test_primefield {
    ($fe:tt, $uint:ident) => {
        $crate::test_primefield_constants!($fe, $uint);
        $crate::test_field_identity!($fe);
        $crate::test_field_invert!($fe);
        $crate::test_field_sqrt!($fe);
    };
}

/// Implement tests for constants defined by the `PrimeField` trait.
#[macro_export]
macro_rules! test_primefield_constants {
    ($fe:tt, $uint:ident) => {
        use $crate::{bigint::modular::Retrieve as _, ff::PrimeField as _};

        // TODO(tarcieri): support for fields with little endian-encoded modulus
        const MODULUS: $crate::bigint::Odd<$uint> = $crate::bigint::Odd::from_be_hex($fe::MODULUS);
        const T: $uint = $crate::compute_t(MODULUS.as_ref());

        #[test]
        fn delta_constant() {
            // DELTA^{t} mod m == 1
            assert_eq!($fe::DELTA.pow_vartime(&T), $fe::ONE);
        }

        // TODO(tarcieri): check generator has order `modulus - 1`
        #[test]
        fn multiplicative_generator_constant() {
            // Sanity-check that the generator is a quadratic non-residue
            assert_eq!(
                $fe::MULTIPLICATIVE_GENERATOR
                    .retrieve()
                    .jacobi_symbol(&MODULUS),
                $crate::bigint::JacobiSymbol::MinusOne
            );
        }

        #[test]
        fn root_of_unity_constant() {
            // ROOT_OF_UNITY^{2^s} mod m == 1
            assert_eq!($fe::ROOT_OF_UNITY.sqn_vartime($fe::S as usize), $fe::ONE);

            // MULTIPLICATIVE_GENERATOR^{t} mod m == ROOT_OF_UNITY
            assert_eq!(
                $fe::MULTIPLICATIVE_GENERATOR.pow_vartime(&T),
                $fe::ROOT_OF_UNITY
            )
        }

        #[test]
        fn root_of_unity_inv_constant() {
            assert_eq!($fe::ROOT_OF_UNITY * $fe::ROOT_OF_UNITY_INV, $fe::ONE);
        }

        #[test]
        fn two_inv_constant() {
            assert_eq!($fe::from(2u32) * $fe::TWO_INV, $fe::ONE);
        }
    };
}

/// Implement field element identity tests.
#[macro_export]
macro_rules! test_field_identity {
    ($fe:tt) => {
        #[test]
        fn zero_is_additive_identity() {
            let zero = $fe::ZERO;
            let one = $fe::ONE;
            assert_eq!(zero.add(&zero), zero);
            assert_eq!(one.add(&zero), one);
        }

        #[test]
        fn one_is_multiplicative_identity() {
            let one = $fe::ONE;
            assert_eq!(one.multiply(&one), one);
        }
    };
}

/// Implement field element inversion tests.
#[macro_export]
macro_rules! test_field_invert {
    ($fe:tt) => {
        #[test]
        fn invert() {
            let one = $fe::ONE;
            assert_eq!(one.invert().unwrap(), one);

            let three = one + &one + &one;
            let inv_three = three.invert().unwrap();
            assert_eq!(three * &inv_three, one);

            let minus_three = -three;
            let inv_minus_three = minus_three.invert().unwrap();
            assert_eq!(inv_minus_three, -inv_three);
            assert_eq!(three * &inv_minus_three, -one);
        }
    };
}

/// Implement field element square root tests.
#[macro_export]
macro_rules! test_field_sqrt {
    ($fe:tt) => {
        #[test]
        fn sqrt() {
            for &n in &[1u64, 4, 9, 16, 25, 36, 49, 64] {
                let fe = $fe::from(n);
                let sqrt = $crate::ff::Field::sqrt(&fe).unwrap();
                assert_eq!(sqrt.square(), fe);
            }
        }
    };
}
