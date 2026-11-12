/// Write a series of `criterion`-based benchmarks for a field implementation.
#[macro_export]
macro_rules! bench_field {
    ($name:ident, $desc:expr, $fe_a:expr, $fe_b:expr) => {
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
        $crate::test_field_ops!($fe);
        $crate::test_field_invert!($fe);
        $crate::test_field_sqrt!($fe);
    };
}

/// Implement tests for constants defined by the `PrimeField` trait.
#[macro_export]
macro_rules! test_primefield_constants {
    ($fe:tt, $uint:ident) => {
        // TODO(tarcieri): support for fields with little endian-encoded modulus
        const MODULUS: $crate::bigint::Odd<$uint> =
            $crate::bigint::Odd::from_be_hex(<$fe as $crate::ff::PrimeField>::MODULUS);
        const T: $uint = $crate::compute_t(MODULUS.as_ref());

        fn aux_pow_vartime(base: &$fe, exp: &$uint) -> $fe {
            use $crate::ff::Field;

            // Alternatively, one could fall back to `$crate::ff::Field::pow_vartime`,
            // but the exponent would have to be converted to an `&[u64]` in the 32-bit case.
            let mut res = <$fe as Field>::ONE;

            // Allow the deprecated `.bits()` to support `crypto-bigint` 0.7.9 and 0.7.10.
            #[allow(deprecated)]
            for i in (0..exp.bits()).rev() {
                res = res * res;
                if exp.bit_vartime(i) {
                    res *= base;
                }
            }
            res
        }

        fn aux_sqn_vartime(base: &$fe, n: usize) -> $fe {
            let mut x = *base;
            for _ in 0..n {
                x = x * x;
            }
            x
        }

        #[test]
        fn delta_constant() {
            // DELTA^{t} mod m == 1
            assert_eq!(
                aux_pow_vartime(&<$fe as $crate::ff::PrimeField>::DELTA, &T),
                <$fe as $crate::ff::Field>::ONE
            );
        }

        // TODO(tarcieri): check generator has order `modulus - 1`
        #[test]
        fn multiplicative_generator_constant() {
            // Sanity-check that the generator is a quadratic non-residue
            assert_eq!(
                $crate::bigint::modular::Retrieve::retrieve(
                    &<$fe as $crate::ff::PrimeField>::MULTIPLICATIVE_GENERATOR
                )
                .jacobi_symbol(&MODULUS),
                $crate::bigint::JacobiSymbol::MinusOne
            );
        }

        #[test]
        fn root_of_unity_constant() {
            use $crate::ff::{Field, PrimeField};

            // ROOT_OF_UNITY^{2^s} mod m == 1
            assert_eq!(
                aux_sqn_vartime(
                    &<$fe as PrimeField>::ROOT_OF_UNITY,
                    <$fe as PrimeField>::S as usize
                ),
                <$fe as Field>::ONE
            );

            // MULTIPLICATIVE_GENERATOR^{t} mod m == ROOT_OF_UNITY
            assert_eq!(
                aux_pow_vartime(&<$fe as PrimeField>::MULTIPLICATIVE_GENERATOR, &T),
                <$fe as PrimeField>::ROOT_OF_UNITY
            )
        }

        #[test]
        fn root_of_unity_inv_constant() {
            use $crate::ff::{Field, PrimeField};

            assert_eq!(
                <$fe as PrimeField>::ROOT_OF_UNITY * <$fe as PrimeField>::ROOT_OF_UNITY_INV,
                <$fe as Field>::ONE
            );
        }

        #[test]
        fn two_inv_constant() {
            use $crate::ff::{Field, PrimeField};

            assert_eq!(
                $fe::from(2u32) * <$fe as PrimeField>::TWO_INV,
                <$fe as Field>::ONE
            );
        }
    };
}

/// Implement field element identity tests.
#[macro_export]
macro_rules! test_field_identity {
    ($fe:tt) => {
        #[test]
        fn zero_is_additive_identity() {
            use $crate::ff::Field;

            let zero = <$fe as Field>::ZERO;
            let one = <$fe as Field>::ONE;
            assert_eq!(zero + &zero, zero);
            assert_eq!(one + &zero, one);
        }

        #[test]
        fn one_is_multiplicative_identity() {
            use $crate::ff::Field;

            let one = <$fe as Field>::ONE;
            assert_eq!(one * &one, one);
        }
    };
}

/// Implement tests for arithmetic operations on field elements.
#[macro_export]
macro_rules! test_field_ops {
    ($fe:tt) => {
        #[test]
        fn arithmetic_ops() {
            use $crate::ff::Field;

            let zero = <$fe as Field>::ZERO;
            let one = <$fe as Field>::ONE;
            let minus_one = -<$fe as Field>::ONE;

            assert_eq!(zero + one, one);
            assert_eq!(zero + &one, one);

            assert_eq!(zero - one, minus_one);
            assert_eq!(zero - &one, minus_one);

            assert_eq!(minus_one * minus_one, one);
            assert_eq!(minus_one * &minus_one, one);

            assert_eq!(-one, minus_one);
            assert_eq!(-zero, zero);
        }

        #[test]
        fn sum() {
            use $crate::ff::Field;

            let x = -<$fe as Field>::ONE;
            let values = [x, x, x];
            assert_eq!(values.into_iter().sum::<$fe>(), x + x + x);
            assert_eq!(values.iter().sum::<$fe>(), x + x + x);
        }

        #[test]
        fn product() {
            use $crate::ff::Field;

            let x = -<$fe as Field>::ONE;
            let values = [x, x, x];
            assert_eq!(values.into_iter().product::<$fe>(), x * x * x);
            assert_eq!(values.iter().product::<$fe>(), x * x * x);
        }
    };
}

/// Implement field element inversion tests.
#[macro_export]
macro_rules! test_field_invert {
    ($fe:tt) => {
        #[test]
        fn invert() {
            use $crate::ff::Field;

            let zero = <$fe as Field>::ZERO;
            assert_eq!(Field::invert(&zero).is_none().unwrap_u8(), 1);

            let one = <$fe as Field>::ONE;
            assert_eq!(Field::invert(&one).unwrap(), one);

            let three = one + &one + &one;
            let inv_three = Field::invert(&three).unwrap();
            assert_eq!(three * &inv_three, one);

            let minus_three = -three;
            let inv_minus_three = Field::invert(&minus_three).unwrap();
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
            use $crate::ff::Field;

            for &n in &[1u64, 4, 9, 16, 25, 36, 49, 64] {
                let fe = $fe::from(n);
                let sqrt = Field::sqrt(&fe).unwrap();
                assert_eq!(Field::square(&sqrt), fe);
            }
        }

        #[test]
        fn sqrt_ratio() {
            use $crate::ff::Field;

            let zero = <$fe as Field>::ZERO;
            let one = <$fe as Field>::ONE;

            let (c, res) = Field::sqrt_ratio(&zero, &one);
            assert_eq!(c.unwrap_u8(), 1);
            assert_eq!(res, <$fe as Field>::ZERO);

            let (c, res) = Field::sqrt_ratio(&one, &zero);
            assert_eq!(c.unwrap_u8(), 0);
            assert_eq!(res, zero);

            // There is no deterministic way to find a non-square for an arbitrary modulus
            // (to make sure all branches are covered), so we just test several small values.
            for num in 1u64..8 {
                for div in 1u64..8 {
                    let fe_num = $fe::from(num);
                    let fe_div = $fe::from(div);
                    let (c, res) = Field::sqrt_ratio(&fe_num, &fe_div);

                    if c.unwrap_u8() == 1 {
                        assert_eq!(
                            Field::square(&res),
                            fe_num * Field::invert(&fe_div).unwrap()
                        );
                    } else {
                        let gs = Field::square(&res)
                            * Field::invert(&(fe_num * Field::invert(&fe_div).unwrap())).unwrap();
                        assert_eq!(Field::sqrt(&gs).is_none().unwrap_u8(), 1);
                    }
                }
            }
        }
    };
}
