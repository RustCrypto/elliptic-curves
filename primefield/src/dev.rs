/// Implement all tests for a type which impls the `PrimeField` trait.
#[macro_export]
macro_rules! test_primefield {
    ($fe:tt, $t:expr) => {
        $crate::test_primefield_constants!($fe, $t);
        $crate::test_field_identity!($fe);
        $crate::test_field_invert!($fe);
        $crate::test_field_sqrt!($fe);
    };
}

/// Implement tests for constants defined by the `PrimeField` trait.
#[macro_export]
macro_rules! test_primefield_constants {
    ($fe:tt, $t:expr) => {
        #[test]
        fn two_inv_constant() {
            use $crate::ff::PrimeField;
            assert_eq!($fe::from(2u32) * $fe::TWO_INV, $fe::ONE);
        }

        #[test]
        fn root_of_unity_constant() {
            use $crate::ff::PrimeField;
            assert!($fe::S < 128);
            let two_to_s = 1u128 << $fe::S;

            // ROOT_OF_UNITY^{2^s} mod m == 1
            assert_eq!(
                $fe::ROOT_OF_UNITY.pow_vartime(&[
                    (two_to_s & 0xFFFFFFFFFFFFFFFF) as u64,
                    (two_to_s >> 64) as u64,
                    0,
                    0
                ]),
                $fe::ONE
            );

            // MULTIPLICATIVE_GENERATOR^{t} mod m == ROOT_OF_UNITY
            assert_eq!(
                $fe::MULTIPLICATIVE_GENERATOR.pow_vartime(&$t),
                $fe::ROOT_OF_UNITY
            )
        }

        #[test]
        fn root_of_unity_inv_constant() {
            use $crate::ff::PrimeField;
            assert_eq!($fe::ROOT_OF_UNITY * $fe::ROOT_OF_UNITY_INV, $fe::ONE);
        }

        #[test]
        fn delta_constant() {
            use $crate::ff::PrimeField;

            // DELTA^{t} mod m == 1
            assert_eq!($fe::DELTA.pow_vartime(&$t), $fe::ONE);
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
                let sqrt = fe.sqrt().unwrap();
                assert_eq!(sqrt.square(), fe);
            }
        }
    };
}
