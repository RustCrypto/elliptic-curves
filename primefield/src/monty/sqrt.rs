//! Modular square root implementations, adapted from <https://eprint.iacr.org/2012/685.pdf>.

use crate::{MontyFieldBytes, MontyFieldElement, MontyFieldParams};
use bigint::{NonZeroUint, Odd, Uint};
use ff::PrimeField;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Square root algorithms.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Algorithm {
    /// Atkins algorithm for `q ≡ 5 (mod 8)`.
    Atkins,

    /// Shanks algorithm for `q ≡ 3 (mod 4)`.
    Shanks,

    /// Tonelli-Shanks algorithm for any odd prime.
    #[default]
    TonelliShanks,
}

impl Algorithm {
    /// Determine the best algorithm to use with a particular modulus.
    const fn for_modulus<const LIMBS: usize>(p: &Odd<Uint<LIMBS>>) -> Self {
        if mod_residue(p, 4) == 3 {
            Self::Shanks
        } else if mod_residue(p, 8) == 5 {
            Self::Atkins
        } else {
            Self::TonelliShanks
        }
    }
}

impl<MOD, const LIMBS: usize> MontyFieldElement<MOD, LIMBS>
where
    Self: PrimeField,
    MOD: MontyFieldParams<LIMBS>,
    MontyFieldBytes<MOD, LIMBS>: Copy,
{
    /// Returns the square root of self mod p, or `None` if no square root exists.
    #[inline]
    pub fn sqrt(&self) -> CtOption<Self> {
        match const { Algorithm::for_modulus(MOD::PARAMS.modulus()) } {
            Algorithm::Atkins => self.sqrt_atkins(),
            Algorithm::Shanks => self.sqrt_shanks(),
            Algorithm::TonelliShanks => self.sqrt_tonelli_shanks(),
        }
    }

    /// Atkins algorithm for `q ≡ 5 (mod 8)`.
    ///
    /// From <https://eprint.iacr.org/2012/685.pdf> (page 10, algorithm 3)
    fn sqrt_atkins(&self) -> CtOption<Self> {
        debug_assert!(mod_residue(MOD::PARAMS.modulus(), 8) == 5);

        let mod_minus_5_over_8 = const {
            MOD::PARAMS
                .modulus()
                .as_ref()
                .wrapping_sub(&Uint::<LIMBS>::from_u64(5))
                .shr(3)
        };

        let t = Self::from_u64(2).pow_vartime(&mod_minus_5_over_8);
        let a1 = self.pow_vartime(&mod_minus_5_over_8);
        let a0 = (a1.square() * self).square();
        let b = t * a1;
        let ab = self * &b;
        let i = Self::from_u64(2) * ab * b;
        let x = ab * (i - Self::ONE);
        CtOption::new(x, !a0.ct_eq(&-Self::ONE))
    }

    /// Shanks algorithm for `q ≡ 3 (mod 4)`.
    ///
    /// For `q = 3 (mod 4)`, sqrt can be computed with only one exponentiation as
    /// `self^((q + 1) / 4) (mod q)`.
    ///
    /// From <https://eprint.iacr.org/2012/685.pdf> (page 12, algorithm 5)
    fn sqrt_shanks(&self) -> CtOption<Self> {
        debug_assert!(mod_residue(MOD::PARAMS.modulus(), 4) == 3);

        let mod_plus_1_over_4 = const {
            MOD::PARAMS
                .modulus()
                .as_ref()
                .wrapping_add(&Uint::<LIMBS>::ONE)
                .shr(2)
        };

        let sqrt = self.pow_vartime(&mod_plus_1_over_4);
        CtOption::new(sqrt, (sqrt * sqrt).ct_eq(self))
    }

    /// Tonelli-Shanks algorithm works for every odd prime.
    ///
    /// From <https://eprint.iacr.org/2012/685.pdf> (page 12, algorithm 5)
    fn sqrt_tonelli_shanks(&self) -> CtOption<MontyFieldElement<MOD, { LIMBS }>> {
        let t_minus_1_over_2 = const { MOD::T.wrapping_sub(&Uint::<LIMBS>::ONE).shr(1) };
        let w = self.pow_vartime(&t_minus_1_over_2);

        let mut v = Self::S;
        let mut x = *self * w;
        let mut b = x * w;
        let mut z = Self::ROOT_OF_UNITY;

        for max_v in (1..=Self::S).rev() {
            let mut k = 1;
            let mut tmp = b.square();
            let mut j_less_than_v = Choice::from(1);

            for j in 2..max_v {
                let tmp_is_one = tmp.ct_eq(&Self::ONE);
                let squared = Self::conditional_select(&tmp, &z, tmp_is_one).square();
                tmp = Self::conditional_select(&squared, &tmp, tmp_is_one);
                let new_z = Self::conditional_select(&z, &squared, tmp_is_one);
                j_less_than_v &= !j.ct_eq(&v);
                k = u32::conditional_select(&j, &k, tmp_is_one);
                z = Self::conditional_select(&z, &new_z, j_less_than_v);
            }

            let result = x * z;
            x = Self::conditional_select(&result, &x, b.ct_eq(&Self::ONE));
            z = z.square();
            b *= z;
            v = k;
        }

        CtOption::new(x, x.square().ct_eq(self))
    }
}

/// Compute residue classes of the modulus for selecting particular square root algorithms.
const fn mod_residue<const LIMBS: usize>(p: &Odd<Uint<LIMBS>>, n: u32) -> u32 {
    let n = core::num::NonZero::new(n).expect("n must be nonzero");
    let residue = p.as_ref().rem_vartime(&NonZeroUint::from_u32(n));
    residue.as_words()[0] as u32
}

#[cfg(test)]
mod tests {
    use super::Algorithm;
    use crate::{ByteOrder, MontyFieldElement, monty_field_params};
    use ff::PrimeField;
    use subtle::CtOption;

    /// Generic sqrt test.
    fn sqrt_test<Fe: PrimeField, F: Fn(&Fe) -> CtOption<Fe>>(f: F) {
        for &n in &[1u64, 4, 9, 16, 25, 36, 49, 64] {
            let fe = Fe::from(n);
            let sqrt = f(&fe).unwrap();
            assert_eq!(sqrt.square(), fe);
        }
    }

    /// Tests the Atkins algorithm implementation
    #[test]
    fn atkins() {
        use bigint::U384;

        // brainpoolP384 scalar field
        monty_field_params!(
            name: Bp384ScalarParams,
            modulus: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
            uint: U384,
            byte_order: ByteOrder::BigEndian,
            multiplicative_generator: 2,
            fe_name: "Scalar",
            doc: "brainpoolP384 scalar modulus"
        );

        assert_eq!(
            Algorithm::for_modulus(Bp384ScalarParams::PARAMS.modulus()),
            Algorithm::Atkins
        );

        type Bp384Scalar = MontyFieldElement<Bp384ScalarParams, { U384::LIMBS }>;
        sqrt_test(Bp384Scalar::sqrt_atkins);
    }

    /// Tests the Shanks algorithm implementation, where `p ≡ 3 mod 4`
    #[test]
    fn shanks() {
        use bigint::U256;

        // P-256 base field
        monty_field_params!(
            name: P256FieldParams,
            modulus: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            uint: U256,
            byte_order: ByteOrder::BigEndian,
            multiplicative_generator: 6,
            fe_name: "FieldElement",
            doc: "P-256 field modulus"
        );

        assert_eq!(
            Algorithm::for_modulus(P256FieldParams::PARAMS.modulus()),
            Algorithm::Shanks
        );

        type P256Fe = MontyFieldElement<P256FieldParams, { U256::LIMBS }>;
        sqrt_test(P256Fe::sqrt_shanks);
    }

    /// Tests the generic Tonelli-Shanks implementation, where `p ≡ 1 mod 4`
    #[test]
    fn tonelli_shanks() {
        use bigint::U192;

        // P-192 scalar field
        monty_field_params!(
            name: P192ScalarParams,
            modulus: "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
            uint: U192,
            byte_order: ByteOrder::BigEndian,
            multiplicative_generator: 3,
            fe_name: "Scalar",
            doc: "P-192 scalar modulus"
        );

        assert_eq!(
            Algorithm::for_modulus(P192ScalarParams::PARAMS.modulus()),
            Algorithm::TonelliShanks
        );

        type P192Scalar = MontyFieldElement<P192ScalarParams, { U192::LIMBS }>;
        sqrt_test(P192Scalar::sqrt_tonelli_shanks);
    }
}
