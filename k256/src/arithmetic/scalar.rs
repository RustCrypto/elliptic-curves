//! Scalar field arithmetic.

use core::ops::{Add, AddAssign, Mul, MulAssign, Shr, Sub, SubAssign};

#[cfg(test)]
use num_bigint::{BigUint, ToBigUint};

#[cfg(not(feature = "scalar-32bit"))]
pub use super::scalar_4x64::Scalar4x64 as ScalarImpl;
#[cfg(not(feature = "scalar-32bit"))]
pub use super::scalar_4x64::WideScalar8x64 as WideScalarImpl;

#[cfg(feature = "scalar-32bit")]
pub use super::scalar_8x32::Scalar8x32 as ScalarImpl;
#[cfg(feature = "scalar-32bit")]
pub use super::scalar_8x32::WideScalar16x32 as WideScalarImpl;

use core::ops::Neg;
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "rand")]
use elliptic_curve::rand_core::{CryptoRng, RngCore};

/// An element in the finite field modulo n.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct Scalar(ScalarImpl);

#[cfg(test)]
impl From<&BigUint> for Scalar {
    fn from(x: &BigUint) -> Self {
        debug_assert!(x < &Scalar::modulus_as_biguint());
        Self(ScalarImpl::from(x))
    }
}

#[cfg(test)]
impl From<BigUint> for Scalar {
    fn from(x: BigUint) -> Self {
        debug_assert!(&x < &Scalar::modulus_as_biguint());
        Self(ScalarImpl::from(&x))
    }
}

#[cfg(test)]
impl ToBigUint for Scalar {
    fn to_biguint(&self) -> Option<BigUint> {
        self.0.to_biguint()
    }
}

impl From<u32> for Scalar {
    fn from(k: u32) -> Self {
        Self(ScalarImpl::from(k))
    }
}

impl Scalar {
    /// Returns the zero scalar.
    pub const fn zero() -> Self {
        Self(ScalarImpl::zero())
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> Scalar {
        Self(ScalarImpl::one())
    }

    pub fn is_zero(&self) -> Choice {
        Choice::from(self.0.is_zero())
    }

    /// Returns the value of the scalar truncated to a 32-bit unsigned integer.
    pub fn truncate_to_u32(&self) -> u32 {
        self.0.truncate_to_u32()
    }

    /// Attempts to parse the given byte array as an SEC-1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        let value = ScalarImpl::from_bytes(bytes);
        CtOption::map(value, |x| Self(x))
    }

    /// Returns the SEC-1 encoding of this scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Is this scalar equal to zero?
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Scalar::zero())
    }

    /// Is this scalar greater than or equal to n / 2?
    pub fn is_high(&self) -> Choice {
        self.0.is_high()
    }

    /// Negates the scalar.
    pub fn negate(&self) -> Self {
        Self(self.0.negate())
    }

    /// Modulo add two scalars
    pub fn add(&self, rhs: &Scalar) -> Scalar {
        Self(self.0.add(&(rhs.0)))
    }

    /// Modulo subtract one scalar from the other.
    pub fn sub(&self, rhs: &Scalar) -> Scalar {
        // TODO: see if a separate sub() implementation is faster
        self.add(&rhs.negate())
    }

    /// Modulo multiply two scalars
    pub fn mul(&self, rhs: &Scalar) -> Scalar {
        Self(self.0.mul(&(rhs.0)))
    }

    /// Right shifts the scalar. Note: not constant-time in `shift`.
    pub fn rshift(&self, shift: usize) -> Scalar {
        Self(self.0.rshift(shift))
    }

    #[cfg(test)]
    /// Returns the scalar modulus as a `BigUint` object.
    pub fn modulus_as_biguint() -> BigUint {
        Self::one().negate().to_biguint().unwrap() + 1.to_biguint().unwrap()
    }

    #[cfg(feature = "zeroize")]
    /// Fills this scalar with zeros.
    pub fn zeroize(&mut self) {
        self.0.zeroize()
    }

    /// Returns a uniformly-random scalar.
    #[cfg(feature = "rand")]
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        // We reduce a random 512-bit value into a 256-bit field, which results in a
        // negligible bias from the uniform distribution.
        let mut buf = [0; 64];
        rng.fill_bytes(&mut buf);
        Scalar(WideScalarImpl::from_bytes(&buf).reduce())
    }
}

impl Shr<usize> for Scalar {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        self.rshift(rhs)
    }
}

impl Shr<usize> for &Scalar {
    type Output = Scalar;

    fn shr(self, rhs: usize) -> Self::Output {
        self.rshift(rhs)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(ScalarImpl::conditional_select(&(a.0), &(b.0), choice))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&(other.0))
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        self.negate()
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar::add(self, other)
    }
}

impl Add<Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar::add(self, &other)
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar::add(&self, other)
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, rhs: Scalar) {
        *self = Scalar::add(self, &rhs);
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar::sub(self, other)
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar::sub(&self, other)
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: Scalar) {
        *self = Scalar::sub(self, &rhs);
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar::mul(self, other)
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar::mul(&self, other)
    }
}

impl MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = Scalar::mul(self, &rhs);
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.zeroize()
    }
}

#[cfg(test)]
mod tests {
    use super::Scalar;
    use crate::arithmetic::util::u64_array_to_biguint;
    use num_bigint::ToBigUint;
    use proptest::prelude::*;

    #[test]
    fn is_high() {
        // 0 is not high
        let high: bool = Scalar::zero().is_high().into();
        assert!(!high);

        let m = Scalar::modulus_as_biguint();
        let m_by_2 = &m >> 1;
        let one = 1.to_biguint().unwrap();

        // M / 2 - 1 is not high
        let high: bool = Scalar::from(&m_by_2 - &one).is_high().into();
        assert!(!high);

        // M / 2 is high
        let high: bool = Scalar::from(&m_by_2).is_high().into();
        assert!(high);

        // MODULUS - 1 is high
        let high: bool = Scalar::from(&m - &one).is_high().into();
        assert!(high);
    }

    #[test]
    fn negate() {
        let zero_neg = -Scalar::zero();
        assert_eq!(zero_neg, Scalar::zero());

        let m = Scalar::modulus_as_biguint();
        let one = 1.to_biguint().unwrap();
        let m_minus_one = &m - &one;
        let m_by_2 = &m >> 1;

        let one_neg = -Scalar::one();
        assert_eq!(one_neg, Scalar::from(&m_minus_one));

        let frac_modulus_2_neg = -Scalar::from(&m_by_2);
        let frac_modulus_2_plus_one = Scalar::from(&m_by_2 + &one);
        assert_eq!(frac_modulus_2_neg, frac_modulus_2_plus_one);

        let modulus_minus_one_neg = -Scalar::from(&m - &one);
        assert_eq!(modulus_minus_one_neg, Scalar::one());
    }

    #[cfg(feature = "rand")]
    #[test]
    fn generate() {
        use elliptic_curve::rand_core::OsRng;
        let a = Scalar::generate(&mut OsRng);
        // just to make sure `a` is not optimized out by the compiler
        assert_eq!((a - &a).is_zero().unwrap_u8(), 1);
    }

    prop_compose! {
        fn scalar()(words in any::<[u64; 4]>()) -> Scalar {
            let mut res = u64_array_to_biguint(&words);
            let m = Scalar::modulus_as_biguint();
            // Modulus is 256 bit long, same as the maximum `res`,
            // so this is guaranteed to land us in the correct range.
            if res >= m {
                res -= m;
            }
            Scalar::from(&res)
        }
    }

    proptest! {

        #[test]
        fn fuzzy_roundtrip_to_bytes(a in scalar()) {
            let bytes = a.to_bytes();
            let a_back = Scalar::from_bytes(bytes).unwrap();
            assert_eq!(a, a_back);
        }

        #[test]
        fn fuzzy_mul(a in scalar(), b in scalar()) {
            let a_bi = a.to_biguint().unwrap();
            let b_bi = b.to_biguint().unwrap();

            let res_bi = (&a_bi * &b_bi) % &Scalar::modulus_as_biguint();
            let res_ref = Scalar::from(&res_bi);
            let res_test = a.mul(&b);

            assert_eq!(res_ref, res_test);
        }

        #[test]
        fn fuzzy_rshift(a in scalar(), b in 0usize..512) {
            let a_bi = a.to_biguint().unwrap();

            let res_bi = &a_bi >> b;
            let res_ref = Scalar::from(&res_bi);
            let res_test = a >> b;

            assert_eq!(res_ref, res_test);
        }
    }
}
