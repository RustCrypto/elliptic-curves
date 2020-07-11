//! Scalar field arithmetic.

use core::{convert::TryInto, ops::Neg};
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::arithmetic::util::sbb;

/// The number of 64-bit limbs used to represent a [`Scalar`].
const LIMBS: usize = 4;

/// Constant representing the modulus
/// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
const MODULUS: [u64; LIMBS] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// Constant representing the modulus / 2
const FRAC_MODULUS_2: [u64; LIMBS] = [
    0xDFE9_2F46_681B_20A0,
    0x5D57_6E73_57A4_501D,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

/// An element in the finite field modulo n.
// TODO: This currently uses native representation internally, but will probably move to
// Montgomery representation later.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct Scalar(pub(crate) [u64; LIMBS]);

impl From<u64> for Scalar {
    fn from(k: u64) -> Self {
        Scalar([k, 0, 0, 0])
    }
}

impl Scalar {
    /// Returns the zero scalar.
    pub const fn zero() -> Scalar {
        Scalar([0, 0, 0, 0])
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> Scalar {
        Scalar([1, 0, 0, 0])
    }

    /// Attempts to parse the given byte array as an SEC-1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        let mut w = [0u64; LIMBS];

        // Interpret the bytes as a big-endian integer w.
        w[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        w[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        w[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        w[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());

        // If w is in the range [0, n) then w - n will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb(w[0], MODULUS[0], 0);
        let (_, borrow) = sbb(w[1], MODULUS[1], borrow);
        let (_, borrow) = sbb(w[2], MODULUS[2], borrow);
        let (_, borrow) = sbb(w[3], MODULUS[3], borrow);
        let is_some = (borrow as u8) & 1;

        CtOption::new(Scalar(w), Choice::from(is_some))
    }

    /// Returns the SEC-1 encoding of this scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut ret = [0; 32];
        ret[0..8].copy_from_slice(&self.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&self.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&self.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&self.0[0].to_be_bytes());
        ret
    }

    /// Is this scalar equal to zero?
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Scalar::zero())
    }

    /// Is this scalar greater than or equal to n / 2?
    pub fn is_high(&self) -> Choice {
        let (_, borrow) = sbb(self.0[0], FRAC_MODULUS_2[0], 0);
        let (_, borrow) = sbb(self.0[1], FRAC_MODULUS_2[1], borrow);
        let (_, borrow) = sbb(self.0[2], FRAC_MODULUS_2[2], borrow);
        let (_, borrow) = sbb(self.0[3], FRAC_MODULUS_2[3], borrow);
        (borrow & 1).ct_eq(&0)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        let (w0, borrow) = sbb(MODULUS[0], self.0[0], 0);
        let (w1, borrow) = sbb(MODULUS[1], self.0[1], borrow);
        let (w2, borrow) = sbb(MODULUS[2], self.0[2], borrow);
        let (w3, _) = sbb(MODULUS[3], self.0[3], borrow);
        Scalar::conditional_select(&Scalar([w0, w1, w2, w3]), &Scalar::zero(), self.is_zero())
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize()
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, FRAC_MODULUS_2, LIMBS, MODULUS};

    /// n - 1
    const MODULUS_MINUS_ONE: [u64; LIMBS] = [MODULUS[0] - 1, MODULUS[1], MODULUS[2], MODULUS[3]];

    #[test]
    fn is_high() {
        // 0 is not high
        let high: bool = Scalar::zero().is_high().into();
        assert!(!high);

        // FRAC_MODULUS_2 - 1 is not high
        let mut scalar = Scalar(FRAC_MODULUS_2);
        scalar.0[3] -= 1;
        let high: bool = scalar.is_high().into();
        assert!(!high);

        // FRAC_MODULUS_2 is high
        let high: bool = Scalar(FRAC_MODULUS_2).is_high().into();
        assert!(high);

        // MODULUS - 1 is high
        let mut scalar = Scalar(MODULUS);
        scalar.0[3] -= 1;
        let high: bool = scalar.is_high().into();
        assert!(high);
    }

    #[test]
    fn negate() {
        let zero_neg = -Scalar::zero();
        assert_eq!(zero_neg.0, [0u64; LIMBS]);

        let one_neg = -Scalar::one();
        assert_eq!(one_neg.0, MODULUS_MINUS_ONE);

        let frac_modulus_2_neg = -Scalar(FRAC_MODULUS_2);
        let mut frac_modulus_2_plus_one = FRAC_MODULUS_2;
        frac_modulus_2_plus_one[0] += 1;
        assert_eq!(frac_modulus_2_neg.0, frac_modulus_2_plus_one);

        let modulus_minus_one_neg = -Scalar(MODULUS_MINUS_ONE);
        assert_eq!(modulus_minus_one_neg.0, Scalar::one().0);
    }
}
