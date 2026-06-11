//! Radix-16 signed-digit decomposition for constant-time scalar multiplication.

use core::ops::Add;

use elliptic_curve::{
    CurveArithmetic, PrimeCurve, PrimeField, Scalar,
    array::typenum::{Prod, U1, U2, Unsigned},
    bigint::ArrayEncoding,
    consts::U66,
};

/// Largest scalar `FieldBytes` size among primeorder curves (P-521).
type MaxScalarFieldBytes = U66;

/// Two nibbles per scalar byte, plus one carry digit for signed recentering.
type MaxDigits = <Prod<MaxScalarFieldBytes, U2> as Add<U1>>::Output;

const MAX_DIGITS: usize = MaxDigits::USIZE;

/// Signed radix-16 decomposition of a scalar
/// Produces `[a_0, ..., a_{len-1}]` such that
/// `scalar = sum(a_j * 16^j)` and each `a_j` is in `[-8, 8]`.
/// `a_0` is the least significant position; `a_{len-1}` absorbs carry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Radix16Decomposition {
    digits: [i8; MAX_DIGITS],
    len: usize,
}

impl Radix16Decomposition {
    /// Decompose a scalar into signed radix-16 digits.
    ///
    /// Uses the scalar's canonical integer encoding in **big-endian** byte order,
    /// matching k256's `Scalar::to_bytes()` layout regardless of a curve's
    /// `FieldBytes` endianness (e.g. bignp256 uses LE `to_repr()`).
    pub(crate) fn new<C>(scalar: &Scalar<C>) -> Self
    where
        C: PrimeCurve + CurveArithmetic,
        Scalar<C>: PrimeField + Into<C::Uint>,
        C::Uint: ArrayEncoding,
    {
        let num_bits = Scalar::<C>::NUM_BITS;
        let byte_len = num_bits.div_ceil(8) as usize;
        let len = 2 * byte_len + 1;

        debug_assert!(len <= MAX_DIGITS);

        let bytes = Into::<C::Uint>::into(*scalar).to_be_byte_array();
        let bytes: &[u8] = bytes.as_ref();
        let uint_byte_len = bytes.len();
        debug_assert!(uint_byte_len >= byte_len);

        let mut digits = [0i8; MAX_DIGITS];

        // Step 1: change radix — BE bytes, LSB byte first in digit order (matches k256).
        // `C::Uint` may be wider than `NUM_BITS` (e.g. p224 in U256, p521 in 72-byte Uint).
        for i in 0..byte_len {
            let b = bytes[uint_byte_len - 1 - i];
            digits[2 * i] = (b & 0xf) as i8;
            digits[2 * i + 1] = ((b >> 4) & 0xf) as i8;
        }

        // Step 2: recenter coefficients from [0, 16) to [-8, 8)
        for i in 0..(len - 1) {
            let carry = (digits[i] + 8) >> 4;
            digits[i] -= carry << 4;
            digits[i + 1] += carry;
        }

        Self { digits, len }
    }

    /// Number of digit slots for this decomposition.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Digit at index `i` (`0` = least significant position).
    #[inline]
    pub(crate) fn digit(&self, i: usize) -> i8 {
        self.digits[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror [`Radix16Decomposition::new`] byte extraction for raw BE `Uint` buffers.
    fn decompose_from_padded_be_uint(bytes: &[u8], byte_len: usize) -> Radix16Decomposition {
        let uint_byte_len = bytes.len();
        assert!(uint_byte_len >= byte_len);

        let len = 2 * byte_len + 1;
        let mut digits = [0i8; MAX_DIGITS];

        for i in 0..byte_len {
            let b = bytes[uint_byte_len - 1 - i];
            digits[2 * i] = (b & 0xf) as i8;
            digits[2 * i + 1] = ((b >> 4) & 0xf) as i8;
        }

        for i in 0..(len - 1) {
            let carry = (digits[i] + 8) >> 4;
            digits[i] -= carry << 4;
            digits[i + 1] += carry;
        }

        Radix16Decomposition { digits, len }
    }

    fn decompose_be_bytes(bytes: &[u8]) -> Radix16Decomposition {
        decompose_from_padded_be_uint(bytes, bytes.len())
    }

    fn assert_digits_in_range(d: &Radix16Decomposition) {
        for i in 0..d.len() {
            let digit = d.digit(i);
            assert!((-8..=8).contains(&digit), "digit[{i}] = {digit}");
        }
    }

    #[test]
    fn digit_range() {
        let d = decompose_be_bytes(&[0xabu8; 32]);
        assert_digits_in_range(&d);
    }

    /// p224 stores 224-bit scalars in a wider `Uint` (e.g. 32-byte U256 on 64-bit).
    #[test]
    fn p224_padded_uint_ignores_high_prefix() {
        let mut bytes = [0xffu8; 32];
        bytes[4..32].fill(0);
        bytes[31] = 2;

        let d = decompose_from_padded_be_uint(&bytes, 28);
        assert_eq!(d.len(), 57);
        assert_eq!(d.digit(0), 2);
        assert_digits_in_range(&d);
        for i in 1..d.len() {
            assert_eq!(d.digit(i), 0);
        }
    }

    /// p521 uses a 72-byte `Uint` for a 521-bit (66-byte) scalar field.
    #[test]
    fn p521_padded_uint_ignores_high_prefix() {
        let mut bytes = [0xffu8; 72];
        bytes[6..72].fill(0);
        bytes[71] = 3;

        let d = decompose_from_padded_be_uint(&bytes, 66);
        assert_eq!(d.len(), 133);
        assert_eq!(d.digit(0), 3);
        assert_digits_in_range(&d);
        for i in 1..d.len() {
            assert_eq!(d.digit(i), 0);
        }
    }

    #[test]
    fn len_formula_p192_p384() {
        assert_eq!(decompose_from_padded_be_uint(&[0u8; 24], 24).len(), 49);
        assert_eq!(decompose_from_padded_be_uint(&[0u8; 48], 48).len(), 97);
    }

    #[test]
    fn reconstruction() {
        let bytes: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let d = decompose_be_bytes(&bytes);

        let mut acc: i128 = 0;
        let mut radix: i128 = 1;
        for i in 0..d.len() {
            acc += i128::from(d.digit(i)) * radix;
            radix *= 16;
        }

        let mut expected: i128 = 0;
        for b in bytes {
            expected = (expected << 8) | i128::from(b);
        }

        assert_eq!(acc, expected);
    }

    #[test]
    fn len_formula() {
        // 256-bit → 32 bytes → 65 digits
        let d = decompose_be_bytes(&[0u8; 32]);
        assert_eq!(d.len(), 65);

        // 521-bit → 66 bytes → 133 digits
        let d = decompose_be_bytes(&[0u8; 66]);
        assert_eq!(d.len(), 133);
    }

    #[test]
    fn zero_scalar() {
        let d = decompose_be_bytes(&[0u8; 32]);
        for i in 0..d.len() {
            assert_eq!(d.digit(i), 0);
        }
    }
}
