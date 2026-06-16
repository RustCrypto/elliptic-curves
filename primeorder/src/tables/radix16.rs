//! Radix-16 signed-digit decomposition for constant-time scalar multiplication.

use crate::PrimeFieldExt;
use core::ops::{Add, Index};
use elliptic_curve::{
    FieldBytesSize,
    array::{Array, ArraySize, sizes::U1},
};

/// Compute number of radix-16 digits for the given elliptic curve's scalar field.
///
/// Two nibbles per scalar byte, plus one carry digit for signed re-centering.
pub type Radix16Digits<C> = <<FieldBytesSize<C> as Add>::Output as Add<U1>>::Output;

/// Signed radix-16 decomposition of a scalar.
#[derive(Clone, Debug, Default)]
pub struct Radix16Decomposition<Digits: ArraySize> {
    digits: Array<i8, Digits>,
}

impl<Digits: ArraySize> Radix16Decomposition<Digits> {
    /// Decompose a scalar into signed radix-16 digits.
    ///
    /// Produces `[a_0, ..., a_{digits-1}]` such that `scalar = sum(a_j * 16^j)` and each `a_j` is
    /// within `[-8, 8]`.
    ///
    /// `a_0` is the least significant position; `a_{digits-1}` absorbs carry: the resulting
    /// decomposition can be negative, so we need an additional byte to store it.
    ///
    /// Assumes `x < 2^(4*(digits-1))`.
    pub fn new<Scalar: PrimeFieldExt>(scalar: &Scalar) -> Self {
        // TODO(tarcieri): `debug_assert!` that `scalar < 2^(4*(digits-1))`
        let mut ret = Self::default();

        // Step 1: change radix.
        // Convert from big endian radix-256 (bytes) to radix-16 (nibbles).
        let repr = scalar.to_be_repr();
        let bytes = repr.as_ref();

        for i in 0..(Digits::USIZE - 1) / 2 {
            let b = bytes[bytes.len() - 1 - i];
            ret.digits[2 * i] = (b & 0xf) as i8;
            ret.digits[2 * i + 1] = ((b >> 4) & 0xf) as i8;
        }

        // Step 2: recenter coefficients from [0, 16) to [-8, 8)
        for i in 0..(Digits::USIZE - 1) {
            let carry = (ret.digits[i] + 8) >> 4;
            ret.digits[i] -= carry << 4;
            ret.digits[i + 1] += carry;
        }

        ret
    }
}

impl<Digits: ArraySize> Index<usize> for Radix16Decomposition<Digits> {
    type Output = i8;

    #[inline]
    fn index(&self, index: usize) -> &i8 {
        &self.digits[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::array::sizes::{U57, U65, U133};

    /// Mirror `Decomposition::new` byte extraction for raw big endian `Uint` buffers.
    fn decompose_from_padded_be_uint<Digits: ArraySize>(
        bytes: &[u8],
        byte_len: usize,
    ) -> Radix16Decomposition<Digits> {
        let uint_byte_len = bytes.len();
        assert!(uint_byte_len >= byte_len);

        let len = 2 * byte_len + 1;
        let mut digits = Array::<i8, Digits>::default();

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

        Radix16Decomposition { digits }
    }

    fn decompose_be_bytes<Digits: ArraySize>(bytes: &[u8]) -> Radix16Decomposition<Digits> {
        decompose_from_padded_be_uint(bytes, bytes.len())
    }

    fn assert_digits_in_range<Digits: ArraySize>(d: &Radix16Decomposition<Digits>) {
        for i in 0..Digits::USIZE {
            let digit = d[i];
            assert!((-8..=8).contains(&digit), "digit[{i}] = {digit}");
        }
    }

    #[test]
    fn digit_range() {
        let d = decompose_be_bytes::<U65>(&[0xabu8; 32]);
        assert_digits_in_range(&d);
    }

    /// p224 stores 224-bit scalars in a wider `Uint` (e.g. 32-byte U256 on 64-bit).
    #[test]
    fn p224_padded_uint_ignores_high_prefix() {
        let mut bytes = [0xffu8; 32];
        bytes[4..32].fill(0);
        bytes[31] = 2;

        let d = decompose_from_padded_be_uint::<U57>(&bytes, 28);
        assert_eq!(d[0], 2);
        assert_digits_in_range(&d);
        for i in 1..57 {
            assert_eq!(d[i], 0);
        }
    }

    /// p521 uses a 72-byte `Uint` for a 521-bit (66-byte) scalar field.
    #[test]
    fn p521_padded_uint_ignores_high_prefix() {
        let mut bytes = [0xffu8; 72];
        bytes[6..72].fill(0);
        bytes[71] = 3;

        let d = decompose_from_padded_be_uint::<U133>(&bytes, 66);
        assert_eq!(d[0], 3);
        assert_digits_in_range(&d);
        for i in 1..133 {
            assert_eq!(d[i], 0);
        }
    }

    #[test]
    fn reconstruction() {
        let bytes: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let d = decompose_be_bytes::<U65>(&bytes);

        let mut acc: i128 = 0;
        let mut radix: i128 = 1;
        for i in 0..17 {
            acc += i128::from(d[i]) * radix;
            radix *= 16;
        }

        let mut expected: i128 = 0;
        for b in bytes {
            expected = (expected << 8) | i128::from(b);
        }

        assert_eq!(acc, expected);
    }

    #[test]
    fn zero_scalar() {
        let d = decompose_be_bytes::<U65>(&[0u8; 32]);
        for i in 0..65 {
            assert_eq!(d[i], 0);
        }
    }
}
