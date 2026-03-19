//! Variable-time wNAF (windowed Non-Adjacent Form) scalar multiplication.
//!
//! Provides a correct wNAF implementation for curves whose
//! `Scalar::to_repr()` returns big-endian bytes (SEC1/NIST convention).
//!
//! The upstream `group::Wnaf` assumes little-endian repr and silently
//! produces wrong results for big-endian curves. It also drops the
//! final carry in `wnaf_form` when the scalar fills all `bit_len`
//! bits, which is masked on BLS12-381 (255-bit modulus in 256-bit
//! repr) but causes incorrect results on p256/k256/p384/p521.

use alloc::vec::Vec;
use core::iter;

use elliptic_curve::group::ff::PrimeField;
use elliptic_curve::point::Double;

use crate::{PrimeCurveParams, ProjectivePoint};

/// Compute the wNAF lookup table for `base` with the given window
/// size: entries are `[P, 3P, 5P, ..., (2^w - 1)P]`.
fn wnaf_table<C>(mut base: ProjectivePoint<C>, window: usize) -> Vec<ProjectivePoint<C>>
where
    C: PrimeCurveParams,
    elliptic_curve::FieldBytes<C>: Copy,
{
    let mut table = Vec::with_capacity(1 << (window - 1));
    let dbl = Double::double(&base);
    for _ in 0..(1 << (window - 1)) {
        table.push(base);
        base += &dbl;
    }
    table
}

/// Convert a big-endian scalar repr to wNAF digit form.
fn wnaf_form(scalar_be: &[u8], window: usize) -> Vec<i64> {
    debug_assert!(window >= 2);
    debug_assert!(window <= 64);

    // Reverse BE repr to LE for the bit-scanning loop.
    let mut le = scalar_be.to_vec();
    le.reverse();

    let bit_len = le.len() * 8;
    let mut wnaf = Vec::with_capacity(bit_len + 1);

    let width = 1u64 << window;
    let window_mask = width - 1;

    let mut pos = 0;
    let mut carry = 0u64;

    while pos < bit_len {
        let u64_idx = pos / 64;
        let bit_idx = pos % 64;

        let cur = read_le_u64(&le, u64_idx);
        let next = read_le_u64(&le, u64_idx + 1);
        let bit_buf = if bit_idx + window < 64 {
            cur >> bit_idx
        } else {
            (cur >> bit_idx) | (next << (64 - bit_idx))
        };

        let window_val = carry + (bit_buf & window_mask);

        if window_val & 1 == 0 {
            wnaf.push(0);
            pos += 1;
        } else if window_val < width / 2 {
            carry = 0;
            wnaf.push(window_val as i64);
            wnaf.extend(iter::repeat_n(0, window - 1));
            pos += window;
        } else {
            carry = 1;
            wnaf.push((window_val as i64).wrapping_sub(width as i64));
            wnaf.extend(iter::repeat_n(0, window - 1));
            pos += window;
        }
    }

    // Emit remaining carry — needed when the scalar fills all
    // `bit_len` bits and the last digit was negative.
    if carry != 0 {
        wnaf.push(carry as i64);
    }

    wnaf
}

/// Read a little-endian `u64` limb from a byte slice, zero-extending
/// past the end.
#[inline]
fn read_le_u64(bytes: &[u8], limb_idx: usize) -> u64 {
    let start = limb_idx * 8;
    if start >= bytes.len() {
        return 0;
    }
    let end = (start + 8).min(bytes.len());
    let mut buf = [0u8; 8];
    buf[..end - start].copy_from_slice(&bytes[start..end]);
    u64::from_le_bytes(buf)
}

/// Evaluate a wNAF digit sequence against a precomputed table.
fn wnaf_exp<C>(table: &[ProjectivePoint<C>], wnaf: &[i64]) -> ProjectivePoint<C>
where
    C: PrimeCurveParams,
    elliptic_curve::FieldBytes<C>: Copy,
{
    use elliptic_curve::group::Group as _;

    let mut result = ProjectivePoint::<C>::identity();
    let mut found_one = false;

    for &n in wnaf.iter().rev() {
        if found_one {
            result = Double::double(&result);
        }
        if n != 0 {
            found_one = true;
            if n > 0 {
                result += &table[(n / 2) as usize];
            } else {
                result -= &table[((-n) / 2) as usize];
            }
        }
    }

    result
}

/// Variable-time wNAF scalar multiplication.
///
/// A self-contained replacement for `group::Wnaf` that correctly
/// handles the big-endian scalar representations used by SEC1/NIST
/// curves.
///
/// # Examples
///
/// ```ignore
/// use primeorder::wnaf::WnafScalarMul;
///
/// // Single multiplication
/// let result = WnafScalarMul::new().mul(&scalar, base);
///
/// // One scalar, many bases (precompute wNAF digits once)
/// let ctx = WnafScalarMul::new().with_scalar(&scalar);
/// let results: Vec<_> = bases.iter().map(|b| ctx.mul_base(*b)).collect();
/// ```
pub struct WnafScalarMul {
    window: usize,
}

impl Default for WnafScalarMul {
    fn default() -> Self {
        Self::new()
    }
}

impl WnafScalarMul {
    /// Create a new context with the default window size (4).
    pub fn new() -> Self {
        Self { window: 4 }
    }

    /// Compute `scalar * base` using wNAF multiplication.
    pub fn mul<C>(
        &self,
        scalar: &elliptic_curve::Scalar<C>,
        base: ProjectivePoint<C>,
    ) -> ProjectivePoint<C>
    where
        C: PrimeCurveParams,
        elliptic_curve::FieldBytes<C>: Copy,
    {
        let repr = scalar.to_repr();
        let digits = wnaf_form(repr.as_ref(), self.window);
        let table = wnaf_table(base, self.window);
        wnaf_exp(&table, &digits)
    }

    /// Precompute the wNAF form of a scalar for reuse with many
    /// bases.
    pub fn with_scalar<C>(&self, scalar: &elliptic_curve::Scalar<C>) -> PreparedScalar
    where
        C: PrimeCurveParams,
        elliptic_curve::FieldBytes<C>: Copy,
    {
        let repr = scalar.to_repr();
        PreparedScalar {
            digits: wnaf_form(repr.as_ref(), self.window),
            window: self.window,
        }
    }
}

/// A scalar whose wNAF digit form has been precomputed.
pub struct PreparedScalar {
    digits: Vec<i64>,
    window: usize,
}

impl PreparedScalar {
    /// Multiply this prepared scalar by a base point.
    pub fn mul_base<C>(&self, base: ProjectivePoint<C>) -> ProjectivePoint<C>
    where
        C: PrimeCurveParams,
        elliptic_curve::FieldBytes<C>: Copy,
    {
        let table = wnaf_table(base, self.window);
        wnaf_exp(&table, &self.digits)
    }
}
