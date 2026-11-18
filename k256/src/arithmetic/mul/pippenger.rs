//! Bucketed Pippenger multiscalar multiplication.
//!
//! The interleaved w-NAF (Straus) implementation in [`super::lincomb_vartime_glv_wnaf`] costs a
//! fixed amount of work per term regardless of how many terms there are, so its cost per element
//! is flat. Pippenger's method instead sorts terms into buckets by scalar window, which makes the
//! per-element cost fall as the term count rises: for `t` terms with window width `c` over
//! `b`-bit scalars it needs roughly `(b/c) * (t + 2 * 2^c)` additions, so a larger `t` permits a
//! larger `c` and therefore fewer window passes.
//!
//! Straus wins for small inputs, where bucket setup and reduction dominate, so
//! [`THRESHOLD`] selects between them.
//!
//! Two details make this cheaper than a textbook implementation:
//!
//! - Scalars are GLV-decomposed first, via [`glv::decompose_scalar`]. That converts `n` terms of
//!   256 bits into `2n` terms of 128 bits, halving the number of window passes and so halving
//!   total bucket-reduction cost. The sign of each half-scalar is folded into its point, exactly
//!   as [`glv::decompose_wnaf_into`] does.
//! - All `2n` points are converted to affine with a single batch inversion, so bucket
//!   accumulation uses mixed addition.

use super::glv;
use crate::{ProjectivePoint, Scalar};
use alloc::{vec, vec::Vec};
use elliptic_curve::{BatchNormalize, scalar::IsHigh};
use primeorder::PrimeFieldExt;

/// Term count at or above which Pippenger beats interleaved w-NAF.
///
/// Measured against `secp256k1_ecmult_multi_var` and the w-NAF path: the two cross at roughly 200
/// input pairs on the benchmarks used to develop this, so this is deliberately conservative.
pub(super) const THRESHOLD: usize = 256;

/// Bytes of each GLV half-scalar.
///
/// GLV decomposition bounds both half-scalars below `2^128`, so 16 bytes is exact rather than a
/// truncation. See the bound proof in [`glv`].
const HALF_SCALAR_BYTES: usize = 16;

/// Bits of each GLV half-scalar.
const HALF_SCALAR_BITS: usize = HALF_SCALAR_BYTES * 8;

/// Window width in bits for a given term count.
///
/// Chosen to minimize `(HALF_SCALAR_BITS / c) * (terms + 2 * 2^c)`, the approximate addition
/// count. The optimum grows slowly with the term count because widening the window trades more
/// bucket-reduction work for fewer window passes.
fn window_width(terms: usize) -> usize {
    if terms <= 512 {
        6
    } else if terms <= 1536 {
        7
    } else if terms <= 5120 {
        8
    } else if terms <= 20480 {
        9
    } else {
        10
    }
}

/// Extract the `width`-bit window starting at `bit_offset` from a little-endian byte string.
///
/// Bits past the end of `bytes` read as zero. Operates on bytes rather than machine words so that
/// the result does not depend on word size or host endianness.
fn window(bytes: &[u8; HALF_SCALAR_BYTES], bit_offset: usize, width: usize) -> usize {
    let mut digit = 0usize;
    let mut filled = 0usize;
    let mut index = bit_offset / 8;
    let mut bit = bit_offset % 8;

    while filled < width && index < bytes.len() {
        let take = core::cmp::min(8 - bit, width - filled);
        let mask = (1usize << take) - 1;
        digit |= ((usize::from(bytes[index]) >> bit) & mask) << filled;
        filled += take;
        index += 1;
        bit = 0;
    }

    digit
}

/// Compute `x1 * k1 + ... + xn * kn` in variable time using bucketed Pippenger.
///
/// Produces the same result as [`elliptic_curve::ops::LinearCombination::lincomb`].
pub(super) fn lincomb_vartime(xks: &[(ProjectivePoint, Scalar)]) -> ProjectivePoint {
    if xks.is_empty() {
        return ProjectivePoint::IDENTITY;
    }

    // GLV-decompose into 2n terms of 128 bits, folding each half-scalar's sign into its point.
    let terms = xks.len() * 2;
    let mut points = Vec::with_capacity(terms);
    let mut scalars = Vec::with_capacity(terms);

    for (x, k) in xks {
        let (r1, r2) = glv::decompose_scalar(k);
        let r1_neg = bool::from(r1.is_high());
        let r2_neg = bool::from(r2.is_high());
        let r1 = if r1_neg { -r1 } else { r1 };
        let r2 = if r2_neg { -r2 } else { r2 };

        points.push(if r1_neg { -*x } else { *x });
        let beta = x.endomorphism();
        points.push(if r2_neg { -beta } else { beta });

        for r in [r1, r2] {
            let mut bytes = [0u8; HALF_SCALAR_BYTES];
            bytes.copy_from_slice(&r.to_le_repr()[..HALF_SCALAR_BYTES]);
            scalars.push(bytes);
        }
    }

    // One inversion for every term, so bucket accumulation can use mixed addition.
    let affine = <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize_vartime(
        points.as_slice(),
    );

    let width = window_width(terms);
    let windows = HALF_SCALAR_BITS.div_ceil(width);

    // Digit zero contributes nothing, so it needs no bucket.
    let mut buckets = vec![ProjectivePoint::IDENTITY; (1usize << width) - 1];
    let mut acc = ProjectivePoint::IDENTITY;

    for w in (0..windows).rev() {
        // Shift the accumulator up by one window, except on the first pass.
        if w != windows - 1 {
            for _ in 0..width {
                acc.double_in_place();
            }
        }

        buckets.fill(ProjectivePoint::IDENTITY);

        for (bytes, point) in scalars.iter().zip(affine.iter()) {
            let digit = window(bytes, w * width, width);
            if digit != 0 {
                buckets[digit - 1] += point;
            }
        }

        // Reduce by running sum from the top bucket down: a point in bucket `j` must be counted
        // `j + 1` times, which this achieves with two additions per bucket.
        let mut running = ProjectivePoint::IDENTITY;
        let mut total = ProjectivePoint::IDENTITY;
        for bucket in buckets.iter().rev() {
            running += bucket;
            total += running;
        }

        acc += total;
    }

    acc
}

#[cfg(test)]
mod tests {
    use super::{THRESHOLD, lincomb_vartime, window};
    use crate::arithmetic::{ProjectivePoint, Scalar};
    use elliptic_curve::ops::LinearCombination;

    /// Deterministic distinct scalars, avoiding a dependency on `getrandom` in these tests.
    fn scalar(i: u64) -> Scalar {
        Scalar::from(i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1))
    }

    fn pairs(n: usize) -> alloc::vec::Vec<(ProjectivePoint, Scalar)> {
        (0..n as u64)
            .map(|i| (ProjectivePoint::mul_by_generator(&scalar(i | 1)), scalar(i)))
            .collect()
    }

    /// The constant-time path is the reference: a `_vartime` function must agree with it.
    fn assert_matches_reference(xks: &[(ProjectivePoint, Scalar)]) {
        let expected = ProjectivePoint::lincomb(xks);
        assert_eq!(lincomb_vartime(xks), expected);
        // And the dispatching entry point must agree too, on both sides of the threshold.
        assert_eq!(ProjectivePoint::lincomb_vartime(xks), expected);
    }

    #[test]
    fn matches_reference_across_sizes() {
        // Sizes straddle THRESHOLD so both dispatch branches are covered, and include
        // window-boundary-adjacent counts.
        for n in [
            1usize,
            2,
            3,
            20,
            100,
            THRESHOLD - 1,
            THRESHOLD,
            THRESHOLD + 1,
            512,
        ] {
            let xks = pairs(n);
            assert_matches_reference(&xks);
        }
    }

    #[test]
    fn empty_input_is_identity() {
        assert_eq!(lincomb_vartime(&[]), ProjectivePoint::IDENTITY);
    }

    #[test]
    fn zero_scalars() {
        let xks: alloc::vec::Vec<_> = (0..THRESHOLD as u64)
            .map(|i| {
                (
                    ProjectivePoint::mul_by_generator(&scalar(i | 1)),
                    Scalar::ZERO,
                )
            })
            .collect();
        assert_eq!(lincomb_vartime(&xks), ProjectivePoint::IDENTITY);
    }

    #[test]
    fn identity_points() {
        // Points generated via `mul_by_generator` are never the identity, so bucket
        // accumulation of identity points is otherwise untested.
        let xks: alloc::vec::Vec<_> = (0..THRESHOLD as u64)
            .map(|i| (ProjectivePoint::IDENTITY, scalar(i)))
            .collect();
        assert_eq!(lincomb_vartime(&xks), ProjectivePoint::IDENTITY);
    }

    #[test]
    fn mixed_identity_and_zero() {
        let mut xks = pairs(THRESHOLD);
        xks[0].0 = ProjectivePoint::IDENTITY;
        xks[1].1 = Scalar::ZERO;
        xks[2] = (ProjectivePoint::IDENTITY, Scalar::ZERO);
        assert_matches_reference(&xks);
    }

    #[test]
    fn edge_scalars() {
        let p = ProjectivePoint::mul_by_generator(&scalar(7));
        let mut xks = pairs(THRESHOLD);
        xks[0] = (p, Scalar::ONE);
        xks[1] = (p, -Scalar::ONE);
        xks[2] = (p, Scalar::ZERO);
        assert_matches_reference(&xks);
    }

    #[test]
    fn duplicate_points() {
        let p = ProjectivePoint::mul_by_generator(&scalar(11));
        let xks: alloc::vec::Vec<_> = (0..THRESHOLD as u64).map(|i| (p, scalar(i))).collect();
        assert_matches_reference(&xks);
    }

    #[test]
    fn window_extraction() {
        // 0x0201 little-endian, rest zero.
        let mut bytes = [0u8; 16];
        bytes[0] = 0x01;
        bytes[1] = 0x02;

        assert_eq!(window(&bytes, 0, 8), 0x01);
        assert_eq!(window(&bytes, 8, 8), 0x02);
        assert_eq!(window(&bytes, 0, 16), 0x0201);
        // A window spanning a byte boundary.
        assert_eq!(window(&bytes, 4, 8), 0x20);
        // Reading past the end yields zero rather than panicking.
        assert_eq!(window(&bytes, 120, 10), 0);
        assert_eq!(window(&bytes, 127, 6), 0);
    }
}
