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
//! - Window digits are signed rather than unsigned, which halves the bucket count from `2^c - 1`
//!   to `2^(c-1)`: a digit's sign decides whether its point is added or subtracted, and point
//!   negation is free. That halves the bucket-reduction term, which in turn makes a wider window
//!   optimal at a given term count.

use super::glv;
use crate::{ProjectivePoint, Scalar};
use alloc::{vec, vec::Vec};
use elliptic_curve::{BatchNormalize, scalar::IsHigh};
use primeorder::PrimeFieldExt;

/// Term count at or above which Pippenger beats interleaved w-NAF.
///
/// Relative cost of Pippenger against w-NAF over identical inputs, both strategies timed in the
/// same run with dense full-width scalars:
///
/// | pairs | 72    | 74    | 76    | 80    | 128   | 256   | 1024  | 4096  |
/// |-------|-------|-------|-------|-------|-------|-------|-------|-------|
/// | ratio | 1.008 | 1.001 | 0.993 | 0.976 | 0.868 | 0.759 | 0.558 | 0.436 |
///
/// 76 is the smallest size at which Pippenger wins with non-overlapping confidence intervals; at
/// 74 the two are indistinguishable. Signed digits moved this down from 128, where the unsigned
/// version crossed.
///
/// Note that [`window_width`] steps from 5 to 6 between 72 and 73 pairs, so the curve has a kink
/// there and should not be interpolated across it. Measured, the step is small: 1.008 at width 5
/// against 1.006 at width 6.
///
/// Scalar density matters when re-measuring: w-NAF's cost scales with each scalar's nonzero digit
/// count whereas Pippenger pays per window regardless, so sparse scalars push the crossing
/// higher. So does the balance between addition, inversion and allocation costs, which varies by
/// machine.
pub(super) const THRESHOLD: usize = 76;

/// Bytes of each GLV half-scalar.
///
/// GLV decomposition bounds both half-scalars below `2^128`, so 16 bytes is exact rather than a
/// truncation. See the bound proof in [`glv`].
const HALF_SCALAR_BYTES: usize = 16;

/// Bits of each GLV half-scalar.
const HALF_SCALAR_BITS: usize = HALF_SCALAR_BYTES * 8;

/// Smallest and largest window width considered.
///
/// The upper bound caps the bucket array at `2^12` points. With signed digits the model reaches
/// width 12 beyond ~20500 half-terms and width 13 beyond ~36900, so the cap only binds on inputs
/// far larger than anything this is expected to see.
const MIN_WINDOW: usize = 2;
const MAX_WINDOW: usize = 13;

/// Window width in bits minimising the approximate addition count for a given term count.
///
/// The cost is `window_count(c) * (terms + 2^c)`: one window pass per `c` bits, each costing one
/// bucket addition per term plus two additions for each of the `2^(c-1)` buckets to reduce. This
/// is minimised directly rather than via a hard-coded table, because a table silently drifts from
/// the model it claims to follow -- and did, in an earlier revision of this file.
///
/// Signed digits halve the bucket term relative to unsigned ones, so the optimum sits about one
/// bit wider than it otherwise would.
///
/// The model weighs every addition equally, so it is only an approximation: mixed additions, full
/// additions and doublings differ in cost. Worth revisiting against measurement.
fn window_width(terms: usize) -> usize {
    (MIN_WINDOW..=MAX_WINDOW)
        .min_by_key(|&c| window_count(c) * (terms + (1 << c)))
        .unwrap_or(MIN_WINDOW)
}

/// Number of window passes for a given width.
///
/// One bit wider than the scalar, because signed-digit recoding carries: a scalar of all ones
/// propagates a carry out of its top window, which needs a window of its own to land in.
fn window_count(width: usize) -> usize {
    (HALF_SCALAR_BITS + 1).div_ceil(width)
}

/// A signed window digit, held as magnitude plus sign.
///
/// Magnitude is at most `2^(MAX_WINDOW - 1)`, so `u16` holds it. Kept unsigned rather than as an
/// `i16` so that nothing is ever converted from `usize`: `usize` is as narrow as 16 bits on some
/// supported targets, where such a conversion could wrap.
#[derive(Clone, Copy, Debug, Default)]
struct SignedDigit {
    magnitude: u16,
    negative: bool,
}

/// Recode a little-endian scalar into `out.len()` signed digits of `width` bits.
///
/// Each digit's magnitude is at most `2^(width-1)`, so only magnitudes `1..=2^(width-1)` need a
/// bucket and a negative digit subtracts its point. `out.len()` must be [`window_count`], which
/// is wide enough for the carry to terminate.
fn recode(bytes: &[u8; HALF_SCALAR_BYTES], width: usize, out: &mut [SignedDigit]) {
    let half: u16 = 1 << (width - 1);
    let full: u16 = 1 << width;
    let mut carry: u16 = 0;

    for (j, slot) in out.iter_mut().enumerate() {
        let d = window(bytes, j * width, width) + carry;

        // `d >= half` means this window sits closer to the next one up, so borrow: emit a
        // negative digit and carry one upward. All arithmetic stays unsigned.
        *slot = if d >= half {
            carry = 1;
            SignedDigit {
                magnitude: full - d,
                negative: true,
            }
        } else {
            carry = 0;
            SignedDigit {
                magnitude: d,
                negative: false,
            }
        };
    }
}

/// Extract the `width`-bit window starting at `bit_offset` from a little-endian byte string.
///
/// Bits past the end of `bytes` read as zero. Operates on bytes rather than machine words so that
/// the result does not depend on word size or host endianness.
fn window(bytes: &[u8; HALF_SCALAR_BYTES], bit_offset: usize, width: usize) -> u16 {
    let mut digit: u16 = 0;
    let mut filled = 0usize;
    let mut index = bit_offset / 8;
    let mut bit = bit_offset % 8;

    while filled < width && index < bytes.len() {
        let take = core::cmp::min(8 - bit, width - filled);
        let mask: u16 = (1 << take) - 1;
        digit |= ((u16::from(bytes[index]) >> bit) & mask) << filled;
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
    lincomb_vartime_with_width(xks, window_width(xks.len() * 2))
}

/// As [`lincomb_vartime`], with the window width supplied rather than derived from the term
/// count, so that each width can be tested independently of the size-to-width mapping.
fn lincomb_vartime_with_width(xks: &[(ProjectivePoint, Scalar)], width: usize) -> ProjectivePoint {
    debug_assert!((MIN_WINDOW..=MAX_WINDOW).contains(&width));

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
            let repr = r.to_le_repr();
            // Exact rather than truncating, by the GLV bound proof in `glv`. Asserted so that a
            // regression in `decompose_scalar` fails a test instead of silently computing the
            // wrong linear combination.
            debug_assert!(
                repr[HALF_SCALAR_BYTES..].iter().all(|&b| b == 0),
                "GLV half-scalar is not below 2^128"
            );

            let mut bytes = [0u8; HALF_SCALAR_BYTES];
            bytes.copy_from_slice(&repr[..HALF_SCALAR_BYTES]);
            scalars.push(bytes);
        }
    }

    // One inversion for every term, so bucket accumulation can use mixed addition.
    let affine = <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize_vartime(
        points.as_slice(),
    );

    let windows = window_count(width);

    // Recode up front: the carry runs from the least significant window upward, while the
    // accumulation below runs from the most significant downward.
    let mut digits = vec![SignedDigit::default(); terms * windows];
    for (bytes, slot) in scalars.iter().zip(digits.chunks_mut(windows)) {
        recode(bytes, width, slot);
    }

    // Signed digits, so only magnitudes `1..=2^(width-1)` need a bucket.
    let mut buckets = vec![ProjectivePoint::IDENTITY; 1usize << (width - 1)];
    let mut acc = ProjectivePoint::IDENTITY;

    for w in (0..windows).rev() {
        // Shift the accumulator up by one window, except on the first pass.
        if w != windows - 1 {
            for _ in 0..width {
                acc.double_in_place();
            }
        }

        buckets.fill(ProjectivePoint::IDENTITY);

        for (chunk, point) in digits.chunks(windows).zip(affine.iter()) {
            let digit = chunk[w];
            if digit.magnitude != 0 {
                let bucket = &mut buckets[usize::from(digit.magnitude) - 1];
                if digit.negative {
                    *bucket -= point;
                } else {
                    *bucket += point;
                }
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
    use super::{
        MAX_WINDOW, MIN_WINDOW, SignedDigit, THRESHOLD, lincomb_vartime,
        lincomb_vartime_with_width, recode, window, window_count, window_width,
    };
    use crate::arithmetic::{ProjectivePoint, Scalar};
    use elliptic_curve::ops::LinearCombination;

    /// Deterministic distinct scalars, avoiding a dependency on `getrandom` in these tests.
    ///
    /// Full width on purpose: a `Scalar::from(u64)` would decompose into ~32-bit GLV halves,
    /// leaving most window digits -- including the partial top window -- permanently zero and so
    /// untested.
    fn scalar(i: u64) -> Scalar {
        // Below the group order, which begins 0xFFFFFFFF.
        let base = Scalar::from_bytes_unchecked(&[
            0x7e, 0x4b, 0x1c, 0xa9, 0x33, 0xd0, 0x62, 0x85, 0x19, 0xf7, 0x40, 0xbc, 0x2a, 0x6d,
            0x8e, 0x51, 0xc3, 0x07, 0x9a, 0x44, 0xe2, 0x7b, 0x15, 0xf0, 0x68, 0xad, 0x39, 0x5c,
            0x81, 0xd6, 0x22, 0x0f,
        ]);
        base * Scalar::from(i.wrapping_add(1))
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

    /// Every window width, independently of the size-to-width mapping.
    ///
    /// Without this, only the widths that `window_width` happens to select for the sizes used
    /// above are ever executed -- widths 8 and up need thousands of pairs. Width 8 matters most:
    /// it divides `HALF_SCALAR_BITS` exactly, so it is the only width with no partial top
    /// window, and a bug confined to a full top window would otherwise go unseen.
    #[test]
    fn every_window_width_matches_reference() {
        for n in [3usize, 20] {
            let xks = pairs(n);
            let expected = ProjectivePoint::lincomb(xks.as_slice());

            for width in MIN_WINDOW..=MAX_WINDOW {
                assert_eq!(
                    lincomb_vartime_with_width(&xks, width),
                    expected,
                    "width {width} disagrees at n={n}"
                );
            }
        }
    }

    /// Tripwire, not a property: while `window_width` is a search over
    /// `MIN_WINDOW..=MAX_WINDOW` this holds by construction. It exists so that reintroducing a
    /// hard-coded table -- the thing that went wrong before -- cannot silently return a width
    /// the bucket array is not sized for.
    #[test]
    fn window_width_is_in_range() {
        for terms in [2usize, 256, 1024, 8192, 65536, usize::from(u16::MAX)] {
            let w = window_width(terms);
            assert!(
                (MIN_WINDOW..=MAX_WINDOW).contains(&w),
                "window_width({terms}) = {w} out of range"
            );
        }
    }

    /// The signed-digit recoding must represent the scalar exactly, at every width.
    ///
    /// Checked directly rather than only through the MSM, and with the all-ones scalar, which is
    /// the case that forces a carry out of the top window -- the reason [`window_count`] covers
    /// one bit more than the scalar.
    #[test]
    fn recoding_reconstructs_the_scalar() {
        let values = [
            0u128,
            1,
            2,
            u128::from(u32::MAX),
            u128::from(u64::MAX),
            1 << 127,
            (1 << 127) - 1,
            u128::MAX,
            0x5555_5555_5555_5555_5555_5555_5555_5555,
            0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA,
        ];

        for width in MIN_WINDOW..=MAX_WINDOW {
            let windows = window_count(width);
            let mut digits = vec![SignedDigit::default(); windows];

            for v in values {
                recode(&v.to_le_bytes(), width, &mut digits);

                // Horner from the top down, wrapping: the representation is exact and the value
                // is below 2^128, so equality modulo 2^128 is equality.
                let mut acc = 0u128;
                for d in digits.iter().rev() {
                    acc = acc.wrapping_mul(1u128 << width);
                    let m = u128::from(d.magnitude);
                    acc = if d.negative {
                        acc.wrapping_sub(m)
                    } else {
                        acc.wrapping_add(m)
                    };
                }

                assert_eq!(acc, v, "width {width} misrepresents {v:#x}");

                // And every magnitude must be within the signed window range.
                let half: u16 = 1 << (width - 1);
                for d in digits.iter() {
                    assert!(
                        d.magnitude <= half,
                        "width {width}: magnitude {} out of range for {v:#x}",
                        d.magnitude
                    );
                }
            }
        }
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
