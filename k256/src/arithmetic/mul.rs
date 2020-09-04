use crate::arithmetic::{scalar::Scalar, ProjectivePoint};
use core::ops::{Mul, MulAssign};
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Lookup table containing precomputed values `[p, 2p, 3p, ..., 8p]`
struct LookupTable([ProjectivePoint; 8]);

impl From<&ProjectivePoint> for LookupTable {
    fn from(p: &ProjectivePoint) -> Self {
        let mut points = [*p; 8];
        for j in 0..7 {
            points[j + 1] = p + &points[j];
        }
        LookupTable(points)
    }
}

impl LookupTable {
    /// Given -8 <= x <= 8, returns x * p in constant time.
    pub fn select(&self, x: i8) -> ProjectivePoint {
        debug_assert!(x >= -8);
        debug_assert!(x <= 8);

        // Compute xabs = |x|
        let xmask = x >> 7;
        let xabs = (x + xmask) ^ xmask;

        // Get an array element in constant time
        let mut t = ProjectivePoint::identity();
        for j in 1..9 {
            let c = (xabs as u8).ct_eq(&(j as u8));
            t.conditional_assign(&self.0[j - 1], c);
        }
        // Now t == |x| * p.

        let neg_mask = Choice::from((xmask & 1) as u8);
        t.conditional_assign(&-t, neg_mask);
        // Now t == x * p.

        t
    }
}

/// Returns `[a_0, ..., a_64]` such that `sum(a_j * 2^(j * 4)) == x`,
/// and `-8 <= a_j <= 7`.
#[cfg(not(feature = "endomorphism-mul"))]
fn to_radix_16(x: &Scalar) -> [i8; 65] {
    // `x` can have up to 256 bits, so we need an additional byte to store the carry.
    let mut output = [0i8; 65];

    // Step 1: change radix.
    // Convert from radix 256 (bytes) to radix 16 (nibbles)
    let bytes = x.to_bytes();
    for i in 0..32 {
        output[2 * i] = (bytes[31 - i] & 0xf) as i8;
        output[2 * i + 1] = ((bytes[31 - i] >> 4) & 0xf) as i8;
    }

    // Step 2: recenter coefficients from [0,16) to [-8,8)
    for i in 0..64 {
        let carry = (output[i] + 8) >> 4;
        output[i] -= carry << 4;
        output[i + 1] += carry;
    }

    output
}

#[cfg(not(feature = "endomorphism-mul"))]
fn mul_windowed(x: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    let scalar_digits = to_radix_16(k);
    let lookup_table = LookupTable::from(x);
    let mut acc = lookup_table.select(scalar_digits[64]);
    for i in (0..64).rev() {
        for _j in 0..4 {
            acc = acc.double();
        }
        acc += &lookup_table.select(scalar_digits[i]);
    }
    acc
}

/*
From libsecp256k1:

The Secp256k1 curve has an endomorphism, where lambda * (x, y) = (beta * x, y), where
lambda is {0x53,0x63,0xad,0x4c,0xc0,0x5c,0x30,0xe0,0xa5,0x26,0x1c,0x02,0x88,0x12,0x64,0x5a,
        0x12,0x2e,0x22,0xea,0x20,0x81,0x66,0x78,0xdf,0x02,0x96,0x7c,0x1b,0x23,0xbd,0x72}

"Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone) gives an algorithm
(algorithm 3.74) to find k1 and k2 given k, such that k1 + k2 * lambda == k mod n, and k1
and k2 have a small size.
It relies on constants a1, b1, a2, b2. These constants for the value of lambda above are:

- a1 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
- b1 =     -{0xe4,0x43,0x7e,0xd6,0x01,0x0e,0x88,0x28,0x6f,0x54,0x7f,0xa9,0x0a,0xbf,0xe4,0xc3}
- a2 = {0x01,0x14,0xca,0x50,0xf7,0xa8,0xe2,0xf3,0xf6,0x57,0xc1,0x10,0x8d,0x9d,0x44,0xcf,0xd8}
- b2 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}

The algorithm then computes c1 = round(b1 * k / n) and c2 = round(b2 * k / n), and gives
k1 = k - (c1*a1 + c2*a2) and k2 = -(c1*b1 + c2*b2). Instead, we use modular arithmetic, and
compute k1 as k - k2 * lambda, avoiding the need for constants a1 and a2.

g1, g2 are precomputed constants used to replace division with a rounded multiplication
when decomposing the scalar for an endomorphism-based point multiplication.

The possibility of using precomputed estimates is mentioned in "Guide to Elliptic Curve
Cryptography" (Hankerson, Menezes, Vanstone) in section 3.5.

The derivation is described in the paper "Efficient Software Implementation of Public-Key
Cryptography on Sensor Networks Using the MSP430X Microcontroller" (Gouvea, Oliveira, Lopez),
Section 4.3 (here we use a somewhat higher-precision estimate):
d = a1*b2 - b1*a2
g1 = round((2^272)*b2/d)
g2 = round((2^272)*b1/d)

(Note that 'd' is also equal to the curve order here because [a1,b1] and [a2,b2] are found
as outputs of the Extended Euclidean Algorithm on inputs 'order' and 'lambda').
*/

/*
@fjarri:

To be precise, the method used here is based on
"An Alternate Decomposition of an Integer for Faster Point Multiplication on Certain Elliptic Curves"
by Young-Ho Park, Sangtae Jeong, Chang Han Kim, and Jongin Lim
(https://link.springer.com/chapter/10.1007%2F3-540-45664-3_23)

The precision used for `g1` and `g2` is not enough to ensure correct approximation at all times.
For example, `2^272 * b1 / n` used to calculate `g2` is rounded down.
This means that the approximation `z' = k * g2 / 2^272` always slightly underestimates
the real value `z = b1 * k / n`. Therefore, when the fractional part of `z` is just slightly above
0.5, it will be rounded up, but `z'` will have the fractional part slightly below 0.5 and will be
rounded down.

The difference `z - z' = k * delta / 2^272`, where `delta = b1 * 2^272 mod n`.
The closest `z` can get to the fractional part equal to .5 is `1 / (2n)` (since `n` is odd).
Therefore, to guarantee that `z'` will always be rounded to the same value, one must have
`delta / 2^m < 1 / (2n * (n - 1))`, where `m` is the power of 2 used for the approximation.
This means that one should use at least `m = 512` (since `0 < delta < 1`).
Indeed, tests show that with only `m = 272` the approximation produces off-by-1 errors occasionally.

Now since `r1` is calculated as `k - r2 * lambda mod n`, the contract `r1 + r2 * lambda = k mod n`
is always satisfied. The method guarantees both `r1` and `r2` to be less than `sqrt(n)`
(so, fit in 128 bits) if the rounding is applied correctly - but in our case the off-by-1 errors
will produce different `r1` and `r2` which are not necessarily bounded by `sqrt(n)`.

In experiments, I was not able to detect any case where they would go outside the 128 bit bound,
but I cannot be sure that it cannot happen.
*/

#[cfg(feature = "endomorphism-mul")]
const MINUS_LAMBDA: Scalar = Scalar::from_bytes_unchecked(&[
    0xac, 0x9c, 0x52, 0xb3, 0x3f, 0xa3, 0xcf, 0x1f, 0x5a, 0xd9, 0xe3, 0xfd, 0x77, 0xed, 0x9b, 0xa4,
    0xa8, 0x80, 0xb9, 0xfc, 0x8e, 0xc7, 0x39, 0xc2, 0xe0, 0xcf, 0xc8, 0x10, 0xb5, 0x12, 0x83, 0xcf,
]);

#[cfg(feature = "endomorphism-mul")]
const MINUS_B1: Scalar = Scalar::from_bytes_unchecked(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc3,
]);

#[cfg(feature = "endomorphism-mul")]
const MINUS_B2: Scalar = Scalar::from_bytes_unchecked(&[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0x8a, 0x28, 0x0a, 0xc5, 0x07, 0x74, 0x34, 0x6d, 0xd7, 0x65, 0xcd, 0xa8, 0x3d, 0xb1, 0x56, 0x2c,
]);

#[cfg(feature = "endomorphism-mul")]
const G1: Scalar = Scalar::from_bytes_unchecked(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x86,
    0xd2, 0x21, 0xa7, 0xd4, 0x6b, 0xcd, 0xe8, 0x6c, 0x90, 0xe4, 0x92, 0x84, 0xeb, 0x15, 0x3d, 0xab,
]);

#[cfg(feature = "endomorphism-mul")]
const G2: Scalar = Scalar::from_bytes_unchecked(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe4, 0x43,
    0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc4, 0x22, 0x12,
]);

/// Find r1 and r2 given k, such that r1 + r2 * lambda == k mod n.
#[cfg(feature = "endomorphism-mul")]
fn decompose_scalar(k: &Scalar) -> (Scalar, Scalar) {
    // these _var calls are constant time since the shift amount is constant
    let c1 = k.mul_shift_var(&G1, 272);
    let c2 = k.mul_shift_var(&G2, 272);

    let c1 = c1 * MINUS_B1;
    let c2 = c2 * MINUS_B2;
    let r2 = c1 + c2;
    let r1 = k + r2 * MINUS_LAMBDA;

    (r1, r2)
}

/// Returns `[a_0, ..., a_32]` such that `sum(a_j * 2^(j * 4)) == x`,
/// and `-8 <= a_j <= 7`.
/// Assumes `x < 2^128`.
#[cfg(feature = "endomorphism-mul")]
fn to_radix_16_half(x: &Scalar) -> [i8; 33] {
    // `x` can have up to 256 bits, so we need an additional byte to store the carry.
    let mut output = [0i8; 33];

    // Step 1: change radix.
    // Convert from radix 256 (bytes) to radix 16 (nibbles)
    let bytes = x.to_bytes();
    for i in 0..16 {
        output[2 * i] = (bytes[31 - i] & 0xf) as i8;
        output[2 * i + 1] = ((bytes[31 - i] >> 4) & 0xf) as i8;
    }

    debug_assert!((x >> 128).is_zero().unwrap_u8() == 1);

    // Step 2: recenter coefficients from [0,16) to [-8,8)
    for i in 0..32 {
        let carry = (output[i] + 8) >> 4;
        output[i] -= carry << 4;
        output[i + 1] += carry;
    }

    output
}

#[cfg(feature = "endomorphism-mul")]
fn mul_windowed(x: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    let (r1, r2) = decompose_scalar(k);
    let x_beta = x.endomorphism();

    let r1_sign = r1.is_high();
    let r1_c = Scalar::conditional_select(&r1, &-r1, r1_sign);
    let r2_sign = r2.is_high();
    let r2_c = Scalar::conditional_select(&r2, &-r2, r2_sign);

    let table1 = LookupTable::from(&ProjectivePoint::conditional_select(x, &-x, r1_sign));
    let table2 = LookupTable::from(&ProjectivePoint::conditional_select(
        &x_beta, &-x_beta, r2_sign,
    ));

    let digits1 = to_radix_16_half(&r1_c);
    let digits2 = to_radix_16_half(&r2_c);

    let mut acc = table1.select(digits1[32]) + table2.select(digits2[32]);
    for i in (0..32).rev() {
        for _j in 0..4 {
            acc = acc.double();
        }

        acc += &table1.select(digits1[i]);
        acc += &table2.select(digits2[i]);
    }
    acc
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: Scalar) -> ProjectivePoint {
        mul_windowed(&self, &other)
    }
}

impl Mul<&Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul_windowed(self, other)
    }
}

impl Mul<&Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul_windowed(&self, other)
    }
}

impl MulAssign<Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = mul_windowed(self, &rhs);
    }
}

impl MulAssign<&Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = mul_windowed(self, rhs);
    }
}
