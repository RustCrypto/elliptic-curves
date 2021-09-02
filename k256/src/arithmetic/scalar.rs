//! Scalar field arithmetic.

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_pointer_width = "32")] {
        mod scalar_8x32;
        use scalar_8x32::{
            Scalar8x32 as ScalarImpl,
            WideScalar16x32 as WideScalarImpl,
        };
    } else if #[cfg(target_pointer_width = "64")] {
        mod scalar_4x64;
        use scalar_4x64::{
            Scalar4x64 as ScalarImpl,
            WideScalar8x64 as WideScalarImpl,
        };
    } else {
        compile_error!("unsupported target word size (i.e. target_pointer_width)");
    }
}

use crate::{FieldBytes, Secp256k1};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Shr, Sub, SubAssign};
use elliptic_curve::{
    generic_array::arr,
    group::ff::{Field, PrimeField},
    rand_core::{CryptoRng, RngCore},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    ScalarArithmetic,
};

#[cfg(feature = "bits")]
use {crate::ScalarBits, elliptic_curve::group::ff::PrimeFieldBits};

#[cfg(feature = "digest")]
use ecdsa_core::{elliptic_curve::consts::U32, hazmat::FromDigest, signature::digest::Digest};

#[cfg(feature = "zeroize")]
use elliptic_curve::zeroize::Zeroize;

#[cfg(test)]
use num_bigint::{BigUint, ToBigUint};

impl ScalarArithmetic for Secp256k1 {
    type Scalar = Scalar;
}

/// Scalars are elements in the finite field modulo n.
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `k256::elliptic_curve::ff`:
///
/// - [`Field`](https://docs.rs/ff/latest/ff/trait.Field.html) -
///   represents elements of finite fields and provides:
///   - [`Field::random`](https://docs.rs/ff/latest/ff/trait.Field.html#tymethod.random) -
///     generate a random scalar
///   - `double`, `square`, and `invert` operations
///   - Bounds for [`Add`], [`Sub`], [`Mul`], and [`Neg`] (as well as `*Assign` equivalents)
///   - Bounds for [`ConditionallySelectable`] from the `subtle` crate
/// - [`PrimeField`](https://docs.rs/ff/latest/ff/trait.PrimeField.html) -
///   represents elements of prime fields and provides:
///   - `from_repr`/`to_repr` for converting field elements from/to big integers.
///   - `char_le_bits`, `multiplicative_generator`, `root_of_unity` constants.
/// - [`PrimeFieldBits`](https://docs.rs/ff/latest/ff/trait.PrimeFieldBits.html) -
///   operations over field elements represented as bits (requires `bits` feature)
///
/// Please see the documentation for the relevant traits for more information.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct Scalar(ScalarImpl);

impl Field for Scalar {
    fn random(rng: impl RngCore) -> Self {
        // Uses rejection sampling as the default random generation method,
        // which produces a uniformly random distribution of scalars.
        //
        // This method is not constant time, but should be secure so long as
        // rejected RNG outputs are unrelated to future ones (which is a
        // necessary property of a `CryptoRng`).
        //
        // With an unbiased RNG, the probability of failing to complete after 4
        // iterations is vanishingly small.
        Self::generate_vartime(rng)
    }

    fn zero() -> Self {
        Scalar::zero()
    }

    fn one() -> Self {
        Scalar::one()
    }

    #[must_use]
    fn square(&self) -> Self {
        Scalar::square(self)
    }

    #[must_use]
    fn double(&self) -> Self {
        self.add(self)
    }

    fn invert(&self) -> CtOption<Self> {
        Scalar::invert(self)
    }

    /// Tonelli-Shank's algorithm for q mod 16 = 1
    /// https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)
    #[allow(clippy::many_single_char_names)]
    fn sqrt(&self) -> CtOption<Self> {
        // TODO(tarcieri): replace with `self.pow((t - 1) >> 1)`
        let w = {
            let t0 = self;
            let t1 = t0.square();
            let t2 = t1 * t0;
            let t3 = t1.square();
            let t4 = t3.square();
            let t5 = t4 * t2;
            let t6 = t5 * t3;
            let t7 = t6.square();
            let t8 = t7 * t6;
            let t9 = t8.square();
            let t10 = t9 * t6;
            let t11 = t10 * t5;
            let t12 = t11 * t6;
            let t13 = t12.square();
            let t14 = t13 * t11;
            let t15 = t14.square();
            let t16 = t15 * t12;
            let t17 = t16.square();
            let t18 = t17 * t16;
            let t19 = t18.square();
            let t21 = t19.square();
            let t22 = t21 * t16;
            let t23 = t22 * t14;
            let t24 = t23 * t16;
            let t25 = t24.square();
            let t26 = t25 * t23;
            let t27 = t26 * t24;
            let t28 = t27.square();
            let t29 = t28 * t27;
            let t30 = t29.square();
            let t31 = t30 * t28;
            let t32 = t31.square();
            let t33 = t32.square();
            let t34 = t33 * t29;
            let t35 = t34 * t26;
            let t36 = t35 * t27;
            let t37 = t36.square();
            let t38 = t37.square();
            let t39 = t38 * t36;
            let t40 = t39.square();
            let t41 = t40.square();
            let t43 = t41 * t35;
            let t44 = t43 * t36;
            let t45 = t44.square();
            let t46 = t45 * t43;
            let t47 = t46 * t44;
            let t48 = t47.square();
            let t49 = t48 * t46;
            let t50 = t49.square();
            let t51 = t50 * t49;
            let t52 = t51.square();
            let t53 = t52 * t50;
            let t54 = t53.square();
            let t55 = t54.square();
            let t56 = t55 * t51;
            let t57 = t56 * t47;
            let t58 = t57.square();
            let t59 = t58.square();
            let t60 = t59 * t57;
            let t61 = t60 * t49;
            let t62 = t61.square();
            let t63 = t62.square();
            let t64 = t63.square();
            let t65 = t64 * t61;
            let t66 = t65 * t57;
            let t67 = t66.square();
            let t68 = t67.square();
            let t69 = t68 * t67;
            let t70 = t69.square();
            let t71 = t70 * t67;
            let t72 = t71 * t66;
            let t73 = t72.square();
            let t74 = t73.square();
            let t75 = t74 * t67;
            let t76 = t75 * t61;
            let t77 = t76 * t66;
            let t78 = t77.square();
            let t79 = t78.square();
            let t80 = t79 * t77;
            let t81 = t80 * t76;
            let t82 = t81.square();
            let t83 = t82 * t77;
            let t84 = t83.square();
            let t85 = t84.square();
            let t87 = t85.square();
            let t88 = t87.square();
            let t89 = t88 * t84;
            let t90 = t89 * t81;
            let t91 = t90.square();
            let t92 = t91 * t83;
            let t93 = t92.square();
            let t94 = t93 * t92;
            let t95 = t94.square();
            let t96 = t95 * t92;
            let t97 = t96.square();
            let t99 = t97.square();
            let t100 = t99.square();
            let t101 = t100.square();
            let t103 = t101 * t90;
            let t104 = t103.square();
            let t105 = t104.square();
            let t106 = t105.square();
            let t107 = t106 * t103;
            let t108 = t107 * t92;
            let t109 = t108.square();
            let t110 = t109 * t103;
            let t111 = t110.square();
            let t112 = t111.square();
            let t113 = t112.square();
            let t114 = t113 * t110;
            let t115 = t114 * t108;
            let t116 = t115 * t110;
            let t117 = t116.square();
            let t118 = t117.square();
            let t119 = t118 * t116;
            let t120 = t119 * t115;
            let t121 = t120.square();
            let t122 = t121 * t116;
            let t123 = t122 * t120;
            let t124 = t123.square();
            let t125 = t124 * t123;
            let t126 = t125.square();
            let t128 = t126.square();
            let t130 = t128 * t122;
            let t131 = t130 * t123;
            let t132 = t131.square();
            let t133 = t132.square();
            let t134 = t133.square();
            let t135 = t134 * t131;
            let t136 = t135.square();
            let t137 = t136.square();
            let t138 = t137.square();
            let t139 = t138 * t132;
            let t140 = t139 * t130;
            let t141 = t140 * t131;
            let t142 = t141.square();
            let t143 = t142.square();
            let t144 = t143 * t141;
            let t145 = t144 * t140;
            let t146 = t145.square();
            let t147 = t146 * t145;
            let t148 = t147.square();
            let t149 = t148 * t145;
            let t150 = t149 * t141;
            let t151 = t150.square();
            let t152 = t151 * t145;
            let t153 = t152 * t150;
            let t154 = t153.square();
            let t155 = t154 * t153;
            let t156 = t155.square();
            let t157 = t156 * t153;
            let t158 = t157 * t152;
            let t159 = t158 * t153;
            let t160 = t159.square();
            let t161 = t160 * t159;
            let t162 = t161 * t158;
            let t163 = t162 * t159;
            let t164 = t163.square();
            let t165 = t164 * t163;
            let t166 = t165 * t162;
            let t167 = t166 * t163;
            let t168 = t167.square();
            let t169 = t168.square();
            let t170 = t169 * t167;
            let t171 = t170.square();
            let t173 = t171 * t166;
            let t174 = t173 * t167;
            let t175 = t174.square();
            let t176 = t175 * t174;
            let t177 = t176.square();
            let t178 = t177 * t174;
            let t179 = t178.square();
            let t180 = t179.square();
            let t182 = t180 * t173;
            let t183 = t182.square();
            let t184 = t183 * t182;
            let t185 = t184 * t174;
            let t186 = t185 * t182;
            let t187 = t186 * t185;
            let t188 = t187 * t186;
            let t189 = t188.square();
            let t190 = t189 * t188;
            let t191 = t190.square();
            let t192 = t191 * t188;
            let t193 = t192 * t187;
            let t194 = t193.square();
            let t195 = t194 * t188;
            let t196 = t195.square();
            let t197 = t196.square();
            let t198 = t197 * t193;
            let t199 = t198.square();
            let t200 = t199.square();
            let t201 = t200 * t198;
            let t202 = t201 * t195;
            let t203 = t202.square();
            let t204 = t203.square();
            let t205 = t204 * t202;
            let t206 = t205 * t198;
            let t207 = t206 * t202;
            let t208 = t207 * t206;
            let t209 = t208 * t207;
            let t210 = t209.square();
            let t211 = t210 * t208;
            let t212 = t211.square();
            let t213 = t212 * t209;
            let t214 = t213.square();
            let t215 = t214.square();
            let t216 = t215.square();
            let t217 = t216.square();
            let t218 = t217.square();
            let t219 = t218.square();
            let t220 = t219.square();
            let t221 = t220.square();
            let t222 = t221.square();
            let t223 = t222.square();
            let t224 = t223.square();
            let t225 = t224.square();
            let t226 = t225.square();
            let t227 = t226.square();
            let t228 = t227.square();
            let t229 = t228.square();
            let t230 = t229.square();
            let t231 = t230.square();
            let t232 = t231.square();
            let t233 = t232.square();
            let t234 = t233.square();
            let t235 = t234.square();
            let t236 = t235.square();
            let t237 = t236.square();
            let t238 = t237.square();
            let t239 = t238.square();
            let t240 = t239.square();
            let t241 = t240.square();
            let t242 = t241.square();
            let t243 = t242.square();
            let t244 = t243.square();
            let t245 = t244.square();
            let t246 = t245.square();
            let t247 = t246.square();
            let t248 = t247.square();
            let t249 = t248.square();
            let t250 = t249.square();
            let t251 = t250.square();
            let t252 = t251.square();
            let t253 = t252.square();
            let t254 = t253.square();
            let t255 = t254.square();
            let t256 = t255.square();
            let t257 = t256.square();
            let t258 = t257.square();
            let t259 = t258.square();
            let t260 = t259.square();
            let t261 = t260.square();
            let t262 = t261.square();
            let t263 = t262.square();
            let t264 = t263.square();
            let t265 = t264.square();
            let t266 = t265.square();
            let t267 = t266.square();
            let t268 = t267.square();
            let t269 = t268.square();
            let t270 = t269.square();
            let t271 = t270.square();
            let t272 = t271.square();
            let t273 = t272.square();
            let t274 = t273.square();
            let t275 = t274.square();
            let t276 = t275.square();
            let t277 = t276.square();
            let t278 = t277.square();
            let t279 = t278.square();
            let t280 = t279.square();
            let t281 = t280.square();
            let t282 = t281.square();
            let t283 = t282.square();
            let t284 = t283.square();
            let t285 = t284.square();
            let t286 = t285.square();
            let t287 = t286.square();
            let t288 = t287.square();
            let t289 = t288.square();
            let t290 = t289.square();
            let t291 = t290.square();
            let t292 = t291.square();
            let t293 = t292.square();
            let t294 = t293.square();
            let t295 = t294.square();
            let t296 = t295.square();
            let t297 = t296.square();
            let t298 = t297.square();
            let t299 = t298.square();
            let t300 = t299.square();
            let t301 = t300.square();
            let t302 = t301.square();
            let t303 = t302.square();
            let t304 = t303.square();
            let t305 = t304.square();
            let t306 = t305.square();
            let t307 = t306.square();
            let t308 = t307.square();
            let t309 = t308.square();
            let t310 = t309.square();
            let t311 = t310.square();
            let t312 = t311.square();
            let t313 = t312.square();
            let t314 = t313.square();
            let t315 = t314.square();
            let t316 = t315.square();
            let t317 = t316.square();
            let t318 = t317.square();
            let t319 = t318.square();
            let t320 = t319.square();
            let t321 = t320.square();
            let t322 = t321.square();
            let t323 = t322.square();
            let t324 = t323.square();
            let t325 = t324.square();
            let t326 = t325.square();
            let t327 = t326.square();
            let t328 = t327.square();
            let t329 = t328.square();
            let t330 = t329.square();
            let t331 = t330.square();
            let t332 = t331.square();
            let t333 = t332.square();
            let t334 = t333.square();
            let t335 = t334.square();
            let t336 = t335.square();
            let t337 = t336.square();
            t337 * t211
        };

        let mut v = Self::S;
        let mut x = *self * w;
        let mut b = x * w;
        let mut z = Self::root_of_unity();

        for max_v in (1..=Self::S).rev() {
            let mut k = 1;
            let mut tmp = b.square();
            let mut j_less_than_v = Choice::from(1);

            for j in 2..max_v {
                let tmp_is_one = tmp.ct_eq(&Self::one());
                let squared = Self::conditional_select(&tmp, &z, tmp_is_one).square();
                tmp = Self::conditional_select(&squared, &tmp, tmp_is_one);
                let new_z = Self::conditional_select(&z, &squared, tmp_is_one);
                j_less_than_v &= !j.ct_eq(&v);
                k = u32::conditional_select(&j, &k, tmp_is_one);
                z = Self::conditional_select(&z, &new_z, j_less_than_v);
            }

            let result = x * z;
            x = Self::conditional_select(&result, &x, b.ct_eq(&Self::one()));
            z = z.square();
            b *= z;
            v = k;
        }

        CtOption::new(x, x.square().ct_eq(self))
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const S: u32 = 6;

    /// Attempts to parse the given byte array as an SEC1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        ScalarImpl::from_bytes(bytes.as_ref()).map(Self)
    }

    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    fn multiplicative_generator() -> Self {
        7u64.into()
    }

    fn root_of_unity() -> Self {
        Scalar::from_repr(arr![u8;
            0x0c, 0x1d, 0xc0, 0x60, 0xe7, 0xa9, 0x19, 0x86, 0xdf, 0x98, 0x79, 0xa3, 0xfb, 0xc4,
            0x83, 0xa8, 0x98, 0xbd, 0xea, 0xb6, 0x80, 0x75, 0x60, 0x45, 0x99, 0x2f, 0x4b, 0x54,
            0x02, 0xb0, 0x52, 0xf2
        ])
        .unwrap()
    }
}

#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
impl PrimeFieldBits for Scalar {
    #[cfg(target_pointer_width = "32")]
    type ReprBits = [u32; 8];

    #[cfg(target_pointer_width = "64")]
    type ReprBits = [u64; 4];

    fn to_le_bits(&self) -> ScalarBits {
        self.into()
    }

    fn char_le_bits() -> ScalarBits {
        crate::ORDER.to_uint_array().into()
    }
}

impl From<u32> for Scalar {
    fn from(k: u32) -> Self {
        Self(ScalarImpl::from(k))
    }
}

impl From<u64> for Scalar {
    fn from(k: u64) -> Self {
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

    /// Checks if the scalar is zero.
    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Returns the value of the scalar truncated to a 32-bit unsigned integer.
    pub fn truncate_to_u32(&self) -> u32 {
        self.0.truncate_to_u32()
    }

    /// Attempts to parse the given byte array as a scalar.
    /// Does not check the result for being in the correct range.
    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        Self(ScalarImpl::from_bytes_unchecked(bytes))
    }

    /// Parses the given byte array as a scalar.
    ///
    /// Subtracts the modulus when the byte array is larger than the modulus.
    pub fn from_bytes_reduced(bytes: &FieldBytes) -> Self {
        Self(ScalarImpl::from_bytes_reduced(bytes.as_ref()))
    }

    /// Returns the SEC1 encoding of this scalar.
    pub fn to_bytes(&self) -> FieldBytes {
        self.0.to_bytes()
    }

    /// Is this scalar greater than or equal to n / 2?
    pub fn is_high(&self) -> Choice {
        self.0.is_high()
    }

    /// Negates the scalar.
    pub fn negate(&self) -> Self {
        Self(self.0.negate())
    }

    /// Modulo adds two scalars
    pub fn add(&self, rhs: &Scalar) -> Scalar {
        Self(self.0.add(&(rhs.0)))
    }

    /// Modulo subtracts one scalar from the other.
    pub fn sub(&self, rhs: &Scalar) -> Scalar {
        Self(self.0.sub(&(rhs.0)))
    }

    /// Modulo multiplies two scalars.
    pub fn mul(&self, rhs: &Scalar) -> Scalar {
        Self(self.0.mul(&(rhs.0)))
    }

    /// Modulo squares the scalar.
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Right shifts the scalar. Note: not constant-time in `shift`.
    pub fn rshift(&self, shift: usize) -> Scalar {
        Self(self.0.rshift(shift))
    }

    /// Raises the scalar to the power `2^k`
    fn pow2k(&self, k: usize) -> Self {
        let mut x = *self;
        for _j in 0..k {
            x = x.square();
        }
        x
    }

    /// Inverts the scalar.
    pub fn invert(&self) -> CtOption<Self> {
        // Using an addition chain from
        // https://briansmith.org/ecc-inversion-addition-chains-01#secp256k1_scalar_inversion

        let x_1 = *self;
        let x_10 = self.pow2k(1);
        let x_11 = x_10.mul(&x_1);
        let x_101 = x_10.mul(&x_11);
        let x_111 = x_10.mul(&x_101);
        let x_1001 = x_10.mul(&x_111);
        let x_1011 = x_10.mul(&x_1001);
        let x_1101 = x_10.mul(&x_1011);

        let x6 = x_1101.pow2k(2).mul(&x_1011);
        let x8 = x6.pow2k(2).mul(&x_11);
        let x14 = x8.pow2k(6).mul(&x6);
        let x28 = x14.pow2k(14).mul(&x14);
        let x56 = x28.pow2k(28).mul(&x28);

        #[rustfmt::skip]
        let res = x56
            .pow2k(56).mul(&x56)
            .pow2k(14).mul(&x14)
            .pow2k(3).mul(&x_101)
            .pow2k(4).mul(&x_111)
            .pow2k(4).mul(&x_101)
            .pow2k(5).mul(&x_1011)
            .pow2k(4).mul(&x_1011)
            .pow2k(4).mul(&x_111)
            .pow2k(5).mul(&x_111)
            .pow2k(6).mul(&x_1101)
            .pow2k(4).mul(&x_101)
            .pow2k(3).mul(&x_111)
            .pow2k(5).mul(&x_1001)
            .pow2k(6).mul(&x_101)
            .pow2k(10).mul(&x_111)
            .pow2k(4).mul(&x_111)
            .pow2k(9).mul(&x8)
            .pow2k(5).mul(&x_1001)
            .pow2k(6).mul(&x_1011)
            .pow2k(4).mul(&x_1101)
            .pow2k(5).mul(&x_11)
            .pow2k(6).mul(&x_1101)
            .pow2k(10).mul(&x_1101)
            .pow2k(4).mul(&x_1001)
            .pow2k(6).mul(&x_1)
            .pow2k(8).mul(&x6);

        CtOption::new(res, !self.is_zero())
    }

    /// Returns the scalar modulus as a `BigUint` object.
    #[cfg(test)]
    pub fn modulus_as_biguint() -> BigUint {
        Self::one().negate().to_biguint().unwrap() + 1.to_biguint().unwrap()
    }

    /// Returns a (nearly) uniformly-random scalar, generated in constant time.
    pub fn generate_biased(mut rng: impl CryptoRng + RngCore) -> Self {
        // We reduce a random 512-bit value into a 256-bit field, which results in a
        // negligible bias from the uniform distribution, but the process is constant-time.
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        Scalar(WideScalarImpl::from_bytes(&buf).reduce())
    }

    /// Returns a uniformly-random scalar, generated using rejection sampling.
    // TODO(tarcieri): make this a `CryptoRng` when `ff` allows it
    pub fn generate_vartime(mut rng: impl RngCore) -> Self {
        let mut bytes = FieldBytes::default();

        // TODO: pre-generate several scalars to bring the probability of non-constant-timeness down?
        loop {
            rng.fill_bytes(&mut bytes);
            if let Some(scalar) = Scalar::from_repr(bytes).into() {
                return scalar;
            }
        }
    }

    /// If `flag` evaluates to `true`, adds `(1 << bit)` to `self`.
    pub fn conditional_add_bit(&self, bit: usize, flag: Choice) -> Self {
        Self(self.0.conditional_add_bit(bit, flag))
    }

    /// Multiplies `self` by `b` (without modulo reduction) divide the result by `2^shift`
    /// (rounding to the nearest integer).
    /// Variable time in `shift`.
    pub fn mul_shift_var(&self, b: &Scalar, shift: usize) -> Self {
        Self(self.0.mul_shift_var(&(b.0), shift))
    }
}

#[cfg(feature = "digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
impl FromDigest<Secp256k1> for Scalar {
    /// Convert the output of a digest algorithm into a [`Scalar`] reduced
    /// modulo n.
    fn from_digest<D>(digest: D) -> Self
    where
        D: Digest<OutputSize = U32>,
    {
        Self::from_bytes_reduced(&digest.finalize())
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

impl Eq for Scalar {}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        self.negate()
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        self.negate()
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar::add(&self, &other)
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

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::add(self, rhs);
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        Scalar::sub(&self, &other)
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

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::sub(self, rhs);
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        Scalar::mul(&self, &other)
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

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::mul(self, rhs);
    }
}

#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
impl From<&Scalar> for ScalarBits {
    fn from(scalar: &Scalar) -> ScalarBits {
        scalar.0.into()
    }
}

impl From<Scalar> for FieldBytes {
    fn from(scalar: Scalar) -> Self {
        scalar.to_bytes()
    }
}

impl From<&Scalar> for FieldBytes {
    fn from(scalar: &Scalar) -> Self {
        scalar.to_bytes()
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

#[cfg(test)]
mod tests {
    use super::Scalar;
    use crate::arithmetic::util::{biguint_to_bytes, bytes_to_biguint};
    use elliptic_curve::group::ff::{Field, PrimeField};
    use num_bigint::{BigUint, ToBigUint};
    use proptest::prelude::*;

    impl From<&BigUint> for Scalar {
        fn from(x: &BigUint) -> Self {
            debug_assert!(x < &Scalar::modulus_as_biguint());
            let bytes = biguint_to_bytes(x);
            Self::from_repr(bytes.into()).unwrap()
        }
    }

    impl From<BigUint> for Scalar {
        fn from(x: BigUint) -> Self {
            Self::from(&x)
        }
    }

    impl ToBigUint for Scalar {
        fn to_biguint(&self) -> Option<BigUint> {
            Some(bytes_to_biguint(self.to_bytes().as_ref()))
        }
    }

    #[test]
    fn is_high() {
        // 0 is not high
        let high: bool = Scalar::zero().is_high().into();
        assert!(!high);

        // 1 is not high
        let one = 1.to_biguint().unwrap();
        let high: bool = Scalar::from(&one).is_high().into();
        assert!(!high);

        let m = Scalar::modulus_as_biguint();
        let m_by_2 = &m >> 1;

        // M / 2 is not high
        let high: bool = Scalar::from(&m_by_2).is_high().into();
        assert!(!high);

        // M / 2 + 1 is high
        let high: bool = Scalar::from(&m_by_2 + &one).is_high().into();
        assert!(high);

        // MODULUS - 1 is high
        let high: bool = Scalar::from(&m - &one).is_high().into();
        assert!(high);
    }

    /// Basic tests that sqrt works.
    #[test]
    fn sqrt() {
        for &n in &[1u64, 4, 9, 16, 25, 36, 49, 64] {
            let scalar = Scalar::from(n);
            let sqrt = scalar.sqrt().unwrap();
            assert_eq!(sqrt.square(), scalar);
        }
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

    #[test]
    fn add_result_within_256_bits() {
        // A regression for a bug where reduction was not applied
        // when the unreduced result of addition was in the range `[modulus, 2^256)`.
        let t = 1.to_biguint().unwrap() << 255;
        let one = 1.to_biguint().unwrap();

        let a = Scalar::from(&t - &one);
        let b = Scalar::from(&t);
        let res = &a + &b;

        let m = Scalar::modulus_as_biguint();
        let res_ref = Scalar::from((&t + &t - &one) % &m);

        assert_eq!(res, res_ref);
    }

    #[test]
    fn generate_biased() {
        use elliptic_curve::rand_core::OsRng;
        let a = Scalar::generate_biased(&mut OsRng);
        // just to make sure `a` is not optimized out by the compiler
        assert_eq!((a - &a).is_zero().unwrap_u8(), 1);
    }

    #[test]
    fn generate_vartime() {
        use elliptic_curve::rand_core::OsRng;
        let a = Scalar::generate_vartime(&mut OsRng);
        // just to make sure `a` is not optimized out by the compiler
        assert_eq!((a - &a).is_zero().unwrap_u8(), 1);
    }

    prop_compose! {
        fn scalar()(bytes in any::<[u8; 32]>()) -> Scalar {
            let mut res = bytes_to_biguint(&bytes);
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
            let a_back = Scalar::from_repr(a.to_bytes()).unwrap();
            assert_eq!(a, a_back);
        }

        #[test]
        fn fuzzy_roundtrip_to_bytes_unchecked(a in scalar()) {
            let bytes = a.to_bytes();
            let a_back = Scalar::from_bytes_unchecked(bytes.as_ref());
            assert_eq!(a, a_back);
        }

        #[test]
        fn fuzzy_add(a in scalar(), b in scalar()) {
            let a_bi = a.to_biguint().unwrap();
            let b_bi = b.to_biguint().unwrap();

            let res_bi = (&a_bi + &b_bi) % &Scalar::modulus_as_biguint();
            let res_ref = Scalar::from(&res_bi);
            let res_test = a.add(&b);

            assert_eq!(res_ref, res_test);
        }

        #[test]
        fn fuzzy_sub(a in scalar(), b in scalar()) {
            let a_bi = a.to_biguint().unwrap();
            let b_bi = b.to_biguint().unwrap();

            let m = Scalar::modulus_as_biguint();
            let res_bi = (&m + &a_bi - &b_bi) % &m;
            let res_ref = Scalar::from(&res_bi);
            let res_test = a.sub(&b);

            assert_eq!(res_ref, res_test);
        }

        #[test]
        fn fuzzy_neg(a in scalar()) {
            let a_bi = a.to_biguint().unwrap();

            let m = Scalar::modulus_as_biguint();
            let res_bi = (&m - &a_bi) % &m;
            let res_ref = Scalar::from(&res_bi);
            let res_test = -a;

            assert_eq!(res_ref, res_test);
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

        #[test]
        fn fuzzy_invert(
            a in scalar()
        ) {
            let a = if bool::from(a.is_zero()) { Scalar::one() } else { a };
            let a_bi = a.to_biguint().unwrap();
            let inv = a.invert().unwrap();
            let inv_bi = inv.to_biguint().unwrap();
            let m = Scalar::modulus_as_biguint();
            assert_eq!((&inv_bi * &a_bi) % &m, 1.to_biguint().unwrap());
        }
    }
}
