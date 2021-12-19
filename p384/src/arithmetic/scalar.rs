//! Scalar field elements for the NIST P-384 elliptic curve.

// TODO(tarcieri): 32-bit backend
#[cfg(not(target_pointer_width = "64"))]
compile_error!("scalar arithmetic is only supported on 64-bit platforms");

use crate::{FieldBytes, NistP384, ScalarCore, ORDER as MODULUS, U384};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    bigint::Limb,
    ff::{Field, PrimeField},
    generic_array::arr,
    ops::Reduce,
    rand_core::RngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    Curve as _, Error, IsHigh, Result, ScalarArithmetic,
};

/// -(m^{-1} mod m) mod m
const INV: u64 = 7986114184663260229;

impl ScalarArithmetic for NistP384 {
    type Scalar = Scalar;
}

/// Scalars are elements in the finite field modulo n.
///
/// # ⚠️ WARNING: experimental implementation!
///
/// The scalar arithmetic implementation provided by this type is experimental,
/// poorly tested, and may produce incorrect results.
///
/// We do not recommend using it in any sort of production capacity at this time.
///
/// USE AT YOUR OWN RISK!
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `p384::elliptic_curve::ff`:
///
/// - [`Field`](https://docs.rs/ff/latest/ff/trait.Field.html) -
///   represents elements of finite fields and provides:
///   - [`Field::random`](https://docs.rs/ff/latest/ff/trait.Field.html#tymethod.random) -
///     generate a random scalar
///   - `double`, `square`, and `invert` operations
///   - Bounds for [`Add`], [`Sub`], [`Mul`], and [`Neg`] (as well as `*Assign` equivalents)
///   - Bounds for [`ConditionallySelectable`] from the `subtle` crate
/// - [`PrimeField`](https://docs.rs/ff/0.9.0/ff/trait.PrimeField.html) -
///   represents elements of prime fields and provides:
///   - `from_repr`/`to_repr` for converting field elements from/to big integers.
///   - `multiplicative_generator` and `root_of_unity` constants.
///
/// Please see the documentation for the relevant traits for more information.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct Scalar(ScalarCore);

impl Field for Scalar {
    fn random(mut rng: impl RngCore) -> Self {
        // NOTE: can't use ScalarCore::random due to CryptoRng bound
        let mut bytes = FieldBytes::default();

        loop {
            rng.fill_bytes(&mut bytes);
            if let Some(scalar) = Self::from_repr(bytes).into() {
                return scalar;
            }
        }
    }

    fn zero() -> Self {
        Self::ZERO
    }

    fn one() -> Self {
        Self::ONE
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    #[must_use]
    fn square(&self) -> Self {
        self.square()
    }

    #[must_use]
    fn double(&self) -> Self {
        self.add(self)
    }

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }

    fn sqrt(&self) -> CtOption<Self> {
        self.sqrt()
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const NUM_BITS: u32 = 384;
    const CAPACITY: u32 = 383;
    const S: u32 = 1;

    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        ScalarCore::from_be_bytes(bytes).map(Self)
    }

    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    fn multiplicative_generator() -> Self {
        2u64.into()
    }

    fn root_of_unity() -> Self {
        Scalar::from_repr(arr![u8;
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
            0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x72
        ])
        .unwrap()
    }
}

impl Scalar {
    /// Zero scalar.
    pub const ZERO: Self = Self(ScalarCore::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self(ScalarCore::ONE);

    /// Returns the SEC1 encoding of this scalar.
    pub fn to_bytes(&self) -> FieldBytes {
        self.0.to_be_bytes()
    }

    /// Multiply a scalar by another scalar.
    #[cfg(target_pointer_width = "64")]
    #[inline]
    pub fn mul(&self, other: &Scalar) -> Self {
        // TODO(tarcieri): replace with a.mul_wide(&b)
        let a = self.0.as_limbs();
        let b = other.0.as_limbs();

        let carry = Limb::ZERO;
        let (r0, carry) = Limb::ZERO.mac(a[0], b[0], carry);
        let (r1, carry) = Limb::ZERO.mac(a[0], b[1], carry);
        let (r2, carry) = Limb::ZERO.mac(a[0], b[2], carry);
        let (r3, carry) = Limb::ZERO.mac(a[0], b[3], carry);
        let (r4, carry) = Limb::ZERO.mac(a[0], b[4], carry);
        let (r5, carry) = Limb::ZERO.mac(a[0], b[5], carry);
        let r6 = carry;

        let carry = Limb::ZERO;
        let (r1, carry) = r1.mac(a[1], b[0], carry);
        let (r2, carry) = r2.mac(a[1], b[1], carry);
        let (r3, carry) = r3.mac(a[1], b[2], carry);
        let (r4, carry) = r4.mac(a[1], b[3], carry);
        let (r5, carry) = r5.mac(a[1], b[4], carry);
        let (r6, carry) = r6.mac(a[1], b[5], carry);
        let r7 = carry;

        let carry = Limb::ZERO;
        let (r2, carry) = r2.mac(a[2], b[0], carry);
        let (r3, carry) = r3.mac(a[2], b[1], carry);
        let (r4, carry) = r4.mac(a[2], b[2], carry);
        let (r5, carry) = r5.mac(a[2], b[3], carry);
        let (r6, carry) = r6.mac(a[2], b[4], carry);
        let (r7, carry) = r7.mac(a[2], b[5], carry);
        let r8 = carry;

        let carry = Limb::ZERO;
        let (r3, carry) = r3.mac(a[3], b[0], carry);
        let (r4, carry) = r4.mac(a[3], b[1], carry);
        let (r5, carry) = r5.mac(a[3], b[2], carry);
        let (r6, carry) = r6.mac(a[3], b[3], carry);
        let (r7, carry) = r7.mac(a[3], b[4], carry);
        let (r8, carry) = r8.mac(a[3], b[5], carry);
        let r9 = carry;

        let carry = Limb::ZERO;
        let (r4, carry) = r4.mac(a[4], b[0], carry);
        let (r5, carry) = r5.mac(a[4], b[1], carry);
        let (r6, carry) = r6.mac(a[4], b[2], carry);
        let (r7, carry) = r7.mac(a[4], b[3], carry);
        let (r8, carry) = r8.mac(a[4], b[4], carry);
        let (r9, carry) = r9.mac(a[4], b[5], carry);
        let r10 = carry;

        let carry = Limb::ZERO;
        let (r5, carry) = r5.mac(a[5], b[0], carry);
        let (r6, carry) = r6.mac(a[5], b[1], carry);
        let (r7, carry) = r7.mac(a[5], b[2], carry);
        let (r8, carry) = r8.mac(a[5], b[3], carry);
        let (r9, carry) = r9.mac(a[5], b[4], carry);
        let (r10, carry) = r10.mac(a[5], b[5], carry);
        let r11 = carry;

        Self::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)
    }

    /// Compute modular square.
    #[must_use]
    pub fn square(&self) -> Self {
        // NOTE: generated by `ff_derive`
        let limbs = self.0.as_limbs();

        let carry = Limb::ZERO;
        let (r1, carry) = Limb::ZERO.mac(limbs[0], limbs[1], carry);
        let (r2, carry) = Limb::ZERO.mac(limbs[0], limbs[2], carry);
        let (r3, carry) = Limb::ZERO.mac(limbs[0], limbs[3], carry);
        let (r4, carry) = Limb::ZERO.mac(limbs[0], limbs[4], carry);
        let (r5, carry) = Limb::ZERO.mac(limbs[0], limbs[5], carry);
        let r6 = carry;

        let carry = Limb::ZERO;
        let (r3, carry) = r3.mac(limbs[1], limbs[2], carry);
        let (r4, carry) = r4.mac(limbs[1], limbs[3], carry);
        let (r5, carry) = r5.mac(limbs[1], limbs[4], carry);
        let (r6, carry) = r6.mac(limbs[1], limbs[5], carry);
        let r7 = carry;

        let carry = Limb::ZERO;
        let (r5, carry) = r5.mac(limbs[2], limbs[3], carry);
        let (r6, carry) = r6.mac(limbs[2], limbs[4], carry);
        let (r7, carry) = r7.mac(limbs[2], limbs[5], carry);
        let r8 = carry;

        let carry = Limb::ZERO;
        let (r7, carry) = r7.mac(limbs[3], limbs[4], carry);
        let (r8, carry) = r8.mac(limbs[3], limbs[5], carry);
        let r9 = carry;

        let carry = Limb::ZERO;
        let (r9, carry) = r9.mac(limbs[4], limbs[5], carry);
        let r10 = carry;
        let r11 = Limb(r10.0 >> 63);
        let r10 = Limb((r10.0 << 1) | (r9.0 >> 63));
        let r9 = Limb((r9.0 << 1) | (r8.0 >> 63));
        let r8 = Limb((r8.0 << 1) | (r7.0 >> 63));
        let r7 = Limb((r7.0 << 1) | (r6.0 >> 63));
        let r6 = Limb((r6.0 << 1) | (r5.0 >> 63));
        let r5 = Limb((r5.0 << 1) | (r4.0 >> 63));
        let r4 = Limb((r4.0 << 1) | (r3.0 >> 63));
        let r3 = Limb((r3.0 << 1) | (r2.0 >> 63));
        let r2 = Limb((r2.0 << 1) | (r1.0 >> 63));
        let r1 = Limb(r1.0 << 1);

        let carry = Limb::ZERO;
        let (r0, carry) = Limb::ZERO.mac(limbs[0], limbs[0], carry);
        let (r1, carry) = r1.adc(Limb::ZERO, carry);
        let (r2, carry) = r2.mac(limbs[1], limbs[1], carry);
        let (r3, carry) = r3.adc(Limb::ZERO, carry);
        let (r4, carry) = r4.mac(limbs[2], limbs[2], carry);
        let (r5, carry) = r5.adc(Limb::ZERO, carry);
        let (r6, carry) = r6.mac(limbs[3], limbs[3], carry);
        let (r7, carry) = r7.adc(Limb::ZERO, carry);
        let (r8, carry) = r8.mac(limbs[4], limbs[4], carry);
        let (r9, carry) = r9.adc(Limb::ZERO, carry);
        let (r10, carry) = r10.mac(limbs[5], limbs[5], carry);
        let (r11, _) = r11.adc(Limb::ZERO, carry);

        Self::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)
    }

    /// Compute scalar inversion.
    pub fn invert(&self) -> CtOption<Self> {
        // NOTE: generated by `ff_derive`
        let t0 = self;
        let t1 = t0.square();
        let t2 = t1.square();
        let t3 = t2.square();
        let t4 = t3.square();
        let t5 = t4 * t0;
        let t6 = t5.square();
        let t7 = t6 * t5;
        let t8 = t7 * t1;
        let t9 = t8.square();
        let t10 = t9 * t8;
        let t11 = t10.square();
        let t12 = t11 * t8;
        let t13 = t12.square();
        let t14 = t13 * t8;
        let t15 = t14 * t5;
        let t16 = t15 * t8;
        let t17 = t16.square();
        let t18 = t17.square();
        let t19 = t18.square();
        let t20 = t19.square();
        let t21 = t20 * t16;
        let t22 = t21 * t15;
        let t23 = t22.square();
        let t24 = t23.square();
        let t25 = t24.square();
        let t26 = t25.square();
        let t27 = t26.square();
        let t28 = t27 * t22;
        let t29 = t28 * t16;
        let t30 = t29 * t22;
        let t31 = t30.square();
        let t32 = t31 * t30;
        let t33 = t32.square();
        let t34 = t33 * t30;
        let t35 = t34.square();
        let t36 = t35.square();
        let t37 = t36 * t30;
        let t38 = t37 * t29;
        let t39 = t38.square();
        let t40 = t39 * t30;
        let t41 = t40 * t38;
        let t42 = t41 * t40;
        let t43 = t42 * t41;
        let t44 = t43 * t42;
        let t45 = t44 * t43;
        let t46 = t45.square();
        let t47 = t46 * t45;
        let t48 = t47 * t44;
        let t49 = t48.square();
        let t50 = t49 * t45;
        let t51 = t50.square();
        let t52 = t51.square();
        let t53 = t52 * t50;
        let t54 = t53 * t48;
        let t55 = t54.square();
        let t56 = t55.square();
        let t57 = t56 * t54;
        let t58 = t57.square();
        //let t59 = t57.square();
        let t60 = t58 * t50;
        let t61 = t60.square();
        let t62 = t61.square();
        let t63 = t62.square();
        let t64 = t63 * t60;
        let t65 = t64 * t54;
        let t66 = t65.square();
        let t67 = t66 * t60;
        let t68 = t67.square();
        let t69 = t68 * t67;
        let t70 = t69 * t65;
        let t71 = t70.square();
        let t72 = t71 * t67;
        let t73 = t72.square();
        let t74 = t73.square();
        let t75 = t74.square();
        let t76 = t75.square();
        let t77 = t76 * t74;
        //let t78 = t76 * t74;
        let t79 = t77.square();
        let t80 = t79.square();
        let t81 = t80.square();
        let t82 = t81 * t74;
        let t83 = t82 * t70;
        let t84 = t83.square();
        let t85 = t84 * t83;
        let t86 = t85 * t72;
        let t87 = t86 * t83;
        let t88 = t87.square();
        let t89 = t88.square();
        let t90 = t89 * t87;
        let t91 = t90 * t86;
        let t92 = t91.square();
        let t93 = t92.square();
        let t94 = t93 * t92;
        let t95 = t94.square();
        let t96 = t95 * t92;
        //let t97 = t95 * t92;
        let t98 = t96.square();
        let t99 = t98.square();
        let t100 = t99.square();
        let t101 = t100 * t92;
        let t102 = t101 * t87;
        let t103 = t102 * t91;
        let t104 = t103 * t102;
        let t105 = t104 * t103;
        let t106 = t105.square();
        let t107 = t106 * t105;
        let t108 = t107.square();
        let t109 = t108 * t105;
        let t110 = t109 * t104;
        let t111 = t110 * t105;
        let t112 = t111 * t110;
        let t113 = t112 * t111;
        let t114 = t113 * t112;
        let t115 = t114.square();
        let t116 = t115 * t113;
        let t117 = t116.square();
        let t118 = t117 * t114;
        let t119 = t118 * t116;
        let t120 = t119.square();
        let t121 = t120 * t119;
        let t122 = t121.square();
        //let t123 = t121.square();
        let t124 = t122.square();
        let t125 = t124.square();
        let t126 = t125 * t119;
        let t127 = t126 * t118;
        let t128 = t127.square();
        let t129 = t128 * t119;
        let t130 = t129 * t127;
        let t131 = t130 * t129;
        let t132 = t131 * t130;
        let t133 = t132 * t131;
        let t134 = t133 * t132;
        let t135 = t134 * t133;
        let t136 = t135.square();
        let t137 = t136.square();
        let t138 = t137 * t134;
        let t139 = t138.square();
        let t140 = t139 * t138;
        let t141 = t140.square();
        //let t142 = t140.square();
        let t143 = t141.square();
        //let t144 = t141.square();
        let t145 = t143 * t135;
        let t146 = t145 * t138;
        let t147 = t146.square();
        let t148 = t147 * t145;
        let t149 = t148 * t146;
        let t150 = t149.square();
        let t151 = t150 * t149;
        let t152 = t151.square();
        //let t153 = t151.square();
        let t154 = t152.square();
        let t155 = t154.square();
        //let t156 = t154.square();
        let t157 = t155 * t148;
        let t158 = t157 * t149;
        let t159 = t158 * t157;
        let t160 = t159.square();
        let t161 = t160.square();
        let t162 = t161.square();
        let t163 = t162 * t159;
        let t164 = t163 * t158;
        let t165 = t164.square();
        let t166 = t165.square();
        let t167 = t166 * t159;
        let t168 = t167.square();
        let t169 = t168 * t164;
        let t170 = t169 * t167;
        let t171 = t170.square();
        let t172 = t171.square();
        let t173 = t172.square();
        let t174 = t173 * t169;
        let t175 = t174.square();
        let t176 = t175 * t170;
        let t177 = t176 * t174;
        let t178 = t177 * t176;
        let t179 = t178.square();
        let t180 = t179 * t177;
        let t181 = t180.square();
        let t182 = t181 * t178;
        let t183 = t182.square();
        let t184 = t183 * t182;
        let t185 = t184.square();
        let t186 = t185 * t182;
        let t187 = t186.square();
        let t188 = t187 * t182;
        let t189 = t188 * t180;
        let t190 = t189 * t182;
        let t191 = t190.square();
        let t192 = t191.square();
        let t193 = t192.square();
        let t194 = t193.square();
        let t195 = t194 * t189;
        let t196 = t195 * t190;
        let t197 = t196 * t195;
        let t198 = t197.square();
        let t199 = t198 * t197;
        let t200 = t199 * t196;
        let t201 = t200 * t197;
        let t202 = t201.square();
        let t203 = t202 * t200;
        let t204 = t203.square();
        let t205 = t204.square();
        let t206 = t205.square();
        let t207 = t206 * t201;
        let t208 = t207.square();
        let t209 = t208 * t207;
        let t210 = t209 * t203;
        let t211 = t210.square();
        let t212 = t211 * t207;
        let t213 = t212 * t210;
        let t214 = t213.square();
        let t215 = t214.square();
        let t216 = t215.square();
        let t217 = t216.square();
        let t218 = t217 * t213;
        let t219 = t218 * t212;
        let t220 = t219 * t213;
        let t221 = t220.square();
        let t222 = t221 * t220;
        let t223 = t222.square();
        //let t224 = t222.square();
        let t225 = t223.square();
        let t226 = t225 * t220;
        let t227 = t226.square();
        let t228 = t227.square();
        //let t229 = t227.square();
        let t230 = t228 * t219;
        let t231 = t230 * t220;
        let t232 = t231.square();
        let t233 = t232.square();
        let t234 = t233.square();
        let t235 = t234 * t230;
        let t236 = t235 * t231;
        let t237 = t236 * t235;
        let t238 = t237 * t236;
        let t239 = t238 * t237;
        let t240 = t239.square();
        let t241 = t240 * t238;
        let t242 = t241.square();
        let t243 = t242 * t239;
        let t244 = t243 * t241;
        let t245 = t244 * t243;
        let t246 = t245.square();
        let t247 = t246.square();
        let t248 = t247 * t245;
        let t249 = t248 * t244;
        let t250 = t249.square();
        let t251 = t250.square();
        let t252 = t251 * t249;
        let t253 = t252 * t245;
        let t254 = t253.square();
        let t255 = t254.square();
        let t256 = t255 * t249;
        let t257 = t256.square();
        let t258 = t257 * t256;
        let t259 = t258 * t253;
        let t260 = t259.square();
        let t261 = t260.square();
        let t262 = t261 * t259;
        let t263 = t262.square();
        //let t264 = t262.square();
        let t265 = t263 * t256;
        let t266 = t265.square();
        let t267 = t266 * t259;
        let t268 = t267.square();
        let t269 = t268.square();
        let t270 = t269.square();
        let t271 = t270 * t267;
        let t272 = t271 * t265;
        let t273 = t272 * t267;
        let t274 = t273.square();
        let t275 = t274 * t273;
        let t276 = t275 * t272;
        let t277 = t276.square();
        let t278 = t277 * t273;
        let t279 = t278.square();
        let t280 = t279 * t278;
        let t281 = t280 * t276;
        let t282 = t281 * t278;
        let t283 = t282 * t281;
        let t284 = t283.square();
        let t285 = t284 * t282;
        let t286 = t285 * t283;
        let t287 = t286.square();
        let t288 = t287.square();
        let t289 = t288 * t285;
        let t290 = t289 * t286;
        let t291 = t290.square();
        let t292 = t291 * t290;
        let t293 = t292.square();
        //let t294 = t292.square();
        let t295 = t293.square();
        let t296 = t295 * t290;
        let t297 = t296 * t289;
        let t298 = t297 * t290;
        let t299 = t298 * t297;
        let t300 = t299.square();
        let t301 = t300 * t298;
        let t302 = t301 * t299;
        let t303 = t302.square();
        let t304 = t303 * t301;
        let t305 = t304.square();
        let t306 = t305 * t304;
        let t307 = t306.square();
        let t308 = t307 * t304;
        let t309 = t308 * t302;
        let t310 = t309.square();
        let t311 = t310.square();
        let t312 = t311 * t309;
        let t313 = t312 * t304;
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
        let t338 = t337.square();
        let t339 = t338.square();
        let t340 = t339.square();
        let t341 = t340.square();
        let t342 = t341.square();
        let t343 = t342.square();
        let t344 = t343.square();
        let t345 = t344.square();
        let t346 = t345.square();
        let t347 = t346.square();
        let t348 = t347.square();
        let t349 = t348.square();
        let t350 = t349.square();
        let t351 = t350.square();
        let t352 = t351.square();
        let t353 = t352.square();
        let t354 = t353.square();
        let t355 = t354.square();
        let t356 = t355.square();
        let t357 = t356.square();
        let t358 = t357.square();
        let t359 = t358.square();
        let t360 = t359.square();
        let t361 = t360.square();
        let t362 = t361.square();
        let t363 = t362.square();
        let t364 = t363.square();
        let t365 = t364.square();
        let t366 = t365.square();
        let t367 = t366.square();
        let t368 = t367.square();
        let t369 = t368.square();
        let t370 = t369.square();
        let t371 = t370.square();
        let t372 = t371.square();
        let t373 = t372.square();
        let t374 = t373.square();
        let t375 = t374.square();
        let t376 = t375.square();
        let t377 = t376.square();
        let t378 = t377.square();
        let t379 = t378.square();
        let t380 = t379.square();
        let t381 = t380.square();
        let t382 = t381.square();
        let t383 = t382.square();
        let t384 = t383.square();
        let t385 = t384.square();
        let t386 = t385.square();
        let t387 = t386.square();
        let t388 = t387.square();
        let t389 = t388.square();
        let t390 = t389.square();
        let t391 = t390.square();
        let t392 = t391.square();
        let t393 = t392.square();
        let t394 = t393.square();
        let t395 = t394.square();
        let t396 = t395.square();
        let t397 = t396.square();
        let t398 = t397.square();
        let t399 = t398.square();
        let t400 = t399.square();
        let t401 = t400.square();
        let t402 = t401.square();
        let t403 = t402.square();
        let t404 = t403.square();
        let t405 = t404.square();
        let t406 = t405.square();
        let t407 = t406.square();
        let t408 = t407.square();
        let t409 = t408.square();
        let t410 = t409.square();
        let t411 = t410.square();
        let t412 = t411.square();
        let t413 = t412.square();
        let t414 = t413.square();
        let t415 = t414.square();
        let t416 = t415.square();
        let t417 = t416.square();
        let t418 = t417.square();
        let t419 = t418.square();
        let t420 = t419.square();
        let t421 = t420.square();
        let t422 = t421.square();
        let t423 = t422.square();
        let t424 = t423.square();
        let t425 = t424.square();
        let t426 = t425.square();
        let t427 = t426.square();
        let t428 = t427.square();
        let t429 = t428.square();
        let t430 = t429.square();
        let t431 = t430.square();
        let t432 = t431.square();
        let t433 = t432.square();
        let t434 = t433.square();
        let t435 = t434.square();
        let t436 = t435.square();
        let t437 = t436.square();
        let t438 = t437.square();
        let t439 = t438.square();
        let t440 = t439.square();
        let t441 = t440.square();
        let t442 = t441.square();
        let t443 = t442.square();
        let t444 = t443.square();
        let t445 = t444.square();
        let t446 = t445.square();
        let t447 = t446.square();
        let t448 = t447.square();
        let t449 = t448.square();
        let t450 = t449.square();
        let t451 = t450.square();
        let t452 = t451.square();
        let t453 = t452.square();
        let t454 = t453.square();
        let t455 = t454.square();
        let t456 = t455.square();
        let t457 = t456.square();
        let t458 = t457.square();
        let t459 = t458.square();
        let t460 = t459.square();
        let t461 = t460.square();
        let t462 = t461.square();
        let t463 = t462.square();
        let t464 = t463.square();
        let t465 = t464.square();
        let t466 = t465.square();
        let t467 = t466.square();
        let t468 = t467.square();
        let t469 = t468.square();
        let t470 = t469.square();
        let t471 = t470.square();
        let t472 = t471.square();
        let t473 = t472.square();
        let t474 = t473.square();
        let t475 = t474.square();
        let t476 = t475.square();
        let t477 = t476.square();
        let t478 = t477.square();
        let t479 = t478.square();
        let t480 = t479.square();
        let t481 = t480.square();
        let t482 = t481.square();
        let t483 = t482.square();
        let t484 = t483.square();
        let t485 = t484.square();
        let t486 = t485.square();
        let t487 = t486.square();
        let t488 = t487.square();
        let t489 = t488.square();
        let t490 = t489.square();
        let t491 = t490.square();
        let t492 = t491.square();
        let t493 = t492.square();
        let t494 = t493.square();
        let t495 = t494.square();
        let t496 = t495.square();
        let t497 = t496.square();
        let t498 = t497.square();
        let t499 = t498.square();
        let t500 = t499.square();
        let t501 = t500.square();
        let t502 = t501.square();
        let t503 = t502.square();
        let t504 = t503 * t309;
        CtOption::new(t504, !self.ct_eq(&Scalar::ZERO))
    }

    /// Compute modular square root.
    pub fn sqrt(&self) -> CtOption<Self> {
        // NOTE: generated by `ff_derive`
        let t0 = self;
        let t1 = t0.square();
        let t2 = t1 * t0;
        let t3 = t2.square();
        let t4 = t3 * t2;
        let t5 = t4.square();
        //let t6 = t4.square();
        let t7 = t5.square();
        let t8 = t7.square();
        //let t9 = t7.square();
        let t10 = t8 * t1;
        let t11 = t10 * t2;
        let t12 = t11.square();
        let t13 = t12 * t11;
        let t14 = t13 * t10;
        let t15 = t14 * t11;
        let t16 = t15.square();
        let t17 = t16 * t15;
        let t18 = t17.square();
        let t19 = t18 * t15;
        let t20 = t19.square();
        let t21 = t20 * t15;
        let t22 = t21 * t14;
        let t23 = t22.square();
        let t24 = t23.square();
        let t25 = t24 * t22;
        let t26 = t25.square();
        let t27 = t26 * t22;
        let t28 = t27 * t15;
        let t29 = t28 * t22;
        let t30 = t29 * t28;
        let t31 = t30 * t29;
        let t32 = t31 * t30;
        let t33 = t32.square();
        let t34 = t33 * t31;
        let t35 = t34.square();
        let t36 = t35 * t34;
        let t37 = t36.square();
        let t38 = t37 * t34;
        let t39 = t38.square();
        let t40 = t39 * t34;
        let t41 = t40 * t32;
        let t42 = t41.square();
        let t43 = t42.square();
        let t44 = t43 * t41;
        let t45 = t44.square();
        //let t46 = t44.square();
        let t47 = t45 * t34;
        let t48 = t47 * t41;
        let t49 = t48.square();
        let t50 = t49 * t47;
        let t51 = t50 * t48;
        let t52 = t51.square();
        let t53 = t52 * t50;
        let t54 = t53 * t51;
        let t55 = t54 * t53;
        let t56 = t55 * t54;
        let t57 = t56 * t55;
        let t58 = t57.square();
        let t59 = t58.square();
        let t60 = t59 * t57;
        let t61 = t60.square();
        let t62 = t61 * t57;
        let t63 = t62 * t56;
        let t64 = t63.square();
        let t65 = t64.square();
        let t66 = t65.square();
        let t67 = t66.square();
        let t68 = t67 * t63;
        let t69 = t68 * t57;
        let t70 = t69.square();
        let t71 = t70.square();
        let t72 = t71.square();
        //let t73 = t71.square();
        let t74 = t72.square();
        let t75 = t74.square();
        let t76 = t75 * t70;
        let t77 = t76 * t63;
        let t78 = t77 * t69;
        let t79 = t78.square();
        let t80 = t79 * t78;
        let t81 = t80.square();
        let t82 = t81.square();
        //let t83 = t81.square();
        let t84 = t82.square();
        let t85 = t84.square();
        let t86 = t85 * t80;
        let t87 = t86 * t77;
        let t88 = t87.square();
        let t89 = t88 * t87;
        let t90 = t89.square();
        //let t91 = t89.square();
        let t92 = t90 * t78;
        let t93 = t92 * t87;
        let t94 = t93.square();
        let t95 = t94.square();
        let t96 = t95 * t93;
        let t97 = t96.square();
        let t98 = t97.square();
        let t99 = t98 * t93;
        let t100 = t99 * t92;
        let t101 = t100 * t93;
        let t102 = t101.square();
        let t103 = t102 * t101;
        let t104 = t103 * t100;
        let t105 = t104 * t101;
        let t106 = t105.square();
        let t107 = t106 * t104;
        let t108 = t107 * t105;
        let t109 = t108.square();
        let t110 = t109 * t107;
        let t111 = t110.square();
        let t112 = t111 * t110;
        let t113 = t112 * t108;
        let t114 = t113 * t110;
        let t115 = t114.square();
        let t116 = t115 * t113;
        let t117 = t116 * t114;
        let t118 = t117.square();
        let t119 = t118 * t117;
        let t120 = t119 * t116;
        let t121 = t120.square();
        let t122 = t121 * t117;
        let t123 = t122 * t120;
        let t124 = t123.square();
        let t125 = t124 * t123;
        let t126 = t125.square();
        //let t127 = t125.square();
        let t128 = t126 * t122;
        let t129 = t128 * t123;
        let t130 = t129 * t128;
        let t131 = t130.square();
        let t132 = t131.square();
        let t133 = t132.square();
        let t134 = t133 * t129;
        let t135 = t134.square();
        let t136 = t135 * t134;
        let t137 = t136.square();
        //let t138 = t136.square();
        let t139 = t137 * t130;
        let t140 = t139 * t134;
        let t141 = t140.square();
        let t142 = t141.square();
        let t143 = t142 * t139;
        let t144 = t143 * t140;
        let t145 = t144.square();
        let t146 = t145 * t143;
        let t147 = t146 * t144;
        let t148 = t147.square();
        let t149 = t148 * t147;
        let t150 = t149.square();
        let t151 = t150 * t147;
        let t152 = t151.square();
        //let t153 = t151.square();
        let t154 = t152 * t146;
        let t155 = t154 * t147;
        let t156 = t155.square();
        let t157 = t156 * t155;
        let t158 = t157.square();
        let t159 = t158 * t155;
        let t160 = t159.square();
        let t161 = t160.square();
        let t162 = t161 * t155;
        let t163 = t162 * t154;
        let t164 = t163.square();
        let t165 = t164.square();
        let t166 = t165 * t163;
        let t167 = t166 * t155;
        let t168 = t167.square();
        let t169 = t168.square();
        let t170 = t169.square();
        let t171 = t170 * t163;
        let t172 = t171 * t167;
        let t173 = t172.square();
        let t174 = t173 * t171;
        let t175 = t174.square();
        let t176 = t175.square();
        let t177 = t176 * t172;
        let t178 = t177.square();
        let t179 = t178.square();
        let t180 = t179 * t177;
        let t181 = t180 * t174;
        let t182 = t181.square();
        let t183 = t182.square();
        let t184 = t183 * t181;
        let t185 = t184 * t177;
        let t186 = t185 * t181;
        let t187 = t186.square();
        let t188 = t187 * t186;
        let t189 = t188.square();
        let t190 = t189 * t186;
        let t191 = t190.square();
        let t192 = t191.square();
        let t193 = t192 * t188;
        let t194 = t193 * t185;
        let t195 = t194 * t186;
        let t196 = t195.square();
        let t197 = t196 * t195;
        let t198 = t197.square();
        let t199 = t198 * t195;
        let t200 = t199 * t194;
        let t201 = t200 * t195;
        let t202 = t201.square();
        let t203 = t202 * t201;
        let t204 = t203 * t200;
        let t205 = t204 * t201;
        let t206 = t205 * t204;
        let t207 = t206.square();
        let t208 = t207.square();
        let t209 = t208 * t206;
        let t210 = t209 * t205;
        let t211 = t210.square();
        let t212 = t211.square();
        let t213 = t212 * t206;
        let t214 = t213.square();
        let t215 = t214 * t213;
        let t216 = t215.square();
        //let t217 = t215.square();
        let t218 = t216 * t210;
        let t219 = t218 * t213;
        let t220 = t219.square();
        let t221 = t220 * t218;
        let t222 = t221.square();
        let t223 = t222.square();
        let t224 = t223.square();
        let t225 = t224 * t219;
        let t226 = t225 * t221;
        let t227 = t226.square();
        let t228 = t227.square();
        let t229 = t228 * t227;
        let t230 = t229.square();
        //let t231 = t229.square();
        let t232 = t230 * t226;
        let t233 = t232.square();
        let t234 = t233.square();
        let t235 = t234.square();
        let t236 = t235 * t227;
        let t237 = t236 * t225;
        let t238 = t237 * t226;
        let t239 = t238.square();
        let t240 = t239 * t238;
        let t241 = t240 * t237;
        let t242 = t241 * t238;
        let t243 = t242.square();
        let t244 = t243.square();
        let t245 = t244 * t241;
        let t246 = t245.square();
        let t247 = t246.square();
        let t248 = t247 * t245;
        let t249 = t248 * t242;
        let t250 = t249 * t245;
        let t251 = t250.square();
        let t252 = t251 * t250;
        let t253 = t252 * t249;
        let t254 = t253 * t250;
        let t255 = t254.square();
        let t256 = t255 * t253;
        let t257 = t256.square();
        let t258 = t257.square();
        let t259 = t258 * t256;
        let t260 = t259.square();
        //let t261 = t259.square();
        let t262 = t260 * t254;
        let t263 = t262.square();
        let t264 = t263 * t256;
        let t265 = t264.square();
        let t266 = t265 * t264;
        let t267 = t266.square();
        //let t268 = t266.square();
        let t269 = t267 * t262;
        let t270 = t269.square();
        let t271 = t270.square();
        let t272 = t271 * t269;
        let t273 = t272 * t264;
        let t274 = t273.square();
        let t275 = t274.square();
        let t276 = t275 * t269;
        let t277 = t276.square();
        let t278 = t277.square();
        let t279 = t278 * t273;
        let t280 = t279 * t276;
        let t281 = t280.square();
        let t282 = t281 * t280;
        let t283 = t282.square();
        let t284 = t283 * t280;
        let t285 = t284 * t279;
        let t286 = t285 * t280;
        let t287 = t286.square();
        let t288 = t287 * t286;
        let t289 = t288.square();
        let t290 = t289 * t286;
        let t291 = t290 * t285;
        let t292 = t291.square();
        let t293 = t292 * t291;
        let t294 = t293.square();
        //let t295 = t293.square();
        let t296 = t294 * t286;
        let t297 = t296 * t291;
        let t298 = t297 * t296;
        let t299 = t298 * t297;
        let t300 = t299.square();
        let t301 = t300 * t299;
        let t302 = t301.square();
        let t303 = t302 * t299;
        let t304 = t303.square();
        let t305 = t304.square();
        //let t306 = t304.square();
        let t307 = t305 * t298;
        let t308 = t307.square();
        let t309 = t308 * t307;
        let t310 = t309.square();
        //let t311 = t309.square();
        let t312 = t310 * t299;
        let t313 = t312.square();
        let t314 = t313 * t307;
        let t315 = t314 * t312;
        let t316 = t315.square();
        let t317 = t316 * t315;
        let t318 = t317 * t314;
        let t319 = t318.square();
        let t320 = t319.square();
        let t321 = t320 * t318;
        let t322 = t321.square();
        //let t323 = t321.square();
        let t324 = t322 * t315;
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
        let t338 = t337.square();
        let t339 = t338.square();
        let t340 = t339.square();
        let t341 = t340.square();
        let t342 = t341.square();
        let t343 = t342.square();
        let t344 = t343.square();
        let t345 = t344.square();
        let t346 = t345.square();
        let t347 = t346.square();
        let t348 = t347.square();
        let t349 = t348.square();
        let t350 = t349.square();
        let t351 = t350.square();
        let t352 = t351.square();
        let t353 = t352.square();
        let t354 = t353.square();
        let t355 = t354.square();
        let t356 = t355.square();
        let t357 = t356.square();
        let t358 = t357.square();
        let t359 = t358.square();
        let t360 = t359.square();
        let t361 = t360.square();
        let t362 = t361.square();
        let t363 = t362.square();
        let t364 = t363.square();
        let t365 = t364.square();
        let t366 = t365.square();
        let t367 = t366.square();
        let t368 = t367.square();
        let t369 = t368.square();
        let t370 = t369.square();
        let t371 = t370.square();
        let t372 = t371.square();
        let t373 = t372.square();
        let t374 = t373.square();
        let t375 = t374.square();
        let t376 = t375.square();
        let t377 = t376.square();
        let t378 = t377.square();
        let t379 = t378.square();
        let t380 = t379.square();
        let t381 = t380.square();
        let t382 = t381.square();
        let t383 = t382.square();
        let t384 = t383.square();
        let t385 = t384.square();
        let t386 = t385.square();
        let t387 = t386.square();
        let t388 = t387.square();
        let t389 = t388.square();
        let t390 = t389.square();
        let t391 = t390.square();
        let t392 = t391.square();
        let t393 = t392.square();
        let t394 = t393.square();
        let t395 = t394.square();
        let t396 = t395.square();
        let t397 = t396.square();
        let t398 = t397.square();
        let t399 = t398.square();
        let t400 = t399.square();
        let t401 = t400.square();
        let t402 = t401.square();
        let t403 = t402.square();
        let t404 = t403.square();
        let t405 = t404.square();
        let t406 = t405.square();
        let t407 = t406.square();
        let t408 = t407.square();
        let t409 = t408.square();
        let t410 = t409.square();
        let t411 = t410.square();
        let t412 = t411.square();
        let t413 = t412.square();
        let t414 = t413.square();
        let t415 = t414.square();
        let t416 = t415.square();
        let t417 = t416.square();
        let t418 = t417.square();
        let t419 = t418.square();
        let t420 = t419.square();
        let t421 = t420.square();
        let t422 = t421.square();
        let t423 = t422.square();
        let t424 = t423.square();
        let t425 = t424.square();
        let t426 = t425.square();
        let t427 = t426.square();
        let t428 = t427.square();
        let t429 = t428.square();
        let t430 = t429.square();
        let t431 = t430.square();
        let t432 = t431.square();
        let t433 = t432.square();
        let t434 = t433.square();
        let t435 = t434.square();
        let t436 = t435.square();
        let t437 = t436.square();
        let t438 = t437.square();
        let t439 = t438.square();
        let t440 = t439.square();
        let t441 = t440.square();
        let t442 = t441.square();
        let t443 = t442.square();
        let t444 = t443.square();
        let t445 = t444.square();
        let t446 = t445.square();
        let t447 = t446.square();
        let t448 = t447.square();
        let t449 = t448.square();
        let t450 = t449.square();
        let t451 = t450.square();
        let t452 = t451.square();
        let t453 = t452.square();
        let t454 = t453.square();
        let t455 = t454.square();
        let t456 = t455.square();
        let t457 = t456.square();
        let t458 = t457.square();
        let t459 = t458.square();
        let t460 = t459.square();
        let t461 = t460.square();
        let t462 = t461.square();
        let t463 = t462.square();
        let t464 = t463.square();
        let t465 = t464.square();
        let t466 = t465.square();
        let t467 = t466.square();
        let t468 = t467.square();
        let t469 = t468.square();
        let t470 = t469.square();
        let t471 = t470.square();
        let t472 = t471.square();
        let t473 = t472.square();
        let t474 = t473.square();
        let t475 = t474.square();
        let t476 = t475.square();
        let t477 = t476.square();
        let t478 = t477.square();
        let t479 = t478.square();
        let t480 = t479.square();
        let t481 = t480.square();
        let t482 = t481.square();
        let t483 = t482.square();
        let t484 = t483.square();
        let t485 = t484.square();
        let t486 = t485.square();
        let t487 = t486.square();
        let t488 = t487.square();
        let t489 = t488.square();
        let t490 = t489.square();
        let t491 = t490.square();
        let t492 = t491.square();
        let t493 = t492.square();
        let t494 = t493.square();
        let t495 = t494.square();
        let t496 = t495.square();
        let t497 = t496.square();
        let t498 = t497.square();
        let t499 = t498.square();
        let t500 = t499.square();
        let t501 = t500.square();
        let t502 = t501.square();
        let t503 = t502.square();
        let t504 = t503.square();
        let t505 = t504.square();
        let t506 = t505.square();
        let t507 = t506.square();
        let t508 = t507.square();
        let t509 = t508.square();
        let t510 = t509.square();
        let t511 = t510.square();
        let t512 = t511.square();
        let t513 = t512.square();
        let sqrt = t513 * t318;
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }

    /// Montgomery reduction.
    #[cfg(target_pointer_width = "64")]
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn montgomery_reduce(
        r0: Limb,
        r1: Limb,
        r2: Limb,
        r3: Limb,
        r4: Limb,
        r5: Limb,
        r6: Limb,
        r7: Limb,
        r8: Limb,
        r9: Limb,
        r10: Limb,
        r11: Limb,
    ) -> Self {
        // NOTE: generated by `ff_derive`
        let modulus = MODULUS.limbs();

        let k = r0.wrapping_mul(Limb(INV));
        let (_, carry) = r0.mac(k, modulus[0], Limb::ZERO);
        let (r1, carry) = r1.mac(k, modulus[1], carry);
        let (r2, carry) = r2.mac(k, modulus[2], carry);
        let (r3, carry) = r3.mac(k, modulus[3], carry);
        let (r4, carry) = r4.mac(k, modulus[4], carry);
        let (r5, carry) = r5.mac(k, modulus[5], carry);
        let (r6, carry2) = r6.adc(Limb::ZERO, carry);

        let k = r1.wrapping_mul(Limb(INV));
        let (_, carry) = r1.mac(k, modulus[0], Limb::ZERO);
        let (r2, carry) = r2.mac(k, modulus[1], carry);
        let (r3, carry) = r3.mac(k, modulus[2], carry);
        let (r4, carry) = r4.mac(k, modulus[3], carry);
        let (r5, carry) = r5.mac(k, modulus[4], carry);
        let (r6, carry) = r6.mac(k, modulus[5], carry);
        let (r7, carry2) = r7.adc(carry2, carry);

        let k = r2.wrapping_mul(Limb(INV));
        let (_, carry) = r2.mac(k, modulus[0], Limb::ZERO);
        let (r3, carry) = r3.mac(k, modulus[1], carry);
        let (r4, carry) = r4.mac(k, modulus[2], carry);
        let (r5, carry) = r5.mac(k, modulus[3], carry);
        let (r6, carry) = r6.mac(k, modulus[4], carry);
        let (r7, carry) = r7.mac(k, modulus[5], carry);
        let (r8, carry2) = r8.adc(carry2, carry);

        let k = r3.wrapping_mul(Limb(INV));
        let (_, carry) = r3.mac(k, modulus[0], Limb::ZERO);
        let (r4, carry) = r4.mac(k, modulus[1], carry);
        let (r5, carry) = r5.mac(k, modulus[2], carry);
        let (r6, carry) = r6.mac(k, modulus[3], carry);
        let (r7, carry) = r7.mac(k, modulus[4], carry);
        let (r8, carry) = r8.mac(k, modulus[5], carry);
        let (r9, carry2) = r9.adc(carry2, carry);

        let k = r4.wrapping_mul(Limb(INV));
        let (_, carry) = r4.mac(k, modulus[0], Limb::ZERO);
        let (r5, carry) = r5.mac(k, modulus[1], carry);
        let (r6, carry) = r6.mac(k, modulus[2], carry);
        let (r7, carry) = r7.mac(k, modulus[3], carry);
        let (r8, carry) = r8.mac(k, modulus[4], carry);
        let (r9, carry) = r9.mac(k, modulus[5], carry);
        let (r10, carry2) = r10.adc(carry2, carry);

        let k = r5.wrapping_mul(Limb(INV));
        let (_, carry) = r5.mac(k, modulus[0], Limb::ZERO);
        let (r6, carry) = r6.mac(k, modulus[1], carry);
        let (r7, carry) = r7.mac(k, modulus[2], carry);
        let (r8, carry) = r8.mac(k, modulus[3], carry);
        let (r9, carry) = r9.mac(k, modulus[4], carry);
        let (r10, carry) = r10.mac(k, modulus[5], carry);
        let (r11, _) = r11.adc(carry2, carry);

        Self::from_uint_reduced(U384::new([r6, r7, r8, r9, r10, r11]))
    }
}

impl From<u64> for Scalar {
    fn from(n: u64) -> Scalar {
        Self(n.into())
    }
}

impl TryFrom<U384> for Scalar {
    type Error = Error;

    fn try_from(w: U384) -> Result<Self> {
        Option::from(ScalarCore::new(w)).map(Self).ok_or(Error)
    }
}

impl From<Scalar> for U384 {
    fn from(scalar: Scalar) -> U384 {
        *scalar.0.as_uint()
    }
}

impl From<ScalarCore> for Scalar {
    fn from(scalar: ScalarCore) -> Scalar {
        Self(scalar)
    }
}

impl From<Scalar> for FieldBytes {
    fn from(scalar: Scalar) -> Self {
        Self::from(&scalar)
    }
}

impl From<&Scalar> for FieldBytes {
    fn from(scalar: &Scalar) -> Self {
        scalar.to_repr()
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(ScalarCore::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl DefaultIsZeroes for Scalar {}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        self.0.is_high()
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        self.add(&other)
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Self(self.0.add(&other.0))
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, other: Scalar) {
        *self = *self + other;
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, other: &Scalar) {
        *self = *self + other;
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        self.sub(&other)
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Self(self.0.sub(&other.0))
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, other: Scalar) {
        *self = *self - other;
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, other: &Scalar) {
        *self = *self - other;
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Self(self.0.neg())
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    #[inline]
    fn mul(self, other: &Scalar) -> Self {
        Self::mul(&self, other)
    }
}

impl Mul for Scalar {
    type Output = Scalar;

    #[allow(clippy::op_ref)]
    #[inline]
    fn mul(self, other: Scalar) -> Self {
        self * &other
    }
}

impl MulAssign<&Scalar> for Scalar {
    #[cfg(target_pointer_width = "64")]
    #[inline]
    fn mul_assign(&mut self, other: &Scalar) {
        *self = *self * other;
    }
}

impl MulAssign for Scalar {
    #[inline]
    fn mul_assign(&mut self, other: Scalar) {
        self.mul_assign(&other);
    }
}

impl Reduce<U384> for Scalar {
    fn from_uint_reduced(w: U384) -> Self {
        let (r, underflow) = w.sbb(&NistP384::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BIT_SIZE - 1)) as u8);
        let reduced = U384::conditional_select(&w, &r, !underflow);
        Self(ScalarCore::new(reduced).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::Scalar;
    use crate::FieldBytes;
    use elliptic_curve::ff::{Field, PrimeField};

    #[test]
    fn from_to_bytes_roundtrip() {
        let k: u64 = 42;
        let mut bytes = FieldBytes::default();
        bytes[40..].copy_from_slice(k.to_be_bytes().as_ref());

        let scalar = Scalar::from_repr(bytes).unwrap();
        assert_eq!(bytes, scalar.to_bytes());
    }

    /// Basic tests that multiplication works.
    #[test]
    #[ignore]
    fn multiply() {
        let one = Scalar::one();
        let two = one + &one;
        let three = two + &one;
        let six = three + &three;
        assert_eq!(six, two * &three);

        let minus_two = -two;
        let minus_three = -three;
        assert_eq!(two, -minus_two);

        assert_eq!(minus_three * &minus_two, minus_two * &minus_three);
        assert_eq!(six, minus_two * &minus_three);
    }

    /// Basic tests that scalar inversion works.
    #[test]
    #[ignore]
    fn invert() {
        let one = Scalar::one();
        let three = one + &one + &one;
        let inv_three = three.invert().unwrap();
        // println!("1/3 = {:x?}", &inv_three);
        assert_eq!(three * &inv_three, one);

        let minus_three = -three;
        // println!("-3 = {:x?}", &minus_three);
        let inv_minus_three = minus_three.invert().unwrap();
        assert_eq!(inv_minus_three, -inv_three);
        // println!("-1/3 = {:x?}", &inv_minus_three);
        assert_eq!(three * &inv_minus_three, -one);
    }

    /// Basic tests that sqrt works.
    #[test]
    #[ignore]
    fn sqrt() {
        for &n in &[1u64, 4, 9, 16, 25, 36, 49, 64] {
            let scalar = Scalar::from(n);
            let sqrt = scalar.sqrt().unwrap();
            assert_eq!(sqrt.square(), scalar);
        }
    }
}
