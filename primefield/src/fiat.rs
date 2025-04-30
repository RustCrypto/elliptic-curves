//! Macros for generating wrappers for `fiat-crypto` synthesized field implementations.

/// Add `fiat-crypto` synthesized arithmetic impls to the given field element.
#[macro_export]
macro_rules! fiat_field_arithmetic {
    (
        $fe:tt,
        $bytes:ty,
        $uint:ty,
        $non_mont_type: expr,
        $mont_type: expr,
        $from_mont:ident,
        $to_mont:ident,
        $add:ident,
        $sub:ident,
        $mul:ident,
        $neg:ident,
        $square:ident,
        $divstep_precomp:ident,
        $divstep:ident,
        $msat:ident,
        $selectznz:ident
    ) => {
        impl $fe {
            /// Decode [`
            #[doc = stringify!($fe)]
            /// `] from [`
            #[doc = stringify!($uint)]
            /// `] converting it into Montgomery form.
            ///
            /// Does *not* perform a check that the field element does not overflow the order.
            ///
            /// Used incorrectly this can lead to invalid results!
            #[inline]
            pub(crate) const fn from_uint_unchecked(w: $uint) -> Self {
                let mut out = $mont_type([0; <$uint>::LIMBS]);
                $to_mont(&mut out, &$non_mont_type(w.to_words()));
                Self(<$uint>::from_words(out.0))
            }

            /// Translate [`
            #[doc = stringify!($fe)]
            /// `] out of the Montgomery domain, returning a [`
            #[doc = stringify!($uint)]
            /// `] in canonical form.
            #[inline]
            pub const fn to_canonical(self) -> $uint {
                let mut out = $non_mont_type([0; <$uint>::LIMBS]);
                $from_mont(&mut out, &$mont_type(self.0.to_words()));
                <$uint>::from_words(out.0)
            }

            /// Add elements.
            #[inline]
            pub const fn add(&self, rhs: &Self) -> Self {
                let mut out = $mont_type([0; <$uint>::LIMBS]);
                $add(
                    &mut out,
                    &$mont_type(self.0.to_words()),
                    &$mont_type(rhs.0.to_words()),
                );
                Self(<$uint>::from_words(out.0))
            }

            /// Double element (add it to itself).
            #[inline]
            #[must_use]
            pub const fn double(&self) -> Self {
                self.add(self)
            }

            /// Subtract elements.
            #[inline]
            pub const fn sub(&self, rhs: &Self) -> Self {
                let mut out = $mont_type([0; <$uint>::LIMBS]);
                $sub(
                    &mut out,
                    &$mont_type(self.0.to_words()),
                    &$mont_type(rhs.0.to_words()),
                );
                Self(<$uint>::from_words(out.0))
            }

            /// Multiply elements.
            #[inline]
            pub const fn multiply(&self, rhs: &Self) -> Self {
                let mut out = $mont_type([0; <$uint>::LIMBS]);
                $mul(
                    &mut out,
                    &$mont_type(self.0.to_words()),
                    &$mont_type(rhs.0.to_words()),
                );
                Self(<$uint>::from_words(out.0))
            }

            /// Negate element.
            #[inline]
            pub const fn neg(&self) -> Self {
                let mut out = $mont_type([0; <$uint>::LIMBS]);
                $neg(&mut out, &$mont_type(self.0.to_words()));
                Self(<$uint>::from_words(out.0))
            }

            /// Compute modular square.
            #[inline]
            #[must_use]
            pub const fn square(&self) -> Self {
                let mut out = $mont_type([0; <$uint>::LIMBS]);
                $square(&mut out, &$mont_type(self.0.to_words()));
                Self(<$uint>::from_words(out.0))
            }

            /// Compute
            #[doc = stringify!($fe)]
            /// inversion: `1 / self`.
            #[inline]
            pub fn invert(&self) -> $crate::subtle::CtOption<Self> {
                $crate::subtle::CtOption::new(self.invert_unchecked(), !self.is_zero())
            }

            /// Returns the multiplicative inverse of self.
            ///
            /// Does not check that self is non-zero.
            const fn invert_unchecked(&self) -> Self {
                let words = $crate::fiat_bernstein_yang_invert!(
                    &$mont_type(self.0.to_words()),
                    &$mont_type(Self::ONE.0.to_words()),
                    <$uint>::BITS as usize,
                    <$uint>::LIMBS,
                    ::elliptic_curve::bigint::Word, // TODO(tarcieri): source from `crypto-bigint` directly?
                    $non_mont_type,
                    $mont_type,
                    $from_mont,
                    $mul,
                    $neg,
                    $divstep_precomp,
                    $divstep,
                    $msat,
                    $selectznz
                );

                Self(<$uint>::from_words(words))
            }
        }

        impl ::core::ops::Neg for $fe {
            type Output = $fe;

            #[inline]
            fn neg(self) -> $fe {
                <$fe>::neg(&self)
            }
        }
    };
}

/// Emit wrapper function for a `fiat-crypto` generated implementation of the Bernstein-Yang
/// (a.k.a. safegcd) modular inversion algorithm.
#[macro_export]
macro_rules! fiat_bernstein_yang_invert {
    (
        $a:expr,
        $one:expr,
        $d:expr,
        $nlimbs:expr,
        $word:ty,
        $non_mont_type: expr,
        $mont_type: expr,
        $from_mont:ident,
        $mul:ident,
        $neg:ident,
        $divstep_precomp:ident,
        $divstep:ident,
        $msat:ident,
        $selectznz:ident
    ) => {{
        // See Bernstein-Yang 2019 p.366
        const ITERATIONS: usize = (49 * $d + 57) / 17;

        let mut a = $non_mont_type([0; $nlimbs]);
        $from_mont(&mut a, $a);
        let mut d = 1;
        let mut f = [0; $nlimbs + 1];
        $msat(&mut f);
        let mut g = [0; $nlimbs + 1];
        let mut v = [0; $nlimbs];
        let mut r = $one.0;
        let mut i = 0;
        let mut j = 0;

        while j < $nlimbs {
            g[j] = a.0[j];
            j += 1;
        }

        while i < ITERATIONS - ITERATIONS % 2 {
            let mut out1 = 0;
            let mut out2 = [0; $nlimbs + 1];
            let mut out3 = [0; $nlimbs + 1];
            let mut out4 = [0; $nlimbs];
            let mut out5 = [0; $nlimbs];

            $divstep(
                &mut out1, &mut out2, &mut out3, &mut out4, &mut out5, d, &f, &g, &v, &r,
            );
            $divstep(
                &mut d, &mut f, &mut g, &mut v, &mut r, out1, &out2, &out3, &out4, &out5,
            );
            i += 2;
        }

        if ITERATIONS % 2 != 0 {
            let mut out1 = 0;
            let mut out2 = [0; $nlimbs + 1];
            let mut out3 = [0; $nlimbs + 1];
            let mut out4 = [0; $nlimbs];
            let mut out5 = [0; $nlimbs];
            $divstep(
                &mut out1, &mut out2, &mut out3, &mut out4, &mut out5, d, &f, &g, &v, &r,
            );
            f = out2;
            v = out4;
        }

        let s = ((f[f.len() - 1] >> <$word>::BITS - 1) & 1) as u8;
        let mut neg_v = $mont_type([0; $nlimbs]);
        $neg(&mut neg_v, &$mont_type(v));

        let mut v2 = $mont_type([0; $nlimbs]);
        $selectznz(&mut v2.0, s, &v, &neg_v.0);

        let mut precomp = $mont_type([0; $nlimbs]);
        $divstep_precomp(&mut precomp.0);

        let mut out = $mont_type([0; $nlimbs]);
        $mul(&mut out, &v2, &precomp);
        out.0
    }};
}
