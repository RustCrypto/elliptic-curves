//! Macros for defining field element types.

mod fiat;

/// Creates a ZST representing the Montgomery parameters for a given field modulus.
///
/// Accepts the following parameters:
///
/// - name of the ZST representing the field modulus
/// - hex serialization of the modulus
/// - `crypto-bigint` unsigned integer type (e.g. U256)
/// - number of bytes in an encoded field element
/// - byte order to use when encoding/decoding field elements
/// - documentation string for the field modulus type
///
/// ```
/// use primefield::{ByteOrder, bigint::U256, consts::U32};
///
/// primefield::monty_field_params!(
///     name: FieldParams,
///     modulus: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
///     uint: U256,
///     byte_order: ByteOrder::BigEndian,
///     multiplicative_generator: 6,
///     doc: "P-256 field modulus"
/// );
/// ```
#[macro_export]
macro_rules! monty_field_params {
    (
        name: $name:ident,
        modulus: $modulus_hex:expr,
        uint: $uint:ty,
        byte_order: $byte_order:expr,
        multiplicative_generator: $multiplicative_generator:expr,
        doc: $doc:expr
    ) => {
        $crate::monty_field_params_with_root_of_unity! {
            name: $name,
            modulus: $modulus_hex,
            uint: $uint,
            byte_order: $byte_order,
            multiplicative_generator: $multiplicative_generator,
            root_of_unity: None,
            doc: $doc
        }
    };
}

/// Same as [`monty_field_params!`], but with a precomputed `ROOT_OF_UNITY` constant.
#[macro_export]
macro_rules! monty_field_params_with_root_of_unity {
    (
        name: $name:ident,
        modulus: $modulus_hex:expr,
        uint: $uint:ty,
        byte_order: $byte_order:expr,
        multiplicative_generator: $multiplicative_generator:expr,
        root_of_unity: $root_of_unity:expr,
        doc: $doc:expr
    ) => {
        use $crate::bigint::modular::ConstMontyParams;

        $crate::bigint::const_monty_params!($name, $uint, $modulus_hex, $doc);

        impl $crate::MontyFieldParams<{ <$uint>::LIMBS }> for $name {
            type ByteSize = $crate::bigint::hybrid_array::typenum::U<
                { $name::PARAMS.modulus().as_ref().bits().div_ceil(8) as usize },
            >;
            const BYTE_ORDER: $crate::ByteOrder = $byte_order;
            const MODULUS_HEX: &'static str = $modulus_hex;
            const MULTIPLICATIVE_GENERATOR: u64 = $multiplicative_generator;
            const T: $uint = $crate::compute_t($name::PARAMS.modulus().as_ref());
            const ROOT_OF_UNITY: Option<$uint> = $root_of_unity;
        }
    };
}

/// Implements a field element type whose internal representation is in
/// Montgomery form, providing a combination of trait impls and inherent impls
/// which are `const fn` where possible.
///
/// Accepts a set of `const fn` arithmetic operation functions as arguments.
///
/// # Inherent impls
/// - `const ZERO: Self`
/// - `const ONE: Self` (multiplicative identity)
/// - `pub fn from_bytes`
/// - `pub fn from_slice`
/// - `pub fn from_uint`
/// - `fn from_uint_unchecked`
/// - `pub fn to_bytes`
/// - `pub fn to_canonical`
/// - `pub fn is_odd`
/// - `pub fn is_zero`
/// - `pub fn double`
///
/// # Trait impls
/// - `ConditionallySelectable`
/// - `ConstantTimeEq`
/// - `ConstantTimeGreater`
/// - `ConstantTimeLess`
/// - `CtEq`
/// - `CtSelect`
/// - `Default`
/// - `DefaultIsZeroes`
/// - `Eq`
/// - `Field`
/// - `PartialEq`
///
/// ## Ops
/// - `Add`
/// - `AddAssign`
/// - `Sub`
/// - `SubAssign`
/// - `Mul`
/// - `MulAssign`
/// - `Neg`
/// - `Shr`
/// - `ShrAssign`
/// - `Invert`
#[macro_export]
macro_rules! monty_field_element {
    (
        name: $fe:tt,
        params: $params:ty,
        uint: $uint:path,
        doc: $doc:expr
    ) => {
        #[doc = $crate::monty_field_element_doc!($doc)]
        #[derive(Clone, Copy, PartialOrd, Ord)]
        pub struct $fe(
            pub(super) $crate::MontyFieldElement<$params, { <$params>::LIMBS }>,
        );

        impl $fe {
            /// Zero element.
            pub const ZERO: Self =
                Self($crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::ZERO);

            /// Multiplicative identity.
            pub const ONE: Self =
                Self($crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::ONE);

            /// Create a [`
            #[doc = stringify!($fe)]
            /// `] from a canonical big-endian representation.
            pub fn from_bytes(
                repr: &$crate::MontyFieldBytes<$params, { <$params>::LIMBS }>,
            ) -> $crate::subtle::CtOption<Self> {
                $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::from_bytes(repr).map(Self)
            }

            /// Decode [`
            #[doc = stringify!($fe)]
            /// `] from a big endian byte slice.
            pub fn from_slice(slice: &[u8]) -> Option<Self> {
                $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::from_slice(slice)
                    .map(Self)
            }

            /// Decode a [`
            #[doc = stringify!($fe)]
            /// `] from big endian hex-encoded bytes.
            ///
            /// This is primarily intended for defining constants using hex literals.
            ///
            /// # Panics
            ///
            /// - When hex is malformed
            /// - When input is the wrong length
            /// - If input overflows the modulus
            pub const fn from_hex_vartime(hex: &str) -> Self {
                use $crate::array::typenum::Unsigned;

                assert!(
                    hex.len() == <$params as $crate::MontyFieldParams<{ <$params>::LIMBS }>>::ByteSize::USIZE * 2,
                    "hex is the wrong length"
                );

                // Build a hex string of the expected size, regardless of the size of `Uint`
                let mut hex_bytes = [b'0'; { <$uint>::BITS as usize / 4 }];

                let offset = match <$params as $crate::MontyFieldParams<{ <$params>::LIMBS }>>::BYTE_ORDER {
                    $crate::ByteOrder::BigEndian => hex_bytes.len() - hex.len(),
                    $crate::ByteOrder::LittleEndian => 0
                };

                let mut i = 0;
                while i < hex.len() {
                    hex_bytes[i + offset] = hex.as_bytes()[i];
                    i += 1;
                }

                match core::str::from_utf8(&hex_bytes) {
                    Ok(padded_hex) => Self(
                        $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::from_hex_vartime(padded_hex),
                    ),
                    Err(_) => panic!("invalid hex string"),
                }


            }

            /// Decode [`
            #[doc = stringify!($fe)]
            /// `]
            /// from [`
            #[doc = stringify!($uint)]
            /// `] converting it into Montgomery form:
            ///
            /// ```text
            /// w * R^2 * R^-1 mod p = wR mod p
            /// ```
            pub fn from_uint(uint: &$uint) -> $crate::subtle::CtOption<Self> {
                $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::from_uint(uint).map(Self)
            }

            /// Convert a `u64` into a [`
            #[doc = stringify!($fe)]
            /// `].
            pub const fn from_u64(w: u64) -> Self {
                Self($crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::from_u64(w))
            }

            /// Returns the big-endian encoding of this [`
            #[doc = stringify!($fe)]
            /// `].
            pub fn to_bytes(self) -> $crate::MontyFieldBytes<$params, { <$params>::LIMBS }> {
                self.0.to_bytes()
            }

            /// Determine if this [`
            #[doc = stringify!($fe)]
            /// `] is odd in the SEC1 sense: `self mod 2 == 1`.
            ///
            /// # Returns
            ///
            /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
            pub fn is_odd(&self) -> $crate::subtle::Choice {
                self.0.is_odd()
            }

            /// Determine if this [`
            #[doc = stringify!($fe)]
            /// `] is even in the SEC1 sense: `self mod 2 == 0`.
            ///
            /// # Returns
            ///
            /// If even, return `Choice(1)`.  Otherwise, return `Choice(0)`.
            pub fn is_even(&self) -> $crate::subtle::Choice {
                !self.is_odd()
            }

            /// Determine if this [`
            #[doc = stringify!($fe)]
            /// `] is zero.
            ///
            /// # Returns
            ///
            /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
            pub fn is_zero(&self) -> $crate::subtle::Choice {
                self.0.is_zero()
            }

            /// Returns `self^exp`, where `exp` is a little-endian integer exponent.
            ///
            /// **This operation is variable time with respect to the exponent `exp`.**
            ///
            /// If the exponent is fixed, this operation is constant time.
            pub const fn pow_vartime<const RHS_LIMBS: usize>(
                &self,
                exp: &$crate::bigint::Uint<RHS_LIMBS>
            ) -> Self {
                Self(self.0.pow_vartime(exp))
            }

            /// Returns `self^(2^n) mod p`.
            ///
            /// **This operation is variable time with respect to the exponent `n`.**
            ///
            /// If the exponent is fixed, this operation is constant time.
            pub const fn sqn_vartime(&self, n: usize) -> Self {
                Self(self.0.sqn_vartime(n))
            }
        }

        impl $crate::bigint::modular::ConstMontyParams<{ <$params>::LIMBS }> for $fe {
            const LIMBS: usize = <$params>::LIMBS;
            const PARAMS: $crate::bigint::modular::MontyParams<{ <$uint>::LIMBS }> =
                <$params>::PARAMS;
        }

        impl $crate::ff::Field for $fe {
            const ZERO: Self = Self::ZERO;
            const ONE: Self = Self::ONE;

            fn try_from_rng<R: $crate::rand_core::TryRngCore + ?Sized>(
                rng: &mut R,
            ) -> ::core::result::Result<Self, R::Error> {
                $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::try_from_rng(rng)
                    .map(Self)
            }

            fn is_zero(&self) -> Choice {
                self.0.is_zero()
            }

            fn square(&self) -> Self {
                self.square()
            }

            fn double(&self) -> Self {
                self.double()
            }

            fn invert(&self) -> CtOption<Self> {
                self.invert()
            }

            fn sqrt(&self) -> CtOption<Self> {
                self.0.sqrt().map(Self)
            }

            fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
                $crate::ff::helpers::sqrt_ratio_generic(num, div)
            }
        }

        impl PrimeField for $fe {
            type Repr = $crate::MontyFieldBytes<$params, { <$params>::LIMBS }>;

            const MODULUS: &'static str =
                <$params as $crate::MontyFieldParams<{ <$uint>::LIMBS }>>::MODULUS_HEX;
            const NUM_BITS: u32 =
                $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::NUM_BITS;
            const CAPACITY: u32 =
                $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::CAPACITY;
            const TWO_INV: Self =
                Self($crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::TWO_INV);
            const MULTIPLICATIVE_GENERATOR: Self = Self(
                $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::MULTIPLICATIVE_GENERATOR,
            );
            const S: u32 = $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::S;
            const ROOT_OF_UNITY: Self =
                Self($crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::ROOT_OF_UNITY);
            const ROOT_OF_UNITY_INV: Self =
                Self($crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::ROOT_OF_UNITY_INV);
            const DELTA: Self =
                Self($crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::DELTA);

            #[inline]
            fn from_repr(bytes: Self::Repr) -> $crate::subtle::CtOption<Self> {
                $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::from_repr(bytes).map(Self)
            }

            #[inline]
            fn to_repr(&self) -> Self::Repr {
                self.0.to_repr()
            }

            #[inline]
            fn is_odd(&self) -> $crate::subtle::Choice {
                self.0.is_odd()
            }
        }

        #[cfg(feature = "bits")]
        impl $crate::ff::PrimeFieldBits for $fe {
            type ReprBits = [$crate::bigint::Word; <$uint>::LIMBS];

            fn to_le_bits(&self) -> $crate::ff::FieldBits<Self::ReprBits> {
                self.to_canonical().to_words().into()
            }

            fn char_le_bits() -> $crate::ff::FieldBits<Self::ReprBits> {
                Self::PARAMS.modulus().to_words().into()
            }
        }

        // TODO(tarcieri): write `Reduce` impls
        // impl $crate::bigint::Reduce<$uint> for $fe {
        //     fn reduce(w: &$uint) -> Self {
        //         Self($crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::reduce(w))
        //     }
        // }
        //
        // impl $crate::bigint::Reduce<$crate::MontyFieldBytes<$params, { <$params>::LIMBS }>> for $fe {
        //     #[inline]
        //     fn reduce(bytes: &$crate::MontyFieldBytes<$params, { <$params>::LIMBS }>) -> Self {
        //         Self($crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::reduce(bytes))
        //     }
        // }

        $crate::field_op!($fe, Add, add, add);
        $crate::field_op!($fe, Sub, sub, sub);
        $crate::field_op!($fe, Mul, mul, multiply);

        impl ::core::ops::AddAssign<$fe> for $fe {
            #[inline]
            fn add_assign(&mut self, other: $fe) {
                *self = *self + other;
            }
        }

        impl ::core::ops::AddAssign<&$fe> for $fe {
            #[inline]
            fn add_assign(&mut self, other: &$fe) {
                *self = *self + other;
            }
        }

        impl ::core::ops::SubAssign<$fe> for $fe {
            #[inline]
            fn sub_assign(&mut self, other: $fe) {
                *self = *self - other;
            }
        }

        impl ::core::ops::SubAssign<&$fe> for $fe {
            #[inline]
            fn sub_assign(&mut self, other: &$fe) {
                *self = *self - other;
            }
        }

        impl ::core::ops::MulAssign<&$fe> for $fe {
            #[inline]
            fn mul_assign(&mut self, other: &$fe) {
                *self = *self * other;
            }
        }

        impl ::core::ops::MulAssign for $fe {
            #[inline]
            fn mul_assign(&mut self, other: $fe) {
                *self = *self * other;
            }
        }

        impl ::core::ops::Neg for $fe {
            type Output = $fe;

            #[inline]
            fn neg(self) -> $fe {
                <$fe>::neg(&self)
            }
        }

        impl ::core::ops::Neg for &$fe {
            type Output = $fe;

            #[inline]
            fn neg(self) -> $fe {
                <$fe>::neg(self)
            }
        }

        impl ::core::fmt::Debug for $fe {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}(0x{:X})", stringify!($fe), &self.0)
            }
        }

        impl Default for $fe {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl Eq for $fe {}
        impl PartialEq for $fe {
            fn eq(&self, rhs: &Self) -> bool {
                self.0.ct_eq(&(rhs.0)).into()
            }
        }

        impl From<u32> for $fe {
            fn from(n: u32) -> $fe {
                Self::from_uint_unchecked(<$uint>::from(n))
            }
        }

        impl From<u64> for $fe {
            fn from(n: u64) -> $fe {
                Self::from_uint_unchecked(<$uint>::from(n))
            }
        }

        impl From<u128> for $fe {
            fn from(n: u128) -> $fe {
                Self::from_uint_unchecked(<$uint>::from(n))
            }
        }

        impl From<$fe> for $crate::MontyFieldBytes<$params, { <$params>::LIMBS }> {
            fn from(fe: $fe) -> Self {
                $crate::MontyFieldBytes::<$params, { <$params>::LIMBS }>::from(&fe)
            }
        }

        impl From<&$fe> for $crate::MontyFieldBytes<$params, { <$params>::LIMBS }> {
            fn from(fe: &$fe) -> Self {
                fe.to_repr()
            }
        }

        impl From<$crate::MontyFieldElement::<$params, { <$params>::LIMBS }>> for $fe {
            fn from(fe: $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>) -> $fe {
                $fe(fe)
            }
        }

        impl From<$fe> for $crate::MontyFieldElement<$params, { <$params>::LIMBS }> {
            fn from(fe: $fe) -> $crate::MontyFieldElement<$params, { <$params>::LIMBS }> {
                fe.0
            }
        }

        impl From<$fe> for $uint {
            fn from(fe: $fe) -> $uint {
                <$uint>::from(&fe)
            }
        }

        impl From<&$fe> for $uint {
            fn from(fe: &$fe) -> $uint {
                fe.to_canonical()
            }
        }

        impl TryFrom<$uint> for $fe {
            type Error = $crate::Error;

            fn try_from(w: $uint) -> $crate::Result<Self> {
                Self::try_from(&w)
            }
        }

        impl TryFrom<&$uint> for $fe {
            type Error = $crate::Error;

            fn try_from(w: &$uint) -> $crate::Result<Self> {
                Self::from_uint(w).into_option().ok_or($crate::Error)
            }
        }

        impl ::core::iter::Sum for $fe {
            #[allow(unused_qualifications)]
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.reduce(core::ops::Add::add).unwrap_or(Self::ZERO)
            }
        }

        impl<'a> ::core::iter::Sum<&'a $fe> for $fe {
            fn sum<I: Iterator<Item = &'a $fe>>(iter: I) -> Self {
                iter.copied().sum()
            }
        }

        impl ::core::iter::Product for $fe {
            #[allow(unused_qualifications)]
            fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.reduce(core::ops::Mul::mul).unwrap_or(Self::ONE)
            }
        }

        impl<'a> ::core::iter::Product<&'a $fe> for $fe {
            fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.copied().product()
            }
        }

        impl $crate::bigint::Invert for $fe {
            type Output = CtOption<Self>;

            fn invert(&self) -> CtOption<Self> {
                self.invert()
            }
        }

        impl $crate::subtle::ConditionallySelectable for $fe {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self(
                    $crate::MontyFieldElement::<$params, { <$params>::LIMBS }>::conditional_select(
                        &a.0, &b.0, choice,
                    ),
                )
            }
        }

        impl $crate::subtle::ConstantTimeEq for $fe {
            fn ct_eq(&self, other: &Self) -> $crate::subtle::Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl $crate::subtle::ConstantTimeGreater for $fe {
            fn ct_gt(&self, other: &Self) -> $crate::subtle::Choice {
                self.0.ct_gt(&other.0)
            }
        }

        impl $crate::subtle::ConstantTimeLess for $fe {
            fn ct_lt(&self, other: &Self) -> $crate::subtle::Choice {
                self.0.ct_lt(&other.0)
            }
        }

        impl $crate::bigint::ctutils::CtSelect for $fe {
            fn ct_select(&self, other: &Self, choice: $crate::bigint::ctutils::Choice) -> Self {
                Self(
                    $crate::bigint::ctutils::CtSelect::ct_select(
                        &self.0, &other.0, choice,
                    ),
                )
            }
        }

        impl $crate::bigint::ctutils::CtEq for $fe {
            fn ct_eq(&self, other: &Self) -> $crate::bigint::ctutils::Choice {
                $crate::bigint::ctutils::CtEq::ct_eq(&self.0, &other.0)
            }
        }

        impl $crate::bigint::ctutils::CtGt for $fe {
            fn ct_gt(&self, other: &Self) -> $crate::bigint::ctutils::Choice {
                $crate::bigint::ctutils::CtGt::ct_gt(&self.0, &other.0)
            }
        }

        impl $crate::bigint::ctutils::CtLt for $fe {
            fn ct_lt(&self, other: &Self) -> $crate::bigint::ctutils::Choice {
                $crate::bigint::ctutils::CtLt::ct_lt(&self.0, &other.0)
            }
        }

        impl $crate::zeroize::DefaultIsZeroes for $fe {}
    };
}

/// Add `const fn` methods to the given field element for performing field arithmetic operations,
/// e.g. `add`, `double`, `sub`, `multiply`, `neg`.
///
/// This macro wraps a generic field implementation provided by the `crypto-bigint` crate, which is
/// exposed as the [`primefield::MontyFieldElement`] type.
#[macro_export]
macro_rules! monty_field_arithmetic {
    (
        name: $fe:tt,
        params: $params:ty,
        uint: $uint:ty
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
                // TODO(tarcieri): this reduces every time, maybe we can find a way to skip that?
                Self($crate::MontyFieldElement::from_uint_reduced(&w))
            }

            /// Translate [`
            #[doc = stringify!($fe)]
            /// `] out of the Montgomery domain, returning a [`
            #[doc = stringify!($uint)]
            /// `] in canonical form.
            #[inline]
            pub const fn to_canonical(self) -> $uint {
                self.0.to_canonical()
            }

            /// Add elements.
            #[inline]
            pub const fn add(&self, rhs: &Self) -> Self {
                Self(self.0.add(&rhs.0))
            }

            /// Double element (add it to itself).
            #[inline]
            #[must_use]
            pub const fn double(&self) -> Self {
                Self(self.0.double())
            }

            /// Subtract elements.
            #[inline]
            pub const fn sub(&self, rhs: &Self) -> Self {
                Self(self.0.sub(&rhs.0))
            }

            /// Multiply elements.
            #[inline]
            pub const fn multiply(&self, rhs: &Self) -> Self {
                Self(self.0.multiply(&rhs.0))
            }

            /// Negate element.
            #[inline]
            pub const fn neg(&self) -> Self {
                Self(self.0.neg())
            }

            /// Compute modular square.
            #[inline]
            #[must_use]
            pub const fn square(&self) -> Self {
                Self(self.0.square())
            }

            /// Compute
            #[doc = stringify!($fe)]
            /// inversion: `1 / self`.
            #[inline]
            pub fn invert(&self) -> $crate::subtle::CtOption<Self> {
                self.0.invert().map(|fe| Self(fe))
            }

            /// Compute field inversion as a `const fn`. Panics if `self` is zero.
            ///
            /// This is mainly intended for inverting constants at compile time.
            pub const fn const_invert(&self) -> Self {
                Self(self.0.const_invert())
            }
        }
    };
}

/// Emit a `core::ops` trait wrapper for an inherent method which is expected to be provided by a
/// backend arithmetic implementation (e.g. `fiat-crypto`)
#[macro_export]
macro_rules! field_op {
    ($fe:path, $op:tt, $func:ident, $inner_func:ident) => {
        impl ::core::ops::$op for $fe {
            type Output = $fe;

            #[inline]
            fn $func(self, rhs: $fe) -> $fe {
                <$fe>::$inner_func(&self, &rhs)
            }
        }

        impl ::core::ops::$op<&$fe> for $fe {
            type Output = $fe;

            #[inline]
            fn $func(self, rhs: &$fe) -> $fe {
                <$fe>::$inner_func(&self, rhs)
            }
        }

        impl ::core::ops::$op<&$fe> for &$fe {
            type Output = $fe;

            #[inline]
            fn $func(self, rhs: &$fe) -> $fe {
                <$fe>::$inner_func(self, rhs)
            }
        }
    };
}

/// Write documentation for a field element type.
#[doc(hidden)]
#[macro_export]
#[rustfmt::skip]
macro_rules! monty_field_element_doc {
    ($about:expr) => {
        concat!(
            $about,
            "\n\n",
            "# Trait impls\n",
            "\n",
            "Much of the important functionality is provided by traits from the [`ff`] crate:\n",
            "\n",
            "- [`Field`] represents elements of finite fields and provides:\n",
            "  - [`Field::random`] generate a random field element\n",
            "  - `double`, `square`, and `invert` operations\n",
            "  - Bounds for [`Add`], [`Sub`], [`Mul`], and [`Neg`] (and `*Assign` equivalents)\n",
            "  - Bounds for [`ConditionallySelectable`] from the `subtle` crate\n",
            "- [`PrimeField`] represents elements of prime fields and provides:\n",
            "  - `from_repr`/`to_repr` for converting field elements from/to big integers.\n",
            "  - `MULTIPLICATIVE_GENERATOR` and `ROOT_OF_UNITY` constants.\n",
            "- [`PrimeFieldBits`] operations over field elements represented as bits ",
            "  (requires `bits` feature)\n",
            "\n",
            "Please see the documentation for the relevant traits for more information.\n"
        )
    };
}
