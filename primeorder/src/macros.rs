//! Macros for writing common patterns that interact with this crate.

/// Writes all impls for scalar field types.
#[macro_export]
macro_rules! scalar_impls {
    ($curve:path, $scalar:ty) => {
        $crate::scalar_from_impls!($curve, $scalar);
        $crate::scalar_mul_impls!($curve, $scalar);
    };
}

/// Writes a series of `From` impls for scalar field types.
#[macro_export]
macro_rules! scalar_from_impls {
    ($curve:path, $scalar:ty) => {
        impl From<$crate::elliptic_curve::NonZeroScalar<$curve>> for $scalar {
            fn from(scalar: $crate::elliptic_curve::NonZeroScalar<$curve>) -> Self {
                *scalar.as_ref()
            }
        }

        impl From<&$crate::elliptic_curve::NonZeroScalar<$curve>> for $scalar {
            fn from(scalar: &$crate::elliptic_curve::NonZeroScalar<$curve>) -> Self {
                *scalar.as_ref()
            }
        }

        impl From<$crate::elliptic_curve::ScalarPrimitive<$curve>> for $scalar {
            fn from(w: $crate::elliptic_curve::ScalarPrimitive<$curve>) -> Self {
                <$scalar>::from(&w)
            }
        }

        impl From<&$crate::elliptic_curve::ScalarPrimitive<$curve>> for $scalar {
            fn from(w: &$crate::elliptic_curve::ScalarPrimitive<$curve>) -> $scalar {
                <$scalar>::from_uint_unchecked(*w.as_uint())
            }
        }

        impl From<$scalar> for $crate::elliptic_curve::ScalarPrimitive<$curve> {
            fn from(scalar: $scalar) -> $crate::elliptic_curve::ScalarPrimitive<$curve> {
                $crate::elliptic_curve::ScalarPrimitive::from(&scalar)
            }
        }

        impl From<&$scalar> for $crate::elliptic_curve::ScalarPrimitive<$curve> {
            fn from(scalar: &$scalar) -> $crate::elliptic_curve::ScalarPrimitive<$curve> {
                $crate::elliptic_curve::ScalarPrimitive::new(scalar.into()).unwrap()
            }
        }

        impl From<&$crate::elliptic_curve::SecretKey<$curve>> for $scalar {
            fn from(secret_key: &$crate::elliptic_curve::SecretKey<$curve>) -> $scalar {
                *secret_key.to_nonzero_scalar()
            }
        }

        /// The constant-time alternative is available at [`$crate::elliptic_curve::NonZeroScalar<$curve>::new()`].
        impl TryFrom<$scalar> for $crate::elliptic_curve::NonZeroScalar<$curve> {
            type Error = $crate::elliptic_curve::Error;

            fn try_from(scalar: $scalar) -> $crate::elliptic_curve::Result<Self> {
                $crate::elliptic_curve::NonZeroScalar::new(scalar)
                    .into_option()
                    .ok_or(Error)
            }
        }
    };
}

/// Writes a series of `Mul` impls for an elliptic curve's scalar field
#[macro_export]
macro_rules! scalar_mul_impls {
    ($curve:path, $scalar:ty) => {
        impl ::core::ops::Mul<$crate::elliptic_curve::AffinePoint<$curve>> for $scalar {
            type Output = $crate::elliptic_curve::ProjectivePoint<$curve>;

            #[inline]
            fn mul(
                self,
                rhs: $crate::elliptic_curve::AffinePoint<$curve>,
            ) -> $crate::elliptic_curve::ProjectivePoint<$curve> {
                rhs * self
            }
        }

        impl ::core::ops::Mul<&$crate::elliptic_curve::AffinePoint<$curve>> for $scalar {
            type Output = $crate::elliptic_curve::ProjectivePoint<$curve>;

            #[inline]
            fn mul(
                self,
                rhs: &$crate::elliptic_curve::AffinePoint<$curve>,
            ) -> $crate::elliptic_curve::ProjectivePoint<$curve> {
                *rhs * self
            }
        }

        impl ::core::ops::Mul<$crate::elliptic_curve::AffinePoint<$curve>> for &$scalar {
            type Output = $crate::elliptic_curve::ProjectivePoint<$curve>;

            #[inline]
            fn mul(
                self,
                rhs: $crate::elliptic_curve::AffinePoint<$curve>,
            ) -> $crate::elliptic_curve::ProjectivePoint<$curve> {
                rhs * self
            }
        }

        impl ::core::ops::Mul<&$crate::elliptic_curve::AffinePoint<$curve>> for &$scalar {
            type Output = $crate::elliptic_curve::ProjectivePoint<$curve>;

            #[inline]
            fn mul(
                self,
                rhs: &$crate::elliptic_curve::AffinePoint<$curve>,
            ) -> $crate::elliptic_curve::ProjectivePoint<$curve> {
                *rhs * self
            }
        }

        impl ::core::ops::Mul<$crate::elliptic_curve::ProjectivePoint<$curve>> for $scalar {
            type Output = $crate::elliptic_curve::ProjectivePoint<$curve>;

            #[inline]
            fn mul(
                self,
                rhs: $crate::elliptic_curve::ProjectivePoint<$curve>,
            ) -> $crate::elliptic_curve::ProjectivePoint<$curve> {
                rhs * self
            }
        }

        impl ::core::ops::Mul<&$crate::elliptic_curve::ProjectivePoint<$curve>> for $scalar {
            type Output = $crate::elliptic_curve::ProjectivePoint<$curve>;

            #[inline]
            fn mul(
                self,
                rhs: &$crate::elliptic_curve::ProjectivePoint<$curve>,
            ) -> $crate::elliptic_curve::ProjectivePoint<$curve> {
                rhs * &self
            }
        }

        impl ::core::ops::Mul<$crate::elliptic_curve::ProjectivePoint<$curve>> for &$scalar {
            type Output = $crate::elliptic_curve::ProjectivePoint<$curve>;

            #[inline]
            fn mul(
                self,
                rhs: $crate::elliptic_curve::ProjectivePoint<$curve>,
            ) -> $crate::elliptic_curve::ProjectivePoint<$curve> {
                rhs * self
            }
        }

        impl ::core::ops::Mul<&$crate::elliptic_curve::ProjectivePoint<$curve>> for &$scalar {
            type Output = $crate::elliptic_curve::ProjectivePoint<$curve>;

            #[inline]
            fn mul(
                self,
                rhs: &$crate::elliptic_curve::ProjectivePoint<$curve>,
            ) -> $crate::elliptic_curve::ProjectivePoint<$curve> {
                rhs * self
            }
        }
    };
}
