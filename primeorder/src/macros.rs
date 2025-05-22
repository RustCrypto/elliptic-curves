//! Macros for writing common patterns that interact with this crate.

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
