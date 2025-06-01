// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis agora lovecruft
// Copyright (c) 2016-2019 Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! Internal macros.

/// Define borrow and non-borrow variants of `Add`.
macro_rules! define_add_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> Add<&'b $rhs> for $lhs {
            type Output = $out;

            fn add(self, rhs: &'b $rhs) -> $out {
                &self + rhs
            }
        }

        impl<'a> Add<$rhs> for &'a $lhs {
            type Output = $out;

            fn add(self, rhs: $rhs) -> $out {
                self + &rhs
            }
        }

        impl Add<$rhs> for $lhs {
            type Output = $out;

            fn add(self, rhs: $rhs) -> $out {
                &self + &rhs
            }
        }
    };
}

/// Define non-borrow variants of `AddAssign`.
macro_rules! define_add_assign_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty) => {
        impl AddAssign<$rhs> for $lhs {
            fn add_assign(&mut self, rhs: $rhs) {
                *self += &rhs;
            }
        }
    };
}

/// Define borrow and non-borrow variants of `Sub`.
macro_rules! define_sub_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> Sub<&'b $rhs> for $lhs {
            type Output = $out;

            fn sub(self, rhs: &'b $rhs) -> $out {
                &self - rhs
            }
        }

        impl<'a> Sub<$rhs> for &'a $lhs {
            type Output = $out;

            fn sub(self, rhs: $rhs) -> $out {
                self - &rhs
            }
        }

        impl Sub<$rhs> for $lhs {
            type Output = $out;

            fn sub(self, rhs: $rhs) -> $out {
                &self - &rhs
            }
        }
    };
}

/// Define non-borrow variants of `SubAssign`.
macro_rules! define_sub_assign_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty) => {
        impl SubAssign<$rhs> for $lhs {
            fn sub_assign(&mut self, rhs: $rhs) {
                *self -= &rhs;
            }
        }
    };
}

/// Define borrow and non-borrow variants of `Mul`.
macro_rules! define_mul_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> Mul<&'b $rhs> for $lhs {
            type Output = $out;

            fn mul(self, rhs: &'b $rhs) -> $out {
                &self * rhs
            }
        }

        impl<'a> Mul<$rhs> for &'a $lhs {
            type Output = $out;

            fn mul(self, rhs: $rhs) -> $out {
                self * &rhs
            }
        }

        impl Mul<$rhs> for $lhs {
            type Output = $out;

            fn mul(self, rhs: $rhs) -> $out {
                &self * &rhs
            }
        }
    };
}

/// Define non-borrow variants of `MulAssign`.
macro_rules! define_mul_assign_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty) => {
        impl MulAssign<$rhs> for $lhs {
            fn mul_assign(&mut self, rhs: $rhs) {
                *self *= &rhs;
            }
        }
    };
}

#[cfg(feature = "zeroize")]
macro_rules! scalar_from_impls {
    ($curve:path, $scalar:ty) => {
        impl From<elliptic_curve::NonZeroScalar<$curve>> for $scalar {
            fn from(scalar: elliptic_curve::NonZeroScalar<$curve>) -> Self {
                *scalar.as_ref()
            }
        }

        impl From<&elliptic_curve::NonZeroScalar<$curve>> for $scalar {
            fn from(scalar: &elliptic_curve::NonZeroScalar<$curve>) -> Self {
                *scalar.as_ref()
            }
        }

        impl From<elliptic_curve::ScalarPrimitive<$curve>> for $scalar {
            fn from(w: elliptic_curve::ScalarPrimitive<$curve>) -> Self {
                <$scalar>::from(&w)
            }
        }

        impl From<&elliptic_curve::ScalarPrimitive<$curve>> for $scalar {
            fn from(w: &elliptic_curve::ScalarPrimitive<$curve>) -> $scalar {
                <$scalar>::from_uint_unchecked(*w.as_uint())
            }
        }

        impl From<$scalar> for elliptic_curve::ScalarPrimitive<$curve> {
            fn from(scalar: $scalar) -> elliptic_curve::ScalarPrimitive<$curve> {
                elliptic_curve::ScalarPrimitive::from(&scalar)
            }
        }

        impl From<&$scalar> for elliptic_curve::ScalarPrimitive<$curve> {
            fn from(scalar: &$scalar) -> elliptic_curve::ScalarPrimitive<$curve> {
                elliptic_curve::ScalarPrimitive::new(scalar.into()).unwrap()
            }
        }

        impl From<&elliptic_curve::SecretKey<$curve>> for $scalar {
            fn from(secret_key: &elliptic_curve::SecretKey<$curve>) -> $scalar {
                *secret_key.to_nonzero_scalar()
            }
        }

        /// The constant-time alternative is available at [`elliptic_curve::NonZeroScalar<$curve>::new()`].
        impl TryFrom<$scalar> for elliptic_curve::NonZeroScalar<$curve> {
            type Error = elliptic_curve::Error;

            fn try_from(scalar: $scalar) -> elliptic_curve::Result<Self> {
                elliptic_curve::NonZeroScalar::new(scalar)
                    .into_option()
                    .ok_or(elliptic_curve::Error)
            }
        }
    };
}
