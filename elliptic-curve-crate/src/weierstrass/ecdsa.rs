//! Low-level ECDSA primitives
//!
//! # ⚠️ Warning: Hazmat!
//!
//! YOU PROBABLY DON'T WANT TO USE THESE!
//!
//! These primitives are easy-to-misuse low-level interfaces intended to be
//! consumed by a higher-level ECDSA implementation.
//!
//! If you are an end user / non-expert in cryptography, do not use these!
//! Failure to use them correctly can lead to catastrophic failures including
//! FULL PRIVATE KEY RECOVERY!

use super::{CompressedPointSize, Curve, PublicKey, UncompressedPointSize};
use crate::{consts::U1, Error, ScalarBytes};
use core::ops::Add;
use generic_array::{ArrayLength, GenericArray};

/// ECDSA signature size
pub type SignatureSize<C> = <<C as Curve>::ScalarSize as Add>::Output;

/// ECDSA signature for the given curve; serialized as "fixed" bytes
pub type Signature<C> = GenericArray<u8, SignatureSize<C>>;

/// Try to sign the given prehashed message using ECDSA
pub trait SignPrimitive: Curve
where
    SignatureSize<Self>: ArrayLength<u8>,
{
    /// Scalar type
    type Scalar;

    /// Try to sign the prehashed message.
    ///
    /// Accepts the following arguments:
    ///
    /// - `secret_scalar`: signing key
    /// - `ephemeral_scalar`: ECDSA `k` value (MUST BE UNIFORMLY RANDOM!!!)
    /// - `masking_scalar`: optional blinding factor for sidechannel resistance
    /// - `hashed_msg`: prehashed message to be signed
    fn try_sign_prehashed(
        secret_scalar: Self::Scalar,
        ephemeral_scalar: Self::Scalar,
        masking_scalar: Option<Self::Scalar>,
        hashed_msg: &ScalarBytes<Self::ScalarSize>,
    ) -> Result<Signature<Self>, Error>;
}

/// Verify the given prehashed message using ECDSA
pub trait VerifyPrimitive: Curve
where
    <Self::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<Self::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<Self::ScalarSize>: ArrayLength<u8>,
    SignatureSize<Self>: ArrayLength<u8>,
{
    /// Scalar type
    type Scalar;

    /// Verify the prehashed message against the provided signature
    ///
    /// Accepts the following arguments:
    ///
    /// - `verify_key`: public key to verify the signature against
    /// - `hashed_msg`: prehashed message to be verified
    /// - `signature`: signature to be verified against the key and message
    fn verify_prehashed(
        verify_key: &PublicKey<Self>,
        hashed_msg: &ScalarBytes<Self::ScalarSize>,
        signature: &Signature<Self>,
    ) -> Result<(), Error>;
}

/// Public key recovery primitive
pub trait RecoverPrimitive: Curve
where
    <Self::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<Self::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<Self::ScalarSize>: ArrayLength<u8>,
    SignatureSize<Self>: ArrayLength<u8>,
{
    /// Recover the public key used to produce a given signature
    ///
    /// Accepts the following arguments:
    ///
    /// - `hashed_msg`: prehashed message the signature was computed against
    /// - `signature`: signature over the prehashed message
    /// - `r_reduced`: did the x-coordinate of `k×G` overflow the curve's order when computing `r`?
    /// - `y_is_odd`: is the y-coordinate of the public key odd?
    fn recover_pubkey(
        hashed_msg: &ScalarBytes<Self::ScalarSize>,
        signature: &Signature<Self>,
        r_reduced: bool,
        y_is_odd: bool,
    ) -> Result<PublicKey<Self>, Error>;
}
