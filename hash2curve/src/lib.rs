#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(non_snake_case)]
#![forbid(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    clippy::mod_module_files,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    unused_attributes,
    unused_imports,
    unused_mut,
    unused_must_use
)]

mod group_digest;
mod hash2field;
mod map2curve;
mod oprf;

pub use group_digest::*;
pub use hash2field::*;
pub use map2curve::*;
pub use oprf::*;

use elliptic_curve::ProjectivePoint;
use elliptic_curve::array::typenum::NonZero;
use elliptic_curve::array::{Array, ArraySize};
use elliptic_curve::group::cofactor::CofactorGroup;
use elliptic_curve::ops::Reduce;

/// Computes the hash to curve routine.
/// See [`GroupDigest::hash_from_bytes()`] for more details.
///
/// For the `expand_message` call, `len_in_bytes = <Self::FieldElement as FromOkm>::Length * 2`.
/// This value must be less than `u16::MAX` or otherwise a compiler error will occur.
///
/// # Errors
///
/// When the chosen [`ExpandMsg`] implementation returns an error. See [`ExpandMsgXmdError`]
/// and [`ExpandMsgXofError`] for examples.
///
/// [`ExpandMsgXmdError`]: crate::ExpandMsgXmdError
/// [`ExpandMsgXofError`]: crate::ExpandMsgXofError
pub fn hash_from_bytes<C, X>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<ProjectivePoint<C>, X::Error>
where
    C: MapToCurve,
    X: ExpandMsg<C::SecurityLevel>,
{
    let [u0, u1] = hash_to_field::<2, X, _, C::FieldElement, C::Length>(msg, dst)?;
    let q0 = C::map_to_curve(u0);
    let q1 = C::map_to_curve(u1);
    Ok((q0 + q1).clear_cofactor())
}

/// Computes the encode to curve routine.
/// See [`GroupDigest::encode_from_bytes()`] for more details.
///
/// For the `expand_message` call, `len_in_bytes = <Self::FieldElement as FromOkm>::Length`.
///
/// # Errors
///
/// When the chosen [`ExpandMsg`] implementation returns an error. See [`ExpandMsgXmdError`]
/// and [`ExpandMsgXofError`] for examples.
///
/// [`ExpandMsgXmdError`]: crate::ExpandMsgXmdError
/// [`ExpandMsgXofError`]: crate::ExpandMsgXofError
pub fn encode_from_bytes<C, X>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<ProjectivePoint<C>, X::Error>
where
    C: MapToCurve,
    X: ExpandMsg<C::SecurityLevel>,
{
    let [u] = hash_to_field::<1, X, _, C::FieldElement, C::Length>(msg, dst)?;
    let q0 = C::map_to_curve(u);
    Ok(q0.clear_cofactor())
}

/// Computes the hash to field routine according to
/// <https://www.rfc-editor.org/rfc/rfc9380.html#section-5-4>
/// and returns a scalar.
///   
/// For the `expand_message` call, `len_in_bytes = <Self::FieldElement as FromOkm>::Length`.
/// This value must be less than `u16::MAX` or otherwise a compiler error will occur.
///
/// # Errors
///
/// When the chosen [`ExpandMsg`] implementation returns an error. See [`ExpandMsgXmdError`]
/// and [`ExpandMsgXofError`] for examples.
///
/// [`ExpandMsgXmdError`]: crate::ExpandMsgXmdError
/// [`ExpandMsgXofError`]: crate::ExpandMsgXofError
pub fn hash_to_scalar<C, X, L>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<C::Scalar, X::Error>
where
    C: MapToCurve,
    X: ExpandMsg<C::SecurityLevel>,
    L: ArraySize + NonZero,
    C::Scalar: Reduce<Array<u8, L>>,
{
    let [u] = hash_to_field::<1, X, _, C::Scalar, L>(msg, dst)?;
    Ok(u)
}
