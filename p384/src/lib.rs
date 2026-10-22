#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
//! ## Backends
//!
//! This crate has support for two different field arithmetic backends which can be selected using
//! `cfg(p384_backend)`, e.g. to select the formally verified `fiat` backend:
//!
//! ```console
//! $ RUSTFLAGS='--cfg p384_backend="fiat"' cargo test
//! ```
//!
//! Or it can be set through [`.cargo/config`][buildrustflags]:
//!
//! ```toml
//! [build]
//! rustflags = ['--cfg', 'p384_backend="fiat"']
//! ```
//!
//! The available backends are:
//! - `bigint` (default): backend provided by [crypto-bigint], which should provide better
//!   performance as well as smaller code size and fewer dependencies, but isn't formally verified
//!   and may contain bugs
//! - `fiat`: formally verified implementation synthesized by [fiat-crypto] which should
//!   be correct for all inputs (though there's a possibility of bugs in the code which glues to it)
//!
//! [buildrustflags]: https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags
//! [crypto-bigint]: https://github.com/RustCrypto/crypto-bigint
//! [fiat-crypto]: https://github.com/mit-plv/fiat-crypto
//!
//! ## `serde` support
//!
//! When the `serde` feature of this crate is enabled, `Serialize` and
//! `Deserialize` are impl'd for the following types:
//!
//! - [`AffinePoint`]
//! - [`ProjectivePoint`]
//! - [`Scalar`]
//! - [`ecdsa::VerifyingKey`]
//!
//! Please see type-specific documentation for more information.
//!
//! ## PKCS#8 Key Encoding
//!
//! PKCS#8 is a private key format with support for multiple algorithms. It can be
//! encoded as binary DER or text PEM.
//!
//! You can recognize PEM encoded PKCS#8 private keys because they do not have an
//! algorithm name in the type label, e.g.:
//!
//! ```text
//! -----BEGIN PRIVATE KEY-----
//! ```
//!
//! PKCS#8 support is gated under the `pkcs8` feature. The `pem` feature, which is
//! enabled by default, adds PEM decoding and also enables `pkcs8`.
//!
//! The same pattern is used by the other curve crates in this repository which
//! re-export `pkcs8`.
//!
//! The following traits can be used to decode/encode secret and public keys as
//! PKCS#8/SPKI. Note that [`pkcs8`] is re-exported from `p384` when the `pkcs8`
//! feature is enabled:
//!
//! - [`pkcs8::DecodePrivateKey`]: decode private keys from PKCS#8
//! - [`pkcs8::EncodePrivateKey`]: encode private keys to PKCS#8
//! - [`pkcs8::DecodePublicKey`]: decode public keys from SPKI
//! - [`pkcs8::EncodePublicKey`]: encode public keys to SPKI
//!
//! For private keys, [`SecretKey::from_der`] and [`SecretKey::from_pem`] provide
//! convenience methods which can decode PKCS#8 keys. Use the trait methods above
//! when the input is expected to be specifically PKCS#8.
//!
//! ### Example
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "pem")]
//! # {
//! use p384::SecretKey;
//!
//! // WARNING: Do not hardcode private keys in your source code. This is for demonstration purposes only.
//! let pem = r#"-----BEGIN PRIVATE KEY-----
//! MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBs2FQo+zKrF8hywWB/
//! mISKUjsyCpYI/tZc0nzXW9zsBE3xqR0gG/f3qsETDG3cSw+hZANiAAR5bOBw+XY+
//! jrppUPPAT9VKB+e9X/4Lk9tpYNpC1dfLXzTa4wzRkCS5MJHgYNnYynzFKG0a1uY5
//! cO4Gd7ngQcruAZwkADecrwDeGtnrTdcRrQ0qhQGlHYfwT4runOeuT2c=
//! -----END PRIVATE KEY-----"#;
//! let secret_key = SecretKey::from_pem(pem)?;
//! # let _ = secret_key;
//! # }
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "ecdh")]
pub mod ecdh;
#[cfg(feature = "ecdsa-core")]
pub mod ecdsa;
#[cfg(any(feature = "test-vectors", test))]
pub mod test_vectors;

#[cfg(feature = "arithmetic")]
mod arithmetic;

pub use elliptic_curve::{
    self,
    bigint::{Odd, U384},
    consts::U48,
};

#[cfg(feature = "arithmetic")]
pub use arithmetic::{AffinePoint, ProjectivePoint, scalar::Scalar};
#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;
#[cfg(feature = "hash2curve")]
pub use hash2curve;

use elliptic_curve::{array::Array, consts::U49};

/// Order of NIST P-384's elliptic curve group (i.e. scalar modulus) in hexadecimal.
const ORDER_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";

/// NIST P-384 elliptic curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct NistP384;

impl elliptic_curve::Curve for NistP384 {
    /// 48-byte serialized field elements.
    type FieldBytesSize = U48;

    /// 384-bit integer type used for internally representing field elements.
    type Uint = U384;

    /// Order of NIST P-384's elliptic curve group (i.e. scalar modulus).
    const ORDER: Odd<U384> = Odd::<U384>::from_be_hex(ORDER_HEX);
}

impl elliptic_curve::PrimeCurve for NistP384 {}

impl elliptic_curve::point::PointCompression for NistP384 {
    /// NIST P-384 points are typically uncompressed.
    const COMPRESS_POINTS: bool = false;
}

impl elliptic_curve::point::PointCompaction for NistP384 {
    /// NIST P-384 points are typically uncompressed.
    const COMPACT_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for NistP384 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34");
}

/// Compressed SEC1-encoded NIST P-384 curve point.
pub type CompressedPoint = Array<u8, U49>;

/// NIST P-384 SEC1 encoded point.
pub type Sec1Point = elliptic_curve::sec1::Sec1Point<NistP384>;

/// NIST P-384 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or
/// scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<NistP384>;

/// Non-zero NIST P-384 scalar field element.
#[cfg(feature = "arithmetic")]
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<NistP384>;

/// NIST P-384 public key.
#[cfg(feature = "arithmetic")]
pub type PublicKey = elliptic_curve::PublicKey<NistP384>;

/// NIST P-384 secret key.
pub type SecretKey = elliptic_curve::SecretKey<NistP384>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for NistP384 {}

#[cfg(feature = "oprf")]
impl hash2curve::OprfParameters for NistP384 {
    /// See <https://www.rfc-editor.org/rfc/rfc9497.html#section-4.4-1>.
    const ID: &'static [u8] = b"P384-SHA384";
}
