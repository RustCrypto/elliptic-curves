#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]

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
//! PKCS#8/SPKI. Note that [`pkcs8`] is re-exported from `p256` when the `pkcs8`
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
//! use p256::SecretKey;
//!
//! // WARNING: Do not hardcode private keys in your source code. This is for demonstration purposes only.
//! let pem = r#"-----BEGIN PRIVATE KEY-----
//! MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaWJBcVYaYzQN4OfY
//! afKgVJJVjhoEhotqn4VKhmeIGI2hRANCAAQcrP+1Xy8s79idies3SyaBFSRSgC3u
//! oJkWBoE32DnPf8SBpESSME1+9mrBF77+g6jQjxVfK1L59hjdRHApBI4P
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

pub use elliptic_curve::{self, bigint::U256, consts::U32};

#[cfg(feature = "arithmetic")]
pub use arithmetic::{AffinePoint, ProjectivePoint, scalar::Scalar};
#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;
#[cfg(feature = "hash2curve")]
pub use hash2curve;

use elliptic_curve::{array::Array, bigint::Odd, consts::U33};

/// Order of NIST P-256's elliptic curve group (i.e. scalar modulus) serialized
/// as hexadecimal.
///
/// ```text
/// n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
/// ```
///
/// # Calculating the order
/// One way to calculate the order is with `GP/PARI`:
///
/// ```text
/// p = (2^224) * (2^32 - 1) + 2^192 + 2^96 - 1
/// b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
/// E = ellinit([Mod(-3, p), Mod(b, p)])
/// default(parisize, 120000000)
/// n = ellsea(E)
/// isprime(n)
/// ```
const ORDER_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/// NIST P-256 elliptic curve.
///
/// This curve is also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG)
/// and is specified in [NIST SP 800-186]:
/// Recommendations for Discrete Logarithm-based Cryptography:
/// Elliptic Curve Domain Parameters.
///
/// It's included in the US National Security Agency's "Suite B" and is widely
/// used in protocols like TLS and the associated X.509 PKI.
///
/// Its equation is `y² = x³ - 3x + b` over a ~256-bit prime field where `b` is
/// the "verifiably random"† constant:
///
/// ```text
/// b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
/// ```
///
/// † *NOTE: the specific origins of this constant have never been fully disclosed
///   (it is the SHA-1 digest of an unknown NSA-selected constant)*
///
/// [NIST SP 800-186]: https://csrc.nist.gov/publications/detail/sp/800-186/final
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct NistP256;

impl elliptic_curve::Curve for NistP256 {
    /// 32-byte serialized field elements.
    type FieldBytesSize = U32;

    /// 256-bit integer type used for internally representing field elements.
    type Uint = U256;

    /// Order of NIST P-256's elliptic curve group (i.e. scalar modulus).
    const ORDER: Odd<U256> = Odd::<U256>::from_be_hex(ORDER_HEX);
}

impl elliptic_curve::PrimeCurve for NistP256 {}

impl elliptic_curve::point::PointCompression for NistP256 {
    /// NIST P-256 points are typically uncompressed.
    const COMPRESS_POINTS: bool = false;
}

impl elliptic_curve::point::PointCompaction for NistP256 {
    /// NIST P-256 points are typically uncompressed.
    const COMPACT_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for NistP256 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
}

/// Blinded scalar.
#[cfg(feature = "arithmetic")]
pub type BlindedScalar = elliptic_curve::scalar::BlindedScalar<NistP256>;

/// Compressed SEC1-encoded NIST P-256 curve point.
pub type CompressedPoint = Array<u8, U33>;

/// NIST P-256 SEC1 encoded point.
pub type Sec1Point = elliptic_curve::sec1::Sec1Point<NistP256>;

/// NIST P-256 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<NistP256>;

/// Non-zero NIST P-256 scalar field element.
#[cfg(feature = "arithmetic")]
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<NistP256>;

/// NIST P-256 public key.
#[cfg(feature = "arithmetic")]
pub type PublicKey = elliptic_curve::PublicKey<NistP256>;

/// NIST P-256 secret key.
pub type SecretKey = elliptic_curve::SecretKey<NistP256>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for NistP256 {}

#[cfg(feature = "oprf")]
impl hash2curve::OprfParameters for NistP256 {
    /// See <https://www.rfc-editor.org/rfc/rfc9497.html#section-4.3-1>.
    const ID: &'static [u8] = b"P256-SHA256";
}
