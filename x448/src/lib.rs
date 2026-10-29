#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]

use ed448_goldilocks::{
    MontgomeryPoint,
    elliptic_curve::{
        Generate,
        array::{Array, typenum::U56},
        bigint::U448,
        rand_core::{CryptoRng, TryCryptoRng},
        scalar::FromUintUnchecked,
        zeroize::Zeroize,
    },
};

type MontgomeryScalar = ed448_goldilocks::Scalar<ed448_goldilocks::Ed448>;

/// Given an [`EphemeralSecret`] Key, compute the corresponding public key
/// using the generator specified in RFC7748
impl From<&EphemeralSecret> for PublicKey {
    fn from(secret: &EphemeralSecret) -> PublicKey {
        let secret = secret.as_scalar();
        let point = &MontgomeryPoint::GENERATOR * &secret;
        PublicKey(point)
    }
}

/// A PublicKey is a point on Curve448.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct PublicKey(MontgomeryPoint);

impl PublicKey {
    /// Converts a bytes slice into a Public key
    /// Returns None if:
    /// -  The length of the slice is not 56
    /// -  The point is a low order point
    pub fn from_bytes(bytes: &[u8]) -> Option<PublicKey> {
        let public_key = PublicKey::from_bytes_unchecked(bytes)?;
        if public_key.0.is_low_order() {
            return None;
        }
        Some(public_key)
    }

    /// Converts a bytes slice into a Public key
    /// Returns None if:
    /// -  The length of the slice is not 56
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Option<PublicKey> {
        // First check if we have 56 bytes
        if bytes.len() != 56 {
            return None;
        }

        // Check if the point has low order
        let arr = slice_to_array(bytes);
        let point = MontgomeryPoint(arr);

        Some(PublicKey(point))
    }

    /// Converts a public key into a byte slice
    pub fn as_bytes(&self) -> &[u8; 56] {
        self.0.as_bytes()
    }
}

/// A SharedSecret is a point on Curve448.
/// This point is the result of a Diffie-Hellman key exchange.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret(MontgomeryPoint);

impl SharedSecret {
    /// Converts a shared secret into a byte slice
    pub fn as_bytes(&self) -> &[u8; 56] {
        self.0.as_bytes()
    }
}

/// An [`EphemeralSecret`] is a Scalar on Curve448.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct EphemeralSecret(EphemeralSecretBytes);

type EphemeralSecretBytes = Array<u8, U56>;

impl EphemeralSecret {
    /// DEPRECATED: Generate a new ephemeral secret from the given RNG.
    #[deprecated(since = "0.14.0", note = "use the `Generate` trait instead")]
    pub fn new<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + ?Sized,
    {
        Self::generate_from_rng(csprng)
    }

    /// Views an Secret as a Scalar
    fn as_scalar(&self) -> MontgomeryScalar {
        let secret = U448::from_le_slice(&self.0);
        MontgomeryScalar::from_uint_unchecked(secret)
    }

    /// Performs a Diffie-hellman key exchange between the secret key and an external public key
    pub fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
        // NOTE(security): it is assumed PublicKey is not a low_order. It should be checked when
        // created.
        let shared_key = &public_key.0 * &self.as_scalar();
        SharedSecret(shared_key)
    }

    /// Converts a secret into a byte array
    pub fn as_bytes(&self) -> &[u8; 56] {
        self.0.as_ref()
    }

    /// Construct an [`EphemeralSecret`] by the secret key according to RFC7748.
    fn clamp(mut bytes: EphemeralSecretBytes) -> Self {
        bytes[0] &= 252;
        bytes[55] |= 128;
        Self(bytes)
    }
}

impl Generate for EphemeralSecret {
    fn try_generate_from_rng<R>(csprng: &mut R) -> Result<Self, R::Error>
    where
        R: TryCryptoRng + ?Sized,
    {
        let mut bytes = Array::default();
        csprng.try_fill_bytes(bytes.as_mut_slice())?;
        Ok(EphemeralSecret::clamp(bytes))
    }
}

fn slice_to_array(bytes: &[u8]) -> [u8; 56] {
    let mut array: [u8; 56] = [0; 56];
    array.copy_from_slice(bytes);
    array
}

/// A safe version of the x448 function defined in RFC448.
/// Currently, the only reason I can think of for using the raw function is FFI.
/// Option is FFI safe[1]. So we can still maintain that the invariant that
/// we do not return a low order point.
///
/// [1]: https://github.com/rust-lang/nomicon/issues/59
pub fn x448(scalar_bytes: [u8; 56], point_bytes: [u8; 56]) -> Option<[u8; 56]> {
    let point = PublicKey::from_bytes(&point_bytes)?;
    let scalar = EphemeralSecret::clamp(scalar_bytes.into()).as_scalar();
    Some((&point.0 * &scalar).0)
}
/// An unchecked version of the x448 function defined in RFC448
/// No checks are made on the points.
pub fn x448_unchecked(scalar_bytes: [u8; 56], point_bytes: [u8; 56]) -> [u8; 56] {
    let point = MontgomeryPoint(point_bytes);
    let scalar = EphemeralSecret::clamp(scalar_bytes.into()).as_scalar();
    (&point * &scalar).0
}

pub const X448_BASEPOINT_BYTES: [u8; 56] = MontgomeryPoint::GENERATOR.0;

/// A Diffie-Hellman secret key that can be used to compute multiple [`SharedSecret`]s.
///
/// This type is identical to the [`EphemeralSecret`] type, except that the
/// [`StaticSecret::diffie_hellman`] method does not consume the secret key, and the type provides
/// serialization methods to save and load key material.  This means that the secret may be used
/// multiple times (but does not *have to be*).
///
/// # Warning
///
/// If you're uncertain about whether you should use this, then you likely
/// should not be using this.  Our strongly recommended advice is to use
/// [`EphemeralSecret`] at all times, as that type enforces at compile-time that
/// secret keys are never reused, which can have very serious security
/// implications for many protocols.
#[cfg(feature = "static_secrets")]
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct StaticSecret(Array<u8, U56>);

#[cfg(feature = "static_secrets")]
impl StaticSecret {
    fn new(value: Array<u8, U56>) -> Self {
        let mut out = Self(value);
        out.clamp();
        out
    }

    /// Generate a new [`StaticSecret`] with the supplied RNG.
    pub fn random_from_rng<R: CryptoRng + ?Sized>(csprng: &mut R) -> Self {
        let mut bytes = Array::default();
        csprng.fill_bytes(bytes.as_mut_slice());
        Self::new(bytes)
    }

    /// Clamps the secret key according to RFC7748
    fn clamp(&mut self) {
        self.0[0] &= 252;
        self.0[55] |= 128;
    }

    /// Views an Secret as a Scalar
    fn as_scalar(&self) -> MontgomeryScalar {
        let secret = U448::from_le_slice(&self.0);
        MontgomeryScalar::from_uint_unchecked(secret)
    }

    /// Perform a Diffie-Hellman key agreement between `self` and
    /// `their_public` key to produce a `SharedSecret`.
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        // NOTE(security): it is assumed PublicKey is not a low_order. It should be checked when
        // created.
        let shared_key = &their_public.0 * &self.as_scalar();
        SharedSecret(shared_key)
    }

    /// View this key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 56] {
        self.0.as_ref()
    }
}

#[cfg(feature = "static_secrets")]
impl From<[u8; 56]> for StaticSecret {
    /// Load a secret key from a byte array.
    fn from(bytes: [u8; 56]) -> StaticSecret {
        StaticSecret::new(bytes.into())
    }
}

#[cfg(feature = "static_secrets")]
impl From<&StaticSecret> for PublicKey {
    /// Given an x448 [`StaticSecret`] key, compute its corresponding [`PublicKey`].
    fn from(secret: &StaticSecret) -> PublicKey {
        let secret = secret.as_scalar();
        let point = &MontgomeryPoint::GENERATOR * &secret;
        PublicKey(point)
    }
}

#[cfg(feature = "static_secrets")]
impl AsRef<[u8]> for StaticSecret {
    /// View this key as a byte array.
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(all(feature = "static_secrets", feature = "serde"))]
impl serdect::serde::Serialize for StaticSecret {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::array::serialize_hex_lower_or_bin(&self.0, s)
    }
}

#[cfg(all(feature = "static_secrets", feature = "serde"))]
impl<'de> serdect::serde::Deserialize<'de> for StaticSecret {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let mut bytes = Array::default();
        serdect::array::deserialize_hex_or_bin(&mut bytes, d)?;
        Ok(StaticSecret::new(bytes))
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::vec;
    use core::array::TryFromSliceError;

    /// Helpers to test properties of EphemeralSecret. Those `From` and `TryFrom` are not meant to
    /// be exposed outside tests.
    impl From<[u8; 56]> for EphemeralSecret {
        fn from(arr: [u8; 56]) -> Self {
            Self::clamp(arr.into())
        }
    }

    impl TryFrom<&[u8]> for EphemeralSecret {
        type Error = TryFromSliceError;

        fn try_from(bytes: &[u8]) -> Result<Self, TryFromSliceError> {
            Ok(Self::clamp(Array::try_from(bytes)?))
        }
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_random_dh() {
        let alice_priv = EphemeralSecret::generate();
        let alice_pub = PublicKey::from(&alice_priv);

        let bob_priv = EphemeralSecret::generate();
        let bob_pub = PublicKey::from(&bob_priv);

        // Since Alice and Bob are both using the API correctly
        // If by chance, a low order point is generated, the clamping function will
        // remove it.
        let low_order = alice_pub.0.is_low_order() || bob_pub.0.is_low_order();
        assert!(!low_order);

        // Both Alice and Bob perform the DH key exchange.
        // As mentioned above, we unwrap because both Parties are using the API correctly.
        let shared_alice = alice_priv.diffie_hellman(&bob_pub);
        let shared_bob = bob_priv.diffie_hellman(&alice_pub);

        assert_eq!(shared_alice.as_bytes()[..], shared_bob.as_bytes()[..]);
    }

    #[test]
    fn test_rfc_test_vectors_alice_bob() {
        let alice_priv = EphemeralSecret::from([
            0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57, 0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58,
            0x0, 0xd4, 0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65, 0xd4, 0x98, 0xc2, 0x8d,
            0xd9, 0xc9, 0xba, 0xf5, 0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91, 0x0, 0x63,
            0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d, 0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
        ]);
        let got_alice_pub = PublicKey::from(&alice_priv);

        let expected_alice_pub = [
            0x9b, 0x8, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6, 0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x7,
            0x4a, 0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63, 0xfa, 0xa7, 0x3d, 0x2c, 0x22,
            0xc5, 0xd9, 0xbb, 0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4, 0xc, 0x5b, 0x12,
            0xda, 0x88, 0x12, 0xd, 0x53, 0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
        ];
        assert_eq!(got_alice_pub.0.as_bytes()[..], expected_alice_pub[..]);

        let bob_priv = EphemeralSecret::from([
            0x1c, 0x30, 0x6a, 0x7a, 0xc2, 0xa0, 0xe2, 0xe0, 0x99, 0xb, 0x29, 0x44, 0x70, 0xcb,
            0xa3, 0x39, 0xe6, 0x45, 0x37, 0x72, 0xb0, 0x75, 0x81, 0x1d, 0x8f, 0xad, 0xd, 0x1d,
            0x69, 0x27, 0xc1, 0x20, 0xbb, 0x5e, 0xe8, 0x97, 0x2b, 0xd, 0x3e, 0x21, 0x37, 0x4c,
            0x9c, 0x92, 0x1b, 0x9, 0xd1, 0xb0, 0x36, 0x6f, 0x10, 0xb6, 0x51, 0x73, 0x99, 0x2d,
        ]);
        let got_bob_pub = PublicKey::from(&bob_priv);

        let expected_bob_pub = [
            0x3e, 0xb7, 0xa8, 0x29, 0xb0, 0xcd, 0x20, 0xf5, 0xbc, 0xfc, 0xb, 0x59, 0x9b, 0x6f,
            0xec, 0xcf, 0x6d, 0xa4, 0x62, 0x71, 0x7, 0xbd, 0xb0, 0xd4, 0xf3, 0x45, 0xb4, 0x30,
            0x27, 0xd8, 0xb9, 0x72, 0xfc, 0x3e, 0x34, 0xfb, 0x42, 0x32, 0xa1, 0x3c, 0xa7, 0x6,
            0xdc, 0xb5, 0x7a, 0xec, 0x3d, 0xae, 0x7, 0xbd, 0xc1, 0xc6, 0x7b, 0xf3, 0x36, 0x9,
        ];
        assert_eq!(got_bob_pub.0.as_bytes()[..], expected_bob_pub[..]);

        let bob_shared = bob_priv.diffie_hellman(&got_alice_pub);
        let alice_shared = alice_priv.diffie_hellman(&got_bob_pub);
        assert_eq!(bob_shared.as_bytes()[..], alice_shared.as_bytes()[..]);

        let expected_shared = [
            0x7, 0xff, 0xf4, 0x18, 0x1a, 0xc6, 0xcc, 0x95, 0xec, 0x1c, 0x16, 0xa9, 0x4a, 0xf, 0x74,
            0xd1, 0x2d, 0xa2, 0x32, 0xce, 0x40, 0xa7, 0x75, 0x52, 0x28, 0x1d, 0x28, 0x2b, 0xb6,
            0xc, 0xb, 0x56, 0xfd, 0x24, 0x64, 0xc3, 0x35, 0x54, 0x39, 0x36, 0x52, 0x1c, 0x24, 0x40,
            0x30, 0x85, 0xd5, 0x9a, 0x44, 0x9a, 0x50, 0x37, 0x51, 0x4a, 0x87, 0x9d,
        ];

        assert_eq!(bob_shared.as_bytes()[..], expected_shared[..]);
    }

    #[test]
    fn test_rfc_test_vectors_fixed() {
        struct Test {
            secret: [u8; 56],
            point: [u8; 56],
            expected: [u8; 56],
        }

        let test_vectors = vec![
            Test {
                secret: [
                    0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88, 0x49, 0x52, 0x66, 0xfe, 0xa1,
                    0x9a, 0x34, 0xd2, 0x88, 0x82, 0xac, 0xef, 0x4, 0x51, 0x4, 0xd0, 0xd1, 0xaa,
                    0xe1, 0x21, 0x70, 0xa, 0x77, 0x9c, 0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f,
                    0xbf, 0xf4, 0x49, 0x43, 0xeb, 0xa3, 0x68, 0xf5, 0x4b, 0x29, 0x25, 0x9a, 0x4f,
                    0x1c, 0x60, 0xa, 0xd3,
                ],
                point: [
                    0x6, 0xfc, 0xe6, 0x40, 0xfa, 0x34, 0x87, 0xbf, 0xda, 0x5f, 0x6c, 0xf2, 0xd5,
                    0x26, 0x3f, 0x8a, 0xad, 0x88, 0x33, 0x4c, 0xbd, 0x7, 0x43, 0x7f, 0x2, 0xf, 0x8,
                    0xf9, 0x81, 0x4d, 0xc0, 0x31, 0xdd, 0xbd, 0xc3, 0x8c, 0x19, 0xc6, 0xda, 0x25,
                    0x83, 0xfa, 0x54, 0x29, 0xdb, 0x94, 0xad, 0xa1, 0x8a, 0xa7, 0xa7, 0xfb, 0x4e,
                    0xf8, 0xa0, 0x86,
                ],
                expected: [
                    0xce, 0x3e, 0x4f, 0xf9, 0x5a, 0x60, 0xdc, 0x66, 0x97, 0xda, 0x1d, 0xb1, 0xd8,
                    0x5e, 0x6a, 0xfb, 0xdf, 0x79, 0xb5, 0xa, 0x24, 0x12, 0xd7, 0x54, 0x6d, 0x5f,
                    0x23, 0x9f, 0xe1, 0x4f, 0xba, 0xad, 0xeb, 0x44, 0x5f, 0xc6, 0x6a, 0x1, 0xb0,
                    0x77, 0x9d, 0x98, 0x22, 0x39, 0x61, 0x11, 0x1e, 0x21, 0x76, 0x62, 0x82, 0xf7,
                    0x3d, 0xd9, 0x6b, 0x6f,
                ],
            },
            Test {
                secret: [
                    0x20, 0x3d, 0x49, 0x44, 0x28, 0xb8, 0x39, 0x93, 0x52, 0x66, 0x5d, 0xdc, 0xa4,
                    0x2f, 0x9d, 0xe8, 0xfe, 0xf6, 0x0, 0x90, 0x8e, 0xd, 0x46, 0x1c, 0xb0, 0x21,
                    0xf8, 0xc5, 0x38, 0x34, 0x5d, 0xd7, 0x7c, 0x3e, 0x48, 0x6, 0xe2, 0x5f, 0x46,
                    0xd3, 0x31, 0x5c, 0x44, 0xe0, 0xa5, 0xb4, 0x37, 0x12, 0x82, 0xdd, 0x2c, 0x8d,
                    0x5b, 0xe3, 0x9, 0x5f,
                ],
                point: [
                    0xf, 0xbc, 0xc2, 0xf9, 0x93, 0xcd, 0x56, 0xd3, 0x30, 0x5b, 0xb, 0x7d, 0x9e,
                    0x55, 0xd4, 0xc1, 0xa8, 0xfb, 0x5d, 0xbb, 0x52, 0xf8, 0xe9, 0xa1, 0xe9, 0xb6,
                    0x20, 0x1b, 0x16, 0x5d, 0x1, 0x58, 0x94, 0xe5, 0x6c, 0x4d, 0x35, 0x70, 0xbe,
                    0xe5, 0x2f, 0xe2, 0x5, 0xe2, 0x8a, 0x78, 0xb9, 0x1c, 0xdf, 0xbd, 0xe7, 0x1c,
                    0xe8, 0xd1, 0x57, 0xdb,
                ],
                expected: [
                    0x88, 0x4a, 0x2, 0x57, 0x62, 0x39, 0xff, 0x7a, 0x2f, 0x2f, 0x63, 0xb2, 0xdb,
                    0x6a, 0x9f, 0xf3, 0x70, 0x47, 0xac, 0x13, 0x56, 0x8e, 0x1e, 0x30, 0xfe, 0x63,
                    0xc4, 0xa7, 0xad, 0x1b, 0x3e, 0xe3, 0xa5, 0x70, 0xd, 0xf3, 0x43, 0x21, 0xd6,
                    0x20, 0x77, 0xe6, 0x36, 0x33, 0xc5, 0x75, 0xc1, 0xc9, 0x54, 0x51, 0x4e, 0x99,
                    0xda, 0x7c, 0x17, 0x9d,
                ],
            },
        ];

        for vector in test_vectors {
            let public_key = PublicKey::from_bytes(&vector.point).unwrap();
            let secret = EphemeralSecret::try_from(&vector.secret[..]).unwrap();

            let got = secret.diffie_hellman(&public_key);

            assert_eq!(got.0.as_bytes()[..], vector.expected[..])
        }
    }

    // This function is needed for the second set of test vectors in RFC7748
    fn swap(secret: &mut [u8; 56], public_key: &mut [u8; 56], result: &[u8; 56]) {
        // set point to be the secret
        *public_key = *secret;
        // set the secret to be the result
        *secret = *result;
    }

    #[test]
    #[ignore]
    fn test_rfc_test_vectors_iteration() {
        let one_iter = [
            0x3f, 0x48, 0x2c, 0x8a, 0x9f, 0x19, 0xb0, 0x1e, 0x6c, 0x46, 0xee, 0x97, 0x11, 0xd9,
            0xdc, 0x14, 0xfd, 0x4b, 0xf6, 0x7a, 0xf3, 0x7, 0x65, 0xc2, 0xae, 0x2b, 0x84, 0x6a,
            0x4d, 0x23, 0xa8, 0xcd, 0xd, 0xb8, 0x97, 0x8, 0x62, 0x39, 0x49, 0x2c, 0xaf, 0x35, 0xb,
            0x51, 0xf8, 0x33, 0x86, 0x8b, 0x9b, 0xc2, 0xb3, 0xbc, 0xa9, 0xcf, 0x41, 0x13,
        ];
        let one_k_iter = [
            0xaa, 0x3b, 0x47, 0x49, 0xd5, 0x5b, 0x9d, 0xaf, 0x1e, 0x5b, 0x0, 0x28, 0x88, 0x26,
            0xc4, 0x67, 0x27, 0x4c, 0xe3, 0xeb, 0xbd, 0xd5, 0xc1, 0x7b, 0x97, 0x5e, 0x9, 0xd4,
            0xaf, 0x6c, 0x67, 0xcf, 0x10, 0xd0, 0x87, 0x20, 0x2d, 0xb8, 0x82, 0x86, 0xe2, 0xb7,
            0x9f, 0xce, 0xea, 0x3e, 0xc3, 0x53, 0xef, 0x54, 0xfa, 0xa2, 0x6e, 0x21, 0x9f, 0x38,
        ];
        let one_mil_iter = [
            0x7, 0x7f, 0x45, 0x36, 0x81, 0xca, 0xca, 0x36, 0x93, 0x19, 0x84, 0x20, 0xbb, 0xe5,
            0x15, 0xca, 0xe0, 0x0, 0x24, 0x72, 0x51, 0x9b, 0x3e, 0x67, 0x66, 0x1a, 0x7e, 0x89,
            0xca, 0xb9, 0x46, 0x95, 0xc8, 0xf4, 0xbc, 0xd6, 0x6e, 0x61, 0xb9, 0xb9, 0xc9, 0x46,
            0xda, 0x8d, 0x52, 0x4d, 0xe3, 0xd6, 0x9b, 0xd9, 0xd9, 0xd6, 0x6b, 0x99, 0x7e, 0x37,
        ];

        let mut point = MontgomeryPoint::GENERATOR.0;
        let mut scalar = MontgomeryPoint::GENERATOR.0;
        let mut result = [0u8; 56];

        // Iterate 1 time then check value on 1st iteration
        for _ in 1..=1 {
            result = x448(scalar, point).unwrap();
            swap(&mut scalar, &mut point, &result);
        }
        assert_eq!(&result[..], &one_iter[..]);

        // Iterate 999 times then check value on 1_000th iteration
        for _ in 1..=999 {
            result = x448(scalar, point).unwrap();
            swap(&mut scalar, &mut point, &result);
        }
        assert_eq!(&result[..], &one_k_iter[..]);

        // Iterate 999_000 times then check value on 1_000_000th iteration
        for _ in 1..=999_000 {
            result = x448(scalar, point).unwrap();
            swap(&mut scalar, &mut point, &result);
        }
        assert_eq!(&result[..], &one_mil_iter[..]);
    }
}
