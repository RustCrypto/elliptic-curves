//! Taproot Schnorr signatures as defined in [BIP340].
//!
//! [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

#![allow(non_snake_case, clippy::many_single_char_names)]

use crate::{
    arithmetic::FieldElement, AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey,
    Scalar,
};
use elliptic_curve::{
    bigint::U256,
    ops::{LinearCombination, Reduce},
};
use sha2::{Digest, Sha256};
use signature::{Error, Result};

const AUX_TAG: &[u8] = b"BIP0340/aux";
const NONCE_TAG: &[u8] = b"BIP0340/nonce";
const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

/// Taproot Schnorr signature as defined in [BIP340].
///
/// [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Signature {
    bytes: [u8; 64],
}

impl Signature {
    /// Borrow the serialized signature as bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// Get the `r` component of this signature.
    fn r(&self) -> FieldElement {
        FieldElement::from_bytes(FieldBytes::from_slice(&self.bytes[..32])).unwrap()
    }

    /// Get the `s` component of this signature.
    fn s(&self) -> NonZeroScalar {
        NonZeroScalar::from_repr(*FieldBytes::from_slice(&self.bytes[32..])).unwrap()
    }

    /// Split this signature into its `r` and `s` components.
    fn split(&self) -> (FieldElement, NonZeroScalar) {
        (self.r(), self.s())
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Taproot Schnorr signing key.
#[derive(Clone)]
pub struct SigningKey {
    /// Secret key material
    secret_key: NonZeroScalar,

    /// Verifying key
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Parse signing key from big endian-encoded bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = NonZeroScalar::try_from(bytes).map_err(|_| Error::new())?;
        let public_key =
            PublicKey::from_affine((ProjectivePoint::GENERATOR * *secret_key).to_affine())
                .map_err(|_| Error::new())?;

        Ok(Self {
            secret_key,
            verifying_key: VerifyingKey { inner: public_key },
        })
    }

    /// Get the [`VerifyingKey`] that corresponds to this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// Compute Schnorr signature.
    // TODO(tarcieri): high-level trait wrappers (e.g. `DigestSigner`)
    pub fn try_sign_raw_digest(
        &self,
        msg_digest: &[u8; 32],
        aux_rand: &[u8; 32],
    ) -> Result<Signature> {
        let d = if self.verifying_key.is_y_even() {
            self.secret_key
        } else {
            -self.secret_key
        };

        let t = xor(
            &self.secret_key.to_bytes(),
            &tagged_hash(AUX_TAG).chain(aux_rand).finalize(),
        );

        let rand = tagged_hash(NONCE_TAG)
            .chain(&t)
            .chain(&self.verifying_key.as_affine().x.to_bytes())
            .chain(msg_digest)
            .finalize();

        let k_prime = <Scalar as Reduce<U256>>::from_be_bytes_reduced(rand);

        if k_prime.is_zero().into() {
            return Err(Error::new());
        }

        let R = (ProjectivePoint::GENERATOR * k_prime).to_affine();
        let r = R.x.normalize().to_bytes();

        let k = if R.y.normalize().is_even().into() {
            k_prime
        } else {
            -k_prime
        };

        let e = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain(&r)
                .chain(&self.verifying_key.to_bytes())
                .chain(msg_digest)
                .finalize(),
        );

        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&r);
        bytes[32..].copy_from_slice(&(k + e * *d).to_bytes());

        let sig = Signature { bytes };

        #[cfg(debug_assertions)]
        self.verifying_key.verify_raw_digest(msg_digest, &sig)?;

        Ok(sig)
    }
}

/// Taproot Schnorr verifying key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey {
    /// Inner public key
    inner: PublicKey,
}

impl VerifyingKey {
    /// Verify Schnorr signature.
    // TODO(tarcieri): high-level trait wrappers (e.g. `DigestVerifier`)
    pub fn verify_raw_digest(&self, msg_digest: &[u8; 32], sig: &Signature) -> Result<()> {
        let (r, s) = sig.split();

        let e = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain(&sig.bytes[..32])
                .chain(self.to_bytes())
                .chain(msg_digest)
                .finalize(),
        );

        let R = ProjectivePoint::lincomb(
            &ProjectivePoint::GENERATOR,
            &*s,
            &self.inner.to_projective(),
            &-e,
        )
        .to_affine();

        if R.y.normalize().is_odd().into() || R.x.normalize() != r {
            return Err(Error::new());
        }

        Ok(())
    }

    /// Borrow the inner [`AffinePoint`] this type wraps.
    pub fn as_affine(&self) -> &AffinePoint {
        self.inner.as_affine()
    }

    /// Serialize as bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.as_affine().x.to_bytes()
    }

    /// Is the y-coordinate of this [`VerifyingKey`] even?
    fn is_y_even(&self) -> bool {
        self.as_affine().y.normalize().is_even().into()
    }
}

impl From<VerifyingKey> for AffinePoint {
    fn from(vk: VerifyingKey) -> AffinePoint {
        *vk.as_affine()
    }
}

impl From<&VerifyingKey> for AffinePoint {
    fn from(vk: &VerifyingKey) -> AffinePoint {
        *vk.as_affine()
    }
}

fn tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(&tag_hash);
    digest.update(&tag_hash);
    digest
}

#[inline]
fn xor(a: &FieldBytes, b: &FieldBytes) -> FieldBytes {
    let mut res = FieldBytes::default();

    for i in 0..32 {
        res[i] = a[i] ^ b[i];
    }

    res
}

// TODO(tarcieri): verification tests
#[cfg(test)]
mod tests {
    use super::SigningKey;
    use hex_literal::hex;

    // Test vectors from:
    // https://docs.rs/argon2/latest/argon2/struct.Argon2.html#method.new_with_secret

    /// Signing test vector
    struct SignVector {
        /// Signing key
        secret_key: [u8; 32],

        /// Verifying key
        public_key: [u8; 32],

        /// Auxilliary randomness value
        aux_rand: [u8; 32],

        /// Message digest
        message: [u8; 32],

        /// Expected signature
        signature: [u8; 64],
    }

    /// BIP340 signing test vectors: index 0-3
    const BIP340_SIGN_VECTORS: &[SignVector] = &[
        // index 0
        SignVector {
            secret_key: hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            public_key: hex!("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
            aux_rand: hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            message: hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            signature: hex!(
                "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215
                 25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
            ),
        },
        // index 1
        SignVector {
            secret_key: hex!("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"),
            public_key: hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
            aux_rand: hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341
                 8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"
            ),
        },
        // index 2
        SignVector {
            secret_key: hex!("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"),
            public_key: hex!("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"),
            aux_rand: hex!("C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"),
            message: hex!("7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
            signature: hex!(
                "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B
                 AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"
            ),
        },
        // index 3
        // TODO(tarcieri): failing; test vector notes: "test fails if msg is reduced modulo p or n"
        // SignVector {
        //     secret_key: hex!("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"),
        //     public_key: hex!("25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"),
        //     aux_rand: hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        //     message: hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        //     signature: hex!(
        //         "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC
        //          97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"
        //     ),
        // },
    ];

    #[test]
    fn bip340_sign_vectors() {
        for vector in BIP340_SIGN_VECTORS {
            let sk = SigningKey::from_bytes(&vector.secret_key).unwrap();
            assert_eq!(sk.verifying_key().to_bytes().as_slice(), &vector.public_key);

            let sig = sk
                .try_sign_raw_digest(&vector.message, &vector.aux_rand)
                .expect("low-level Schnorr signing failure");

            assert_eq!(&vector.signature, sig.as_ref());
        }
    }
}
