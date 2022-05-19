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
    subtle::ConditionallySelectable,
    DecompactPoint,
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
    // TODO(nickray): maybe store (FieldElement, NonScalar), avoiding the unwraps.
    // However, this
    // a) contradicts tarcieri's philosophy of storing "bag of bytes"
    // b) makes the Debug, Eq, PartialEq, PartialOrd, Ord impls tricky,
    // as FieldElement + NonZeroScalar don't implement them, so we'd have to
    // either modify upstream or implement in terms of the calculated `to_bytes`.
    bytes: [u8; 64],
}

impl Signature {
    /// Parse signature from big endian-encoded bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 64] = bytes.try_into()
            .map_err(|_| Error::new())?;

        let _: FieldElement = Option::from(FieldElement::from_bytes(FieldBytes::from_slice(&bytes[..32])))
            .ok_or(Error::new())?;
        let _: NonZeroScalar = Option::from(NonZeroScalar::from_repr(*FieldBytes::from_slice(&bytes[32..])))
            .ok_or(Error::new())?;

        Ok(Self { bytes })
    }

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

        let trial_secret_key = NonZeroScalar::try_from(bytes).map_err(|_| Error::new())?;
        let trial_public_key =
            PublicKey::from_affine((ProjectivePoint::GENERATOR * *trial_secret_key).to_affine())
                .map_err(|_| Error::new())?;

        let other_secret_key = -trial_secret_key;
        // let other_public_key =
        //     PublicKey::from_affine((ProjectivePoint::generator() * *other_secret_key).to_affine())
        //         .map_err(|_| Error::new())?;

        let even = trial_public_key.as_affine().y.normalize().is_even();

        let secret_key = NonZeroScalar::conditional_select(
            &other_secret_key,
            &trial_secret_key,
            even,
        );

        // let public_key = PublicKey::conditional_select(
        //     &trial_public_key,
        //     &other_public_key,
        //     even,
        // );

        // redundant, but don't have conditional select on PublicKey
        let verifying_key = VerifyingKey { inner:
            PublicKey::from_affine((ProjectivePoint::GENERATOR * *secret_key).to_affine())
                .map_err(|_| Error::new())?
        };

        Ok(Self {
            secret_key,
            verifying_key,
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

        let t = xor(
            &self.secret_key.to_bytes(),
            &tagged_hash(AUX_TAG).chain(aux_rand).finalize(),
        );

        // k0 in Python
        let rand = tagged_hash(NONCE_TAG)
            .chain(&t)
            .chain(&self.verifying_key.as_affine().x.to_bytes())
            .chain(msg_digest)
            .finalize();

        let k = SigningKey::from_bytes(&rand)?;

        let r = k.verifying_key().to_bytes();

        let e = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain(&r)
                .chain(&self.verifying_key.to_bytes())
                .chain(msg_digest)
                .finalize(),
        );

        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&r);
        bytes[32..].copy_from_slice(&(*k.secret_key + e * *self.secret_key).to_bytes());

        let sig = Signature { bytes };

        #[cfg(debug_assertions)]
        self.verifying_key.verify_raw_digest(msg_digest, &sig).unwrap();//?;

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

    /// Parse verifying key from big endian-encoded x-coordinate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let maybe_affine_point = AffinePoint::decompact(FieldBytes::from_slice(bytes));
        let affine_point = match maybe_affine_point.is_some().into() {
            true => maybe_affine_point.unwrap(),
            false => return Err(Error::new()),
        };

        Ok(Self { inner: PublicKey::from_affine(affine_point).map_err(|_| Error::new())? })
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

// Test vectors from:
// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
#[cfg(test)]
mod tests {
    use super::{Signature, SigningKey, VerifyingKey};
    use hex_literal::hex;

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
        // test fails if msg is reduced modulo p or n
        SignVector {
            secret_key: hex!("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"),
            public_key: hex!("25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"),
            aux_rand: hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            message: hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            signature: hex!(
                "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC
                 97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"
            ),
        },
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

    /// Verification test vector
    struct VerifyVector {
        /// Index of test case
        index: u8,

        /// Verifying key
        public_key: [u8; 32],

        /// Message digest
        message: [u8; 32],

        /// Claimed signature
        signature: [u8; 64],

        /// Is signature valid
        valid: bool,
    }

    /// BIP340 verification test vectors: index 4-14
    const BIP340_VERIFY_VECTORS: &[VerifyVector] = &[
        // index 4
        VerifyVector {
            index: 4,
            public_key: hex!("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"),
            message: hex!("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703"),
            signature: hex!(
                "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63
                 76AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4"
            ),
            valid: true,
        },
        // index 5
        // public key not on curve
        VerifyVector {
            index: 5,
            public_key: hex!("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769
                 69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
            valid: false,
        },
        // index 6
        // has_even_y(R) is false
        VerifyVector {
            index: 6,
            public_key: hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556
                 3CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2"),
            valid: false,
        },
        // index 7
        // negated message
        VerifyVector {
            index: 7,
            public_key: hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F
                 28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD"),
            valid: false,
        },
        // index 8
        // negated s value
        VerifyVector {
            index: 8,
            public_key: hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769
                 961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6"),
            valid: false,
        },
        // // index 9
        // // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
        // VerifyVector {
        //     index: 9,
        //     public_key: hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
        //     message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
        //     signature: hex!(
        //         "0000000000000000000000000000000000000000000000000000000000000000
        //          123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051"),
        //     valid: false,
        // },
        // index 10
        // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
        VerifyVector {
            index: 10,
            public_key: hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "0000000000000000000000000000000000000000000000000000000000000001
                 7615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197"),
            valid: false,
        },
        // index 11
        // sig[0:32] is not an X coordinate on the curve
        VerifyVector {
            index: 11,
            public_key: hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D
                 69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
            valid: false,
        },
        // index 12
        // sig[0:32] is equal to field size
        VerifyVector {
            index: 12,
            public_key: hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
                 69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
            valid: false,
        },
        // index 13
        // sig[32:64] is equal to curve order
        VerifyVector {
            index: 13,
            public_key: hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769
                 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
            valid: false,
        },
        // index 14
        // public key is not a valid X coordinate because it exceeds the field size
        VerifyVector {
            index: 14,
            public_key: hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"),
            message: hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
            signature: hex!(
                "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769
                 69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
            valid: false,
        },
    ];

    #[test]
    fn bip340_verify_vectors() {
        for vector in BIP340_VERIFY_VECTORS {
            let maybe_pk = VerifyingKey::from_bytes(&vector.public_key);
            let maybe_sig = Signature::from_bytes(&vector.signature);
            let verification = match (maybe_pk, maybe_sig) {
                (Ok(pk), Ok(sig)) => pk.verify_raw_digest(&vector.message, &sig).is_ok(),
                _ => false,
            };

            assert_eq!(vector.valid, verification, "incorrect validation for index {}", vector.index);
        }
    }

}
