//! Much of this code is borrowed from Thomas Pornin's [CRRL Project](https://github.com/pornin/crrl/blob/main/src/ed448.rs)
//! and adapted to mirror `ed25519-dalek`'s API.

use crate::curve::edwards::extended::PointBytes;
use crate::sign::HASH_HEAD;
use crate::{
    CompressedEdwardsY, Context, EdwardsPoint, PreHash, Scalar, ScalarBytes, Signature,
    SigningError, WideScalarBytes, PUBLIC_KEY_LENGTH,
};
use core::{
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
};
use crypto_signature::Error;
use elliptic_curve::Group;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Shake256,
};

/// Ed448 public key as defined in [RFC8032 § 5.2.5]
#[derive(Copy, Clone, Default, Eq)]
pub struct VerifyingKey {
    pub(crate) compressed: CompressedEdwardsY,
    pub(crate) point: EdwardsPoint,
}

impl Debug for VerifyingKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey({:?}), {:?}", self.compressed, self.point)
    }
}

impl AsRef<[u8]> for VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        self.compressed.as_bytes()
    }
}

impl Hash for VerifyingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.compressed.as_bytes().hash(state);
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.compressed.as_bytes() == other.compressed.as_bytes()
    }
}

impl crypto_signature::Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        self.verify_raw(signature, msg)
    }
}

impl<D> crypto_signature::DigestVerifier<D, Signature> for VerifyingKey
where
    D: Digest,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> Result<(), Error> {
        let mut prehashed_message = [0u8; 64];
        prehashed_message.copy_from_slice(digest.finalize().as_slice());
        self.verify_inner(signature, 1, &[], &prehashed_message)
    }
}

impl crypto_signature::Verifier<Signature> for Context<'_, '_, VerifyingKey> {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        self.key.verify_ctx(signature, self.value, msg)
    }
}

impl<D> crypto_signature::DigestVerifier<D, Signature> for Context<'_, '_, VerifyingKey>
where
    D: Digest,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> Result<(), Error> {
        let mut prehashed_message = [0u8; 64];
        prehashed_message.copy_from_slice(digest.finalize().as_slice());
        self.key
            .verify_inner(signature, 1, self.value, &prehashed_message)
    }
}

#[cfg(feature = "pkcs8")]
/// This type is primarily useful for decoding/encoding SPKI public key files (either DER or PEM)
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PublicKeyBytes(pub [u8; PUBLIC_KEY_LENGTH]);

#[cfg(feature = "pkcs8")]
impl TryFrom<PublicKeyBytes> for VerifyingKey {
    type Error = pkcs8::spki::Error;

    fn try_from(value: PublicKeyBytes) -> Result<Self, Self::Error> {
        VerifyingKey::try_from(&value)
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<&PublicKeyBytes> for VerifyingKey {
    type Error = pkcs8::spki::Error;

    fn try_from(value: &PublicKeyBytes) -> Result<Self, Self::Error> {
        VerifyingKey::from_bytes(&value.0).map_err(|_| pkcs8::spki::Error::KeyMalformed)
    }
}

#[cfg(feature = "pkcs8")]
impl From<VerifyingKey> for PublicKeyBytes {
    fn from(key: VerifyingKey) -> Self {
        Self(key.compressed.to_bytes())
    }
}

#[cfg(feature = "pkcs8")]
impl pkcs8::EncodePublicKey for PublicKeyBytes {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<pkcs8::Document> {
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: super::ALGORITHM_ID,
            subject_public_key: pkcs8::der::asn1::BitStringRef::new(0, &self.0)?,
        }
        .try_into()
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<pkcs8::spki::SubjectPublicKeyInfoRef<'_>> for PublicKeyBytes {
    type Error = pkcs8::spki::Error;

    fn try_from(value: pkcs8::spki::SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        value.algorithm.assert_algorithm_oid(super::ALGORITHM_OID)?;

        if value.algorithm.parameters.is_some() {
            return Err(pkcs8::spki::Error::KeyMalformed);
        }

        value
            .subject_public_key
            .as_bytes()
            .ok_or(pkcs8::spki::Error::KeyMalformed)?
            .try_into()
            .map(Self)
            .map_err(|_| pkcs8::spki::Error::KeyMalformed)
    }
}

#[cfg(all(any(feature = "alloc", feature = "std"), feature = "pkcs8"))]
impl pkcs8::EncodePublicKey for VerifyingKey {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<pkcs8::Document> {
        PublicKeyBytes::from(*self).to_public_key_der()
    }
}

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
impl pkcs8::spki::DynSignatureAlgorithmIdentifier for VerifyingKey {
    fn signature_algorithm_identifier(
        &self,
    ) -> pkcs8::spki::Result<pkcs8::spki::AlgorithmIdentifierOwned> {
        // From https://datatracker.ietf.org/doc/html/rfc8410
        Ok(pkcs8::spki::AlgorithmIdentifierOwned {
            oid: super::ALGORITHM_OID,
            parameters: None,
        })
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<pkcs8::spki::SubjectPublicKeyInfoRef<'_>> for VerifyingKey {
    type Error = pkcs8::spki::Error;

    fn try_from(public_key: pkcs8::spki::SubjectPublicKeyInfoRef<'_>) -> pkcs8::spki::Result<Self> {
        PublicKeyBytes::try_from(public_key)?.try_into()
    }
}

#[cfg(feature = "serde")]
impl serdect::serde::Serialize for VerifyingKey {
    fn serialize<S: serdect::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(self.compressed.as_bytes(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serdect::serde::Deserialize<'de> for VerifyingKey {
    fn deserialize<D: serdect::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
        serdect::array::deserialize_hex_or_bin(&mut bytes, d)?;
        VerifyingKey::from_bytes(&bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl VerifyingKey {
    /// Convert this verifying key into byte slice
    pub fn to_bytes(&self) -> PointBytes {
        self.compressed.to_bytes()
    }

    /// View this public key as a byte slice.
    pub fn as_bytes(&self) -> &PointBytes {
        self.compressed.as_bytes()
    }

    /// Construct a `VerifyingKey` from a slice of bytes.
    pub fn from_bytes(bytes: &PointBytes) -> Result<Self, Error> {
        let compressed = CompressedEdwardsY(*bytes);
        let point = Option::<EdwardsPoint>::from(compressed.decompress())
            .ok_or(SigningError::InvalidPublicKeyBytes)?;
        if point.is_identity().into() {
            return Err(SigningError::InvalidPublicKeyBytes.into());
        }
        Ok(Self { compressed, point })
    }

    /// Create a context for this verifying key that can be used with [`DigestVerifier`].
    pub fn with_context<'k, 'v>(&'k self, context: &'v [u8]) -> Context<'k, 'v, Self> {
        Context {
            key: self,
            value: context,
        }
    }

    /// Return the verifying key in Edwards form.
    pub fn to_edwards(self) -> EdwardsPoint {
        self.point
    }

    /// Verifies a signature on a message.
    ///
    /// This is the "Ed448" mode of RFC 8032 (no pre-hashing, a
    /// context is provided). This is equivalent to `verify_ctx()`
    /// with an empty (zero-length) context.
    ///
    /// Note: this function is not constant-time; it assumes that the
    /// public key and signature value are public data.
    pub fn verify_raw(&self, signature: &Signature, message: &[u8]) -> Result<(), Error> {
        self.verify_inner(signature, 0, &[], message)
    }

    /// Verifies a signature on a message (with context).
    ///
    /// This is the "Ed448" mode of RFC 8032 (no pre-hashing, a
    /// context is provided). The context string MUST have length at most
    /// 255 bytes. Return value is `Ok` on a valid signature, `Error`
    /// otherwise.
    ///
    /// Note: this function is not constant-time; it assumes that the
    /// public key and signature value are public data.
    pub fn verify_ctx(self, sig: &Signature, ctx: &[u8], message: &[u8]) -> Result<(), Error> {
        self.verify_inner(sig, 0, ctx, message)
    }

    /// Verifies a signature on a hashed message.
    ///
    /// This is the "Ed448ph" mode of RFC 8032 (message is pre-hashed),
    /// also known as "HashEdDSA on Curve448". The hashed message `prehashed_message`
    /// is provided (presumably, that hash value was obtained with
    /// SHAKE256 and a 64-byte output; the caller does the hashing itself).
    /// A context string `ctx` is
    /// also provided; it MUST have length at most 255 bytes. Return
    /// value is `Ok` on a valid signature, `Error` otherwise.
    ///
    /// Note: this function is not constant-time; it assumes that the
    /// public key and signature value are public data.
    pub fn verify_prehashed<D>(
        self,
        sig: &Signature,
        ctx: Option<&[u8]>,
        mut prehashed_message: D,
    ) -> Result<(), Error>
    where
        D: PreHash,
    {
        let mut m = [0u8; 64];
        prehashed_message.fill_bytes(&mut m);
        self.verify_inner(sig, 1, ctx.unwrap_or_default(), &m)
    }

    fn verify_inner(
        &self,
        signature: &Signature,
        phflag: u8,
        ctx: &[u8],
        m: &[u8],
    ) -> Result<(), Error> {
        // `signature` should already be valid but check to make sure
        // Note that the scalar itself uses only 56 bytes; the extra
        // 57th byte must be 0x00.
        if signature.s[56] != 0x00 {
            return Err(SigningError::InvalidSignatureSComponent.into());
        }
        if self.point.is_identity().into() {
            return Err(SigningError::InvalidPublicKeyBytes.into());
        }

        let r = Option::<EdwardsPoint>::from(signature.r.decompress())
            .ok_or(SigningError::InvalidSignatureRComponent)?;
        if r.is_identity().into() {
            return Err(SigningError::InvalidSignatureRComponent.into());
        }

        let s_bytes = ScalarBytes::from_slice(&signature.s);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
            .ok_or(SigningError::InvalidSignatureSComponent)?;

        if s.is_zero().into() {
            return Err(SigningError::InvalidSignatureSComponent.into());
        }

        // SHAKE256(dom4(F, C) || R || A || PH(M), 114) -> scalar k
        let mut bytes = WideScalarBytes::default();
        let clen = ctx.len() as u8;
        let mut reader = Shake256::default()
            .chain(HASH_HEAD)
            .chain([phflag])
            .chain([clen])
            .chain(ctx)
            .chain(signature.r.as_bytes())
            .chain(self.compressed.as_bytes())
            .chain(m)
            .finalize_xof();
        reader.read(&mut bytes);
        let k = Scalar::from_bytes_mod_order_wide(&bytes);
        // Check the verification equation [S]B = R + [k]A.
        let lhs = EdwardsPoint::GENERATOR * s;
        let rhs = r + (self.point * k);
        if lhs == rhs {
            Ok(())
        } else {
            Err(SigningError::Verify.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PreHasherXof, SecretKey, SigningKey, PUBLIC_KEY_LENGTH};

    struct Ed448TestVector<'a> {
        s: &'a str,
        q: &'a str,
        m: &'a str,
        ph: bool,
        ctx: &'a str,
        sig: &'a str,
    }

    // Test vectors from RFC 8032.
    const TEST_VECTORS: [Ed448TestVector; 6] = [
        // Empty message, empty context.
        Ed448TestVector {
            s:   "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
            q:   "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
            m:   "",
            ph:  false,
            ctx: "",
            sig: "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
        },
        // 1-byte message, empty context.
        Ed448TestVector {
            s:   "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
            q:   "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
            m:   "03",
            ph:  false,
            ctx: "",
            sig: "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
        },
        // 1-byte message, 3-byte context.
        Ed448TestVector {
            s:   "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
            q:   "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
            m:   "03",
            ph:  false,
            ctx: "666f6f",
            sig: "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00",
        },
        // 256-byte message, empty context.
        Ed448TestVector {
            s:   "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
            q:   "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
            m:   "15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072fc1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a6039c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce012d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11",
            ph:  false,
            ctx: "",
            sig: "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00",
        },
        // 3-byte message, pre-hashed, empty context.
        Ed448TestVector {
            s:   "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49",
            q:   "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880",
            m:   "616263",
            ph:  true,
            ctx: "",
            sig: "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00",
        },
        Ed448TestVector {
            s:   "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49",
            q:   "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880",
            m:   "616263",
            ph:  true,
            ctx: "666f6f",
            sig: "c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa481065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab71284f8d0704a608c54a6b62d97beb511d132100",
        },
    ];

    #[test]
    fn signatures() {
        for tv in TEST_VECTORS.iter() {
            let mut seed = SecretKey::default();
            hex::decode_to_slice(tv.s, &mut seed).unwrap();
            let mut q_enc = [0u8; PUBLIC_KEY_LENGTH];
            hex::decode_to_slice(tv.q, &mut q_enc).unwrap();
            let msg = hex::decode(tv.m).unwrap();
            let ctx = hex::decode(tv.ctx).unwrap();
            let mut sig = [0u8; 114];
            hex::decode_to_slice(tv.sig, &mut sig[..]).unwrap();
            let sig = Signature::try_from(&sig[..]).unwrap();

            let skey = SigningKey::from(&seed);
            assert_eq!(&q_enc[..], skey.verifying_key().as_bytes());
            if tv.ph {
                assert_eq!(
                    skey.sign_prehashed::<PreHasherXof<Shake256>>(
                        Some(&ctx[..]),
                        Shake256::default().chain(&msg).into(),
                    )
                    .unwrap(),
                    sig
                );
            } else {
                assert_eq!(skey.sign_ctx(&ctx[..], &msg[..]).unwrap(), sig);
                if ctx.len() == 0 {
                    assert_eq!(skey.sign_raw(&msg[..]), sig);
                }
            }

            let pkey = VerifyingKey::from_bytes(&q_enc).unwrap();
            if tv.ph {
                let mut reader = Shake256::default().chain(&msg).finalize_xof();
                let mut hm = [0u8; 64];
                reader.read(&mut hm);
                assert!(pkey.verify_inner(&sig, 1, &ctx[..], &hm).is_ok());
                assert!(pkey.verify_inner(&sig, 1, &[1u8], &hm).is_err());
                hm[42] ^= 0x08;
                assert!(pkey.verify_inner(&sig, 1, &ctx[..], &hm).is_err());
            } else {
                assert!(pkey.verify_ctx(&sig, &ctx[..], &msg[..]).is_ok());
                assert!(pkey.verify_ctx(&sig, &[1u8], &msg[..]).is_err());
                assert!(pkey.verify_ctx(&sig, &ctx[..], &[0u8]).is_err());
                if ctx.len() == 0 {
                    assert!(pkey.verify_raw(&sig, &msg[..]).is_ok());
                }
            }
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialization() {
        use rand_chacha::ChaCha8Rng;
        use rand_core::SeedableRng;

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let bytes = serde_bare::to_vec(&verifying_key).unwrap();
        let verifying_key2: VerifyingKey = serde_bare::from_slice(&bytes).unwrap();
        assert_eq!(verifying_key, verifying_key2);

        let string = serde_json::to_string(&verifying_key).unwrap();
        let verifying_key3: VerifyingKey = serde_json::from_str(&string).unwrap();
        assert_eq!(verifying_key, verifying_key3);
    }
}
