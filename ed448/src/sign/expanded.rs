use crate::sign::{InnerSignature, HASH_HEAD};
use crate::{
    EdwardsPoint, Scalar, ScalarBytes, SecretKey, SigningError, VerifyingKey, WideScalarBytes,
    SECRET_KEY_LENGTH,
};
use sha3::digest::ExtendableOutputReset;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct ExpandedSecretKey {
    pub(crate) seed: SecretKey,
    pub(crate) scalar: Scalar,
    pub(crate) public_key: VerifyingKey,
    pub(crate) hash_prefix: ScalarBytes,
}

impl Zeroize for ExpandedSecretKey {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.scalar.zeroize();
        self.hash_prefix.zeroize();
    }
}

impl Drop for ExpandedSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<&SecretKey> for ExpandedSecretKey {
    fn from(secret_key: &SecretKey) -> Self {
        Self::from_seed(secret_key)
    }
}

impl ZeroizeOnDrop for ExpandedSecretKey {}

impl ExpandedSecretKey {
    pub fn from_seed(seed: &SecretKey) -> Self {
        let mut reader = Shake256::default().chain(seed).finalize_xof();
        let mut bytes = WideScalarBytes::default();
        reader.read(&mut bytes);
        let mut scalar_bytes = ScalarBytes::default();
        scalar_bytes.copy_from_slice(&bytes[..SECRET_KEY_LENGTH]);

        // The two least significant bits of the first byte are cleared
        // All eight most significant bits of the last byte are cleared
        // with the highest bit of the second byte set.
        scalar_bytes[0] &= 0xFC;
        scalar_bytes[56] = 0;
        scalar_bytes[55] |= 0x80;

        let scalar = Scalar::from_bytes_mod_order(&scalar_bytes);

        let mut hash_prefix = ScalarBytes::default();
        hash_prefix.copy_from_slice(&bytes[SECRET_KEY_LENGTH..]);

        let point = EdwardsPoint::GENERATOR * scalar;
        let public_key = VerifyingKey {
            compressed: point.compress(),
            point,
        };

        Self {
            seed: *seed,
            scalar,
            public_key,
            hash_prefix,
        }
    }

    /// Signs a message.
    ///
    /// This is the "Ed448" mode of RFC 8032 (no pre-hashing),
    /// also known as "PureEdDSA on Curve448". No context is provided;
    /// this is equivalent to `sign_ctx()` with an empty (zero-length)
    /// context.
    pub fn sign_raw(&self, m: &[u8]) -> Result<InnerSignature, SigningError> {
        self.sign_inner(0, &[], m)
    }

    /// Signs a message (with context).
    ///
    /// This is the "Ed448" mode of RFC 8032 (no pre-hashing),
    /// also known as "PureEdDSA on Curve448". A context string is also
    /// provided; it MUST have length at most 255 bytes.
    pub fn sign_ctx(&self, ctx: &[u8], m: &[u8]) -> Result<InnerSignature, SigningError> {
        self.sign_inner(0, ctx, m)
    }

    /// Signs a pre-hashed message.
    ///
    /// This is the "Ed448ph" mode of RFC 8032 (message is pre-hashed),
    /// also known as "HashEdDSA on Curve448". The hashed message `hm`
    /// is provided (presumably, that hash value was obtained with
    /// SHAKE256 and an output of 64 bytes; the caller does the hashing
    /// itself). A context string is also provided; it MUST have length
    /// at most 255 bytes.
    pub fn sign_prehashed(&self, ctx: &[u8], m: &[u8]) -> Result<InnerSignature, SigningError> {
        self.sign_inner(1, ctx, m)
    }

    fn sign_inner(&self, phflag: u8, ctx: &[u8], m: &[u8]) -> Result<InnerSignature, SigningError> {
        if ctx.len() > 255 {
            return Err(SigningError::PrehashedContextLength);
        }
        // SHAKE256(dom4(F, C) || prefix || PH(M), 114) -> scalar r
        let clen = ctx.len() as u8;
        let mut reader = Shake256::default()
            .chain(HASH_HEAD)
            .chain([phflag])
            .chain([clen])
            .chain(ctx)
            .chain(self.hash_prefix)
            .chain(m)
            .finalize_xof_reset();
        let mut bytes = WideScalarBytes::default();
        reader.read(&mut bytes);
        let r = Scalar::from_bytes_mod_order_wide(&bytes);

        // R = r*B
        let big_r = EdwardsPoint::GENERATOR * r;
        let compressed_r = big_r.compress();

        // SHAKE256(dom4(F, C) || R || A || PH(M), 114) -> scalar k
        reader = Shake256::default()
            .chain(HASH_HEAD)
            .chain([phflag])
            .chain([clen])
            .chain(ctx)
            .chain(compressed_r.as_bytes())
            .chain(self.public_key.compressed.as_bytes())
            .chain(m)
            .finalize_xof();
        reader.read(&mut bytes);
        let k = Scalar::from_bytes_mod_order_wide(&bytes);
        Ok(InnerSignature {
            r: big_r,
            s: r + k * self.scalar,
        })
    }
}
