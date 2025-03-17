#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};
use elliptic_curve::{
    CurveArithmetic, Error, Result, SecretKey,
    sec1::{ModulusSize, ToEncodedPoint},
};
use primeorder::PrimeCurveParams;

use signature::digest::{Digest, FixedOutputReset, Output};
use sm3::Sm3;

use super::{Cipher, kdf};

/// Decrypt messages using elliptic curve cryptography.
pub trait EcDecrypt<C>
where
    C: CurveArithmetic,
{
    /// Decrypt the [`Cipher`] using the default digest algorithm [`Sm3`].
    #[cfg(feature = "alloc")]
    fn decrypt(&self, cipher: &Cipher<'_, C, Sm3>) -> Result<Vec<u8>> {
        self.decrypt_digest::<Sm3>(cipher)
    }
    /// Decrypt the [`Cipher`] using the specified digest algorithm.
    #[cfg(feature = "alloc")]
    fn decrypt_digest<D: Digest + FixedOutputReset>(
        &self,
        cipher: &Cipher<'_, C, D>,
    ) -> Result<Vec<u8>> {
        let mut out = vec![0; cipher.c2.len()];
        self.decrypt_digest_into(cipher, &mut out)?;
        Ok(out)
    }
    /// Decrypt the [`Cipher`] to out using the default digest algorithm [`Sm3`].   
    /// The length of out is equal to the length of C2.
    fn decrypt_into(&self, cipher: &Cipher<'_, C, Sm3>, out: &mut [u8]) -> Result<()> {
        self.decrypt_digest_into(cipher, out)
    }
    /// Decrypt the [`Cipher`] to out using the specified digest algorithm.
    /// The length of out is equal to the length of C2.
    fn decrypt_digest_into<D: Digest + FixedOutputReset>(
        &self,
        cipher: &Cipher<'_, C, D>,
        out: &mut [u8],
    ) -> Result<()>;
}

impl<C> EcDecrypt<C> for SecretKey<C>
where
    C: PrimeCurveParams,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToEncodedPoint<C>,
{
    fn decrypt_digest_into<D: Digest + FixedOutputReset>(
        &self,
        cipher: &Cipher<'_, C, D>,
        out: &mut [u8],
    ) -> Result<()> {
        let scalar = self.to_nonzero_scalar();
        let mut digest = D::new();
        decrypt_into(scalar.as_ref(), cipher, &mut digest, out)
    }
}

fn decrypt_into<C, D>(
    secret_scalar: &C::Scalar,
    cipher: &Cipher<'_, C, D>,
    digest: &mut D,
    out: &mut [u8],
) -> Result<()>
where
    C: PrimeCurveParams,
    D: FixedOutputReset,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToEncodedPoint<C>,
{
    if out.len() < cipher.c2.len() {
        return Err(Error);
    }
    let out = &mut out[..cipher.c2.len()];

    // B3: compute [𝑑𝐵]𝐶1 = (𝑥2, 𝑦2)
    let c1_point = (cipher.c1 * secret_scalar).to_affine();

    #[cfg(feature = "alloc")]
    let c2 = &cipher.c2;
    #[cfg(not(feature = "alloc"))]
    let c2 = cipher.c2;

    // B4: compute 𝑡 = 𝐾𝐷𝐹(𝑥2 ∥ 𝑦2, 𝑘𝑙𝑒𝑛)
    // B5: get 𝐶2 from 𝐶 and compute 𝑀′ = 𝐶2 ⊕ t
    kdf::<D, C>(digest, c1_point, c2, out)?;

    // compute 𝑢 = 𝐻𝑎𝑠ℎ(𝑥2 ∥ 𝑀′∥ 𝑦2).
    let mut u = Output::<D>::default();
    let encode_point = c1_point.to_encoded_point(false);
    digest.update(encode_point.x().ok_or(Error)?);
    digest.update(out);
    digest.update(encode_point.y().ok_or(Error)?);
    digest.finalize_into_reset(&mut u);

    // If 𝑢 ≠ 𝐶3, output “ERROR” and exit
    if cipher.c3 != u {
        return Err(Error);
    }

    Ok(())
}
