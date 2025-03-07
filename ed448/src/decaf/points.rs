use crate::constants::{BASEPOINT_ORDER, DECAF_BASEPOINT};
use crate::curve::twedwards::extended::ExtendedPoint;
use crate::field::FieldElement;
use crate::*;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::{String, ToString};

use elliptic_curve::{
    generic_array::{
        typenum::{U56, U84},
        GenericArray,
    },
    group::{cofactor::CofactorGroup, prime::PrimeGroup, Curve, GroupEncoding},
    hash2curve::{ExpandMsg, Expander, FromOkm},
    ops::{LinearCombination, MulByGenerator},
    Group,
};

use core::fmt::{Display, Formatter, LowerHex, Result as FmtResult, UpperHex};
use rand_core::{CryptoRngCore, RngCore};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, CtOption};

/// The bytes representation of a compressed point
pub type DecafPointBytes = [u8; 56];
/// The group bytes representation
pub type DecafPointRepr = GenericArray<u8, U56>;

/// A Decaf point in the Twisted Edwards curve
#[derive(Copy, Clone, Debug)]
pub struct DecafPoint(pub(crate) ExtendedPoint);

impl Default for DecafPoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl Display for DecafPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ X: {}, Y: {}, Z: {}, T: {} }}",
            self.0.X, self.0.Y, self.0.Z, self.0.T
        )
    }
}

impl LowerHex for DecafPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ X: {:x}, Y: {:x}, Z: {:x}, T: {:x} }}",
            self.0.X, self.0.Y, self.0.Z, self.0.T
        )
    }
}

impl UpperHex for DecafPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ X: {:X}, Y: {:X}, Z: {:X}, T: {:X} }}",
            self.0.X, self.0.Y, self.0.Z, self.0.T
        )
    }
}

impl ConstantTimeEq for DecafPoint {
    fn ct_eq(&self, other: &DecafPoint) -> Choice {
        (self.0.X * other.0.Y).ct_eq(&(self.0.Y * other.0.X))
    }
}

impl ConditionallySelectable for DecafPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        DecafPoint(ExtendedPoint {
            X: FieldElement::conditional_select(&a.0.X, &b.0.X, choice),
            Y: FieldElement::conditional_select(&a.0.Y, &b.0.Y, choice),
            Z: FieldElement::conditional_select(&a.0.Z, &b.0.Z, choice),
            T: FieldElement::conditional_select(&a.0.T, &b.0.T, choice),
        })
    }
}

impl PartialEq for DecafPoint {
    fn eq(&self, other: &DecafPoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for DecafPoint {}

impl From<DecafPoint> for DecafPointBytes {
    fn from(point: DecafPoint) -> DecafPointBytes {
        point.compress().0
    }
}

impl From<&DecafPoint> for DecafPointBytes {
    fn from(compressed: &DecafPoint) -> DecafPointBytes {
        Self::from(*compressed)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl From<DecafPoint> for Vec<u8> {
    fn from(compressed: DecafPoint) -> Vec<u8> {
        Self::from(&compressed)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl From<&DecafPoint> for Vec<u8> {
    fn from(point: &DecafPoint) -> Vec<u8> {
        point.compress().0.to_vec()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<Vec<u8>> for DecafPoint {
    type Error = &'static str;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<&Vec<u8>> for DecafPoint {
    type Error = &'static str;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<&[u8]> for DecafPoint {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let compressed =
            <DecafPointBytes>::try_from(bytes).map_err(|_| "bytes is not the correct length")?;
        Self::try_from(compressed)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<Box<[u8]>> for DecafPoint {
    type Error = &'static str;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

impl TryFrom<DecafPointBytes> for DecafPoint {
    type Error = &'static str;

    fn try_from(bytes: DecafPointBytes) -> Result<Self, Self::Error> {
        let pt = CompressedDecaf(bytes);
        Option::<DecafPoint>::from(pt.decompress()).ok_or("Invalid point encoding")
    }
}

impl TryFrom<&DecafPointBytes> for DecafPoint {
    type Error = &'static str;

    fn try_from(bytes: &DecafPointBytes) -> Result<Self, Self::Error> {
        Self::try_from(*bytes)
    }
}

impl Group for DecafPoint {
    type Scalar = Scalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut uniform_bytes = [0u8; 112];
        rng.fill_bytes(&mut uniform_bytes);
        Self::from_uniform_bytes(&uniform_bytes)
    }

    fn identity() -> Self {
        Self::IDENTITY
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::IDENTITY)
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }
}

impl GroupEncoding for DecafPoint {
    type Repr = DecafPointRepr;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let pt = CompressedDecaf(*(bytes.as_ref()));
        pt.decompress()
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        let pt = CompressedDecaf(*(bytes.as_ref()));
        pt.decompress()
    }

    fn to_bytes(&self) -> Self::Repr {
        DecafPointRepr::from(self.compress().0)
    }
}

impl CofactorGroup for DecafPoint {
    type Subgroup = DecafPoint;

    fn clear_cofactor(&self) -> Self::Subgroup {
        self.double().double()
    }

    fn into_subgroup(self) -> CtOption<Self::Subgroup> {
        CtOption::new(self.clear_cofactor(), self.is_torsion_free())
    }

    fn is_torsion_free(&self) -> Choice {
        (self * BASEPOINT_ORDER).ct_eq(&Self::IDENTITY)
    }
}

impl PrimeGroup for DecafPoint {}

impl MulByGenerator for DecafPoint {}

impl LinearCombination for DecafPoint {}

impl Curve for DecafPoint {
    type AffineRepr = DecafAffinePoint;

    fn to_affine(&self) -> Self::AffineRepr {
        DecafAffinePoint(self.0.to_affine())
    }
}

impl From<EdwardsPoint> for DecafPoint {
    fn from(point: EdwardsPoint) -> Self {
        Self(point.to_twisted())
    }
}

impl From<&EdwardsPoint> for DecafPoint {
    fn from(point: &EdwardsPoint) -> Self {
        Self(point.to_twisted())
    }
}

impl From<DecafPoint> for EdwardsPoint {
    fn from(point: DecafPoint) -> Self {
        point.0.to_untwisted()
    }
}

impl From<&DecafPoint> for EdwardsPoint {
    fn from(point: &DecafPoint) -> Self {
        point.0.to_untwisted()
    }
}

impl From<DecafAffinePoint> for DecafPoint {
    fn from(point: DecafAffinePoint) -> Self {
        Self(point.0.to_extended())
    }
}

impl From<&DecafAffinePoint> for DecafPoint {
    fn from(point: &DecafAffinePoint) -> Self {
        Self(point.0.to_extended())
    }
}

impl From<DecafPoint> for DecafAffinePoint {
    fn from(point: DecafPoint) -> Self {
        DecafAffinePoint(point.0.to_affine())
    }
}

impl From<&DecafPoint> for DecafAffinePoint {
    fn from(point: &DecafPoint) -> Self {
        DecafAffinePoint(point.0.to_affine())
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for DecafPoint {}

impl DecafPoint {
    /// The generator point
    pub const GENERATOR: DecafPoint = DECAF_BASEPOINT;
    /// The identity point
    pub const IDENTITY: DecafPoint = DecafPoint(ExtendedPoint::IDENTITY);

    /// Check if the point is the identity
    pub fn is_identity(&self) -> Choice {
        self.ct_eq(&DecafPoint::IDENTITY)
    }

    /// Add two points
    pub fn add(&self, other: &DecafPoint) -> DecafPoint {
        DecafPoint(self.0.to_extensible().add_extended(&other.0).to_extended())
    }

    /// Subtract two points
    pub fn sub(&self, other: &DecafPoint) -> DecafPoint {
        DecafPoint(self.0.to_extensible().sub_extended(&other.0).to_extended())
    }

    /// Compress this point
    pub fn compress(&self) -> CompressedDecaf {
        let X = self.0.X;
        // let Y = self.0.Y;
        let Z = self.0.Z;
        let T = self.0.T;

        let XX_TT = (X + T) * (X - T);

        let (isr, _) = (X.square() * XX_TT * FieldElement::NEG_EDWARDS_D).inverse_square_root();
        let mut ratio = isr * XX_TT;
        let altx = ratio * FieldElement::DECAF_FACTOR; // Sign choice
        ratio.conditional_negate(altx.is_negative());
        let k = ratio * Z - T;

        let mut s = k * FieldElement::NEG_EDWARDS_D * isr * X;
        s.conditional_negate(s.is_negative());

        CompressedDecaf(s.to_bytes())
    }

    /// Return a `DecafPoint` chosen uniformly at random using a user-provided RNG.
    ///
    /// Uses the Decaf448 map, so that the discrete log
    /// of the output point with respect to any other point
    /// is unknown.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        let mut uniform_bytes = [0u8; 112];
        rng.fill_bytes(&mut uniform_bytes);
        Self::from_uniform_bytes(&uniform_bytes)
    }

    /// Construct a `DecafPoint` using `ExpandMsg`.
    ///
    /// This function is similar to `hash_to_curve` in the IETF draft
    /// where an expand_message function can be chosen and a domain
    /// separation tag.
    pub fn hash<X>(msg: &[u8], dst: &[u8]) -> Self
    where
        X: for<'a> ExpandMsg<'a>,
    {
        let dst = [dst];
        let mut random_bytes = GenericArray::<u8, U84>::default();
        let mut expander =
            X::expand_message(&[msg], &dst, random_bytes.len() * 2).expect("bad dst");
        expander.fill_bytes(&mut random_bytes);
        let u0 = FieldElement::from_okm(&random_bytes);
        expander.fill_bytes(&mut random_bytes);
        let u1 = FieldElement::from_okm(&random_bytes);

        let q0 = u0.map_to_curve_decaf448();
        let q1 = u1.map_to_curve_decaf448();
        Self(q0.add(&q1))
    }

    /// Construct a `DecafPoint` from 112 bytes of data.
    ///
    /// If the input bytes are uniformly distributed, the resulting
    /// point will be uniformly distributed over the group, and its
    /// discrete log with respect to other points is unknown.
    ///
    /// Implements map to curve according
    /// see <https://datatracker.ietf.org/doc/rfc9380/>
    /// section 5.3.4 by splitting the input into two 56-byte halves,
    /// then applies the decaf448_map to each, and adds the results.
    pub fn from_uniform_bytes(bytes: &[u8; 112]) -> Self {
        let lo: [u8; 56] = (&bytes[..56])
            .try_into()
            .expect("how does the slice have an incorrect length");
        let hi: [u8; 56] = (&bytes[56..])
            .try_into()
            .expect("how does the slice have an incorrect length");

        let u0 = FieldElement::from_bytes(&lo);
        let u1 = FieldElement::from_bytes(&hi);
        let q0 = u0.map_to_curve_decaf448();
        let q1 = u1.map_to_curve_decaf448();
        Self(q0.add(&q1))
    }
}

/// A compressed decaf point
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct CompressedDecaf(pub DecafPointBytes);

impl Default for CompressedDecaf {
    fn default() -> CompressedDecaf {
        Self::IDENTITY
    }
}

impl ConstantTimeEq for CompressedDecaf {
    fn ct_eq(&self, other: &CompressedDecaf) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl ConditionallySelectable for CompressedDecaf {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes = [0u8; 56];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::conditional_select(&a.0[i], &b.0[i], choice);
        }
        Self(bytes)
    }
}

impl PartialEq for CompressedDecaf {
    fn eq(&self, other: &CompressedDecaf) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for CompressedDecaf {}

impl From<CompressedDecaf> for DecafPointBytes {
    fn from(compressed: CompressedDecaf) -> DecafPointBytes {
        compressed.0
    }
}

impl From<&CompressedDecaf> for DecafPointBytes {
    fn from(compressed: &CompressedDecaf) -> DecafPointBytes {
        Self::from(*compressed)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl From<CompressedDecaf> for Vec<u8> {
    fn from(compressed: CompressedDecaf) -> Vec<u8> {
        Self::from(&compressed)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl From<&CompressedDecaf> for Vec<u8> {
    fn from(compressed: &CompressedDecaf) -> Vec<u8> {
        compressed.0.to_vec()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<Vec<u8>> for CompressedDecaf {
    type Error = String;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<&Vec<u8>> for CompressedDecaf {
    type Error = String;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<&[u8]> for CompressedDecaf {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let compressed = <DecafPointBytes>::try_from(bytes).map_err(|e| e.to_string())?;
        Self::try_from(compressed)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<Box<[u8]>> for CompressedDecaf {
    type Error = String;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<DecafPointBytes> for CompressedDecaf {
    type Error = String;

    fn try_from(bytes: DecafPointBytes) -> Result<Self, Self::Error> {
        let pt = CompressedDecaf(bytes);
        let _ = Option::<DecafPoint>::from(pt.decompress())
            .ok_or_else(|| "Invalid point encoding".to_string())?;
        Ok(pt)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<&DecafPointBytes> for CompressedDecaf {
    type Error = String;

    fn try_from(bytes: &DecafPointBytes) -> Result<Self, Self::Error> {
        Self::try_from(*bytes)
    }
}

impl AsRef<DecafPointBytes> for CompressedDecaf {
    fn as_ref(&self) -> &DecafPointBytes {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl serdect::serde::Serialize for CompressedDecaf {
    fn serialize<S: serdect::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::slice::serialize_hex_lower_or_bin(&self.0, s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serdect::serde::Deserialize<'de> for CompressedDecaf {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let mut bytes = [0u8; 56];
        serdect::array::deserialize_hex_or_bin(&mut bytes, d)?;
        Self::try_from(bytes).map_err(serdect::serde::de::Error::custom)
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for CompressedDecaf {}

impl CompressedDecaf {
    /// The compressed generator point
    pub const GENERATOR: Self = Self([
        102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
        102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51,
        51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51,
    ]);
    /// The compressed identity point
    pub const IDENTITY: Self = Self([0u8; 56]);

    /// Decompress a point if it is valid
    pub fn decompress(&self) -> CtOption<DecafPoint> {
        let s = FieldElement::from_bytes(&self.0);
        //XX: Check for canonical encoding and sign,
        // Copied this check from Dalek: The From_bytes function does not throw an error, if the bytes exceed the prime.
        // However, to_bytes reduces the Field element before serialising
        // So we can use to_bytes -> from_bytes and if the representations are the same, then the element was already in reduced form
        let s_bytes_check = s.to_bytes();
        let s_encoding_is_canonical = s_bytes_check[..].ct_eq(&self.0);
        let s_is_negative = s.is_negative();
        // if s_encoding_is_canonical.unwrap_u8() == 0u8 || s.is_negative().unwrap_u8() == 1u8 {
        //     return None;
        // }

        let ss = s.square();
        let u1 = FieldElement::ONE - ss;
        let u2 = FieldElement::ONE + ss;
        let u1_sqr = u1.square();

        let v = ss * (FieldElement::NEG_FOUR_TIMES_TWISTED_D) + u1_sqr; // XXX: constantify please

        let (I, ok) = (v * u1_sqr).inverse_square_root();

        let Dx = I * u1;
        let Dxs = (s + s) * Dx;

        let mut X = (Dxs * I) * v;
        let k = Dxs * FieldElement::DECAF_FACTOR;
        X.conditional_negate(k.is_negative());

        let Y = Dx * u2;
        let Z = FieldElement::ONE;
        let T = X * Y;
        let pt = ExtendedPoint { X, Y, Z, T };

        CtOption::new(
            DecafPoint(pt),
            ok & pt.is_on_curve() & s_encoding_is_canonical & !s_is_negative,
        )
    }

    /// Get the bytes of this compressed point
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::TWISTED_EDWARDS_BASE_POINT;

    #[test]
    fn test_edwards_ristretto_operations() {
        // Basic test that if P1 + P2 = P3
        // Then Decaf(P1) + Decaf(P2) = Decaf(P3)

        let P = TWISTED_EDWARDS_BASE_POINT;

        let P2 = P.double();
        let P3 = P2.to_extensible().add_extended(&P).to_extended();

        // Encode and decode to make them Decaf points
        let Decaf_P = DecafPoint(P).compress().decompress().unwrap();
        let Decaf_P2 = DecafPoint(P2).compress().decompress().unwrap();
        let expected_Decaf_P3 = DecafPoint(P3).compress().decompress().unwrap();

        // Adding the DecafPoint should be the same as adding the Edwards points and encoding the result as Decaf
        let Decaf_P3 = Decaf_P + Decaf_P2;

        assert_eq!(Decaf_P3, expected_Decaf_P3);
    }

    #[test]
    fn test_identity() {
        // Basic test to check the identity is being encoded properly
        let compress_identity = DecafPoint::IDENTITY.compress();
        assert!(compress_identity == CompressedDecaf::IDENTITY)
    }

    #[test]
    fn test_vectors_lib_decaf() {
        // Testing small multiples of basepoint. Taken from reference implementation.
        let compressed = [
            // Taken from libdecaf, where they were computed using SAGE script
            CompressedDecaf([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            CompressedDecaf([
                102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
                102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 51, 51, 51, 51, 51, 51,
                51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51,
                51,
            ]),
            CompressedDecaf([
                200, 152, 235, 79, 135, 249, 124, 86, 76, 111, 214, 31, 199, 228, 150, 137, 49, 74,
                31, 129, 142, 200, 94, 235, 59, 213, 81, 74, 200, 22, 211, 135, 120, 246, 158, 243,
                71, 168, 159, 202, 129, 126, 102, 222, 253, 237, 206, 23, 140, 124, 199, 9, 178,
                17, 110, 117,
            ]),
            CompressedDecaf([
                160, 192, 155, 242, 186, 114, 8, 253, 160, 244, 191, 227, 208, 245, 178, 154, 84,
                48, 18, 48, 109, 67, 131, 27, 90, 220, 111, 231, 248, 89, 111, 163, 8, 118, 61,
                177, 84, 104, 50, 59, 17, 207, 110, 74, 235, 140, 24, 254, 68, 103, 143, 68, 84,
                90, 105, 188,
            ]),
            CompressedDecaf([
                180, 111, 24, 54, 170, 40, 124, 10, 90, 86, 83, 240, 236, 94, 249, 233, 3, 244, 54,
                226, 28, 21, 112, 194, 154, 217, 229, 245, 150, 218, 151, 238, 175, 23, 21, 10,
                227, 11, 203, 49, 116, 208, 75, 194, 215, 18, 200, 199, 120, 157, 124, 180, 253,
                161, 56, 244,
            ]),
            CompressedDecaf([
                28, 91, 190, 207, 71, 65, 223, 170, 231, 157, 183, 45, 250, 206, 0, 234, 170, 197,
                2, 194, 6, 9, 52, 182, 234, 174, 202, 106, 32, 189, 61, 169, 224, 190, 135, 119,
                247, 208, 32, 51, 209, 177, 88, 132, 35, 34, 129, 164, 31, 199, 248, 14, 237, 4,
                175, 94,
            ]),
            CompressedDecaf([
                134, 255, 1, 130, 212, 15, 127, 158, 219, 120, 98, 81, 88, 33, 189, 103, 191, 214,
                22, 90, 60, 68, 222, 149, 215, 223, 121, 184, 119, 156, 207, 100, 96, 227, 198,
                139, 112, 193, 106, 170, 40, 15, 45, 123, 63, 34, 215, 69, 185, 122, 137, 144, 108,
                252, 71, 108,
            ]),
            CompressedDecaf([
                80, 43, 203, 104, 66, 235, 6, 240, 228, 144, 50, 186, 232, 124, 85, 76, 3, 29, 109,
                77, 45, 118, 148, 239, 191, 156, 70, 141, 72, 34, 12, 80, 248, 202, 40, 132, 51,
                100, 215, 12, 238, 146, 214, 254, 36, 110, 97, 68, 143, 157, 185, 128, 139, 59, 36,
                8,
            ]),
            CompressedDecaf([
                12, 152, 16, 241, 226, 235, 211, 137, 202, 167, 137, 55, 77, 120, 0, 121, 116, 239,
                77, 23, 34, 115, 22, 244, 14, 87, 139, 51, 104, 39, 218, 63, 107, 72, 42, 71, 148,
                235, 106, 57, 117, 185, 113, 181, 225, 56, 143, 82, 233, 30, 162, 241, 188, 176,
                249, 18,
            ]),
            CompressedDecaf([
                32, 212, 29, 133, 161, 141, 86, 87, 162, 150, 64, 50, 21, 99, 187, 208, 76, 47,
                251, 208, 163, 122, 123, 164, 58, 79, 125, 38, 60, 226, 111, 175, 78, 31, 116, 249,
                244, 181, 144, 198, 146, 41, 174, 87, 31, 227, 127, 166, 57, 181, 184, 235, 72,
                189, 154, 85,
            ]),
            CompressedDecaf([
                230, 180, 184, 244, 8, 199, 1, 13, 6, 1, 231, 237, 160, 195, 9, 161, 164, 39, 32,
                214, 208, 107, 87, 89, 253, 196, 225, 239, 226, 45, 7, 109, 108, 68, 212, 47, 80,
                141, 103, 190, 70, 41, 20, 210, 139, 142, 220, 227, 46, 112, 148, 48, 81, 100, 175,
                23,
            ]),
            CompressedDecaf([
                190, 136, 187, 184, 108, 89, 193, 61, 142, 157, 9, 171, 152, 16, 95, 105, 194, 209,
                221, 19, 77, 188, 211, 176, 134, 54, 88, 245, 49, 89, 219, 100, 192, 225, 57, 209,
                128, 243, 200, 155, 130, 150, 208, 174, 50, 68, 25, 192, 111, 168, 127, 199, 218,
                175, 52, 193,
            ]),
            CompressedDecaf([
                164, 86, 249, 54, 151, 105, 232, 240, 137, 2, 18, 74, 3, 20, 199, 160, 101, 55,
                160, 110, 50, 65, 31, 79, 147, 65, 89, 80, 161, 123, 173, 250, 116, 66, 182, 33,
                116, 52, 163, 160, 94, 244, 91, 229, 241, 11, 215, 178, 239, 142, 160, 12, 67, 30,
                222, 197,
            ]),
            CompressedDecaf([
                24, 110, 69, 44, 68, 102, 170, 67, 131, 180, 192, 2, 16, 213, 46, 121, 34, 219,
                249, 119, 30, 139, 71, 226, 41, 169, 183, 183, 60, 141, 16, 253, 126, 240, 182,
                228, 21, 48, 249, 31, 36, 163, 237, 154, 183, 31, 163, 139, 152, 178, 254, 71, 70,
                213, 29, 104,
            ]),
            CompressedDecaf([
                74, 231, 253, 202, 233, 69, 63, 25, 90, 142, 173, 92, 190, 26, 123, 150, 153, 103,
                59, 82, 196, 10, 178, 121, 39, 70, 72, 135, 190, 83, 35, 127, 127, 58, 33, 185, 56,
                212, 13, 14, 201, 225, 91, 29, 81, 48, 177, 63, 254, 216, 19, 115, 165, 62, 43, 67,
            ]),
            CompressedDecaf([
                132, 25, 129, 195, 191, 238, 195, 246, 12, 254, 202, 117, 217, 216, 220, 23, 244,
                108, 240, 16, 111, 36, 34, 181, 154, 236, 88, 10, 88, 243, 66, 39, 46, 58, 94, 87,
                90, 5, 93, 219, 5, 19, 144, 197, 76, 36, 198, 236, 177, 224, 172, 235, 7, 95, 96,
                86,
            ]),
        ];
        let mut point = DecafPoint::IDENTITY;
        let generator = DecafPoint::GENERATOR;
        for compressed_point in compressed.iter() {
            assert_eq!(&point.compress(), compressed_point);
            point = &point + &generator;
            let decompressed_point = compressed_point.decompress();
            assert_eq!(decompressed_point.is_some().unwrap_u8(), 1u8);
        }
    }

    #[test]
    fn test_invalid_point() {
        // Test that the identity point is not on the curve
        let all_ones = CompressedDecaf([1u8; 56]);
        assert_eq!(all_ones.decompress().is_none().unwrap_u8(), 1u8);
        let all_twos = CompressedDecaf([2u8; 56]);
        assert_eq!(all_twos.decompress().is_none().unwrap_u8(), 1u8);
    }

    #[test]
    fn test_hash_to_curve() {
        use elliptic_curve::hash2curve::ExpandMsgXof;

        let msg = b"Hello, world!";
        let point = DecafPoint::hash::<ExpandMsgXof<sha3::Shake256>>(msg, b"test_hash_to_curve");
        assert_eq!(point.0.is_on_curve().unwrap_u8(), 1u8);
        assert_ne!(point, DecafPoint::IDENTITY);
        assert_ne!(point, DecafPoint::GENERATOR);
    }

    #[test]
    fn test_sum_of_products() {
        use elliptic_curve_tools::SumOfProducts;
        let values = [
            (Scalar::from(8u8), DecafPoint::GENERATOR),
            (Scalar::from(9u8), DecafPoint::GENERATOR),
            (Scalar::from(10u8), DecafPoint::GENERATOR),
            (Scalar::from(11u8), DecafPoint::GENERATOR),
            (Scalar::from(12u8), DecafPoint::GENERATOR),
        ];

        let expected = DecafPoint::GENERATOR * Scalar::from(50u8);
        let result = DecafPoint::sum_of_products(&values);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sum_of_products2() {
        use elliptic_curve_tools::SumOfProducts;
        use rand_core::SeedableRng;

        const TESTS: usize = 5;
        const CHUNKS: usize = 10;
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([3u8; 32]);

        for _ in 0..TESTS {
            let scalars = (0..CHUNKS)
                .map(|_| Scalar::random(&mut rng))
                .collect::<Vec<_>>();
            let points = (0..CHUNKS)
                .map(|_| DecafPoint::random(&mut rng))
                .collect::<Vec<_>>();

            let input = scalars
                .iter()
                .zip(points.iter())
                .map(|(&s, &p)| (s, p))
                .collect::<Vec<_>>();
            let rhs = DecafPoint::sum_of_products(&input);

            let expected = points
                .iter()
                .zip(scalars.iter())
                .fold(DecafPoint::IDENTITY, |acc, (&p, &s)| acc + (p * s));

            assert_eq!(rhs, expected);
        }
    }
}
