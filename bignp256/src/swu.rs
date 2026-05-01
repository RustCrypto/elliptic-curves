//! SWU implementation for `BignP256`

use crate::{BignP256, ProjectivePoint, Sec1Point, U256, arithmetic::FieldElement};
use belt_kwp::{BeltKwp, KeyInit};
use core::num::{NonZero, NonZeroU16};
use elliptic_curve::{
    Field,
    array::Array,
    bigint::U384,
    consts::{U32, U48, U128},
    sec1::FromSec1Point,
    subtle::ConditionallySelectable,
};
use hash2curve::{ExpandMsg, Expander, MapToCurve};
use primefield::bigint::{NonZero as BigintNonZero, Reduce};
use primeorder::PrimeCurveParams;

impl Reduce<Array<u8, U48>> for FieldElement {
    #[allow(clippy::arithmetic_side_effects)]
    fn reduce(value: &Array<u8, U48>) -> Self {
        const WIDE_MODULUS: BigintNonZero<U384> = BigintNonZero::<U384>::new_unwrap(
            U384::from_be_hex(
                "00000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43",
            ),
        );

        let value = U384::from_le_slice(value);
        let value = value % WIDE_MODULUS;

        let mut words = [0; U256::LIMBS];
        words.copy_from_slice(&value.to_words()[..U256::LIMBS]);

        FieldElement::from_uint_unchecked(U256::from_words(words))
    }
}

/// Expander with `belt-keywrap` algorithm
struct BeltKwpExpander {
    /// Output buffer containing the 48-byte result of belt-keywrap
    buf: [u8; 48],
    /// Current position in the buffer for reading
    offset: usize,
    /// Remaining bytes available to read
    remaining: usize,
}

impl Expander for BeltKwpExpander {
    /// Fill destination buffer with expanded bytes.
    ///
    /// Copies bytes from the internal 48-byte buffer to the destination.
    /// Can be called multiple times to read the full output.
    #[allow(clippy::arithmetic_side_effects)]
    fn fill_bytes(&mut self, dst: &mut [u8]) -> Result<usize, elliptic_curve::Error> {
        if self.remaining == 0 {
            return Err(elliptic_curve::Error);
        }

        let len = dst.len().min(self.remaining);
        dst[..len].copy_from_slice(&self.buf[self.offset..self.offset + len]);
        self.offset += len;
        self.remaining -= len;
        Ok(len)
    }
}

impl ExpandMsg<U32> for BeltKwpExpander {
    type Hash = ();
    type Expander<'dst> = Self;
    type Error = elliptic_curve::Error;

    #[allow(clippy::arithmetic_side_effects)]
    fn expand_message<'dst>(
        msg: &[&[u8]],
        dst: &'dst [&[u8]],
        len_in_bytes: NonZero<u16>,
    ) -> Result<Self::Expander<'dst>, Self::Error> {
        if len_in_bytes.get() != 48 {
            return Err(elliptic_curve::Error);
        }

        let mut input = [0u8; 32];
        let mut pos = 0;

        // Copy msg slices
        for m in msg {
            let to_copy = (m.len()).min(32 - pos);
            if to_copy == 0 {
                break;
            }
            input[pos..pos + to_copy].copy_from_slice(&m[..to_copy]);
            pos += to_copy;
        }

        // Copy dst slices
        for d in dst {
            let to_copy = (d.len()).min(32 - pos);
            if to_copy == 0 {
                break;
            }
            input[pos..pos + to_copy].copy_from_slice(&d[..to_copy]);
            pos += to_copy;
        }

        // Initialize Belt-KWP with zero key (0^256)
        let kwp = BeltKwp::new_from_slice(&[0u8; 32]).map_err(|_| elliptic_curve::Error)?;

        // Apply belt-keywrap(input, 0^128, 0^256)
        let mut buf = [0u8; 48];
        kwp.wrap_key(&input, &[0u8; 16], &mut buf)
            .map_err(|_| elliptic_curve::Error)?;

        Ok(Self {
            buf,
            offset: 0,
            remaining: 48,
        })
    }
}

impl FieldElement {
    #[allow(clippy::arithmetic_side_effects)]
    /// Implements the bake-swu algorithm from STB 34.101.66-2014, section 6.2.3.
    /// Input `self` is the field element s obtained after belt-keywrap preprocessing.
    fn swu(&self) -> ProjectivePoint {
        // Step 3: t ← -s² mod p
        let t = self.square().neg();
        let t_squared = t.square();

        // Step 4: Compute numerator = (1 + t + t²) and denominator = a(t + t²)
        let num = FieldElement::ONE + t + t_squared;
        let den = BignP256::EQUATION_A * (t + t_squared);

        // Step 4: x₁ ← -b(1 + t + t²)(a(t + t²))^(-1) mod p
        let x1 = -BignP256::EQUATION_B * num * den.invert().unwrap();

        // Step 5: x₂ ← t·x₁ mod p
        let x2 = t * x1;

        // Step 6: y ← (x₁³ + a·x₁ + b) mod p
        let gx1 = x1.cube() + BignP256::EQUATION_A * x1 + BignP256::EQUATION_B;

        // Steps 7-8: Compute square root and check if gx1 is a quadratic residue
        let (is_square, y1) = gx1.sqrt_alt();

        // Step 7: s³·y mod p (for alternative case)
        let y2 = self.cube() * y1;

        // Step 9: Constant-time selection of final coordinates
        let x = FieldElement::conditional_select(&x2, &x1, is_square);
        let y = FieldElement::conditional_select(&y2, &y1, is_square);

        // Step 10: Return W
        let point = Sec1Point::from_affine_coordinates(&x.to_bytes(), &y.to_bytes(), false);
        ProjectivePoint::from_sec1_point(&point).expect("Always possible")
    }
}

impl MapToCurve for BignP256 {
    type SecurityLevel = U128;
    type FieldElement = FieldElement;
    type Length = U48;

    fn map_to_curve(element: Self::FieldElement) -> ProjectivePoint {
        element.swu()
    }
}

impl BignP256 {
    /// Implements the complete `bake-swu` map-to-curve flow specified in STB 34.101.66-2014, section 6.2
    pub fn hash_secret_to_curve(secret: &[u8]) -> elliptic_curve::Result<ProjectivePoint> {
        // 1. H ← belt-keywrap(X, 0^128, 0^256)
        let mut expander = BeltKwpExpander::expand_message(
            &[secret],
            &[],
            NonZeroU16::new(48).expect("48 is always nonzero"),
        )?;

        let mut buf = Array::<u8, U48>::default();
        expander.fill_bytes(&mut buf)?;

        // 2. s ← H mod p
        let s = FieldElement::reduce(&buf);

        // 3-10. Apply simplified SWU mapping
        let point = BignP256::map_to_curve(s);

        Ok(point)
    }
}

#[test]
fn test_expander() {
    use hex_literal::hex;

    // Test vector from STB 34.101.66-2014, Appendix B.4
    let input = hex!(
        "AD1362A8 F9A3D42F BE1B8E6F 1C88AAD5"
        "0F51D913 47617C20 BD4AB07A EF4F26A1"
    );

    let expected = hex!(
        "CFE573F6745C633867EFBF702504394B585B1D6F454721F4"
        "7BD28E3DFF19230E18D8A279A5C2047069585F26315BF1A5"
    );

    let mut expander =
        BeltKwpExpander::expand_message(&[&input], &[b""], NonZeroU16::new(48).unwrap()).unwrap();
    let mut output = [0u8; 48];
    expander.fill_bytes(&mut output).unwrap();

    assert_eq!(output, expected);
}
