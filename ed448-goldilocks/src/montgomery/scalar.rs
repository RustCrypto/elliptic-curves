use elliptic_curve::array::Array;
use elliptic_curve::bigint::{Limb, U448};
use elliptic_curve::consts::{U56, U84};
use elliptic_curve::ops::Reduce;
use elliptic_curve::scalar::FromUintUnchecked;
use subtle::{Choice, CtOption};

use crate::field::{CurveWithScalar, ScalarBytes, WideScalarBytes};
use crate::{Curve448, ORDER, Scalar};

impl CurveWithScalar for Curve448 {
    type ReprSize = U56;

    fn from_bytes_mod_order_wide(input: &WideScalarBytes<Self>) -> Scalar<Self> {
        let value = (
            U448::from_le_slice(&input[..56]),
            U448::from_le_slice(&input[56..112]),
        );
        Scalar::new(U448::rem_wide_vartime(value, ORDER.as_nz_ref()))
    }

    fn from_canonical_bytes(bytes: &ScalarBytes<Self>) -> subtle::CtOption<Scalar<Self>> {
        fn is_zero(b: u8) -> Choice {
            let res = b as i8;
            Choice::from((((res | -res) >> 7) + 1) as u8)
        }

        // Check that the 10 high bits are not set
        let is_valid = is_zero(bytes[55] >> 6);
        let bytes: [u8; 56] = core::array::from_fn(|i| bytes[i]);
        let candidate = Scalar::new(U448::from_le_slice(&bytes));

        // underflow means candidate < ORDER, thus canonical
        let (_, underflow) = candidate.scalar.borrowing_sub(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        CtOption::new(candidate, underflow & is_valid)
    }

    fn to_repr(scalar: &Scalar<Self>) -> ScalarBytes<Self> {
        scalar.to_bytes().into()
    }
}

/// [`Curve448`] scalar field.
pub type MontgomeryScalar = Scalar<Curve448>;

impl MontgomeryScalar {
    /// Construct a `Scalar` by reducing a 896-bit little-endian integer
    /// modulo the group order ℓ.
    pub fn from_bytes_mod_order_wide(input: &WideMontgomeryScalarBytes) -> MontgomeryScalar {
        Curve448::from_bytes_mod_order_wide(input)
    }
}

elliptic_curve::scalar_impls!(Curve448, MontgomeryScalar);

/// The number of bytes needed to represent the scalar field
pub type MontgomeryScalarBytes = ScalarBytes<Curve448>;
/// The number of bytes needed to represent the safely create a scalar from a random bytes
pub type WideMontgomeryScalarBytes = WideScalarBytes<Curve448>;

#[cfg(feature = "bits")]
impl From<&MontgomeryScalar> for elliptic_curve::scalar::ScalarBits<Curve448> {
    fn from(scalar: &MontgomeryScalar) -> Self {
        scalar.scalar.to_words().into()
    }
}

impl Reduce<Array<u8, U84>> for MontgomeryScalar {
    fn reduce(value: &Array<u8, U84>) -> Self {
        Self::from_okm_u84(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use elliptic_curve::PrimeField;
    use hash2curve::ExpandMsgXof;
    use hex_literal::hex;
    use sha3::Shake256;

    #[test]
    fn test_basic_add() {
        let five = MontgomeryScalar::from(5u8);
        let six = MontgomeryScalar::from(6u8);

        assert_eq!(five + six, MontgomeryScalar::from(11u8))
    }

    #[test]
    fn test_basic_sub() {
        let ten = MontgomeryScalar::from(10u8);
        let five = MontgomeryScalar::from(5u8);
        assert_eq!(ten - five, MontgomeryScalar::from(5u8))
    }

    #[test]
    fn test_basic_mul() {
        let ten = MontgomeryScalar::from(10u8);
        let five = MontgomeryScalar::from(5u8);

        assert_eq!(ten * five, MontgomeryScalar::from(50u8))
    }

    #[test]
    fn test_mul() {
        let a = MontgomeryScalar::new(U448::from_be_hex(
            "1e63e8073b089f0747cf8cac2c3dc2732aae8688a8fa552ba8cb0ae8c0be082e74d657641d9ac30a087b8fb97f8ed27dc96a3c35ffb823a3",
        ));

        let b = MontgomeryScalar::new(U448::from_be_hex(
            "16c5450acae1cb680a92de2d8e59b30824e8d4991adaa0e7bc343bcbd099595b188c6b1a1e30b38b17aa6d9be416b899686eb329d8bedc42",
        ));

        let exp = MontgomeryScalar::new(U448::from_be_hex(
            "31e055c14ca389edfccd61b3203d424bb9036ff6f2d89c1e07bcd93174e9335f36a1492008a3a0e46abd26f5994c9c2b1f5b3197a18d010a",
        ));

        assert_eq!(a * b, exp)
    }
    #[test]
    fn test_basic_square() {
        let a = MontgomeryScalar::new(U448::from_be_hex(
            "3162081604b3273b930392e5d2391f9d21cc3078f22c69514bb395e08dccc4866f08f3311370f8b83fa50692f640922b7e56a34bcf5fac3d",
        ));
        let expected_a_squared = MontgomeryScalar::new(U448::from_be_hex(
            "1c1e32fc66b21c9c42d6e8e20487193cf6d49916421b290098f30de3713006cfe8ee9d21eeef7427f82a1fe036630c74b9acc2c2ede40f04",
        ));

        assert_eq!(a.square(), expected_a_squared)
    }

    #[test]
    fn test_sanity_check_index_mut() {
        let mut x = MontgomeryScalar::ONE;
        x[0] = 2;
        assert_eq!(x, MontgomeryScalar::from(2u8))
    }
    #[test]
    fn test_basic_halving() {
        let eight = MontgomeryScalar::from(8u8);
        let four = MontgomeryScalar::from(4u8);
        let two = MontgomeryScalar::from(2u8);
        assert_eq!(eight.div_by_2(), four);
        assert_eq!(four.div_by_2(), two);
        assert_eq!(two.div_by_2(), MontgomeryScalar::ONE);
    }

    #[test]
    fn test_equals() {
        let a = MontgomeryScalar::from(5u8);
        let b = MontgomeryScalar::from(5u8);
        let c = MontgomeryScalar::from(10u8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_basic_inversion() {
        // Test inversion from 2 to 100
        for i in 1..=100u8 {
            let x = MontgomeryScalar::from(i);
            let x_inv = x.invert();
            assert_eq!(x_inv * x, MontgomeryScalar::ONE)
        }

        // Inversion of zero is zero
        let zero = MontgomeryScalar::ZERO;
        let expected_zero = zero.invert();
        assert_eq!(expected_zero, zero)
    }
    #[test]
    fn test_serialise() {
        let scalar = MontgomeryScalar::new(U448::from_be_hex(
            "0d79f6e375d3395ed9a6c4c3c49a1433fd7c58aa38363f74e9ab2c22a22347d79988f8e01e8a309f862a9f1052fcd042b9b1ed7115598f62",
        ));
        let got = MontgomeryScalar::from_canonical_bytes(&scalar.into()).unwrap();
        assert_eq!(scalar, got)
    }
    #[test]
    fn test_from_canonical_bytes() {
        // ff..ff should fail
        let mut bytes = MontgomeryScalarBytes::from(hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        bytes.reverse();
        let s = MontgomeryScalar::from_canonical_bytes(&bytes);
        assert!(<Choice as Into<bool>>::into(s.is_none()));

        // n should fail
        let mut bytes = MontgomeryScalarBytes::from(hex!(
            "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"
        ));
        bytes.reverse();
        let s = MontgomeryScalar::from_canonical_bytes(&bytes);
        assert!(<Choice as Into<bool>>::into(s.is_none()));

        // n-1 should work
        let mut bytes = MontgomeryScalarBytes::from(hex!(
            "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"
        ));
        bytes.reverse();
        let s = MontgomeryScalar::from_canonical_bytes(&bytes);
        match Option::<MontgomeryScalar>::from(s) {
            Some(s) => assert_eq!(s, MontgomeryScalar::ZERO - MontgomeryScalar::ONE),
            None => panic!("should not return None"),
        };
    }

    #[test]
    fn test_from_bytes_mod_order_wide() {
        // n should become 0
        let mut bytes = WideMontgomeryScalarBytes::from(hex!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"
        ));
        bytes.reverse();
        let s = MontgomeryScalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, MontgomeryScalar::ZERO);

        // n-1 should stay the same
        let mut bytes = WideMontgomeryScalarBytes::from(hex!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"
        ));
        bytes.reverse();
        let s = MontgomeryScalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, MontgomeryScalar::ZERO - MontgomeryScalar::ONE);

        // n+1 should become 1
        let mut bytes = WideMontgomeryScalarBytes::from(hex!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f4"
        ));
        bytes.reverse();
        let s = MontgomeryScalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, MontgomeryScalar::ONE);

        // 2^896-1 should become 0x3402a939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf725ee4d8380d66de2388ea18597af32c4bc1b195d9e3539257049b9b5f
        let bytes = WideMontgomeryScalarBytes::from(hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        let s = MontgomeryScalar::from_bytes_mod_order_wide(&bytes);
        let mut bytes = MontgomeryScalarBytes::from(hex!(
            "3402a939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf725ee4d8380d66de2388ea18597af32c4bc1b195d9e3539257049b9b5f"
        ));
        bytes.reverse();
        let reduced = MontgomeryScalar::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(s, reduced);
    }

    #[cfg(all(feature = "alloc", feature = "serde"))]
    #[test]
    fn serde() {
        use elliptic_curve::PrimeField;

        let res = serde_json::to_string(&MontgomeryScalar::TWO_INV);
        assert!(res.is_ok());
        let sj = res.unwrap();

        let res = serde_json::from_str::<MontgomeryScalar>(&sj);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), MontgomeryScalar::TWO_INV);

        let res = serde_bare::to_vec(&MontgomeryScalar::TWO_INV);
        assert!(res.is_ok());
        let sb = res.unwrap();
        assert_eq!(sb.len(), 57);

        let res = serde_bare::from_slice::<MontgomeryScalar>(&sb);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), MontgomeryScalar::TWO_INV);
    }

    #[test]
    fn scalar_hash() {
        let msg = b"hello world";
        let res = hash2curve::hash_to_scalar::<Curve448, ExpandMsgXof<Shake256>, U84>(
            &[msg],
            &[b"test DST"],
        )
        .unwrap();
        let expected: [u8; 56] = hex_literal::hex!(
            "1db46e2f81d60ff23cc532d371e0c0aa3956746ca7d57c0089da8e313f5fdc770a846ea9932cc2f0a6aa59bfb94af97a402f0317add21c10"
        );
        assert_eq!(res.to_repr(), Array::from(expected));
    }
}
