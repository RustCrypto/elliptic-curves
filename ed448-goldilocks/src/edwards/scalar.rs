use crate::field::{CurveWithScalar, NZ_ORDER, Scalar, ScalarBytes, WideScalarBytes};
use crate::{Ed448, ORDER};

use elliptic_curve::array::Array;
use elliptic_curve::bigint::{Limb, NonZero, U448, U704};
use elliptic_curve::consts::{U57, U84, U88};
use elliptic_curve::scalar::FromUintUnchecked;
use hash2curve::FromOkm;
use subtle::{Choice, CtOption};

impl CurveWithScalar for Ed448 {
    type ReprSize = U57;

    fn from_bytes_mod_order_wide(input: &WideScalarBytes<Self>) -> Scalar<Self> {
        // top multiplier = 2^896 mod ℓ
        const TOP_MULTIPLIER: U448 = U448::from_be_hex(
            "3402a939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf725ee4d8380d66de2388ea18597af32c4bc1b195d9e3539257049b9b60",
        );
        let value = (
            U448::from_le_slice(&input[..56]),
            U448::from_le_slice(&input[56..112]),
        );
        let mut top = [0u8; 56];
        top[..2].copy_from_slice(&input[112..]);
        let top = U448::from_le_slice(&top).mul_mod(&TOP_MULTIPLIER, &NZ_ORDER);
        let bottom = U448::rem_wide_vartime(value, &NZ_ORDER);
        Scalar::new(bottom.add_mod(&top, &ORDER))
    }

    fn from_canonical_bytes(bytes: &ScalarBytes<Self>) -> subtle::CtOption<Scalar<Self>> {
        fn is_zero(b: u8) -> Choice {
            let res = b as i8;
            Choice::from((((res | -res) >> 7) + 1) as u8)
        }

        // Check that the 10 high bits are not set
        let is_valid = is_zero(bytes[56]) | is_zero(bytes[55] >> 6);
        let bytes: [u8; 56] = core::array::from_fn(|i| bytes[i]);
        let candidate = Scalar::new(U448::from_le_slice(&bytes));

        // underflow means candidate < ORDER, thus canonical
        let (_, underflow) = candidate.scalar.borrowing_sub(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        CtOption::new(candidate, underflow & is_valid)
    }

    fn to_repr(scalar: &Scalar<Self>) -> ScalarBytes<Self> {
        scalar.to_bytes_rfc_8032()
    }
}

/// [`Ed448`] scalar field.
pub type EdwardsScalar = Scalar<Ed448>;

impl EdwardsScalar {
    /// Serialize the scalar into 57 bytes, per RFC 8032.
    /// Byte 56 will always be zero.
    pub fn to_bytes_rfc_8032(&self) -> EdwardsScalarBytes {
        let mut bytes = EdwardsScalarBytes::default();
        bytes[..56].copy_from_slice(&self.to_bytes());
        bytes
    }

    /// Construct a `Scalar` by reducing a 912-bit little-endian integer
    /// modulo the group order ℓ.
    pub fn from_bytes_mod_order_wide(input: &WideEdwardsScalarBytes) -> EdwardsScalar {
        Ed448::from_bytes_mod_order_wide(input)
    }
}

elliptic_curve::scalar_impls!(Ed448, EdwardsScalar);

/// The number of bytes needed to represent the scalar field
pub type EdwardsScalarBytes = ScalarBytes<Ed448>;
/// The number of bytes needed to represent the safely create a scalar from a random bytes
pub type WideEdwardsScalarBytes = WideScalarBytes<Ed448>;

#[cfg(feature = "bits")]
impl From<&EdwardsScalar> for elliptic_curve::scalar::ScalarBits<Ed448> {
    fn from(scalar: &EdwardsScalar) -> Self {
        scalar.scalar.to_words().into()
    }
}

impl FromOkm for EdwardsScalar {
    type Length = U84;

    fn from_okm(data: &Array<u8, Self::Length>) -> Self {
        const SEMI_WIDE_MODULUS: NonZero<U704> = NonZero::<U704>::new_unwrap(U704::from_be_hex(
            "00000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
        ));
        let mut tmp = Array::<u8, U88>::default();
        tmp[4..].copy_from_slice(&data[..]);

        let mut num = U704::from_be_slice(&tmp[..]);
        num %= SEMI_WIDE_MODULUS;
        let mut words = [0; U448::LIMBS];
        words.copy_from_slice(&num.to_words()[..U448::LIMBS]);
        Scalar::new(U448::from_words(words))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use elliptic_curve::array::Array;
    use hash2curve::GroupDigest;
    use hex_literal::hex;

    #[test]
    fn test_basic_add() {
        let five = EdwardsScalar::from(5u8);
        let six = EdwardsScalar::from(6u8);

        assert_eq!(five + six, EdwardsScalar::from(11u8))
    }

    #[test]
    fn test_basic_sub() {
        let ten = EdwardsScalar::from(10u8);
        let five = EdwardsScalar::from(5u8);
        assert_eq!(ten - five, EdwardsScalar::from(5u8))
    }

    #[test]
    fn test_basic_mul() {
        let ten = EdwardsScalar::from(10u8);
        let five = EdwardsScalar::from(5u8);

        assert_eq!(ten * five, EdwardsScalar::from(50u8))
    }

    #[test]
    fn test_mul() {
        let a = EdwardsScalar::new(U448::from_be_hex(
            "1e63e8073b089f0747cf8cac2c3dc2732aae8688a8fa552ba8cb0ae8c0be082e74d657641d9ac30a087b8fb97f8ed27dc96a3c35ffb823a3",
        ));

        let b = EdwardsScalar::new(U448::from_be_hex(
            "16c5450acae1cb680a92de2d8e59b30824e8d4991adaa0e7bc343bcbd099595b188c6b1a1e30b38b17aa6d9be416b899686eb329d8bedc42",
        ));

        let exp = EdwardsScalar::new(U448::from_be_hex(
            "31e055c14ca389edfccd61b3203d424bb9036ff6f2d89c1e07bcd93174e9335f36a1492008a3a0e46abd26f5994c9c2b1f5b3197a18d010a",
        ));

        assert_eq!(a * b, exp)
    }
    #[test]
    fn test_basic_square() {
        let a = EdwardsScalar::new(U448::from_be_hex(
            "3162081604b3273b930392e5d2391f9d21cc3078f22c69514bb395e08dccc4866f08f3311370f8b83fa50692f640922b7e56a34bcf5fac3d",
        ));
        let expected_a_squared = EdwardsScalar::new(U448::from_be_hex(
            "1c1e32fc66b21c9c42d6e8e20487193cf6d49916421b290098f30de3713006cfe8ee9d21eeef7427f82a1fe036630c74b9acc2c2ede40f04",
        ));

        assert_eq!(a.square(), expected_a_squared)
    }

    #[test]
    fn test_sanity_check_index_mut() {
        let mut x = EdwardsScalar::ONE;
        x[0] = 2;
        assert_eq!(x, EdwardsScalar::from(2u8))
    }
    #[test]
    fn test_basic_halving() {
        let eight = EdwardsScalar::from(8u8);
        let four = EdwardsScalar::from(4u8);
        let two = EdwardsScalar::from(2u8);
        assert_eq!(eight.halve(), four);
        assert_eq!(four.halve(), two);
        assert_eq!(two.halve(), EdwardsScalar::ONE);
    }

    #[test]
    fn test_equals() {
        let a = EdwardsScalar::from(5u8);
        let b = EdwardsScalar::from(5u8);
        let c = EdwardsScalar::from(10u8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_basic_inversion() {
        // Test inversion from 2 to 100
        for i in 1..=100u8 {
            let x = EdwardsScalar::from(i);
            let x_inv = x.invert();
            assert_eq!(x_inv * x, EdwardsScalar::ONE)
        }

        // Inversion of zero is zero
        let zero = EdwardsScalar::ZERO;
        let expected_zero = zero.invert();
        assert_eq!(expected_zero, zero)
    }
    #[test]
    fn test_serialise() {
        let scalar = EdwardsScalar::new(U448::from_be_hex(
            "0d79f6e375d3395ed9a6c4c3c49a1433fd7c58aa38363f74e9ab2c22a22347d79988f8e01e8a309f862a9f1052fcd042b9b1ed7115598f62",
        ));
        let got = EdwardsScalar::from_canonical_bytes(&scalar.into()).unwrap();
        assert_eq!(scalar, got)
    }
    #[test]
    fn test_from_canonical_bytes() {
        // ff..ff should fail
        let mut bytes = EdwardsScalarBytes::from(hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        bytes.reverse();
        let s = EdwardsScalar::from_canonical_bytes(&bytes);
        assert!(<Choice as Into<bool>>::into(s.is_none()));

        // n should fail
        let mut bytes = EdwardsScalarBytes::from(hex!(
            "003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"
        ));
        bytes.reverse();
        let s = EdwardsScalar::from_canonical_bytes(&bytes);
        assert!(<Choice as Into<bool>>::into(s.is_none()));

        // n-1 should work
        let mut bytes = EdwardsScalarBytes::from(hex!(
            "003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"
        ));
        bytes.reverse();
        let s = EdwardsScalar::from_canonical_bytes(&bytes);
        match Option::<EdwardsScalar>::from(s) {
            Some(s) => assert_eq!(s, EdwardsScalar::ZERO - EdwardsScalar::ONE),
            None => panic!("should not return None"),
        };
    }

    #[test]
    fn test_from_bytes_mod_order_wide() {
        // n should become 0
        let mut bytes = WideEdwardsScalarBytes::from(hex!(
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"
        ));
        bytes.reverse();
        let s = EdwardsScalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, EdwardsScalar::ZERO);

        // n-1 should stay the same
        let mut bytes = WideEdwardsScalarBytes::from(hex!(
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"
        ));
        bytes.reverse();
        let s = EdwardsScalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, EdwardsScalar::ZERO - EdwardsScalar::ONE);

        // n+1 should become 1
        let mut bytes = WideEdwardsScalarBytes::from(hex!(
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f4"
        ));
        bytes.reverse();
        let s = EdwardsScalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, EdwardsScalar::ONE);

        // 2^912-1 should become 0x2939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf72c985bb24b6c520e319fb37a63e29800f160787ad1d2e11883fa931e7de81
        let bytes = WideEdwardsScalarBytes::from(hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        let s = EdwardsScalar::from_bytes_mod_order_wide(&bytes);
        let mut bytes = EdwardsScalarBytes::from(hex!(
            "002939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf72c985bb24b6c520e319fb37a63e29800f160787ad1d2e11883fa931e7de81"
        ));
        bytes.reverse();
        let reduced = EdwardsScalar::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(s, reduced);
    }

    #[test]
    fn test_to_bytes_rfc8032() {
        // n-1
        let mut bytes: [u8; 57] = hex!(
            "003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"
        );
        bytes.reverse();
        let x = EdwardsScalar::ZERO - EdwardsScalar::ONE;
        let candidate = x.to_bytes_rfc_8032();
        assert_eq!(&bytes[..], &candidate[..]);
    }

    #[cfg(all(feature = "alloc", feature = "serde"))]
    #[test]
    fn serde() {
        use elliptic_curve::PrimeField;

        let res = serde_json::to_string(&EdwardsScalar::TWO_INV);
        assert!(res.is_ok());
        let sj = res.unwrap();

        let res = serde_json::from_str::<EdwardsScalar>(&sj);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), EdwardsScalar::TWO_INV);

        let res = serde_bare::to_vec(&EdwardsScalar::TWO_INV);
        assert!(res.is_ok());
        let sb = res.unwrap();
        assert_eq!(sb.len(), 57);

        let res = serde_bare::from_slice::<EdwardsScalar>(&sb);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), EdwardsScalar::TWO_INV);
    }

    #[test]
    fn scalar_hash() {
        let msg = b"hello world";
        let dst = b"edwards448_XOF:SHAKE256_ELL2_RO_";
        let res = Ed448::hash_to_scalar::<hash2curve::ExpandMsgXof<sha3::Shake256>>(&[msg], &[dst])
            .unwrap();
        let expected: [u8; 57] = hex_literal::hex!(
            "2d32a08f09b88275cc5f437e625696b18de718ed94559e17e4d64aafd143a8527705132178b5ce7395ea6214735387398a35913656b4951300"
        );
        assert_eq!(res.to_bytes_rfc_8032(), Array::from(expected));
    }
}
