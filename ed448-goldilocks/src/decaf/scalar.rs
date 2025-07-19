use crate::field::{CurveWithScalar, NZ_ORDER, Scalar, ScalarBytes, WideScalarBytes};
use crate::{Decaf448, ORDER};

use elliptic_curve::array::Array;
use elliptic_curve::bigint::{Limb, NonZero, U448, U512};
use elliptic_curve::consts::{U56, U64};
use elliptic_curve::scalar::FromUintUnchecked;
use hash2curve::FromOkm;
use subtle::{Choice, CtOption};

impl CurveWithScalar for Decaf448 {
    type ReprSize = U56;

    fn from_bytes_mod_order_wide(input: &WideScalarBytes<Self>) -> Scalar<Self> {
        let value = (
            U448::from_le_slice(&input[..56]),
            U448::from_le_slice(&input[56..112]),
        );
        Scalar::new(U448::rem_wide_vartime(value, &NZ_ORDER))
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

/// [`Decaf448`] scalar field.
pub type DecafScalar = Scalar<Decaf448>;

impl DecafScalar {
    /// Construct a `Scalar` by reducing a 896-bit little-endian integer
    /// modulo the group order ℓ.
    pub fn from_bytes_mod_order_wide(input: &WideDecafScalarBytes) -> DecafScalar {
        Decaf448::from_bytes_mod_order_wide(input)
    }
}

elliptic_curve::scalar_impls!(Decaf448, DecafScalar);

/// The number of bytes needed to represent the scalar field
pub type DecafScalarBytes = ScalarBytes<Decaf448>;
/// The number of bytes needed to represent the safely create a scalar from a random bytes
pub type WideDecafScalarBytes = WideScalarBytes<Decaf448>;

#[cfg(feature = "bits")]
impl From<&DecafScalar> for elliptic_curve::scalar::ScalarBits<Decaf448> {
    fn from(scalar: &DecafScalar) -> Self {
        scalar.scalar.to_words().into()
    }
}

impl FromOkm for DecafScalar {
    type Length = U64;

    fn from_okm(data: &Array<u8, Self::Length>) -> Self {
        const SEMI_WIDE_MODULUS: NonZero<U512> = NonZero::<U512>::new_unwrap(U512::from_be_hex(
            "00000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
        ));

        let mut num = U512::from_le_slice(data);
        num %= SEMI_WIDE_MODULUS;
        let mut words = [0; U448::LIMBS];
        words.copy_from_slice(&num.to_words()[..U448::LIMBS]);
        Scalar::new(U448::from_words(words))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use elliptic_curve::PrimeField;
    use elliptic_curve::array::Array;
    use hash2curve::{ExpandMsgXof, GroupDigest};
    use hex_literal::hex;
    use sha3::Shake256;

    #[test]
    fn test_basic_add() {
        let five = DecafScalar::from(5u8);
        let six = DecafScalar::from(6u8);

        assert_eq!(five + six, DecafScalar::from(11u8))
    }

    #[test]
    fn test_basic_sub() {
        let ten = DecafScalar::from(10u8);
        let five = DecafScalar::from(5u8);
        assert_eq!(ten - five, DecafScalar::from(5u8))
    }

    #[test]
    fn test_basic_mul() {
        let ten = DecafScalar::from(10u8);
        let five = DecafScalar::from(5u8);

        assert_eq!(ten * five, DecafScalar::from(50u8))
    }

    #[test]
    fn test_mul() {
        let a = DecafScalar::new(U448::from_be_hex(
            "1e63e8073b089f0747cf8cac2c3dc2732aae8688a8fa552ba8cb0ae8c0be082e74d657641d9ac30a087b8fb97f8ed27dc96a3c35ffb823a3",
        ));

        let b = DecafScalar::new(U448::from_be_hex(
            "16c5450acae1cb680a92de2d8e59b30824e8d4991adaa0e7bc343bcbd099595b188c6b1a1e30b38b17aa6d9be416b899686eb329d8bedc42",
        ));

        let exp = DecafScalar::new(U448::from_be_hex(
            "31e055c14ca389edfccd61b3203d424bb9036ff6f2d89c1e07bcd93174e9335f36a1492008a3a0e46abd26f5994c9c2b1f5b3197a18d010a",
        ));

        assert_eq!(a * b, exp)
    }
    #[test]
    fn test_basic_square() {
        let a = DecafScalar::new(U448::from_be_hex(
            "3162081604b3273b930392e5d2391f9d21cc3078f22c69514bb395e08dccc4866f08f3311370f8b83fa50692f640922b7e56a34bcf5fac3d",
        ));
        let expected_a_squared = DecafScalar::new(U448::from_be_hex(
            "1c1e32fc66b21c9c42d6e8e20487193cf6d49916421b290098f30de3713006cfe8ee9d21eeef7427f82a1fe036630c74b9acc2c2ede40f04",
        ));

        assert_eq!(a.square(), expected_a_squared)
    }

    #[test]
    fn test_sanity_check_index_mut() {
        let mut x = DecafScalar::ONE;
        x[0] = 2;
        assert_eq!(x, DecafScalar::from(2u8))
    }
    #[test]
    fn test_basic_halving() {
        let eight = DecafScalar::from(8u8);
        let four = DecafScalar::from(4u8);
        let two = DecafScalar::from(2u8);
        assert_eq!(eight.halve(), four);
        assert_eq!(four.halve(), two);
        assert_eq!(two.halve(), DecafScalar::ONE);
    }

    #[test]
    fn test_equals() {
        let a = DecafScalar::from(5u8);
        let b = DecafScalar::from(5u8);
        let c = DecafScalar::from(10u8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_basic_inversion() {
        // Test inversion from 2 to 100
        for i in 1..=100u8 {
            let x = DecafScalar::from(i);
            let x_inv = x.invert();
            assert_eq!(x_inv * x, DecafScalar::ONE)
        }

        // Inversion of zero is zero
        let zero = DecafScalar::ZERO;
        let expected_zero = zero.invert();
        assert_eq!(expected_zero, zero)
    }
    #[test]
    fn test_serialise() {
        let scalar = DecafScalar::new(U448::from_be_hex(
            "0d79f6e375d3395ed9a6c4c3c49a1433fd7c58aa38363f74e9ab2c22a22347d79988f8e01e8a309f862a9f1052fcd042b9b1ed7115598f62",
        ));
        let got = DecafScalar::from_canonical_bytes(&scalar.into()).unwrap();
        assert_eq!(scalar, got)
    }
    #[test]
    fn test_from_canonical_bytes() {
        // ff..ff should fail
        let mut bytes = DecafScalarBytes::from(hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        bytes.reverse();
        let s = DecafScalar::from_canonical_bytes(&bytes);
        assert!(<Choice as Into<bool>>::into(s.is_none()));

        // n should fail
        let mut bytes = DecafScalarBytes::from(hex!(
            "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"
        ));
        bytes.reverse();
        let s = DecafScalar::from_canonical_bytes(&bytes);
        assert!(<Choice as Into<bool>>::into(s.is_none()));

        // n-1 should work
        let mut bytes = DecafScalarBytes::from(hex!(
            "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"
        ));
        bytes.reverse();
        let s = DecafScalar::from_canonical_bytes(&bytes);
        match Option::<DecafScalar>::from(s) {
            Some(s) => assert_eq!(s, DecafScalar::ZERO - DecafScalar::ONE),
            None => panic!("should not return None"),
        };
    }

    #[test]
    fn test_from_bytes_mod_order_wide() {
        // n should become 0
        let mut bytes = WideDecafScalarBytes::from(hex!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"
        ));
        bytes.reverse();
        let s = DecafScalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, DecafScalar::ZERO);

        // n-1 should stay the same
        let mut bytes = WideDecafScalarBytes::from(hex!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"
        ));
        bytes.reverse();
        let s = DecafScalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, DecafScalar::ZERO - DecafScalar::ONE);

        // n+1 should become 1
        let mut bytes = WideDecafScalarBytes::from(hex!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f4"
        ));
        bytes.reverse();
        let s = DecafScalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, DecafScalar::ONE);

        // 2^896-1 should become 0x3402a939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf725ee4d8380d66de2388ea18597af32c4bc1b195d9e3539257049b9b5f
        let bytes = WideDecafScalarBytes::from(hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        let s = DecafScalar::from_bytes_mod_order_wide(&bytes);
        let mut bytes = DecafScalarBytes::from(hex!(
            "3402a939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf725ee4d8380d66de2388ea18597af32c4bc1b195d9e3539257049b9b5f"
        ));
        bytes.reverse();
        let reduced = DecafScalar::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(s, reduced);
    }

    #[cfg(all(feature = "alloc", feature = "serde"))]
    #[test]
    fn serde() {
        use elliptic_curve::PrimeField;

        let res = serde_json::to_string(&DecafScalar::TWO_INV);
        assert!(res.is_ok());
        let sj = res.unwrap();

        let res = serde_json::from_str::<DecafScalar>(&sj);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), DecafScalar::TWO_INV);

        let res = serde_bare::to_vec(&DecafScalar::TWO_INV);
        assert!(res.is_ok());
        let sb = res.unwrap();
        assert_eq!(sb.len(), 57);

        let res = serde_bare::from_slice::<DecafScalar>(&sb);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), DecafScalar::TWO_INV);
    }

    #[test]
    fn scalar_hash() {
        let msg = b"hello world";
        let dst = b"decaf448_XOF:SHAKE256_D448MAP_RO_";
        let res = Decaf448::hash_to_scalar::<ExpandMsgXof<Shake256>>(&[msg], &[dst]).unwrap();
        let expected: [u8; 56] = hex_literal::hex!(
            "55e7b59aa035db959409c6b69b817a18c8133d9ad06687665f5720672924da0a84eab7fee415ef13e7aaebdd227291ee8e156f32c507ad2e"
        );
        assert_eq!(res.to_repr(), Array::from(expected));
    }

    /// Taken from <https://www.rfc-editor.org/rfc/rfc9497.html#name-decaf448-shake256>.
    #[test]
    fn hash_to_scalar_voprf() {
        struct TestVector {
            dst: &'static [u8],
            sk_sm: &'static [u8],
        }

        const KEY_INFO: &[u8] = b"test key";
        const SEED: &[u8] =
            &hex!("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");

        const TEST_VECTORS: &[TestVector] = &[
            TestVector {
                dst: b"DeriveKeyPairOPRFV1-\x00-decaf448-SHAKE256",
                sk_sm: &hex!(
                    "e8b1375371fd11ebeb224f832dcc16d371b4188951c438f751425699ed29ecc80c6c13e558ccd67634fd82eac94aa8d1f0d7fee990695d1e"
                ),
            },
            TestVector {
                dst: b"DeriveKeyPairOPRFV1-\x01-decaf448-SHAKE256",
                sk_sm: &hex!(
                    "e3c01519a076a326a0eb566343e9b21c115fa18e6e85577ddbe890b33104fcc2835ddfb14a928dc3f5d79b936e17c76b99e0bf6a1680930e"
                ),
            },
            TestVector {
                dst: b"DeriveKeyPairOPRFV1-\x02-decaf448-SHAKE256",
                sk_sm: &hex!(
                    "792a10dcbd3ba4a52a054f6f39186623208695301e7adb9634b74709ab22de402990eb143fd7c67ac66be75e0609705ecea800992aac8e19"
                ),
            },
        ];

        let key_info_len = u16::try_from(KEY_INFO.len()).unwrap().to_be_bytes();

        'outer: for test_vector in TEST_VECTORS {
            for counter in 0_u8..=u8::MAX {
                let scalar = Decaf448::hash_to_scalar::<ExpandMsgXof<Shake256>>(
                    &[SEED, &key_info_len, KEY_INFO, &counter.to_be_bytes()],
                    &[test_vector.dst],
                )
                .unwrap();

                if !bool::from(scalar.is_zero()) {
                    assert_eq!(scalar.to_bytes().as_slice(), test_vector.sk_sm);
                    continue 'outer;
                }
            }

            panic!("deriving key failed");
        }
    }
}
