#![no_main]
use bign256;
use std::any::{Any, TypeId};
// bp256 and bp384 are under construction
use ciborium::de;
use elliptic_curve::{Field, PrimeField};
use k256;
use libfuzzer_sys::fuzz_target;
use p192;
use p224;
use p256;
use p384;
use p521;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use sm2;

fn test_field<F: PrimeField + Any>(fe1: F, fe2: F, fe3: F) {
    // Associativity
    assert_eq!(fe1 + (fe2 + fe3), (fe1 + fe2) + fe3);
    assert_eq!(fe1 * (fe2 * fe3), (fe1 * fe2) * fe3);

    // Commutativity
    assert_eq!(fe1 + fe2, fe2 + fe1);
    assert_eq!(fe1 * fe2, fe2 * fe1);

    // Identity
    assert_eq!(fe1 + F::ZERO, fe1);
    assert_eq!(fe1 * F::ONE, fe1);
    assert_eq!(fe1 - fe1, F::ZERO);

    // Distributivity
    assert_eq!(fe1 * (fe2 + fe3), fe1 * fe2 + fe1 * fe3);
    assert_eq!((fe1 + fe2) * fe3, fe1 * fe3 + fe2 * fe3);

    // Inverse, square, cube, sqrt_ratio
    assert_eq!(fe1 + (-fe1), F::ZERO);
    let fe1_sq = fe1.square();
    let fe1_cube = fe1.cube();
    if !bool::from(fe1.is_zero()) {
        assert_eq!(fe1_cube * fe1_sq.invert().unwrap(), fe1);
        if TypeId::of::<p521::Scalar>() != fe1.type_id() {
            assert_eq!(fe1_sq.sqrt().unwrap().square(), fe1_sq);
            assert!(bool::from(fe1_sq.sqrt_alt().0));
            assert!(bool::from(F::sqrt_ratio(&fe1_cube, &fe1).0));
        }
    }
    assert_eq!(
        bool::from(fe1_sq.is_zero()),
        bool::from(fe1_sq.is_zero_vartime())
    );

    // Double, even, odd
    let fe1_double: F = fe1.double();
    assert_eq!(fe1_double, fe1 + fe1);
    assert_ne!(
        bool::from(fe1_double.is_odd()),
        bool::from(fe1_double.is_even())
    );

    let limb0 = u64::from_le_bytes(fe3.to_repr().as_ref()[0..8].try_into().unwrap());
    let limb1 = u64::from_le_bytes(fe3.to_repr().as_ref()[8..16].try_into().unwrap());
    let limb2 = u64::from_le_bytes(fe3.to_repr().as_ref()[16..24].try_into().unwrap());
    let xx = fe1.pow(&[limb0, limb1, limb2, limb1.wrapping_add(limb2)]);
    let yy = fe1.pow_vartime(&[limb0, limb1, limb2, limb1.wrapping_add(limb2)]);
    assert_eq!(xx, yy);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 256 {
        return;
    }

    // Backup plan for `from` failures
    let mut rng = ChaChaRng::from_seed(data[0..32].try_into().unwrap());

    //
    //
    ///////////////////////////////////////////////////////////////////////////
    // Test bign256 (does not support serde)
    let repr1 = &data[16..(16 + (bign256::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe1 = bign256::Scalar::from_bytes(repr1.try_into().unwrap());
    let fe1 = opt_fe1.unwrap_or(bign256::Scalar::random(&mut rng));

    // bign256 de::from_reader() not supported/implemented

    let repr2 = &data[32..(32 + (bign256::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe2 = bign256::Scalar::from_repr(repr2.try_into().unwrap());
    let fe2 = opt_fe2.unwrap_or(bign256::Scalar::random(&mut rng));

    let repr3 = &data[48..(48 + (bign256::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe3 = bign256::Scalar::from_repr_vartime(repr3.try_into().unwrap());
    let fe3 = opt_fe3.unwrap_or(bign256::Scalar::random(&mut rng));

    let repr4 = &data[64..64 + usize::from(data[1] & 0x7f)];
    let opt_fe4 = bign256::Scalar::from_slice(repr4);
    let fe4 = opt_fe4.unwrap_or(bign256::Scalar::random(&mut rng));

    let repr5 = &data[96..(96 + usize::from(data[2] & 0x7f))];
    let str5 = std::str::from_utf8(&repr5).unwrap_or("123");
    let fe5 = bign256::Scalar::from_str_vartime(str5).unwrap_or(bign256::Scalar::random(&mut rng));

    let uint6 = bign256::elliptic_curve::bigint::U256::from_le_slice(&data[128..160]);
    let fe6 = bign256::Scalar::from_uint(uint6).unwrap_or(bign256::Scalar::random(&mut rng));

    let fe7 = bign256::Scalar::from_u64(u64::from_le_bytes(data[160..168].try_into().unwrap()));

    let fe8 = bign256::Scalar::from_u128(u128::from_le_bytes(data[168..184].try_into().unwrap()));

    // bign256::Scalar::generate_biased() not supported/implemented

    // bign256::Scalar::generate_vartime() not supported/implemented

    test_field(fe1 + fe2 + fe3, fe4 + fe5 + fe6, fe7 + fe8);

    //
    //
    ///////////////////////////////////////////////////////////////////////////
    // Test k256 (secp256k1)

    // k256::Scalar::from_bytes() not supported/implemented

    let fe1 = de::from_reader(&data[32..]).unwrap_or(k256::Scalar::random(&mut rng));

    let repr2 = &data[32..(32 + (k256::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe2 = k256::Scalar::from_repr(repr2.try_into().unwrap());
    let fe2 = opt_fe2.unwrap_or(k256::Scalar::random(&mut rng));

    let repr3 = &data[48..(48 + (k256::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe3 = k256::Scalar::from_repr_vartime(repr3.try_into().unwrap());
    let fe3 = opt_fe3.unwrap_or(k256::Scalar::random(&mut rng));

    // k256::Scalar::from_slice() not supported/implemented

    let repr4 = &data[96..(96 + usize::from(data[1] & 0x7f))];
    let str4 = std::str::from_utf8(&repr4).unwrap_or("123");
    let fe4 = k256::Scalar::from_str_vartime(str4).unwrap_or(k256::Scalar::random(&mut rng));

    // k256::Scalar::from_uint() not supported/implemented

    // k256::Scalar::from_u64() not supported/implemented

    let fe5 = k256::Scalar::from_u128(u128::from_le_bytes(data[168..184].try_into().unwrap()));

    let fe6 = k256::Scalar::generate_biased(&mut rng);

    let fe7 = k256::Scalar::generate_vartime(&mut rng);

    test_field(fe1 + fe2 + fe3, fe4 + fe5 + fe6, fe7);

    //
    //
    ///////////////////////////////////////////////////////////////////////////
    // Test p192
    let repr1 = &data[16..(16 + (p192::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe1 = p192::Scalar::from_bytes(repr1.try_into().unwrap());
    let fe1 = opt_fe1.unwrap_or(p192::Scalar::random(&mut rng));

    let fe2 = de::from_reader(&data[32..]).unwrap_or(p192::Scalar::random(&mut rng));

    let repr3 = &data[32..(32 + (p192::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe3 = p192::Scalar::from_repr(repr3.try_into().unwrap());
    let fe3 = opt_fe3.unwrap_or(p192::Scalar::random(&mut rng));

    let repr4 = &data[48..(48 + (p192::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe4 = p192::Scalar::from_repr_vartime(repr4.try_into().unwrap());
    let fe4 = opt_fe4.unwrap_or(p192::Scalar::random(&mut rng));

    let repr5 = &data[64..64 + usize::from(data[1] & 0x7f)];
    let opt_fe5 = p192::Scalar::from_slice(repr5);
    let fe5 = opt_fe5.unwrap_or(p192::Scalar::random(&mut rng));

    let repr6 = &data[96..(96 + usize::from(data[2] & 0x7f))];
    let str6 = std::str::from_utf8(&repr6).unwrap_or("123");
    let fe6 = p192::Scalar::from_str_vartime(str6).unwrap_or(p192::Scalar::random(&mut rng));

    let uint7 = p192::elliptic_curve::bigint::U192::from_le_slice(&data[128..152]);
    let fe7 = p192::Scalar::from_uint(uint7).unwrap_or(p192::Scalar::random(&mut rng));

    let fe8 = p192::Scalar::from_u64(u64::from_le_bytes(data[160..168].try_into().unwrap()));

    let fe9 = p192::Scalar::from_u128(u128::from_le_bytes(data[168..184].try_into().unwrap()));

    // p192::Scalar::generate_biased() not supported/implemented

    // p192::Scalar::generate_vartime() not supported/implemented

    test_field(fe1 + fe2 + fe3, fe4 + fe5 + fe6, fe7 + fe8 + fe9);

    //
    //
    ///////////////////////////////////////////////////////////////////////////
    // Test p224
    let repr1 = &data[16..(16 + (p224::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe1 = p224::Scalar::from_bytes(repr1.try_into().unwrap());
    let fe1 = opt_fe1.unwrap_or(p224::Scalar::random(&mut rng));

    let fe2 = de::from_reader(&data[32..]).unwrap_or(p224::Scalar::random(&mut rng));

    let repr3 = &data[32..(32 + (p224::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe3 = p224::Scalar::from_repr(repr3.try_into().unwrap());
    let fe3 = opt_fe3.unwrap_or(p224::Scalar::random(&mut rng));

    let repr4 = &data[48..(48 + (p224::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe4 = p224::Scalar::from_repr_vartime(repr4.try_into().unwrap());
    let fe4 = opt_fe4.unwrap_or(p224::Scalar::random(&mut rng));

    let repr5 = &data[64..64 + usize::from(data[1] & 0x7f)];
    let opt_fe5 = p224::Scalar::from_slice(repr5);
    let fe5 = opt_fe5.unwrap_or(p224::Scalar::random(&mut rng));

    let repr6 = &data[96..(96 + usize::from(data[2] & 0x7f))];
    let str6 = std::str::from_utf8(&repr6).unwrap_or("123");
    let fe6 = p224::Scalar::from_str_vartime(str6).unwrap_or(p224::Scalar::random(&mut rng));

    let uint7 = p224::elliptic_curve::bigint::U256::from_le_slice(&data[128..160]); // note U256 vs U224
    let fe7 = p224::Scalar::from_uint(uint7).unwrap_or(p224::Scalar::random(&mut rng));

    let fe8 = p224::Scalar::from_u64(u64::from_le_bytes(data[160..168].try_into().unwrap()));

    let fe9 = p224::Scalar::from_u128(u128::from_le_bytes(data[168..184].try_into().unwrap()));

    // p224::Scalar::generate_biased() not supported/implemented

    // p224::Scalar::generate_vartime() not supported/implemented

    test_field(fe1 + fe2 + fe3, fe4 + fe5 + fe6, fe7 + fe8 + fe9);

    //
    //
    ///////////////////////////////////////////////////////////////////////////
    // Test p256

    // p256::Scalar::from_bytes() not supported/implemented

    let fe2 = de::from_reader(&data[32..]).unwrap_or(p256::Scalar::random(&mut rng));

    let repr3 = &data[32..(32 + (p256::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe3 = p256::Scalar::from_repr(repr3.try_into().unwrap());
    let fe3 = opt_fe3.unwrap_or(p256::Scalar::random(&mut rng));

    let repr4 = &data[48..(48 + (p256::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe4 = p256::Scalar::from_repr_vartime(repr4.try_into().unwrap());
    let fe4 = opt_fe4.unwrap_or(p256::Scalar::random(&mut rng));

    // p256::Scalar::from_slice() not supported/implemented

    let repr6 = &data[96..(96 + usize::from(data[1] & 0x7f))];
    let str6 = std::str::from_utf8(&repr6).unwrap_or("123");
    let fe6 = p256::Scalar::from_str_vartime(str6).unwrap_or(p256::Scalar::random(&mut rng));

    // p256::Scalar::from_uint() not supported/implemented

    // p256::Scalar::from_u64() not supported/implemented

    let fe9 = p256::Scalar::from_u128(u128::from_le_bytes(data[168..184].try_into().unwrap()));

    // p256::Scalar::generate_biased() not supported/implemented

    // p256::Scalar::generate_vartime() not supported/implemented

    test_field(fe2 + fe3, fe4 + fe6, fe9);

    //
    //
    ///////////////////////////////////////////////////////////////////////////
    // Test p384
    let repr1 = &data[16..(16 + (p384::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe1 = p384::Scalar::from_bytes(repr1.try_into().unwrap());
    let fe1 = opt_fe1.unwrap_or(p384::Scalar::random(&mut rng));

    let fe2 = de::from_reader(&data[32..]).unwrap_or(p384::Scalar::random(&mut rng));

    let repr3 = &data[32..(32 + (p384::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe3 = p384::Scalar::from_repr(repr3.try_into().unwrap());
    let fe3 = opt_fe3.unwrap_or(p384::Scalar::random(&mut rng));

    let repr4 = &data[48..(48 + (p384::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe4 = p384::Scalar::from_repr_vartime(repr4.try_into().unwrap());
    let fe4 = opt_fe4.unwrap_or(p384::Scalar::random(&mut rng));

    let repr5 = &data[64..64 + usize::from(data[1] & 0x7f)];
    let opt_fe5 = p384::Scalar::from_slice(repr5);
    let fe5 = opt_fe5.unwrap_or(p384::Scalar::random(&mut rng));

    let repr6 = &data[96..(96 + usize::from(data[2] & 0x7f))];
    let str6 = std::str::from_utf8(&repr6).unwrap_or("123");
    let fe6 = p384::Scalar::from_str_vartime(str6).unwrap_or(p384::Scalar::random(&mut rng));

    let uint7 = p384::elliptic_curve::bigint::U384::from_le_slice(&data[128..176]);
    let fe7 = p384::Scalar::from_uint(uint7).unwrap_or(p384::Scalar::random(&mut rng));

    let fe8 = p384::Scalar::from_u64(u64::from_le_bytes(data[160..168].try_into().unwrap()));

    let fe9 = p384::Scalar::from_u128(u128::from_le_bytes(data[168..184].try_into().unwrap()));

    // p384::Scalar::generate_biased() not supported/implemented

    // p384::Scalar::generate_vartime() not supported/implemented

    test_field(fe1 + fe2 + fe3, fe4 + fe5 + fe6, fe7 + fe8 + fe9);

    //
    //
    ///////////////////////////////////////////////////////////////////////////
    // Test p521
    let repr1 = &data[16..(16 + (p521::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe1 = p521::Scalar::from_bytes(repr1.try_into().unwrap());
    let fe1 = opt_fe1.unwrap_or(p521::Scalar::random(&mut rng));

    let fe2 = de::from_reader(&data[32..]).unwrap_or(p521::Scalar::random(&mut rng));

    let repr3 = &data[32..(32 + (p521::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe3 = p521::Scalar::from_repr(repr3.try_into().unwrap());
    let fe3 = opt_fe3.unwrap_or(p521::Scalar::random(&mut rng));

    let repr4 = &data[48..(48 + (p521::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe4 = p521::Scalar::from_repr_vartime(repr4.try_into().unwrap());
    let fe4 = opt_fe4.unwrap_or(p521::Scalar::random(&mut rng));

    let repr5 = &data[64..64 + usize::from(data[1] & 0x7f)];
    let opt_fe5 = p521::Scalar::from_slice(repr5);
    let fe5 = opt_fe5.unwrap_or(p521::Scalar::random(&mut rng));

    let repr6 = &data[96..(96 + usize::from(data[2] & 0x7f))];
    let str6 = std::str::from_utf8(&repr6).unwrap_or("123");
    let fe6 = p521::Scalar::from_str_vartime(str6).unwrap_or(p521::Scalar::random(&mut rng));

    let uint7 = p521::elliptic_curve::bigint::U576::from_le_slice(&data[128..200]);
    let fe7 = p521::Scalar::from_uint(uint7).unwrap_or(p521::Scalar::random(&mut rng));

    let fe8 = p521::Scalar::from_u64(u64::from_le_bytes(data[160..168].try_into().unwrap()));

    let fe9 = p521::Scalar::from_u128(u128::from_le_bytes(data[168..184].try_into().unwrap()));

    // p521::Scalar::generate_biased() not supported/implemented

    // p521::Scalar::generate_vartime() not supported/implemented

    test_field(fe1 + fe2 + fe3, fe4 + fe5 + fe6, fe7 + fe8 + fe9);

    //
    //
    ///////////////////////////////////////////////////////////////////////////
    // Test sm2
    let repr1 = &data[16..(16 + (sm2::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe1 = sm2::Scalar::from_bytes(repr1.try_into().unwrap());
    let fe1 = opt_fe1.unwrap_or(sm2::Scalar::random(&mut rng));

    let fe2 = de::from_reader(&data[32..]).unwrap_or(sm2::Scalar::random(&mut rng));

    let repr3 = &data[32..(32 + (sm2::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe3 = sm2::Scalar::from_repr(repr3.try_into().unwrap());
    let fe3 = opt_fe3.unwrap_or(sm2::Scalar::random(&mut rng));

    let repr4 = &data[48..(48 + (sm2::Scalar::NUM_BITS + 7) / 8) as usize];
    let opt_fe4 = sm2::Scalar::from_repr_vartime(repr4.try_into().unwrap());
    let fe4 = opt_fe4.unwrap_or(sm2::Scalar::random(&mut rng));

    let repr5 = &data[64..64 + usize::from(data[1] & 0x7f)];
    let opt_fe5 = sm2::Scalar::from_slice(repr5);
    let fe5 = opt_fe5.unwrap_or(sm2::Scalar::random(&mut rng));

    let repr6 = &data[96..(96 + usize::from(data[1] & 0x7f))];
    let str6 = std::str::from_utf8(&repr6).unwrap_or("123");
    let fe6 = sm2::Scalar::from_str_vartime(str6).unwrap_or(sm2::Scalar::random(&mut rng));

    let uint7 = sm2::elliptic_curve::bigint::U256::from_le_slice(&data[128..160]);
    let fe7 = sm2::Scalar::from_uint(uint7).unwrap_or(sm2::Scalar::random(&mut rng));

    let fe8 = sm2::Scalar::from_u64(u64::from_le_bytes(data[160..168].try_into().unwrap()));

    let fe9 = sm2::Scalar::from_u128(u128::from_le_bytes(data[168..184].try_into().unwrap()));

    // sm2::Scalar::generate_biased() not supported/implemented

    // sm2::Scalar::generate_vartime() not supported/implemented

    test_field(fe1 + fe2 + fe3, fe4 + fe5 + fe6, fe7 + fe8 + fe9);
});
