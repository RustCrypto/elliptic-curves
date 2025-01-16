#![no_main]
// Targets: bign256, k256, p192, p224, p256, p384, p521, sm2
// bp256 and bp384 are under construction
use ciborium::de;
use elliptic_curve::{group::GroupEncoding, Field, Group};
use libfuzzer_sys::fuzz_target;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

static mut I: u64 = 0;

fn test_group<G: Group>(p1: G, p2: G, s: G::Scalar) {
    unsafe {
        I = I.wrapping_add(1);
        // Our goal is primarily to test deserialization, so we skip 6 of every 7 group tests
        if I % 7 != 0 {
            return;
        }
    }

    // Test point arithmetic
    let sum = p1 + p2;
    let scalar_mul = p1 * s;

    // Test that addition and doubling are consistent
    assert!(p1.double() == p1 + p1 - G::identity());

    // Test that negation works correctly
    assert!(sum + (-sum) == G::identity());

    // Test scalar multiplication distributive property
    assert!(scalar_mul + scalar_mul == p1 * (s + s));
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 160 {
        return;
    }

    let mut rng = ChaChaRng::from_seed(data[0..32].try_into().unwrap());

    //
    // Test bign256

    let len = bign256::ProjectivePoint::random(&mut rng).to_bytes().len(); //affine and projective
    let pp1 = bign256::ProjectivePoint::from_bytes(&data[16..16 + len].try_into().unwrap())
        .unwrap_or_else(|| bign256::ProjectivePoint::random(&mut rng));
    let ap1 = bign256::AffinePoint::from(pp1);
    let ap2 = bign256::AffinePoint::from_bytes(&data[32..32 + len].try_into().unwrap())
        .unwrap_or_else(|| bign256::AffinePoint::GENERATOR);
    let ap3 = de::from_reader(&data[48..48 + usize::from(data[3] & 0x3f)])
        .unwrap_or(bign256::AffinePoint::GENERATOR);
    let ap4 = bign256::AffinePoint::try_from(bign256::EncodedPoint::from_affine_coordinates(
        &data[24..24 + len - 1].try_into().unwrap(),
        &data[40..40 + len - 1].try_into().unwrap(),
        true,
    ))
    .unwrap_or(bign256::AffinePoint::GENERATOR);
    let ap5 = bign256::AffinePoint::try_from(
        bign256::EncodedPoint::from_bytes(&data[64..64 + usize::from(data[4] & 0x3f)])
            .unwrap_or_else(|_| bign256::EncodedPoint::identity()),
    )
    .unwrap_or(bign256::AffinePoint::GENERATOR);
    let pp2 = bign256::ProjectivePoint::from(ap2);
    let scalar = bign256::Scalar::from_slice(&data[96..96 + len])
        .unwrap_or_else(|_| bign256::Scalar::random(&mut rng));

    test_group(pp1 + pp2, pp1 + ap1 + ap2 + ap3 + ap4 + ap5, scalar);

    //
    // Test k256 (secp256k1)

    let len = k256::ProjectivePoint::random(&mut rng).to_bytes().len(); //affine and projective
    let pp1 = k256::ProjectivePoint::from_bytes(&data[16..16 + len].try_into().unwrap())
        .unwrap_or_else(|| k256::ProjectivePoint::random(&mut rng));
    let ap1 = k256::AffinePoint::from(pp1);
    let ap2 = k256::AffinePoint::from_bytes(&data[32..32 + len].try_into().unwrap())
        .unwrap_or_else(|| k256::AffinePoint::GENERATOR);
    let ap3 = de::from_reader(&data[48..48 + usize::from(data[3] & 0x3f)])
        .unwrap_or(k256::AffinePoint::GENERATOR);
    let ap4 = k256::AffinePoint::try_from(k256::EncodedPoint::from_affine_coordinates(
        &data[24..24 + len - 1].try_into().unwrap(),
        &data[40..40 + len - 1].try_into().unwrap(),
        true,
    ))
    .unwrap_or(k256::AffinePoint::GENERATOR);
    let ap5 = k256::AffinePoint::try_from(
        k256::EncodedPoint::from_bytes(&data[64..64 + usize::from(data[4] & 0x3f)])
            .unwrap_or_else(|_| k256::EncodedPoint::identity()),
    )
    .unwrap_or(k256::AffinePoint::GENERATOR);
    let pp2 = k256::ProjectivePoint::from(ap2);
    let scalar = de::from_reader(&data[96..96 + usize::from(data[5] & 0x3f)])
        .unwrap_or(k256::Scalar::random(&mut rng));

    test_group(pp1 + pp2, pp1 + ap1 + ap2 + ap3 + ap4 + ap5, scalar);

    //
    // Test p192

    let len = p192::ProjectivePoint::random(&mut rng).to_bytes().len(); //affine and projective
    let pp1 = p192::ProjectivePoint::from_bytes(&data[16..16 + len].try_into().unwrap())
        .unwrap_or_else(|| p192::ProjectivePoint::random(&mut rng));
    let ap1 = p192::AffinePoint::from(pp1);
    let ap2 = p192::AffinePoint::from_bytes(&data[32..32 + len].try_into().unwrap())
        .unwrap_or_else(|| p192::AffinePoint::GENERATOR);
    let ap3 = de::from_reader(&data[48..48 + usize::from(data[3] & 0x3f)])
        .unwrap_or(p192::AffinePoint::GENERATOR);
    let ap4 = p192::AffinePoint::try_from(p192::EncodedPoint::from_affine_coordinates(
        &data[24..24 + len - 1].try_into().unwrap(),
        &data[40..40 + len - 1].try_into().unwrap(),
        true,
    ))
    .unwrap_or(p192::AffinePoint::GENERATOR);
    let ap5 = p192::AffinePoint::try_from(
        p192::EncodedPoint::from_bytes(&data[64..64 + usize::from(data[4] & 0x3f)])
            .unwrap_or_else(|_| p192::EncodedPoint::identity()),
    )
    .unwrap_or(p192::AffinePoint::GENERATOR);
    let pp2 = p192::ProjectivePoint::from(ap2);
    let scalar = de::from_reader(&data[96..96 + usize::from(data[5] & 0x3f)])
        .unwrap_or(p192::Scalar::random(&mut rng));

    test_group(pp1 + pp2, pp1 + ap1 + ap2 + ap3 + ap4 + ap5, scalar);

    //
    // Test p224

    let len = p224::ProjectivePoint::random(&mut rng).to_bytes().len(); //affine and projective
    let pp1 = p224::ProjectivePoint::from_bytes(&data[16..16 + len].try_into().unwrap())
        .unwrap_or_else(|| p224::ProjectivePoint::random(&mut rng));
    let ap1 = p224::AffinePoint::from(pp1);
    let ap2 = p224::AffinePoint::from_bytes(&data[32..32 + len].try_into().unwrap())
        .unwrap_or_else(|| p224::AffinePoint::GENERATOR);
    let ap3 = de::from_reader(&data[48..48 + usize::from(data[3] & 0x3f)])
        .unwrap_or(p224::AffinePoint::GENERATOR);
    let ap4 = p224::AffinePoint::try_from(p224::EncodedPoint::from_affine_coordinates(
        &data[24..24 + len - 1].try_into().unwrap(),
        &data[40..40 + len - 1].try_into().unwrap(),
        true,
    ))
    .unwrap_or(p224::AffinePoint::GENERATOR);
    let ap5 = p224::AffinePoint::try_from(
        p224::EncodedPoint::from_bytes(&data[64..64 + usize::from(data[4] & 0x3f)])
            .unwrap_or_else(|_| p224::EncodedPoint::identity()),
    )
    .unwrap_or(p224::AffinePoint::GENERATOR);
    let pp2 = p224::ProjectivePoint::from(ap2);
    let scalar = de::from_reader(&data[96..96 + usize::from(data[5] & 0x3f)])
        .unwrap_or(p224::Scalar::random(&mut rng));

    test_group(pp1 + pp2, pp1 + ap1 + ap2 + ap3 + ap4 + ap5, scalar);

    //
    // Test p256
    let len = p256::ProjectivePoint::random(&mut rng).to_bytes().len(); //affine and projective
    let pp1 = p256::ProjectivePoint::from_bytes(&data[16..16 + len].try_into().unwrap())
        .unwrap_or_else(|| p256::ProjectivePoint::random(&mut rng));
    let ap1 = p256::AffinePoint::from(pp1);
    let ap2 = p256::AffinePoint::from_bytes(&data[32..32 + len].try_into().unwrap())
        .unwrap_or_else(|| p256::AffinePoint::GENERATOR);
    let ap3 = de::from_reader(&data[48..48 + usize::from(data[3] & 0x3f)])
        .unwrap_or(p256::AffinePoint::GENERATOR);
    let ap4 = p256::AffinePoint::try_from(p256::EncodedPoint::from_affine_coordinates(
        &data[24..24 + len - 1].try_into().unwrap(),
        &data[40..40 + len - 1].try_into().unwrap(),
        true,
    ))
    .unwrap_or(p256::AffinePoint::GENERATOR);
    let ap5 = p256::AffinePoint::try_from(
        p256::EncodedPoint::from_bytes(&data[64..64 + usize::from(data[4] & 0x3f)])
            .unwrap_or_else(|_| p256::EncodedPoint::identity()),
    )
    .unwrap_or(p256::AffinePoint::GENERATOR);
    let pp2 = p256::ProjectivePoint::from(ap2);
    let scalar = de::from_reader(&data[96..96 + usize::from(data[5] & 0x3f)])
        .unwrap_or(p256::Scalar::random(&mut rng));

    test_group(pp1 + pp2, pp1 + ap1 + ap2 + ap3 + ap4 + ap5, scalar);

    // Test p384
    let len = p384::ProjectivePoint::random(&mut rng).to_bytes().len(); //affine and projective
    let pp1 = p384::ProjectivePoint::from_bytes(&data[16..16 + len].try_into().unwrap())
        .unwrap_or_else(|| p384::ProjectivePoint::random(&mut rng));
    let ap1 = p384::AffinePoint::from(pp1);
    let ap2 = p384::AffinePoint::from_bytes(&data[32..32 + len].try_into().unwrap())
        .unwrap_or_else(|| p384::AffinePoint::GENERATOR);
    let ap3 = de::from_reader(&data[48..48 + usize::from(data[3] & 0x3f)])
        .unwrap_or(p384::AffinePoint::GENERATOR);
    let ap4 = p384::AffinePoint::try_from(p384::EncodedPoint::from_affine_coordinates(
        &data[24..24 + len - 1].try_into().unwrap(),
        &data[40..40 + len - 1].try_into().unwrap(),
        true,
    ))
    .unwrap_or(p384::AffinePoint::GENERATOR);
    let ap5 = p384::AffinePoint::try_from(
        p384::EncodedPoint::from_bytes(&data[64..64 + usize::from(data[4] & 0x3f)])
            .unwrap_or_else(|_| p384::EncodedPoint::identity()),
    )
    .unwrap_or(p384::AffinePoint::GENERATOR);
    let pp2 = p384::ProjectivePoint::from(ap2);
    let scalar = de::from_reader(&data[96..96 + usize::from(data[5] & 0x3f)])
        .unwrap_or(p384::Scalar::random(&mut rng));

    test_group(pp1 + pp2, pp1 + ap1 + ap2 + ap3 + ap4 + ap5, scalar);

    // Test p521
    let len = p521::ProjectivePoint::random(&mut rng).to_bytes().len(); //affine and projective
    let pp1 = p521::ProjectivePoint::from_bytes(&data[16..16 + len].try_into().unwrap())
        .unwrap_or_else(|| p521::ProjectivePoint::random(&mut rng));
    let ap1 = p521::AffinePoint::from(pp1);
    let ap2 = p521::AffinePoint::from_bytes(&data[32..32 + len].try_into().unwrap())
        .unwrap_or_else(|| p521::AffinePoint::GENERATOR);
    let ap3 = de::from_reader(&data[48..48 + usize::from(data[3] & 0x3f)])
        .unwrap_or(p521::AffinePoint::GENERATOR);
    let ap4 = p521::AffinePoint::try_from(p521::EncodedPoint::from_affine_coordinates(
        &data[24..24 + len - 1].try_into().unwrap(),
        &data[40..40 + len - 1].try_into().unwrap(),
        true,
    ))
    .unwrap_or(p521::AffinePoint::GENERATOR);
    let ap5 = p521::AffinePoint::try_from(
        p521::EncodedPoint::from_bytes(&data[64..64 + usize::from(data[4] & 0x3f)])
            .unwrap_or_else(|_| p521::EncodedPoint::identity()),
    )
    .unwrap_or(p521::AffinePoint::GENERATOR);
    let pp2 = p521::ProjectivePoint::from(ap2);
    let scalar = de::from_reader(&data[96..96 + usize::from(data[5] & 0x3f)])
        .unwrap_or(p521::Scalar::random(&mut rng));

    test_group(pp1 + pp2, pp1 + ap1 + ap2 + ap3 + ap4 + ap5, scalar);

    // Test sm2
    let len = sm2::ProjectivePoint::random(&mut rng).to_bytes().len(); //affine and projective
    let pp1 = sm2::ProjectivePoint::from_bytes(&data[16..16 + len].try_into().unwrap())
        .unwrap_or_else(|| sm2::ProjectivePoint::random(&mut rng));
    let ap1 = sm2::AffinePoint::from(pp1);
    let ap2 = sm2::AffinePoint::from_bytes(&data[32..32 + len].try_into().unwrap())
        .unwrap_or_else(|| sm2::AffinePoint::GENERATOR);
    let ap3 = de::from_reader(&data[48..48 + usize::from(data[3] & 0x3f)])
        .unwrap_or(sm2::AffinePoint::GENERATOR);
    let ap4 = sm2::AffinePoint::try_from(sm2::EncodedPoint::from_affine_coordinates(
        &data[24..24 + len - 1].try_into().unwrap(),
        &data[40..40 + len - 1].try_into().unwrap(),
        true,
    ))
    .unwrap_or(sm2::AffinePoint::GENERATOR);
    let ap5 = sm2::AffinePoint::try_from(
        sm2::EncodedPoint::from_bytes(&data[64..64 + usize::from(data[4] & 0x3f)])
            .unwrap_or_else(|_| sm2::EncodedPoint::identity()),
    )
    .unwrap_or(sm2::AffinePoint::GENERATOR);
    let pp2 = sm2::ProjectivePoint::from(ap2);
    let scalar = de::from_reader(&data[96..96 + usize::from(data[5] & 0x3f)])
        .unwrap_or(sm2::Scalar::random(&mut rng));

    test_group(pp1 + pp2, pp1 + ap1 + ap2 + ap3 + ap4 + ap5, scalar);
});
