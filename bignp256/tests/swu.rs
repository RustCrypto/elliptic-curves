//! Test vectors from [STB 34.101.66-2014](https://apmi.bsu.by/assets/files/std/bake-spec191.pdf)
#![cfg(feature = "swu")]

use bignp256::BignP256;
use elliptic_curve::sec1::ToSec1Point;
use hex_literal::hex;

#[test]
fn test_bake_b4() {
    let secret = hex!(
        "AD1362A8 F9A3D42F BE1B8E6F 1C88AAD5"
        "0F51D913 47617C20 BD4AB07A EF4F26A1"
    );

    let point = BignP256::hash_secret_to_curve(&secret).expect("hash should succeed");

    let affine = point.to_affine();
    let encoded = affine.to_sec1_bytes();

    let expected = hex!(
        "014417D3355557317D2E2AB6D08754878D19E8D97B71FDC95DBB2A9B894D16D7"
        "7704A0B5CAA9CDA10791E4760671E1050DDEAB7083A7458447866ADB01473810"
    );

    assert_eq!(encoded[1..], expected);
}

#[test]
fn test_secret_length() {
    let secret = [0x42u8; 33];
    assert!(BignP256::hash_secret_to_curve(&secret[..32]).is_ok());
    assert!(BignP256::hash_secret_to_curve(&secret).is_err());
    assert!(BignP256::hash_secret_to_curve(&secret[..31]).is_err());
    assert!(BignP256::hash_secret_to_curve(&[]).is_err());
}
