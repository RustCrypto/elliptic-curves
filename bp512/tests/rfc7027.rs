//! RFC 7027 Appendix A.3 test vectors for brainpoolP512r1.

use bp512::r1::{AffinePoint, ProjectivePoint, Scalar};
use elliptic_curve::{ff::PrimeField, ops::MulVartime, sec1::ToSec1Point};
use hex_literal::hex;

const D_A: Scalar = Scalar::from_hex_vartime(
    "16302ff0dbbb5a8d733dab7141c1b45acbc8715939677f6a56850a38bd87bd59b09e80279609ff333eb9d4c061231fb26f92eeb04982a5f1d1764cad57665422",
);
const D_B: Scalar = Scalar::from_hex_vartime(
    "230e18e1bcc88a362fa54e4ea3902009292f7f8033624fd471b5d8ace49d12cfabbc19963dab8e2f1eba00bffb29e4d72d13f2224562f405cb80503666b25429",
);

fn assert_coordinates(point: ProjectivePoint, expected_x: &[u8; 64], expected_y: &[u8; 64]) {
    let encoded = AffinePoint::from(point).to_sec1_point(false);
    assert_eq!(encoded.x().expect("uncompressed point has x"), expected_x);
    assert_eq!(encoded.y().expect("uncompressed point has y"), expected_y);
}

#[test]
fn public_keys_and_shared_secret() {
    assert_eq!(
        D_A.to_repr().as_slice(),
        &hex!(
            "16302ff0dbbb5a8d733dab7141c1b45acbc8715939677f6a56850a38bd87bd59"
            "b09e80279609ff333eb9d4c061231fb26f92eeb04982a5f1d1764cad57665422"
        )
    );

    assert_coordinates(
        ProjectivePoint::GENERATOR,
        &hex!(
            "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098e"
            "ff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822"
        ),
        &hex!(
            "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111"
            "b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892"
        ),
    );

    let q_a = ProjectivePoint::GENERATOR * D_A;
    let q_b = ProjectivePoint::GENERATOR * D_B;

    assert_eq!(
        ProjectivePoint::GENERATOR.mul_vartime(&D_A),
        q_a,
        "variable-time and constant-time multiplication must agree"
    );

    assert_coordinates(
        q_a,
        &hex!(
            "0a420517e406aac0acdce90fcd71487718d3b953efd7fbec5f7f27e28c614999"
            "9397e91e029e06457db2d3e640668b392c2a7e737a7f0bf04436d11640fd09fd"
        ),
        &hex!(
            "72e6882e8db28aad36237cd25d580db23783961c8dc52dfa2ec138ad472a0fce"
            "f3887cf62b623b2a87de5c588301ea3e5fc269b373b60724f5e82a6ad147fde7"
        ),
    );

    assert_coordinates(
        q_b,
        &hex!(
            "9d45f66de5d67e2e6db6e93a59ce0bb48106097ff78a081de781cdb31fce8ccb"
            "aaea8dd4320c4119f1e9cd437a2eab3731fa9668ab268d871deda55a5473199f"
        ),
        &hex!(
            "2fdc313095bcdd5fb3a91636f07a959c8e86b5636a1e930e8396049cb481961d"
            "365cc11453a06c719835475b12cb52fc3c383bce35e27ef194512b71876285fa"
        ),
    );

    assert_coordinates(
        q_a * D_B,
        &hex!(
            "a7927098655f1f9976fa50a9d566865dc530331846381c87256baf3226244b76"
            "d36403c024d7bbf0aa0803eaff405d3d24f11a9b5c0bef679fe1454b21c4cd1f"
        ),
        &hex!(
            "7db71c3def63212841c463e881bdcf055523bd368240e6c3143bd8def8b3b322"
            "3b95e0f53082ff5e412f4222537a43df1c6d25729ddb51620a832be6a26680a2"
        ),
    );
}
