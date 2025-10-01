// This will be the module for Decaf over Ed448
// This is the newer version of the Decaf strategy, which looks simpler

pub mod affine;
mod ops;
pub mod points;

pub use affine::AffinePoint;
pub use points::{CompressedDecaf, DecafPoint};

// https://www.rfc-editor.org/rfc/rfc9496#name-group-elements-from-uniform-
#[test]
fn hash_to_curve() {
    use hex_literal::hex;

    const TEST_VECTORS: [TestVector; 7] = [
        TestVector {
            input: hex!(
                "cbb8c991fd2f0b7e1913462d6463e4fd2ce4ccdd28274dc2ca1f4165d5ee6cdccea57be3416e166fd06718a31af45a2f8e987e301be59ae6673e963001dbbda80df47014a21a26d6c7eb4ebe0312aa6fffb8d1b26bc62ca40ed51f8057a635a02c2b8c83f48fa6a2d70f58a1185902c0"
            ),
            output: hex!(
                "0c709c9607dbb01c94513358745b7c23953d03b33e39c7234e268d1d6e24f34014ccbc2216b965dd231d5327e591dc3c0e8844ccfd568848"
            ),
        },
        TestVector {
            input: hex!(
                "b6d8da654b13c3101d6634a231569e6b85961c3f4b460a08ac4a5857069576b64428676584baa45b97701be6d0b0ba18ac28d443403b45699ea0fbd1164f5893d39ad8f29e48e399aec5902508ea95e33bc1e9e4620489d684eb5c26bc1ad1e09aba61fabc2cdfee0b6b6862ffc8e55a"
            ),
            output: hex!(
                "76ab794e28ff1224c727fa1016bf7f1d329260b7218a39aea2fdb17d8bd9119017b093d641cedf74328c327184dc6f2a64bd90eddccfcdab"
            ),
        },
        TestVector {
            input: hex!(
                "36a69976c3e5d74e4904776993cbac27d10f25f5626dd45c51d15dcf7b3e6a5446a6649ec912a56895d6baa9dc395ce9e34b868d9fb2c1fc72eb6495702ea4f446c9b7a188a4e0826b1506b0747a6709f37988ff1aeb5e3788d5076ccbb01a4bc6623c92ff147a1e21b29cc3fdd0e0f4"
            ),
            output: hex!(
                "c8d7ac384143500e50890a1c25d643343accce584caf2544f9249b2bf4a6921082be0e7f3669bb5ec24535e6c45621e1f6dec676edd8b664"
            ),
        },
        TestVector {
            input: hex!(
                "d5938acbba432ecd5617c555a6a777734494f176259bff9dab844c81aadcf8f7abd1a9001d89c7008c1957272c1786a4293bb0ee7cb37cf3988e2513b14e1b75249a5343643d3c5e5545a0c1a2a4d3c685927c38bc5e5879d68745464e2589e000b31301f1dfb7471a4f1300d6fd0f99"
            ),
            output: hex!(
                "62beffc6b8ee11ccd79dbaac8f0252c750eb052b192f41eeecb12f2979713b563caf7d22588eca5e80995241ef963e7ad7cb7962f343a973"
            ),
        },
        TestVector {
            input: hex!(
                "4dec58199a35f531a5f0a9f71a53376d7b4bdd6bbd2904234a8ea65bbacbce2a542291378157a8f4be7b6a092672a34d85e473b26ccfbd4cdc6739783dc3f4f6ee3537b7aed81df898c7ea0ae89a15b5559596c2a5eeacf8b2b362f3db2940e3798b63203cae77c4683ebaed71533e51"
            ),
            output: hex!(
                "f4ccb31d263731ab88bed634304956d2603174c66da38742053fa37dd902346c3862155d68db63be87439e3d68758ad7268e239d39c4fd3b"
            ),
        },
        TestVector {
            input: hex!(
                "df2aa1536abb4acab26efa538ce07fd7bca921b13e17bc5ebcba7d1b6b733deda1d04c220f6b5ab35c61b6bcb15808251cab909a01465b8ae3fc770850c66246d5a9eae9e2877e0826e2b8dc1bc08009590bc6778a84e919fbd28e02a0f9c49b48dc689eb5d5d922dc01469968ee81b5"
            ),
            output: hex!(
                "7e79b00e8e0a76a67c0040f62713b8b8c6d6f05e9c6d02592e8a22ea896f5deacc7c7df5ed42beae6fedb9000285b482aa504e279fd49c32"
            ),
        },
        TestVector {
            input: hex!(
                "e9fb440282e07145f1f7f5ecf3c273212cd3d26b836b41b02f108431488e5e84bd15f2418b3d92a3380dd66a374645c2a995976a015632d36a6c2189f202fc766e1c82f50ad9189be190a1f0e8f9b9e69c9c18cc98fdd885608f68bf0fdedd7b894081a63f70016a8abf04953affbefa"
            ),
            output: hex!(
                "20b171cb16be977f15e013b9752cf86c54c631c4fc8cbf7c03c4d3ac9b8e8640e7b0e9300b987fe0ab5044669314f6ed1650ae037db853f1"
            ),
        },
    ];

    struct TestVector {
        input: [u8; 112],
        output: [u8; 56],
    }

    for TestVector { input, output } in TEST_VECTORS {
        let point = DecafPoint::from_uniform_bytes(&input);
        assert_eq!(point.compress().as_bytes(), output);
    }
}
