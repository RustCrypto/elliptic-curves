//! ECDSA/secp224r1 test vectors

use ecdsa_core::dev::TestVector;
use hex_literal::hex;

/// ECDSA/P-521 test vectors.
///
/// Adapted from the FIPS 186-4 ECDSA test vectors
/// (P-521, SHA-521, from `SigGen.txt` in `186-4ecdsatestvectors.zip`)
/// <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>
///
/// The `m` field contains a SHA-512 prehash of the `Msg` field in the
/// original `SigTen.txt`.
pub const ECDSA_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        m: &hex!(
            "000065f83408092261bda599389df03382c5be01a81fe00a36f3f4bb6541263f801627c440e50809712b0cace7c217e6e5051af81de9bfec3204dcd63c4f9a741047"
        ),
        d: &hex!(
            "00f749d32704bc533ca82cef0acf103d8f4fba67f08d2678e515ed7db886267ffaf02fab0080dca2359b72f574ccc29a0f218c8655c0cccf9fee6c5e567aa14cb926"
        ),
        q_x: &hex!(
            "0061387fd6b95914e885f912edfbb5fb274655027f216c4091ca83e19336740fd81aedfe047f51b42bdf68161121013e0d55b117a14e4303f926c8debb77a7fdaad1"
        ),
        q_y: &hex!(
            "00e7d0c75c38626e895ca21526b9f9fdf84dcecb93f2b233390550d2b1463b7ee3f58df7346435ff0434199583c97c665a97f12f706f2357da4b40288def888e59e6"
        ),
        k: &hex!(
            "003af5ab6caa29a6de86a5bab9aa83c3b16a17ffcd52b5c60c769be3053cdddeac60812d12fecf46cfe1f3db9ac9dcf881fcec3f0aa733d4ecbb83c7593e864c6df1"
        ),
        r: &hex!(
            "004de826ea704ad10bc0f7538af8a3843f284f55c8b946af9235af5af74f2b76e099e4bc72fd79d28a380f8d4b4c919ac290d248c37983ba05aea42e2dd79fdd33e8"
        ),
        s: &hex!(
            "0087488c859a96fea266ea13bf6d114c429b163be97a57559086edb64aed4a18594b46fb9efc7fd25d8b2de8f09ca0587f54bd287299f47b2ff124aac566e8ee3b43"
        ),
    },
    TestVector {
        m: &hex!(
            "0000a6200971c6a289e2fcb80f78ec08a5079ea2675efd68bcab479552aa5bcb8edf3c993c79d7cebcc23c20e5af41723052b871134cc71d5c57206182a7068cc39b"
        ),
        d: &hex!(
            "01a4d2623a7d59c55f408331ba8d1523b94d6bf8ac83375ceb57a2b395a5bcf977cfc16234d4a97d6f6ee25a99aa5bff15ff535891bcb7ae849a583e01ac49e0e9b6"
        ),
        q_x: &hex!(
            "004d5c8afee038984d2ea96681ec0dccb6b52dfa4ee2e2a77a23c8cf43ef19905a34d6f5d8c5cf0981ed804d89d175b17d1a63522ceb1e785c0f5a1d2f3d15e51352"
        ),
        q_y: &hex!(
            "0014368b8e746807b2b68f3615cd78d761a464ddd7918fc8df51d225962fdf1e3dc243e265100ff0ec133359e332e44dd49afd8e5f38fe86133573432d33c02fa0a3"
        ),
        k: &hex!(
            "00bc2c0f37155859303de6fa539a39714e195c37c6ea826e224c8218584ae09cd0d1cc14d94d93f2d83c96e4ef68517fdb3f383da5404e5a426bfc5d424e253c181b"
        ),
        r: &hex!(
            "01a3c4a6386c4fb614fba2cb9e74201e1aaa0001aa931a2a939c92e04b8344535a20f53c6e3c69c75c2e5d2fe3549ed27e6713cb0f4a9a94f6189eb33bff7d453fce"
        ),
        s: &hex!(
            "016a997f81aa0bea2e1469c8c1dab7df02a8b2086ba482c43af04f2174831f2b1761658795adfbdd44190a9b06fe10e578987369f3a2eced147cff89d8c2818f7471"
        ),
    },
    TestVector {
        m: &hex!(
            "000046ff533622cc90321a3aeb077ec4db4fbf372c7a9db48b59de7c5d59e6314110676ba5491bd20d0f02774eef96fc2e88ca99857d21ef255184c93fb1ff4f01d3"
        ),
        d: &hex!(
            "014787f95fb1057a2f3867b8407e54abb91740c097dac5024be92d5d65666bb16e4879f3d3904d6eab269cf5e7b632ab3c5f342108d1d4230c30165fba3a1bf1c66f"
        ),
        q_x: &hex!(
            "00c2d540a7557f4530de35bbd94da8a6defbff783f54a65292f8f76341c996cea38795805a1b97174a9147a8644282e0d7040a6f83423ef2a0453248156393a1782e"
        ),
        q_y: &hex!(
            "0119f746c5df8cec24e4849ac1870d0d8594c799d2ceb6c3bdf891dfbd2242e7ea24d6aec3166214734acc4cbf4da8f71e2429c5c187b2b3a048527c861f58a9b97f"
        ),
        k: &hex!(
            "0186cd803e6e0c9925022e41cb68671adba3ead5548c2b1cd09348ab19612b7af3820fd14da5fe1d7b550ed1a3c8d2f30592cd7745a3c09ee7b5dcfa9ed31bdd0f1f"
        ),
        r: &hex!(
            "010ed3ab6d07a15dc3376494501c27ce5f78c8a2b30cc809d3f9c3bf1aef437e590ef66abae4e49065ead1af5f752ec145acfa98329f17bca9991a199579c41f9229"
        ),
        s: &hex!(
            "008c3457fe1f93d635bb52df9218bf3b49a7a345b8a8a988ac0a254340546752cddf02e6ce47eee58ea398fdc9130e55a4c09f5ae548c715f5bcd539f07a34034d78"
        ),
    },
    TestVector {
        m: &hex!(
            "00006b514f8d85145e30ced23b4b22c85d79ed2bfcfed5b6b2b03f7c730f1981d46d4dadd6699c28627d41c8684bac305b59eb1d9c966de184ae3d7470a801c99fd4"
        ),
        d: &hex!(
            "015807c101099c8d1d3f24b212af2c0ce525432d7779262eed0709275de9a1d8a8eeeadf2f909cf08b4720815bc1205a23ad1f825618cb78bde747acad8049ca9742"
        ),
        q_x: &hex!(
            "0160d7ea2e128ab3fabd1a3ad5455cb45e2f977c2354a1345d4ae0c7ce4e492fb9ff958eddc2aa61735e5c1971fa6c99beda0f424a20c3ce969380aaa52ef5f5daa8"
        ),
        q_y: &hex!(
            "014e4c83f90d196945fb4fe1e41913488aa53e24c1d2142d35a1eed69fed784c0ef44d71bc21afe0a0065b3b87069217a5abab4355cf8f4ceae5657cd4b9c8008f1f"
        ),
        k: &hex!(
            "0096731f8c52e72ffcc095dd2ee4eec3da13c628f570dba169b4a7460ab471149abdede0b63e4f96faf57eab809c7d2f203fd5ab406c7bd79869b7fae9c62f97c794"
        ),
        r: &hex!(
            "01e2bf98d1186d7bd3509f517c220de51c9200981e9b344b9fb0d36f34d969026c80311e7e73bb13789a99e0d59e82ebe0e9595d9747204c5f5550c30d934aa30c05"
        ),
        s: &hex!(
            "012fed45cc874dc3ed3a11dd70f7d5c61451fbea497dd63e226e10364e0718d3722c27c7b4e5027051d54b8f2a57fc58bc070a55b1a5877b0f388d768837ef2e9cec"
        ),
    },
    TestVector {
        m: &hex!(
            "000053c86e0b08b28e22131324f6bfad52984879ab09363d6b6c051aac78bf3568be3faeade6a2dda57dece4527abaa148326d3adbd2d725374bdac9ccb8ac39e51e"
        ),
        d: &hex!(
            "018692def0b516edcdd362f42669999cf27a65482f9358fcab312c6869e22ac469b82ca9036fe123935b8b9ed064acb347227a6e377fb156ec833dab9f170c2ac697"
        ),
        q_x: &hex!(
            "01ceee0be3293d8c0fc3e38a78df55e85e6b4bbce0b9995251f0ac55234140f82ae0a434b2bb41dc0aa5ecf950d4628f82c7f4f67651b804d55d844a02c1da6606f7"
        ),
        q_y: &hex!(
            "01f775eb6b3c5e43fc754052d1f7fc5b99137afc15d231a0199a702fc065c917e628a54e038cbfebe05c90988b65183b368a2061e5b5c1b025bbf2b748fae00ba297"
        ),
        k: &hex!(
            "0161cf5d37953e09e12dc0091dc35d5fb3754c5c874e474d2b4a4f1a90b870dff6d99fb156498516e25b9a6a0763170702bb8507fdba4a6131c7258f6ffc3add81fd"
        ),
        r: &hex!(
            "014dfa43046302b81fd9a34a454dea25ccb594ace8df4f9d98556ca5076bcd44b2a9775dfaca50282b2c8988868e5a31d9eb08e794016996942088d43ad3379eb9a1"
        ),
        s: &hex!(
            "0120be63bd97691f6258b5e78817f2dd6bf5a7bf79d01b8b1c3382860c4b00f89894c72f93a69f3119cb74c90b03e9ede27bd298b357b9616a7282d176f3899aaa24"
        ),
    },
    TestVector {
        m: &hex!(
            "0000a9e9a9cb1febc380a22c03bacd18f8c46761180badd2e58b94703bd82d5987c52baec418388bc3f1e6831a130c400b3c865c51b73514f5b0a9026d9e8da2e342"
        ),
        d: &hex!(
            "00a63f9cdefbccdd0d5c9630b309027fa139c31e39ca26686d76c22d4093a2a5e5ec4e2308ce43eb8e563187b5bd811cc6b626eace4063047ac0420c3fdcff5bdc04"
        ),
        q_x: &hex!(
            "014cab9759d4487987b8a00afd16d7199585b730fb0bfe63796272dde9135e7cb9e27cec51207c876d9214214b8c76f82e7363f5086902a577e1c50b4fbf35ce9966"
        ),
        q_y: &hex!(
            "01a83f0caa01ca2166e1206292342f47f358009e8b891d3cb817aec290e0cf2f47e7fc637e39dca03949391839684f76b94d34e5abc7bb750cb44486cce525eb0093"
        ),
        k: &hex!(
            "001e51fd877dbbcd2ab138fd215d508879298d10c7fcbdcc918802407088eb6ca0f18976a13f2c0a57867b0298512fc85515b209c4435e9ef30ab01ba649838bc7a0"
        ),
        r: &hex!(
            "011a1323f6132d85482d9b0f73be838d8f9e78647934f2570fededca7c234cc46aa1b97da5ac1b27b714f7a171dc4209cbb0d90e4f793c4c192dc039c31310d6d99b"
        ),
        s: &hex!(
            "00386a5a0fc55d36ca7231a9537fee6b9e51c2255363d9c9e7cb7185669b302660e23133eb21eb56d305d36e69a79f5b6fa25b46ec61b7f699e1e9e927fb0bceca06"
        ),
    },
    TestVector {
        m: &hex!(
            "00007e324819033de8f2bffded5472853c3e68f4872ed25db79636249aecc24242cc3ca229ce7bd6d74eac8ba32f779e7002095f5d452d0bf24b30e1ce2eb56bb413"
        ),
        d: &hex!(
            "0024f7d67dfc0d43a26cc7c19cb511d30a097a1e27e5efe29e9e76e43849af170fd9ad57d5b22b1c8840b59ebf562371871e12d2c1baefc1abaedc872ed5d2666ad6"
        ),
        q_x: &hex!(
            "009da1536154b46e3169265ccba2b4da9b4b06a7462a067c6909f6c0dd8e19a7bc2ac1a47763ec4be06c1bec57d28c55ee936cb19588cc1398fe4ea3bd07e6676b7f"
        ),
        q_y: &hex!(
            "014150cdf25da0925926422e1fd4dcfcffb05bdf8682c54d67a9bd438d21de5af43a15d979b320a847683b6d12ac1383a7183095e9da491c3b4a7c28874625e70f87"
        ),
        k: &hex!(
            "01c1308f31716d85294b3b5f1dc87d616093b7654907f55289499b419f38ceeb906d2c9fe4cc3d80c5a38c53f9739311b0b198111fede72ebde3b0d2bc4c2ef090d2"
        ),
        r: &hex!(
            "000dbf787ce07c453c6c6a67b0bf6850c8d6ca693a3e9818d7453487844c9048a7a2e48ff982b64eb9712461b26b5127c4dc57f9a6ad1e15d8cd56d4fd6da7186429"
        ),
        s: &hex!(
            "00c6f1c7774caf198fc189beb7e21ca92ceccc3f9875f0e2d07dc1d15bcc8f210b6dd376bf65bb6a454bf563d7f563c1041d62d6078828a57538b25ba54723170665"
        ),
    },
    TestVector {
        m: &hex!(
            "00004541f9a04b289cd3b13d31d2f513d9243b7e8c3a0cbd3e0c790892235a4d4569ef8aef62444ecc64608509e6ad082bf7cd060d172550faa158b2fd396aa1e37b"
        ),
        d: &hex!(
            "00349471460c205d836aa37dcd6c7322809e4e8ef81501e5da87284b267d843897746b33016f50a7b702964910361ed51d0afd9d8559a47f0b7c25b2bc952ce8ed9e"
        ),
        q_x: &hex!(
            "000bbd4e8a016b0c254e754f68f0f4ed081320d529ecdc7899cfb5a67dd04bc85b3aa6891a3ed2c9861ae76c3847d81780c23ad84153ea2042d7fd5d517a26ff3ce4"
        ),
        q_y: &hex!(
            "00645953afc3c1b3b74fdf503e7d3f982d7ee17611d60f8eb42a4bddbec2b67db1f09b54440c30b44e8071d404658285cb571462001218fc8c5e5b98b9fae28272e6"
        ),
        k: &hex!(
            "000eb2bd8bb56b9d2e97c51247baf734cc655c39e0bfda35375f0ac2fe82fad699bf1989577e24afb33c3868f91111e24fefe7dec802f3323ac013bec6c048fe5568"
        ),
        r: &hex!(
            "014bf63bdbc014aa352544bd1e83ede484807ed760619fa6bc38c4f8640840195e1f2f149b29903ca4b6934404fb1f7de5e39b1ea04dba42819c75dbef6a93ebe269"
        ),
        s: &hex!(
            "005d1bcf2295240ce4415042306abd494b4bda7cf36f2ee2931518d2454faa01c606be120b057062f2f3a174cb09c14f57ab6ef41cb3802140da22074d0e46f908d4"
        ),
    },
    TestVector {
        m: &hex!(
            "00007ec0906f9fbe0e001460852c0b6111b1cd01c9306c0c57a5e746d43f48f50ebb111551d04a90255b22690d79ea60e58bed88220d485daaf9b6431740bb499e39"
        ),
        d: &hex!(
            "007788d34758b20efc330c67483be3999d1d1a16fd0da81ed28895ebb35ee21093d37ea1ac808946c275c44454a216195eb3eb3aea1b53a329eca4eb82dd48c784f5"
        ),
        q_x: &hex!(
            "00157d80bd426f6c3cee903c24b73faa02e758607c3e102d6e643b7269c299684fdaba1acddb83ee686a60acca53cddb2fe976149205c8b8ab6ad1458bc00993cc43"
        ),
        q_y: &hex!(
            "016e33cbed05721b284dacc8c8fbe2d118c347fc2e2670e691d5d53daf6ef2dfec464a5fbf46f8efce81ac226915e11d43c11c8229fca2327815e1f8da5fe95021fc"
        ),
        k: &hex!(
            "00a73477264a9cc69d359464abb1ac098a18c0fb3ea35e4f2e6e1b060dab05bef1255d9f9c9b9fbb89712e5afe13745ae6fd5917a9aedb0f2860d03a0d8f113ea10c"
        ),
        r: &hex!(
            "007e315d8d958b8ce27eaf4f3782294341d2a46fb1457a60eb9fe93a9ae86f3764716c4f5f124bd6b114781ed59c3f24e18aa35c903211b2f2039d85862932987d68"
        ),
        s: &hex!(
            "01bcc1d211ebc120a97d465b603a1bb1e470109e0a55d2f1b5c597803931bd6d7718f010d7d289b31533e9fcef3d141974e5955bc7f0ee342b9cad05e29a3dded30e"
        ),
    },
    TestVector {
        m: &hex!(
            "00007230642b79eed2fd50f19f79f943d67d6ef609ec06c9adbb4b0a62126926080ecd474922d1af6c01f4c354affde016b284b13dbb3122555dea2a2e6ca2a357dc"
        ),
        d: &hex!(
            "01f98696772221e6cccd5569ed8aed3c435ee86a04689c7a64d20c30f6fe1c59cc10c6d2910261d30c3b96117a669e19cfe5b696b68feeacf61f6a3dea55e6e5837a"
        ),
        q_x: &hex!(
            "007002872c200e16d57e8e53f7bce6e9a7832c387f6f9c29c6b75526262c57bc2b56d63e9558c5761c1d62708357f586d3aab41c6a7ca3bf6c32d9c3ca40f9a2796a"
        ),
        q_y: &hex!(
            "01fe3e52472ef224fb38d5a0a14875b52c2f50b82b99eea98d826c77e6a9ccf798de5ffa92a0d65965f740c702a3027be66b9c844f1b2e96c134eb3fdf3edddcf11c"
        ),
        k: &hex!(
            "01a277cf0414c6adb621d1cc0311ec908401ce040c6687ed45a0cdf2910c42c9f1954a4572d8e659733d5e26cbd35e3260be40017b2f5d38ec42315f5c0b056c596d"
        ),
        r: &hex!(
            "00d732ba8b3e9c9e0a495249e152e5bee69d94e9ff012d001b140d4b5d082aa9df77e10b65f115a594a50114722db42fa5fbe457c5bd05e7ac7ee510aa68fe7b1e7f"
        ),
        s: &hex!(
            "0134ac5e1ee339727df80c35ff5b2891596dd14d6cfd137bafd50ab98e2c1ab4008a0bd03552618d217912a9ec502a902f2353e757c3b5776309f7f2cfebf913e9cd"
        ),
    },
    TestVector {
        m: &hex!(
            "0000d209f43006e29ada2b9fe840afdf5fe6b0abeeef5662acf3fbca7e6d1bf4538f7e860332ef6122020e70104b541c30c3c0581e2b1daa0d767271769d0f073133"
        ),
        d: &hex!(
            "013c3852a6bc8825b45fd7da1754078913d77f4e586216a6eb08b6f03adce7464f5dbc2bea0eb7b12d103870ef045f53d67e3600d7eba07aac5db03f71b64db1cceb"
        ),
        q_x: &hex!(
            "00c97a4ebcbbe701c9f7be127e87079edf479b76d3c14bfbee693e1638e5bff8d4705ac0c14597529dbe13356ca85eb03a418edfe144ce6cbf3533016d4efc29dbd4"
        ),
        q_y: &hex!(
            "011c75b7a8894ef64109ac2dea972e7fd5f79b75dab1bf9441a5b8b86f1dc1324426fa6cf4e7b973b44e3d0576c52e5c9edf8ce2fc18cb3c28742d44419f044667f8"
        ),
        k: &hex!(
            "01e25b86db041f21c2503d547e2b1b655f0b99d5b6c0e1cf2bdbd8a8c6a053f5d79d78c55b4ef75bff764a74edc920b35536e3c470b6f6b8fd53898f3bbc467539ef"
        ),
        r: &hex!(
            "01dce45ea592b34d016497882c48dc0c7afb1c8e0f81a051800d7ab8da9d237efd892207bc9401f1d30650f66af8d5349fc5b19727756270722d5a8adb0a49b72d0a"
        ),
        s: &hex!(
            "00b79ffcdc33e028b1ab894cb751ec792a69e3011b201a76f3b878655bc31efd1c0bf3b98aea2b14f262c19d142e008b98e890ebbf464d3b025764dd2f73c4251b1a"
        ),
    },
    TestVector {
        m: &hex!(
            "0000c992314e8d282d10554b2e6e8769e8b10f85686cccafb30e7db62beaad080e0da6b5cf7cd1fc5614df56705fb1a841987cb950101e2f66d55f3a285fc75829ff"
        ),
        d: &hex!(
            "01654eaa1f6eec7159ee2d36fb24d15d6d33a128f36c52e2437f7d1b5a44ea4fa965c0a26d0066f92c8b82bd136491e929686c8bde61b7c704daab54ed1e1bdf6b77"
        ),
        q_x: &hex!(
            "01f269692c47a55242bb08731ff920f4915bfcecf4d4431a8b487c90d08565272c52ca90c47397f7604bc643982e34d05178e979c2cff7ea1b9eaec18d69ca7382de"
        ),
        q_y: &hex!(
            "00750bdd866fba3e92c29599c002ac6f9e2bf39af8521b7b133f70510e9918a94d3c279edec97ab75ecda95e3dd7861af84c543371c055dc74eeeff7061726818327"
        ),
        k: &hex!(
            "01b7519becd00d750459d63a72f13318b6ac61b8c8e7077cf9415c9b4b924f35514c9c28a0fae43d06e31c670a873716156aa7bc744577d62476e038b116576a9e53"
        ),
        r: &hex!(
            "0183bddb46c249e868ef231a1ebd85d0773bf8105a092ab7d884d677a1e9b7d6014d6358c09538a99d9dca8f36f163ac1827df420c3f9360cc66900a9737a7f756f3"
        ),
        s: &hex!(
            "00d05ee3e64bac4e56d9d8bd511c8a43941e953cba4e5d83c0553acb87091ff54f3aad4d69d9f15e520a2551cc14f2c86bb45513fef0295e381a7635486bd3917b50"
        ),
    },
    TestVector {
        m: &hex!(
            "00006e14c91db5309a075fe69f6fe8ecd663a5ba7fab14770f96b05c22e1f631cde9e086c44335a25f63d5a43ddf57da899fcedbc4a3a4350ad2edd6f70c01bb051e"
        ),
        d: &hex!(
            "01cba5d561bf18656991eba9a1dde8bde547885ea1f0abe7f2837e569ca52f53df5e64e4a547c4f26458b5d9626ed6d702e5ab1dd585cf36a0c84f768fac946cfd4c"
        ),
        q_x: &hex!(
            "012857c2244fa04db3b73db4847927db63cce2fa6cb22724466d3e20bc950a9250a15eafd99f236a801e5271e8f90d9e8a97f37c12f7da65bce8a2c93bcd25526205"
        ),
        q_y: &hex!(
            "00f394e37c17d5b8e35b488fa05a607dbc74264965043a1fb60e92edc212296ae72d7d6fe2e3457e67be853664e1da64f57e44bd259076b3bb2b06a2c604fea1be9d"
        ),
        k: &hex!(
            "00e790238796fee7b5885dc0784c7041a4cc7ca4ba757d9f7906ad1fcbab5667e3734bc2309a48047442535ff89144b518f730ff55c0c67eeb4c880c2dfd2fb60d69"
        ),
        r: &hex!(
            "01d7ce382295a2a109064ea03f0ad8761dd60eefb9c207a20e3c5551e82ac6d2ee5922b3e9655a65ba6c359dcbf8fa843fbe87239a5c3e3eaecec0407d2fcdb687c2"
        ),
        s: &hex!(
            "0161963a6237b8955a8a756d8df5dbd303140bb90143b1da5f07b32f9cb64733dc6316080924733f1e2c81ade9d0be71b5b95b55666026a035a93ab3004d0bc0b19f"
        ),
    },
    TestVector {
        m: &hex!(
            "000026b4f562053f7aed8b7268e95eff336ac80a448fae52329d2771b138c9c7f70de936ef54158446afa72b0a27c2a73ca45dfa38a2ba2bf323d31aba499651128f"
        ),
        d: &hex!(
            "00972e7ff25adf8a032535e5b19463cfe306b90803bf27fabc6046ae0807d2312fbab85d1da61b80b2d5d48f4e5886f27fca050b84563aee1926ae6b2564cd756d63"
        ),
        q_x: &hex!(
            "01d7f1e9e610619daa9d2efa563610a371677fe8b58048fdc55a98a49970f6afa6649c516f9c72085ca3722aa595f45f2803402b01c832d28aac63d9941f1a25dfea"
        ),
        q_y: &hex!(
            "01571facce3fcfe733a8eef4e8305dfe99103a370f82b3f8d75085414f2592ad44969a2ef8196c8b9809f0eca2f7ddc71c47879e3f37a40b9fecf97992b97af29721"
        ),
        k: &hex!(
            "00517f6e4002479dc89e8cbb55b7c426d128776ca82cf81be8c1da9557178783f40e3d047db7e77867f1af030a51de470ee3128c22e9c2d642d71e4904ab5a76edfa"
        ),
        r: &hex!(
            "01c3262a3a3fb74fa5124b71a6c7f7b7e6d56738eabaf7666b372b299b0c99ee8a16be3df88dd955de093fc8c049f76ee83a4138cee41e5fe94755d27a52ee44032f"
        ),
        s: &hex!(
            "0072fd88bb1684c4ca9531748dfce4c161037fcd6ae5c2803b7117fb60d3db5df7df380591aaf3073a3031306b76f062dcc547ded23f6690293c34a710e7e9a226c3"
        ),
    },
    TestVector {
        m: &hex!(
            "0000ea13b25b80ec89ffa649a00ce85a494892f9fb7389df56eed084d670efb020c05508ac3f04872843c92a67ee5ea02e0445dad8495cd823ca16f5510d5863002b"
        ),
        d: &hex!(
            "01f0ec8da29295394f2f072672db014861be33bfd9f91349dad5566ff396bea055e53b1d61c8c4e5c9f6e129ed75a49f91cce1d5530ad4e78c2b793a63195eb9f0da"
        ),
        q_x: &hex!(
            "009ec1a3761fe3958073b9647f34202c5e8ca2428d056facc4f3fedc7077fa87f1d1eb30cc74f6e3ff3d3f82df2641cea1eb3ff1529e8a3866ae2055aacec0bf68c4"
        ),
        q_y: &hex!(
            "00bed0261b91f664c3ff53e337d8321cb988c3edc03b46754680097e5a8585245d80d0b7045c75a9c5be7f599d3b5eea08d828acb6294ae515a3df57a37f903ef62e"
        ),
        k: &hex!(
            "00ac3b6d61ebda99e23301fa198d686a13c0832af594b289c9a55669ce6d62011384769013748b68465527a597ed6858a06a99d50493562b3a7dbcee975ad34657d8"
        ),
        r: &hex!(
            "00cef3f4babe6f9875e5db28c27d6a197d607c3641a90f10c2cc2cb302ba658aa151dc76c507488b99f4b3c8bb404fb5c852f959273f412cbdd5e713c5e3f0e67f94"
        ),
        s: &hex!(
            "00097ed9e005416fc944e26bcc3661a09b35c128fcccdc2742739c8a301a338dd77d9d13571612a3b9524a6164b09fe73643bbc31447ee31ef44a490843e4e7db23f"
        ),
    },
];
