//! ECDSA/secp224r1 test vectors

use ecdsa_core::dev::TestVector;
use hex_literal::hex;

/// ECDSA/P-224 test vectors.
///
/// Adapted from the FIPS 186-4 ECDSA test vectors
/// (P-224, SHA-224, from `SigGen.txt` in `186-4ecdsatestvectors.zip`)
/// <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>
///
/// The `m` field contains a SHA-224 prehash of the `Msg` field in the
/// original `SigTen.txt`.

pub const ECDSA_TEST_VECTORS: &[TestVector; 15] = &[
    TestVector {
        m: &hex!("07eb2a50bf70eee87467600614a490e7600437d077ec651a27e65e67"),
        d: &hex!("16797b5c0c7ed5461e2ff1b88e6eafa03c0f46bf072000dfc830d615"),
        q_x: &hex!("605495756e6e88f1d07ae5f98787af9b4da8a641d1a9492a12174eab"),
        q_y: &hex!("f5cc733b17decc806ef1df861a42505d0af9ef7c3df3959b8dfc6669"),
        k: &hex!("d9a5a7328117f48b4b8dd8c17dae722e756b3ff64bd29a527137eec0"),
        r: &hex!("2fc2cff8cdd4866b1d74e45b07d333af46b7af0888049d0fdbc7b0d6"),
        s: &hex!("8d9cc4c8ea93e0fd9d6431b9a1fd99b88f281793396321b11dac41eb"),
    },
    TestVector {
        m: &hex!("bde0fbb390fb05d0b75df5bd0d0a4ea29516125f19830e3b0c93b641"),
        d: &hex!("cf020a1ff36c28511191482ed1e5259c60d383606c581948c3fbe2c5"),
        q_x: &hex!("fa21f85b99d3dc18c6d53351fbcb1e2d029c00fa7d1663a3dd94695e"),
        q_y: &hex!("e9e79578f8988b168edff1a8b34a5ed9598cc20acd1f0aed36715d88"),
        k: &hex!("c780d047454824af98677cf310117e5f9e99627d02414f136aed8e83"),
        r: &hex!("45145f06b566ec9fd0fee1b6c6551a4535c7a3bbfc0fede45f4f5038"),
        s: &hex!("7302dff12545b069cf27df49b26e4781270585463656f2834917c3ca"),
    },
    TestVector {
        m: &hex!("c2c03fe07e10538f6a38d5831b5dda9ce7478b3ed31323d60617dc95"),
        d: &hex!("dde6f173fa9f307d206ce46b4f02851ebce9638a989330249fd30b73"),
        q_x: &hex!("fc21a99b060afb0d9dbf3250ea3c4da10be94ce627a65874d8e4a630"),
        q_y: &hex!("e8373ab7190890326aac4aacca3eba89e15d1086a05434dd033fd3f3"),
        k: &hex!("6629366a156840477df4875cfba4f8faa809e394893e1f5525326d07"),
        r: &hex!("41f8e2b1ae5add7c24da8725a067585a3ad6d5a9ed9580beb226f23a"),
        s: &hex!("a5d71bff02dce997305dd337128046f36714398f4ef6647599712fae"),
    },
    TestVector {
        m: &hex!("5d52747226f37a5afcd94d1b95867c0111bcb34402dad12bee76c1b7"),
        d: &hex!("aeee9071248f077590ac647794b678ad371f8e0f1e14e9fbff49671e"),
        q_x: &hex!("fad0a34991bbf89982ad9cf89337b4bd2565f84d5bdd004289fc1cc3"),
        q_y: &hex!("5d8b6764f28c8163a12855a5c266efeb9388df4994b85a8b4f1bd3bc"),
        k: &hex!("1d35d027cd5a569e25c5768c48ed0c2b127c0f99cb4e52ea094fe689"),
        r: &hex!("2258184ef9f0fa698735379972ce9adf034af76017668bfcdab978de"),
        s: &hex!("866fb8e505dea6c909c2c9143ec869d1bac2282cf12366130ff2146c"),
    },
    TestVector {
        m: &hex!("a1ab56bd011b7e6c7e066f25333d08cf81ac0d9c1abfa09f004ab52f"),
        d: &hex!("29c204b2954e1406a015020f9d6b3d7c00658298feb2d17440b2c1a4"),
        q_x: &hex!("0e0fc15e775a75d45f872e5021b554cc0579da19125e1a49299c7630"),
        q_y: &hex!("cb64fe462d025ae2a1394746bdbf8251f7ca5a1d6bb13e0edf6b7b09"),
        k: &hex!("39547c10bb947d69f6c3af701f2528e011a1e80a6d04cc5a37466c02"),
        r: &hex!("86622c376d326cdf679bcabf8eb034bf49f0c188f3fc3afd0006325d"),
        s: &hex!("26613d3b33c70e635d7a998f254a5b15d2a3642bf321e8cff08f1e84"),
    },
    TestVector {
        m: &hex!("8ef4d8a368fad480bac518d625e97206adcafa87c52aef3d179cbfa9"),
        d: &hex!("8986a97b24be042a1547642f19678de4e281a68f1e794e343dabb131"),
        q_x: &hex!("2c070e68e8478341938f3d5026a1fe01e778cdffbebbdd7a4cd29209"),
        q_y: &hex!("cde21c9c7c6590ba300715a7adac278385a5175b6b4ea749c4b6a681"),
        k: &hex!("509712f9c0f3370f6a09154159975945f0107dd1cee7327c68eaa90b"),
        r: &hex!("57afda5139b180de96373c3d649700682e37efd56ae182335f081013"),
        s: &hex!("eb6cd58650cfb26dfdf21de32fa17464a6efc46830eedc16977342e6"),
    },
    TestVector {
        m: &hex!("28fabbac167f3d6a20c2f5a4bcee527c96be04bdd2c596f09d8fbab7"),
        d: &hex!("d9aa95e14cb34980cfddadddfa92bde1310acaff249f73ff5b09a974"),
        q_x: &hex!("3a0d4b8e5fad1ea1abb8d3fb742cd45cd0b76d136e5bbb33206ad120"),
        q_y: &hex!("c90ac83276b2fa3757b0f226cd7360a313bc96fd8329c76a7306cc7d"),
        k: &hex!("1f1739af68a3cee7c5f09e9e09d6485d9cd64cc4085bc2bc89795aaf"),
        r: &hex!("09bbdd003532d025d7c3204c00747cd52ecdfbc7ce3dde8ffbea23e1"),
        s: &hex!("1e745e80948779a5cc8dc5cb193beebb550ec9c2647f4948bf58ba7d"),
    },
    TestVector {
        m: &hex!("50dd74b5af40978e809cee3eb41195402ebb5056e4437f753f9a9d0d"),
        d: &hex!("380fb6154ad3d2e755a17df1f047f84712d4ec9e47d34d4054ea29a8"),
        q_x: &hex!("4772c27cca3348b1801ae87b01cb564c8cf9b81c23cc74468a907927"),
        q_y: &hex!("de9d253935b09617a1655c42d385bf48504e06fa386f5fa533a21dcb"),
        k: &hex!("14dbdffa326ba2f3d64f79ff966d9ee6c1aba0d51e9a8e59f5686dc1"),
        r: &hex!("ff6d52a09ca4c3b82da0440864d6717e1be0b50b6dcf5e1d74c0ff56"),
        s: &hex!("09490be77bc834c1efaa23410dcbf800e6fae40d62a737214c5a4418"),
    },
    TestVector {
        m: &hex!("9fee01807ab6c43a794abf6dcd6118915252ca7d3a31a1ff96b88a8d"),
        d: &hex!("6b98ec50d6b7f7ebc3a2183ff9388f75e924243827ddded8721186e2"),
        q_x: &hex!("1f249911b125348e6e0a473479105cc4b8cfb4fa32d897810fc69ffe"),
        q_y: &hex!("a17db03b9877d1b6328329061ea67aec5a38a884362e9e5b7d7642dc"),
        k: &hex!("ab3a41fedc77d1f96f3103cc7dce215bf45054a755cf101735fef503"),
        r: &hex!("70ccc0824542e296d17a79320d422f1edcf9253840dafe4427033f40"),
        s: &hex!("e3823699c355b61ab1894be3371765fae2b720405a7ce5e790ca8c00"),
    },
    TestVector {
        m: &hex!("c349032f84384b913bd5d19b9211ddce221d66a45e8a051878254117"),
        d: &hex!("8dda0ef4170bf73077d685e7709f6f747ced08eb4cde98ef06ab7bd7"),
        q_x: &hex!("7df67b960ee7a2cb62b22932457360ab1e046c1ec84b91ae65642003"),
        q_y: &hex!("c764ca9fc1b0cc2233fa57bdcfedaab0131fb7b5f557d6ca57f4afe0"),
        k: &hex!("9ef6ebd178a76402968bc8ec8b257174a04fb5e2d65c1ab34ab039b9"),
        r: &hex!("eef9e8428105704133e0f19636c89e570485e577786df2b09f99602a"),
        s: &hex!("8c01f0162891e4b9536243cb86a6e5c177323cca09777366caf2693c"),
    },
    TestVector {
        m: &hex!("63fe0d82cf5edf972e97316666a0914432e420f80b4f78ceb92afd1d"),
        d: &hex!("3dbe18cd88fa49febfcb60f0369a67b2379a466d906ac46a8b8d522b"),
        q_x: &hex!("b10150fd797eb870d377f1dbfa197f7d0f0ad29965af573ec13cc42a"),
        q_y: &hex!("17b63ccefbe27fb2a1139e5757b1082aeaa564f478c23a8f631eed5c"),
        k: &hex!("385803b262ee2ee875838b3a645a745d2e199ae112ef73a25d68d15f"),
        r: &hex!("1d293b697f297af77872582eb7f543dc250ec79ad453300d264a3b70"),
        s: &hex!("517a91b89c4859fcc10834242e710c5f0fed90ac938aa5ccdb7c66de"),
    },
    TestVector {
        m: &hex!("9b44ee16e576c50c0b6b37ac1437bf8f013a745615012451e54a12f2"),
        d: &hex!("c906b667f38c5135ea96c95722c713dbd125d61156a546f49ddaadc6"),
        q_x: &hex!("3c9b4ef1748a1925578658d3af51995b989ad760790157b25fe09826"),
        q_y: &hex!("55648f4ff4edfb899e9a13bd8d20f5c24b35dc6a6a4e42ed5983b4a0"),
        k: &hex!("b04d78d8ac40fefadb99f389a06d93f6b5b72198c1be02dbff6195f0"),
        r: &hex!("4bdd3c84647bad93dcaffd1b54eb87fc61a5704b19d7e6d756d11ad0"),
        s: &hex!("fdd81e5dca54158514f44ba2330271eff4c618330328451e2d93b9fb"),
    },
    TestVector {
        m: &hex!("3c89c15dee194b3223e7b53a8a5845d4873a12a2f1581d5413359828"),
        d: &hex!("3456745fbd51eac9b8095cd687b112f93d1b58352dbe02c66bb9b0cc"),
        q_x: &hex!("f0acdfbc75a748a4a0ac55281754b5c4a364b7d61c5390b334daae10"),
        q_y: &hex!("86587a6768f235bf523fbfc6e062c7401ac2b0242cfe4e5fb34f4057"),
        k: &hex!("854b20c61bcdf7a89959dbf0985880bb14b628f01c65ef4f6446f1c1"),
        r: &hex!("a2601fbb9fe89f39814735febb349143baa934170ffb91c6448a7823"),
        s: &hex!("bf90f9305616020a0e34ef30803fc15fa97dffc0948452bbf6cb5f66"),
    },
    TestVector {
        m: &hex!("2b7faf36fdf0e393ddeb9fc875dd99f670e3d538fd0462395ea06c8f"),
        d: &hex!("2c522af64baaca7b7a08044312f5e265ec6e09b2272f462cc705e4c3"),
        q_x: &hex!("5fad3c047074b5de1960247d0cc216b4e3fb7f3b9cd960575c8479fc"),
        q_y: &hex!("e4fc9c7f05ff0b040eb171fdd2a1dfe2572c564c2003a08c3179a422"),
        k: &hex!("9267763383f8db55eed5b1ca8f4937dc2e0ca6175066dc3d4a4586af"),
        r: &hex!("422e2e9fe535eb62f11f5f8ce87cf2e9ec65e61c06737cf6a0019ae6"),
        s: &hex!("116cfcf0965b7bc63aecade71d189d7e98a0434b124f2afbe3ccf0a9"),
    },
    TestVector {
        m: &hex!("5b24b6157c0d1edf3a40c22a0745d23bdb59379e5e5e776ed040288d"),
        d: &hex!("3eff7d07edda14e8beba397accfee060dbe2a41587a703bbe0a0b912"),
        q_x: &hex!("6dd84f4d66f362844e41a7913c40b4aad5fa9ba56bb44c2d2ed9efac"),
        q_y: &hex!("15f65ebcdf2fd9f8035385a330bdabec0f1cd9cc7bc31d2fadbe7cda"),
        k: &hex!("7bb48839d7717bab1fdde89bf4f7b4509d1c2c12510925e13655dead"),
        r: &hex!("127051d85326049115f307af2bc426f6c2d08f4774a0b496fb6982b1"),
        s: &hex!("6857e84418c1d1179333b4e5307e92abade0b74f7521ad78044bf597"),
    },
];
