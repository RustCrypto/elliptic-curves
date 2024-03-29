//! Test vectors for the secp224r1 group.

use hex_literal::hex;

/// Repeated addition of the generator.
///
/// These are the first 20 test vectors for P-224 from: <http://point-at-infinity.org/ecc/nisttv>
pub const ADD_TEST_VECTORS: &[([u8; 28], [u8; 28])] = &[
    (
        hex!("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"),
        hex!("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"),
    ),
    (
        hex!("706A46DC76DCB76798E60E6D89474788D16DC18032D268FD1A704FA6"),
        hex!("1C2B76A7BC25E7702A704FA986892849FCA629487ACF3709D2E4E8BB"),
    ),
    (
        hex!("DF1B1D66A551D0D31EFF822558B9D2CC75C2180279FE0D08FD896D04"),
        hex!("A3F7F03CADD0BE444C0AA56830130DDF77D317344E1AF3591981A925"),
    ),
    (
        hex!("AE99FEEBB5D26945B54892092A8AEE02912930FA41CD114E40447301"),
        hex!("0482580A0EC5BC47E88BC8C378632CD196CB3FA058A7114EB03054C9"),
    ),
    (
        hex!("31C49AE75BCE7807CDFF22055D94EE9021FEDBB5AB51C57526F011AA"),
        hex!("27E8BFF1745635EC5BA0C9F1C2EDE15414C6507D29FFE37E790A079B"),
    ),
    (
        hex!("1F2483F82572251FCA975FEA40DB821DF8AD82A3C002EE6C57112408"),
        hex!("89FAF0CCB750D99B553C574FAD7ECFB0438586EB3952AF5B4B153C7E"),
    ),
    (
        hex!("DB2F6BE630E246A5CF7D99B85194B123D487E2D466B94B24A03C3E28"),
        hex!("0F3A30085497F2F611EE2517B163EF8C53B715D18BB4E4808D02B963"),
    ),
    (
        hex!("858E6F9CC6C12C31F5DF124AA77767B05C8BC021BD683D2B55571550"),
        hex!("046DCD3EA5C43898C5C5FC4FDAC7DB39C2F02EBEE4E3541D1E78047A"),
    ),
    (
        hex!("2FDCCCFEE720A77EF6CB3BFBB447F9383117E3DAA4A07E36ED15F78D"),
        hex!("371732E4F41BF4F7883035E6A79FCEDC0E196EB07B48171697517463"),
    ),
    (
        hex!("AEA9E17A306517EB89152AA7096D2C381EC813C51AA880E7BEE2C0FD"),
        hex!("39BB30EAB337E0A521B6CBA1ABE4B2B3A3E524C14A3FE3EB116B655F"),
    ),
    (
        hex!("EF53B6294ACA431F0F3C22DC82EB9050324F1D88D377E716448E507C"),
        hex!("20B510004092E96636CFB7E32EFDED8265C266DFB754FA6D6491A6DA"),
    ),
    (
        hex!("6E31EE1DC137F81B056752E4DEAB1443A481033E9B4C93A3044F4F7A"),
        hex!("207DDDF0385BFDEAB6E9ACDA8DA06B3BBEF224A93AB1E9E036109D13"),
    ),
    (
        hex!("34E8E17A430E43289793C383FAC9774247B40E9EBD3366981FCFAECA"),
        hex!("252819F71C7FB7FBCB159BE337D37D3336D7FEB963724FDFB0ECB767"),
    ),
    (
        hex!("A53640C83DC208603DED83E4ECF758F24C357D7CF48088B2CE01E9FA"),
        hex!("D5814CD724199C4A5B974A43685FBF5B8BAC69459C9469BC8F23CCAF"),
    ),
    (
        hex!("BAA4D8635511A7D288AEBEEDD12CE529FF102C91F97F867E21916BF9"),
        hex!("979A5F4759F80F4FB4EC2E34F5566D595680A11735E7B61046127989"),
    ),
    (
        hex!("0B6EC4FE1777382404EF679997BA8D1CC5CD8E85349259F590C4C66D"),
        hex!("3399D464345906B11B00E363EF429221F2EC720D2F665D7DEAD5B482"),
    ),
    (
        hex!("B8357C3A6CEEF288310E17B8BFEFF9200846CA8C1942497C484403BC"),
        hex!("FF149EFA6606A6BD20EF7D1B06BD92F6904639DCE5174DB6CC554A26"),
    ),
    (
        hex!("C9FF61B040874C0568479216824A15EAB1A838A797D189746226E4CC"),
        hex!("EA98D60E5FFC9B8FCF999FAB1DF7E7EF7084F20DDB61BB045A6CE002"),
    ),
    (
        hex!("A1E81C04F30CE201C7C9ACE785ED44CC33B455A022F2ACDBC6CAE83C"),
        hex!("DCF1F6C3DB09C70ACC25391D492FE25B4A180BABD6CEA356C04719CD"),
    ),
    (
        hex!("FCC7F2B45DF1CD5A3C0C0731CA47A8AF75CFB0347E8354EEFE782455"),
        hex!("0D5D7110274CBA7CDEE90E1A8B0D394C376A5573DB6BE0BF2747F530"),
    ),
];

/// Scalar multiplication with the generator.
///
/// These are the test vectors for P-224 from <http://point-at-infinity.org/ecc/nisttv>
/// that are not part of [`ADD_TEST_VECTORS`].
pub const MUL_TEST_VECTORS: &[([u8; 28], [u8; 28], [u8; 28])] = &[
    (
        hex!("0000000000000000000000000000000000000000018ebbb95eed0e13"),
        hex!("61F077C6F62ED802DAD7C2F38F5C67F2CC453601E61BD076BB46179E"),
        hex!("2272F9E9F5933E70388EE652513443B5E289DD135DCC0D0299B225E4"),
    ),
    (
        hex!("00000000000000000000000000159d893d4cdd747246cdca43590e13"),
        hex!("029895F0AF496BFC62B6EF8D8A65C88C613949B03668AAB4F0429E35"),
        hex!("3EA6E53F9A841F2019EC24BDE1A75677AA9B5902E61081C01064DE93"),
    ),
    (
        hex!("41ffc1fffffe01fffc0003fffe0007c001fff00003fff07ffe0007c0"),
        hex!("AB689930BCAE4A4AA5F5CB085E823E8AE30FD365EB1DA4ABA9CF0379"),
        hex!("3345A121BBD233548AF0D210654EB40BAB788A03666419BE6FBD34E7"),
    ),
    (
        hex!("7fffffc03fffc003fffffc007fff00000000070000100000000e00ff"),
        hex!("BDB6A8817C1F89DA1C2F3DD8E97FEB4494F2ED302A4CE2BC7F5F4025"),
        hex!("4C7020D57C00411889462D77A5438BB4E97D177700BF7243A07F1680"),
    ),
    (
        hex!("7fffff0400000000fffff01ffff8ffffc00fffffffffc000000fffff"),
        hex!("D58B61AA41C32DD5EBA462647DBA75C5D67C83606C0AF2BD928446A9"),
        hex!("D24BA6A837BE0460DD107AE77725696D211446C5609B4595976B16BD"),
    ),
    (
        hex!("7fffffc000fffe3ffffc10000020003fffff000000fc00003fffffff"),
        hex!("DC9FA77978A005510980E929A1485F63716DF695D7A0C18BB518DF03"),
        hex!("EDE2B016F2DDFFC2A8C015B134928275CE09E5661B7AB14CE0D1D403"),
    ),
    (
        hex!("7001f0001c0001c000001ffffffc00001ffffff8000fc0000001fc00"),
        hex!("499D8B2829CFB879C901F7D85D357045EDAB55028824D0F05BA279BA"),
        hex!("BF929537B06E4015919639D94F57838FA33FC3D952598DCDBB44D638"),
    ),
    (
        hex!("000000001ffc000000fff030001f0000fffff0000038000000000002"),
        hex!("8246C999137186632C5F9EDDF3B1B0E1764C5E8BD0E0D8A554B9CB77"),
        hex!("E80ED8660BC1CB17AC7D845BE40A7A022D3306F116AE9F81FEA65947"),
    ),
    (
        hex!("7fff80000000000007ff0000000000000000fffe0800001ff0001fff"),
        hex!("6670C20AFCCEAEA672C97F75E2E9DD5C8460E54BB38538EBB4BD30EB"),
        hex!("F280D8008D07A4CAF54271F993527D46FF3FF46FD1190A3F1FAA4F74"),
    ),
    (
        hex!("00007fffffffffffffc00007ffffe0fffffffffffff800ffffffffff"),
        hex!("000ECA934247425CFD949B795CB5CE1EFF401550386E28D1A4C5A8EB"),
        hex!("D4C01040DBA19628931BC8855370317C722CBD9CA6156985F1C2E9CE"),
    ),
    (
        hex!("7ffffc03ff807fffe0001fffff800fff800001ffff0001fffffe001f"),
        hex!("EF353BF5C73CD551B96D596FBC9A67F16D61DD9FE56AF19DE1FBA9CD"),
        hex!("21771B9CDCE3E8430C09B3838BE70B48C21E15BC09EE1F2D7945B91F"),
    ),
    (
        hex!("00000007ffc07fffffff01fffe03fffe4000380007e0003ffe000000"),
        hex!("4036052A3091EB481046AD3289C95D3AC905CA0023DE2C03ECD451CF"),
        hex!("D768165A38A2B96F812586A9D59D4136035D9C853A5BF2E1C86A4993"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a29"),
        hex!("FCC7F2B45DF1CD5A3C0C0731CA47A8AF75CFB0347E8354EEFE782455"),
        hex!("F2A28EEFD8B345832116F1E574F2C6B2C895AA8C24941F40D8B80AD1"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a2a"),
        hex!("A1E81C04F30CE201C7C9ACE785ED44CC33B455A022F2ACDBC6CAE83C"),
        hex!("230E093C24F638F533DAC6E2B6D01DA3B5E7F45429315CA93FB8E634"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a2b"),
        hex!("C9FF61B040874C0568479216824A15EAB1A838A797D189746226E4CC"),
        hex!("156729F1A003647030666054E208180F8F7B0DF2249E44FBA5931FFF"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a2c"),
        hex!("B8357C3A6CEEF288310E17B8BFEFF9200846CA8C1942497C484403BC"),
        hex!("00EB610599F95942DF1082E4F9426D086FB9C6231AE8B24933AAB5DB"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a2d"),
        hex!("0B6EC4FE1777382404EF679997BA8D1CC5CD8E85349259F590C4C66D"),
        hex!("CC662B9BCBA6F94EE4FF1C9C10BD6DDD0D138DF2D099A282152A4B7F"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a2e"),
        hex!("BAA4D8635511A7D288AEBEEDD12CE529FF102C91F97F867E21916BF9"),
        hex!("6865A0B8A607F0B04B13D1CB0AA992A5A97F5EE8CA1849EFB9ED8678"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a2f"),
        hex!("A53640C83DC208603DED83E4ECF758F24C357D7CF48088B2CE01E9FA"),
        hex!("2A7EB328DBE663B5A468B5BC97A040A3745396BA636B964370DC3352"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a30"),
        hex!("34E8E17A430E43289793C383FAC9774247B40E9EBD3366981FCFAECA"),
        hex!("DAD7E608E380480434EA641CC82C82CBC92801469C8DB0204F13489A"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a31"),
        hex!("6E31EE1DC137F81B056752E4DEAB1443A481033E9B4C93A3044F4F7A"),
        hex!("DF82220FC7A4021549165325725F94C3410DDB56C54E161FC9EF62EE"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a32"),
        hex!("EF53B6294ACA431F0F3C22DC82EB9050324F1D88D377E716448E507C"),
        hex!("DF4AEFFFBF6D1699C930481CD102127C9A3D992048AB05929B6E5927"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a33"),
        hex!("AEA9E17A306517EB89152AA7096D2C381EC813C51AA880E7BEE2C0FD"),
        hex!("C644CF154CC81F5ADE49345E541B4D4B5C1ADB3EB5C01C14EE949AA2"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a34"),
        hex!("2FDCCCFEE720A77EF6CB3BFBB447F9383117E3DAA4A07E36ED15F78D"),
        hex!("C8E8CD1B0BE40B0877CFCA1958603122F1E6914F84B7E8E968AE8B9E"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a35"),
        hex!("858E6F9CC6C12C31F5DF124AA77767B05C8BC021BD683D2B55571550"),
        hex!("FB9232C15A3BC7673A3A03B0253824C53D0FD1411B1CABE2E187FB87"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a36"),
        hex!("DB2F6BE630E246A5CF7D99B85194B123D487E2D466B94B24A03C3E28"),
        hex!("F0C5CFF7AB680D09EE11DAE84E9C1072AC48EA2E744B1B7F72FD469E"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a37"),
        hex!("1F2483F82572251FCA975FEA40DB821DF8AD82A3C002EE6C57112408"),
        hex!("76050F3348AF2664AAC3A8B05281304EBC7A7914C6AD50A4B4EAC383"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a38"),
        hex!("31C49AE75BCE7807CDFF22055D94EE9021FEDBB5AB51C57526F011AA"),
        hex!("D817400E8BA9CA13A45F360E3D121EAAEB39AF82D6001C8186F5F866"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a39"),
        hex!("AE99FEEBB5D26945B54892092A8AEE02912930FA41CD114E40447301"),
        hex!("FB7DA7F5F13A43B81774373C879CD32D6934C05FA758EEB14FCFAB38"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3a"),
        hex!("DF1B1D66A551D0D31EFF822558B9D2CC75C2180279FE0D08FD896D04"),
        hex!("5C080FC3522F41BBB3F55A97CFECF21F882CE8CBB1E50CA6E67E56DC"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3b"),
        hex!("706A46DC76DCB76798E60E6D89474788D16DC18032D268FD1A704FA6"),
        hex!("E3D4895843DA188FD58FB0567976D7B50359D6B78530C8F62D1B1746"),
    ),
    (
        hex!("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3c"),
        hex!("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"),
        hex!("42C89C774A08DC04B3DD201932BC8A5EA5F8B89BBB2A7E667AFF81CD"),
    ),
];
