use generic_array::typenum::U256;
use crate::{WeirstrassCurve, Word, Words, WordsP1};
use crate::field::FieldElement;
use biguint_literal::hex_biguint;

#[derive(Copy, Default, Debug, Clone)]
pub struct GostTest256;

impl WeirstrassCurve for GostTest256 {
    type Bits = U256;

    const A: FieldElement<Self> = FieldElement { words: hex_biguint!("
        7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC983
    ") };
    const B: FieldElement<Self> = FieldElement { words: hex_biguint!("
        58DF983A171CD5AE20391ABE272C66AD004469B4541A2542807BBFA323A3952A
    ") };
    const MODULUS_P: Words<Self> = hex_biguint!("
        8000000000000000000000000000000000000000000000000000000000000431
    ");
    const MODULUS_P_M2: Words<Self> = hex_biguint!("
        800000000000000000000000000000000000000000000000000000000000042f
    ");
    const MODULUS_Q: Words<Self> = hex_biguint!("
        8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3
    ");
    const MODULUS_Q_M2: Words<Self> = hex_biguint!("
        8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B1
    ");
    const GENERATOR_X: FieldElement<Self> = FieldElement { words: hex_biguint!("
        7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF36D
    ") };
    const GENERATOR_Y: FieldElement<Self> = FieldElement { words: hex_biguint!("
        03F66B354AA3DAA467617A63E4B6DDE67CE5090AF69BF9AE9AF45A5A471125F5
    ") };
    const R: FieldElement<Self> = FieldElement { words: hex_biguint!("
        7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBCF
    ") };
    const R2: FieldElement<Self> = FieldElement { words: hex_biguint!("
        0000000000000000000000000000000000000000000000000000000000464584
    ") };
    const MU: WordsP1<Self> = hex_biguint!("
        0000000000000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFABC05D79DB5A27AACE98C0F9B14CC2941
    ");

    #[cfg(target_pointer_width = "64")]
    const PT: Word = 0xdbf9_51d5_883b_2b2f;
}