use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{
    self,
    U1, U4, U8,
    Unsigned,
    operator_aliases::{Sum, Quot},
};
use rand_core::{RngCore, CryptoRng};
use core::ops::{Div, Add};

mod affine;
mod field;
mod scalar;
mod projective;
mod utils;

mod gost_test256;

pub use affine::AffinePoint;
pub use field::FieldElement;
pub use scalar::Scalar;
pub use projective::ProjectivePoint;
pub use gost_test256::GostTest256;

// TODO: add cfgs for other word sizes
type Word = u64;
type DoubleWord = u128;
type WordWidth = typenum::U64;
/// Divisor for getting number of words in the wider buffer, it's equal
/// to `Quot<WordWidth, U2>`, but to simplify trait bounds we use an explicit
/// value
type WideWordsDiv = typenum::U32;
fn random_word(mut rng: impl CryptoRng + RngCore) -> Word {
    rng.next_u64()
}

type WordsLen<C> = Quot<<C as WeirstrassCurve>::Bits, WordWidth>;
type Words<C> = GenericArray<Word, WordsLen<C>>;
type WordsBytesLen<C> = Quot<<C as WeirstrassCurve>::Bits, U8>;
type WordsBytes<C> = GenericArray<u8, WordsBytesLen<C>>;

type WordsP1Len<C> = Sum<WordsLen<C>, U1>;
type WordsP1<C> = GenericArray<Word, WordsP1Len<C>>;

type WideWordsLen<C> = Quot<<C as WeirstrassCurve>::Bits, WideWordsDiv>;
type WideWords<C> = GenericArray<Word, WideWordsLen<C>>;

pub trait WeirstrassCurve
    where
        Self: Sized + Copy + Default,
        WordsLen<Self>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<Self>: ArrayLength<Word>,
        WordsP1Len<Self>: ArrayLength<Word>,
        WordsBytesLen<Self>: ArrayLength<u8>,
        Words<Self>: Copy,
{
    type Bits: Unsigned + Div<WordWidth> + Div<WideWordsDiv> + Div<U8> + Div<U4>;

    const A: FieldElement<Self>;
    const B: FieldElement<Self>;
    const MODULUS_P: Words<Self>;
    /// p - 2
    const MODULUS_P_M2: Words<Self>;
    const MODULUS_Q: Words<Self>;
    /// q - 2
    const MODULUS_Q_M2: Words<Self>;

    // we can't define GENERATOR, bacause `Choice` does not
    // support const construction
    const GENERATOR_X: FieldElement<Self>;
    const GENERATOR_Y: FieldElement<Self>;
    /// R = 2^Bits mod p
    const R: FieldElement<Self>;
    /// R2 = 2^(2*Bits) mod p
    const R2: FieldElement<Self>;

    /// P*PT (mod 2^WORD_WIDTH) == -1
    const PT: Word;

    /// MU = floor(2^512 / n)
    const MU: WordsP1<Self>;
}

