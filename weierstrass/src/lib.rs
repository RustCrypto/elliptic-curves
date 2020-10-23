#![no_std]
pub use {generic_array, subtle};
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{
    self,
    B1, U1, U2,
    Unsigned,
    operator_aliases::{Sum, Quot, Double},
};
use rand_core::{RngCore, CryptoRng};
use core::ops::{Div, Add, Shl};

mod affine;
mod field;
mod scalar;
mod projective;
mod utils;

pub use affine::AffinePoint;
pub use field::FieldElement;
pub use scalar::Scalar;
pub use projective::ProjectivePoint;

// TODO: add cfgs for other word sizes
pub type Word = u64;
type DoubleWord = u128;
type WordWidth = typenum::U8;
fn random_word(mut rng: impl CryptoRng + RngCore) -> Word {
    rng.next_u64()
}


const WORD_WIDTH_BITS: usize = 8*WordWidth::USIZE;

pub type WordsLen<C> = Quot<<C as WeierstrassCurve>::Size, WordWidth>;
pub type Words<C> = GenericArray<Word, WordsLen<C>>;
pub type WordsBytesLen<C> = <C as WeierstrassCurve>::Size;
pub type WordsBytes<C> = GenericArray<u8, WordsBytesLen<C>>;

pub type WordsP1Len<C> = Sum<WordsLen<C>, U1>;
pub type WordsP1<C> = GenericArray<Word, WordsP1Len<C>>;

pub type DoubleWordsLen<C> = Double<WordsLen<C>>;
pub type DoubleWords<C> = GenericArray<Word, DoubleWordsLen<C>>;
pub type DoubleWordsBytesLen<C> = Double<<C as WeierstrassCurve>::Size>;
pub type DoubleWordsBytes<C> = GenericArray<u8, DoubleWordsBytesLen<C>>;

pub enum CurveKind {
    General,
    Minus3,
    Zero,
}

pub trait WeierstrassCurve
    where
        Self: Sized + Copy + Default,
        WordsLen<Self>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<Self>: ArrayLength<Word>,
        WordsP1Len<Self>: ArrayLength<Word>,
        WordsBytesLen<Self>: ArrayLength<u8>,
        Words<Self>: Copy,
{
    type Size: Unsigned + Div<WordWidth> + Div<U2> + Shl<B1>;

    const A: FieldElement<Self>;
    const B: FieldElement<Self>;
    /// 3*B
    const B3: FieldElement<Self>;
    const CURVE_KIND: CurveKind;
    const MODULUS_P: Words<Self>;
    /// p - 2
    const MODULUS_P_M2: Words<Self>;

    const MODULUS_Q: Words<Self>;
    /// q - 2
    const MODULUS_Q_M2: Words<Self>;
    /// floor(q/m), where `m` is a biggest representable number with given
    /// number of bits (i.e. `0xFFFF...FFFF`)
    const MODULUS_Q_REDUCE_N: usize;

    // we can't define GENERATOR, bacause `Choice` does not
    // support const construction
    const GENERATOR_X: FieldElement<Self>;
    const GENERATOR_Y: FieldElement<Self>;
    /// R = 2^Bits mod p
    const R: FieldElement<Self>;
    /// R2 = 2^(2*Bits) mod p
    const R2: FieldElement<Self>;

    /// MU = floor(2^512 / q)
    const MU: WordsP1<Self>;
    /// P*PT (mod 2^WORD_WIDTH) == -1
    const PT: Word;
}
