use core::ops::{Mul, Neg, Shl};
use generic_array::{ArrayLength, typenum::{B1, U1}};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use core::ops::Add;

use crate::{
    WeirstrassCurve, Word, 
    Words, WordsLen,
    DoubleWordsLen,
    WordsBytesLen,
    WordsP1Len,
};
use crate::scalar::Scalar;
use crate::projective::ProjectivePoint;
use crate::field::FieldElement;

#[derive(Clone, Copy)]
pub struct AffinePoint<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    pub x: FieldElement<C>,
    pub y: FieldElement<C>,
    pub infinity: Choice,
}

impl<C> AffinePoint<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    /// Returns the base point
    pub fn generator() -> Self {
        Self {
            x: C::GENERATOR_X,
            y: C::GENERATOR_Y,
            infinity: Choice::from(0),
        }
    }

    /// Returns the identity of the group: the point at infinity.
    pub fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            infinity: Choice::from(1),
        }
    }

    /// Is this point the identity point?
    pub fn is_identity(&self) -> Choice {
        self.infinity
    }
}

impl<C> ConditionallySelectable for AffinePoint<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        AffinePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            infinity: Choice::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl<C> ConstantTimeEq for AffinePoint<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.ct_eq(&other.x)
            & self.y.ct_eq(&other.y)
            & self.infinity.ct_eq(&other.infinity)
    }
}

impl<C> PartialEq for AffinePoint<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C> Eq for AffinePoint<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{}

impl<C> Mul<Scalar<C>> for AffinePoint<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    fn mul(self, scalar: Scalar<C>) -> Self {
        (ProjectivePoint::from(self) * scalar).to_affine()
    }
}

impl<C> Neg for AffinePoint<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        AffinePoint {
            x: self.x,
            y: -self.y,
            infinity: self.infinity,
        }
    }
}

#[cfg(feature = "zeroize")]
impl<C> Zeroize for AffinePoint<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}
