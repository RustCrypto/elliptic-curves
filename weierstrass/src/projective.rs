use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign, Shl};
use core::iter::Sum;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use generic_array::{ArrayLength, typenum::{B1, U1, Unsigned}};

use crate::{
    WeierstrassCurve, CurveKind,
    Word, WordWidth,
    Words, WordsLen,
    DoubleWordsLen,
    WordsBytesLen,
    WordsP1Len,
};
use crate::field::FieldElement;
use crate::affine::AffinePoint;
use crate::scalar::Scalar;


#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    pub x: FieldElement<C>,
    pub y: FieldElement<C>,
    pub z: FieldElement<C>,
}

impl<C> From<AffinePoint<C>> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn from(p: AffinePoint<C>) -> Self {
        let projective = ProjectivePoint {
            x: p.x,
            y: p.y,
            z: FieldElement::one(),
        };
        Self::conditional_select(&projective, &Self::identity(), p.infinity)
    }
}

impl<C> ConditionallySelectable for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ProjectivePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl<C> ConstantTimeEq for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_affine().ct_eq(&other.to_affine())
    }
}

impl<C> PartialEq for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
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

impl<C> Eq for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{}

impl<C> ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    /// Returns the additive identity of P-256, also known as the "neutral element" or
    /// "point at infinity".
    pub fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Returns the base point of P-256.
    pub fn generator() -> Self {
        AffinePoint::generator().into()
    }

    /// Returns the affine representation of this point, or `None` if it is the identity.
    pub fn to_affine(&self) -> AffinePoint<C> {
        self.z
            .invert()
            .map(|zinv| AffinePoint {
                x: self.x * zinv,
                y: self.y * zinv,
                infinity: Choice::from(0),
            })
            .unwrap_or_else(AffinePoint::identity)
    }

    /// Returns `-self`.
    fn neg(&self) -> Self {
        ProjectivePoint {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Returns `self + other`.
    fn add(&self, other: &Self) -> Self {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060). The comments after each line
        // indicate which algorithm steps are being performed.
        let &ProjectivePoint { x: x1, y: y1, z: z1 } = self;
        let &ProjectivePoint { x: x2, y: y2, z: z2 } = other;

        let b1 = C::B;
        let b3 = C::B3;
        let a1 = C::A;

        let (mut t0, mut t1, mut t2, mut t3, mut t4, mut t5);
        let (mut x3, mut y3, mut z3);


        match C::CURVE_KIND {
            CurveKind::General => {
                // Algorithm 1
                t0 = x1 * x2; // 1
                t1 = y1 * y2; // 2
                t2 = z1 * z2; // 3

                t3 = x1 + y1; // 4
                t4 = x2 + y2; // 5
                t3 = t3 * t4; // 6

                t4 = t0 + t1; // 7
                t3 = t3 - t4; // 8
                t4 = x1 + z1; // 9

                t5 = x2 + z2; // 10
                t4 = t4 * t5; // 11
                t5 = t0 + t2; // 12

                t4 = t4 - t5; // 13
                t5 = y1 + z1; // 14
                x3 = y2 + z2; // 15

                t5 = t5 * x3; // 16
                x3 = t1 + t2; // 17
                t5 = t5 - x3; // 18

                z3 = a1 * t4; // 19
                x3 = b3 * t2; // 20
                z3 = x3 + z3; // 21

                x3 = t1 - z3; // 22
                z3 = t1 + z3; // 23
                y3 = x3 * z3; // 24

                t1 = t0 + t0; // 25
                t1 = t1 + t0; // 26
                t2 = a1 * t2; // 27

                t4 = b3 * t4; // 28
                t1 = t1 + t2; // 29
                t2 = t0 - t2; // 30

                t2 = a1 * t2; // 31
                t4 = t4 + t2; // 32
                t0 = t1 * t4; // 33

                y3 = y3 + t0; // 34
                t0 = t5 * t4; // 35
                x3 = t3 * x3; // 36

                x3 = x3 - t0; // 37
                t0 = t3 * t1; // 38
                z3 = t5 * z3; // 39

                z3 = z3 + t0; // 40
            }
            CurveKind::Minus3 => {
                // Algorithm 4
                t0 = x1 * x2; // 1
                t1 = y1 * y2; // 2
                t2 = z1 * z2; // 3

                t3 = x1 + y1; // 4
                t4 = x2 + y2; // 5
                t3 = t3 * t4; // 6

                t4 = t0 + t1; // 7
                t3 = t3 - t4; // 8
                t4 = y1 + z1; // 9

                x3 = y2 + z2; // 10
                t4 = t4 * x3; // 11
                x3 = t1 + t2; // 12

                t4 = t4 - x3; // 13
                x3 = x1 + z1; // 14
                y3 = x2 + z2; // 15

                x3 = x3 * y3; // 16
                y3 = t0 + t2; // 17
                y3 = x3 - y3; // 18

                z3 = b1 * t2; // 19
                x3 = y3 - z3; // 20
                z3 = x3 + x3; // 21

                x3 = x3 + z3; // 22
                z3 = t1 - x3; // 23
                x3 = t1 + x3; // 24

                y3 = b1 * y3; // 25
                t1 = t2 + t2; // 26
                t2 = t1 + t2; // 27

                y3 = y3 - t2; // 28
                y3 = y3 - t0; // 29
                t1 = y3 + y3; // 30

                y3 = t1 + y3; // 31
                t1 = t0 + t0; // 32
                t0 = t1 + t0; // 33

                t0 = t0 - t2; // 34
                t1 = t4 * y3; // 35
                t2 = t0 * y3; // 36

                y3 = x3 * z3; // 37
                y3 = y3 + t2; // 38
                x3 = t3 * x3; // 39

                x3 = x3 - t1; // 40
                z3 = t4 * z3; // 41
                t1 = t3 * t0; // 42

                z3 = z3 + t1; // 43
            }
            CurveKind::Zero => {
                // Algorithm 7
                t0 = x1 * x2; // 1
                t1 = y1 * y2; // 2
                t2 = z1 * z2; // 3

                t3 = x1 + y1; // 4
                t4 = x2 + y2; // 5
                t3 = t3 * t4; // 6

                t4 = t0 + t1; // 7
                t3 = t3 - t4; // 8
                t4 = y1 + z1; // 9

                x3 = y2 + z2; // 10
                t4 = t4 * x3; // 11
                x3 = t1 + t2; // 12

                t4 = t4 - x3; // 13
                x3 = x1 + z1; // 14
                y3 = x2 + z2; // 15

                x3 = x3 * y3; // 16
                y3 = t0 + t2; // 17
                y3 = x3 - y3; // 18

                x3 = t0 + t0; // 19
                t0 = x3 + t0; // 20
                t2 = b3 * t2; // 21

                z3 = t1 + t2; // 22
                t1 = t1 - t2; // 23
                y3 = b3 * y3; // 24

                x3 = t4 * y3; // 25
                t2 = t3 * t1; // 26
                x3 = t2 - x3; // 27

                y3 = y3 * t0; // 28
                t1 = t1 * z3; // 29
                y3 = t1 + y3; // 30

                t0 = t0 * t3; // 31
                z3 = z3 * t4; // 32
                z3 = z3 + t0; // 33
            }
        }
        ProjectivePoint { x: x3, y: y3, z: z3 }
    }

    /// Returns `self + other`.
    fn add_mixed(&self, other: &AffinePoint<C>) -> Self {
        // We implement the complete mixed addition formula from Renes-Costello-Batina
        // 2015. The comments after each line indicate which algorithm steps
        // are being performed.
        let &ProjectivePoint { x: x1, y: y1, z: z1 } = self;
        let &AffinePoint { x: x2, y: y2, .. } = other;

        let b1 = C::B;
        let b3 = C::B;
        let a1 = C::A;

        let (mut t0, mut t1, mut t2, mut t3, mut t4, mut t5);
        let (mut x3, mut y3, mut z3);

        match C::CURVE_KIND {
            CurveKind::General => {
                // Algorithm 2
                t0 = x1 * x2; // 1
                t1 = y1 * y2; // 2
                t3 = x2 + y2; // 3

                t4 = x1 + y1; // 4
                t3 = t3 * t4; // 5
                t4 = t0 + t1; // 6

                t3 = t3 - t4; // 7
                t4 = x2 * z1; // 8
                t4 = t4 + x1; // 9

                t5 = y2 * z1; // 10
                t5 = t5 + y1; // 11
                z3 = a1 * t4; // 12

                x3 = b3 * z1; // 13
                z3 = x3 + z3; // 14
                x3 = t1 - z3; // 15

                z3 = t1 + z3; // 16
                y3 = x3 * z3; // 17
                t1 = t0 + t0; // 18

                t1 = t1 + t0; // 19
                t2 = a1 * z1; // 20
                t4 = b3 * t4; // 21

                t1 = t1 + t2; // 22
                t2 = t0 - t2; // 23
                t2 = a1 * t2; // 24

                t4 = t4 + t2; // 25
                t0 = t1 * t4; // 26
                y3 = y3 + t0; // 27

                t0 = t5 * t4; // 28
                x3 = t3 * x3; // 29
                x3 = x3 - t0; // 30

                t0 = t3 * t1; // 31
                z3 = t5 * z3; // 32
                z3 = z3 + t0; // 33
            }
            CurveKind::Minus3 => {
                // Algorithm 5
                t0 = x1 * x2; // 1
                t1 = y1 * y2; // 2
                t3 = x2 + y2; // 3

                t4 = x1 + y1; // 4
                t3 = t3 * t4; // 5
                t4 = t0 + t1; // 6

                t3 = t3 - t4; // 7
                t4 = y2 * z1; // 8
                t4 = t4 + y1; // 9

                y3 = x2 * z1; // 10
                y3 = y3 + x1; // 11
                z3 = b1 * z1; // 12

                x3 = y3 - z3; // 13
                z3 = x3 + x3; // 14
                x3 = x3 + z3; // 15

                z3 = t1 - x3; // 16
                x3 = t1 + x3; // 17
                y3 = b1 * y3; // 18

                t1 = z1 + z1; // 19
                t2 = t1 + z1; // 20
                y3 = y3 - t2; // 21

                y3 = y3 - t0; // 22
                t1 = y3 + y3; // 23
                y3 = t1 + y3; // 24

                t1 = t0 + t0; // 25
                t0 = t1 + t0; // 26
                t0 = t0 - t2; // 27

                t1 = t4 * y3; // 28
                t2 = t0 * y3; // 29
                y3 = x3 * z3; // 30

                y3 = y3 + t2; // 31
                x3 = t3 * x3; // 32
                x3 = x3 - t1; // 33

                z3 = t4 * z3; // 34
                t1 = t3 * t0; // 35
                z3 = z3 + t1; // 36
            }
            CurveKind::Zero => {
                // Algorithm 8
                t0 = x1 * x2; // 1
                t1 = y1 * y2; // 2
                t3 = x2 + y2; // 3

                t4 = x1 + y1; // 4
                t3 = t3 * t4; // 5
                t4 = t0 + t1; // 6

                t3 = t3 - t4; // 7
                t4 = y2 * z1; // 8
                t4 = t4 + y1; // 9

                y3 = x2 * z1; // 10
                y3 = y3 + x1; // 11
                x3 = t0 + t0; // 12

                t0 = x3 + t0; // 13
                t2 = b3 * z1; // 14
                z3 = t1 + t2; // 15

                t1 = t1 - t2; // 16
                y3 = b3 * y3; // 17
                x3 = t4 * y3; // 18

                t2 = t3 * t1; // 19
                x3 = t2 - x3; // 20
                y3 = y3 * t0; // 21

                t1 = t1 * z3; // 22
                y3 = t1 + y3; // 23
                t0 = t0 * t3; // 24

                z3 = z3 * t4; // 25
                z3 = z3 + t0; // 26
            }
        }
        ProjectivePoint { x: x3, y: y3, z: z3 }
    }

    /// Doubles this point.
    pub fn double(&self) -> Self {
        // We implement the complete doubling formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060). The comments after each line
        // indicate which algorithm steps are being performed.
        let &ProjectivePoint { x: x1, y: y1, z: z1 } = self;

        let b1 = C::B;
        let b3 = C::B3;
        let a1 = C::A;

        let (mut t0, mut t1, mut t2, mut t3);
        let (mut x3, mut y3, mut z3);
        match C::CURVE_KIND {
            CurveKind::General => {
                // Algorithm 3
                t0 = x1 * x1; // 1
                t1 = y1 * y1; // 2
                t2 = z1 * z1; // 3

                t3 = x1 * y1; // 4
                t3 = t3 + t3; // 5
                z3 = x1 * z1; // 6

                z3 = z3 + z3; // 7
                x3 = a1 * z3; // 8
                y3 = b3 * t2; // 9

                y3 = x3 + y3; // 10
                x3 = t1 - y3; // 11
                y3 = t1 + y3; // 12

                y3 = x3 * y3; // 13
                x3 = t3 * x3; // 14
                z3 = b3 * z3; // 15

                t2 = a1 * t2; // 16
                t3 = t0 - t2; // 17
                t3 = a1 * t3; // 18

                t3 = t3 + z3; // 19
                z3 = t0 + t0; // 20
                t0 = z3 + t0; // 21

                t0 = t0 + t2; // 22
                t0 = t0 * t3; // 23
                y3 = y3 + t0; // 24

                t2 = y1 * z1; // 25
                t2 = t2 + t2; // 26
                t0 = t2 * t3; // 27

                x3 = x3 - t0; // 28
                z3 = t2 * t1; // 29
                z3 = z3 + z3; // 30

                z3 = z3 + z3; // 31
            }
            CurveKind::Minus3 => {
                // Algorithm 6
                t0 = x1 * x1; // 1
                t1 = y1 * y1; // 2
                t2 = z1 * z1; // 3

                t3 = x1 * y1; // 4
                t3 = t3 + t3; // 5
                z3 = x1 * z1; // 6

                z3 = z3 + z3; // 7
                y3 = b1 * t2; // 8
                y3 = y3 - z3; // 9

                x3 = y3 + y3; // 10
                y3 = x3 + y3; // 11
                x3 = t1 - y3; // 12

                y3 = t1 + y3; // 13
                y3 = x3 * y3; // 14
                x3 = x3 * t3; // 15

                t3 = t2 + t2; // 16
                t2 = t2 + t3; // 17
                z3 = b1 * z3; // 18

                z3 = z3 - t2; // 19
                z3 = z3 - t0; // 20
                t3 = z3 + z3; // 21

                z3 = z3 + t3; // 22
                t3 = t0 + t0; // 23
                t0 = t3 + t0; // 24

                t0 = t0 - t2; // 25
                t0 = t0 * z3; // 26
                y3 = y3 + t0; // 27

                t0 = y1 * z1; // 28
                t0 = t0 + t0; // 29
                z3 = t0 * z3; // 30

                x3 = x3 - z3; // 31
                z3 = t0 * t1; // 32
                z3 = z3 + z3; // 33

                z3 = z3 + z3; // 34
            }
            CurveKind::Zero => {
                // Algorithm 9
                t0 = y1 * y1; // 1
                z3 = t0 + t0; // 2
                z3 = z3 + z3; // 3

                z3 = z3 + z3; // 4
                t1 = y1 * z1; // 5
                t2 = z1 * z1; // 6

                t2 = b3 * t2; // 7
                x3 = t2 * z3; // 8
                y3 = t0 + t2; // 9

                z3 = t1 * z3; // 10
                t1 = t2 + t2; // 11
                t2 = t1 + t2; // 12

                t0 = t0 - t2; // 13
                y3 = t0 * y3; // 14
                y3 = x3 + y3; // 15

                t1 = x1 * y1; // 16
                x3 = t0 * t1; // 17
                x3 = x3 + x3; // 18
            }
        }
        ProjectivePoint { x: x3, y: y3, z: z3 }
    }

    /// Returns `self - other`.
    fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Returns `self - other`.
    fn sub_mixed(&self, other: &AffinePoint<C>) -> Self {
        self.add_mixed(&other.neg())
    }

    /// Returns `[k] self`.
    fn mul(&self, k: &Scalar<C>) -> Self {
        let mut ret = ProjectivePoint::identity();

        for word in k.words.iter().rev() {
            for i in (0..WordWidth::USIZE).rev() {
                ret = ret.double();
                let choice = ((word >> i) & (1 as Word)) as u8;
                ret.conditional_assign(&(ret + *self), Choice::from(choice));
            }
        }

        ret
    }
}

impl<C> Default for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn default() -> Self {
        Self::identity()
    }
}

impl<C> Add<Self> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        ProjectivePoint::add(&self, &other)
    }
}

impl<C> AddAssign<Self> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn add_assign(&mut self, rhs: Self) {
        *self = ProjectivePoint::add(self, &rhs);
    }
}

impl<C> Add<AffinePoint<C>> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    fn add(self, other: AffinePoint<C>) -> Self {
        ProjectivePoint::add_mixed(&self, &other)
    }
}

impl<C> AddAssign<AffinePoint<C>> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn add_assign(&mut self, rhs: AffinePoint<C>) {
        *self = ProjectivePoint::add_mixed(self, &rhs);
    }
}

impl<C> Sum for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(ProjectivePoint::identity(), |a, b| a + b)
    }
}

impl<C> Sub<Self> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        ProjectivePoint::sub(&self, &other)
    }
}

impl<C> SubAssign<Self> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn sub_assign(&mut self, rhs: Self) {
        *self = ProjectivePoint::sub(self, &rhs);
    }
}

impl<C> Sub<AffinePoint<C>> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    fn sub(self, other: AffinePoint<C>) -> Self {
        ProjectivePoint::sub_mixed(&self, &other)
    }
}

impl<C> SubAssign<AffinePoint<C>> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn sub_assign(&mut self, rhs: AffinePoint<C>) {
        *self = ProjectivePoint::sub_mixed(self, &rhs);
    }
}

impl<C> Mul<Scalar<C>> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    fn mul(self, other: Scalar<C>) -> Self {
        ProjectivePoint::mul(&self, &other)
    }
}

impl<C> MulAssign<Scalar<C>> for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn mul_assign(&mut self, rhs: Scalar<C>) {
        *self = ProjectivePoint::mul(self, &rhs);
    }
}

impl<C> Neg for ProjectivePoint<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    fn neg(self) -> Self {
        ProjectivePoint::neg(&self)
    }
}
