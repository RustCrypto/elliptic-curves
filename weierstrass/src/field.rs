use core::{fmt, mem};
use core::convert::TryInto;
use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Neg, Shl};
use generic_array::ArrayLength;
use generic_array::typenum::{B1, U1};
use subtle::{ConditionallySelectable, Choice, ConstantTimeEq, CtOption};
use rand_core::{RngCore, CryptoRng};

use crate::{
    WeierstrassCurve, Word, WORD_WIDTH_BITS,
    Words, WordsLen,
    DoubleWords, DoubleWordsLen,
    WordsBytes, WordsBytesLen,
    WordsP1, WordsP1Len,
    random_word
};
use crate::utils::{adc, sbb, mac};

#[derive(Default, Debug, Copy, Clone)]
pub struct FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    pub words: Words<C>,
}

impl<C> FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    /// Returns the zero element (additive identity).
    pub fn zero() -> Self {
        Self {
            words: Default::default(),
        }
    }

    /// Returns the multiplicative identity.
    pub fn one() -> Self {
        C::R
    }

    /// Returns a uniformly-random element within the field.
    pub fn generate(mut rng: impl CryptoRng + RngCore) -> Self {
        // We reduce a random value with a double length, which results in a
        // negligible bias from the uniform distribution.
        let mut t = DoubleWords::<C>::default();
        t.iter_mut().for_each(|wt| *wt = random_word(&mut rng));
        FieldElement::montgomery_reduce(t)
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: &WordsBytes<C>) -> CtOption<Self> {
        let mut words = Words::<C>::default();
        let m = mem::size_of::<Word>();
        let iter = words.iter_mut().zip(bytes.chunks_exact(m).rev());
        for (w, chunk) in iter {
            *w = Word::from_be_bytes(chunk.try_into().unwrap());
        }

        let mut borrow = Word::default();
        for (&w, &wm) in words.iter().zip(C::MODULUS_P.iter()) {
            borrow = sbb(w, wm, borrow).1;
        }
        let is_some = (borrow as u8) & 1;

        // Convert w to Montgomery form: w * R^2 * R^-1 mod p = wR mod p
        CtOption::new(Self { words }.mul(C::R2), Choice::from(is_some))
    }

    /// Returns the SEC1 encoding of this field element.
    pub fn to_bytes(&self) -> WordsBytes<C> {
        // Convert from Montgomery form to canonical form
        let mut w = DoubleWords::<C>::default();
        let n = self.words.len();
        w[..n].copy_from_slice(&self.words);
        let t = Self::montgomery_reduce(w);

        let m = mem::size_of::<Word>();
        let mut buf = WordsBytes::<C>::default();
        let iter = buf.chunks_exact_mut(m).rev().zip(t.words.iter());
        for (chunk, wt) in iter {
            chunk.copy_from_slice(&wt.to_be_bytes());
        }
        buf
    }

    /// Determine if this `FieldElement` is zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&FieldElement::zero())
    }

    /// Returns self + rhs mod p
    pub fn add(&self, rhs: &Self) -> Self {
        // Last bit of p is usually set, so addition can result in five words.
        let mut t: WordsP1<C> = Default::default();
        let mut carry = Word::default();
        let pairs = self.words.iter().zip(rhs.words.iter());
        for (wt, (&wb, &wa)) in t.iter_mut().zip(pairs) {
            let t = adc(wa, wb, carry);
            *wt = t.0;
            carry = t.1;
        }
        *t.last_mut().unwrap() = carry;
        // Attempt to subtract the MODULUS_P, to ensure the result is in the field.
        Self::sub_inner(t, Self { words: C::MODULUS_P })
    }

    /// Returns 2*self.
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Returns self - rhs mod p
    pub fn subtract(&self, rhs: &Self) -> Self {
        let mut t: WordsP1<C> = Default::default();
        let n = self.words.len();
        t[..n].copy_from_slice(&self.words);
        Self::sub_inner(t, *rhs)
    }

    fn sub_inner(a: WordsP1<C>, mut b: Self) -> Self {
        let mut borrow = Word::default();
        for (wb, wa) in b.words.iter_mut().zip(a.iter()) {
            let t = sbb(*wa, *wb, borrow);
            *wb = t.0;
            borrow = t.1;
        }
        let (_, borrow) = sbb(a[a.len() - 1], 0, borrow);

        // If underflow occurred on the final word, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the
        // MODULUS_P.
        let mut carry = Word::default();
        for (wb, &wm) in b.words.iter_mut().zip(C::MODULUS_P.iter()) {
            let t = adc(*wb, wm & borrow, carry);
            *wb = t.0;
            carry = t.1;
        }
        b
    }

    /// Montgomery Reduction
    fn montgomery_reduce(v: DoubleWords<C>) -> Self {
        // `DoubleWords` length is always multiple of 2
        let n = v.len() / 2;
        let mut r = WordsP1::<C>::default();
        r[..n].copy_from_slice(&v[..n]);
        for i in 0..n {
            let u = r[0].wrapping_mul(C::PT);
            let (_, mut carry) = mac(r[0], u, C::MODULUS_P[0], 0);
            for j in 1..n {
                let t = mac(r[j], u, C::MODULUS_P[j], carry);
                r[j - 1] = t.0;
                carry = t.1;
            }
            let t = adc(v[i + n], r[n], carry);
            r[n - 1] = t.0;
            r[n] = t.1;
        }
        Self::sub_inner(r, Self { words: C::MODULUS_P })
    }

    /// Returns self * rhs mod p
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut w = DoubleWords::<C>::default();
        let n = rhs.words.len();

        // Schoolbook multiplication.
        for i in 0..n {
            let mut carry = Word::default();
            for j in 0..n {
                let t = mac(w[i + j], self.words[i], rhs.words[j], carry);
                w[i + j] = t.0;
                carry = t.1;
            }
            w[i + n] = carry;
        }

        Self::montgomery_reduce(w)
    }

    /// Returns self * self mod p
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Returns `self^by mod p`, where `by` is a little-endian integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.**
    /// If the exponent is fixed, this operation is effectively constant time.
    pub fn pow_vartime(&self, by: &Words<C>) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..WORD_WIDTH_BITS).rev() {
                res = res.square();
                if ((*e >> i) & 1) == 1 {
                    res = res.mul(*self);
                }
            }
        }
        res
    }

    /// Returns the multiplicative inverse of self, if self is non-zero.
    pub fn invert(&self) -> CtOption<Self> {
        // We need to find b such that b * a ≡ 1 mod p. As we are in a prime
        // field, we can apply Fermat's Little Theorem:
        //
        //    a^p         ≡ a mod p
        //    a^(p-1)     ≡ 1 mod p
        //    a^(p-2) * a ≡ 1 mod p
        //
        // Thus inversion can be implemented with a single exponentiation.
        let inverse = self.pow_vartime(&C::MODULUS_P_M2);
        CtOption::new(inverse, !self.is_zero())
    }

    /// Returns the square root of self mod p, or `None` if no square root exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        todo!();
    }
}

impl<C> fmt::UpperHex for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for word in self.words.iter().rev() {
            write!(f, "{:016X}", word)?;
        }
        Ok(())
    }
}

impl<C> ConditionallySelectable for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut res = Self::zero();
        let pairs = a.words.iter().zip(b.words.iter());
        for (vr, (va, vb)) in res.words.iter_mut().zip(pairs) {
            *vr = Word::conditional_select(va, vb, choice);
        }
        res
    }
}

impl<C> ConstantTimeEq for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut res = 1u8.into();
        for (a, b) in self.words.iter().zip(other.words.iter()) {
            res &= a.ct_eq(b);
        }
        res
    }
}

impl<C> PartialEq for FieldElement<C>
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

impl<C> Add<FieldElement<C>> for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        FieldElement::add(&self, &other)
    }
}

impl<C> AddAssign<FieldElement<C>> for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = FieldElement::add(self, &other);
    }
}

impl<C> Sub<FieldElement<C>> for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        FieldElement::subtract(&self, &other)
    }
}

impl<C> SubAssign<FieldElement<C>> for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        *self = FieldElement::subtract(self, &other);
    }
}


impl<C> Mul<FieldElement<C>> for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        FieldElement::mul(&self, &other)
    }
}

impl<C> MulAssign<FieldElement<C>> for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = FieldElement::mul(self, &other);
    }
}

impl<C> Neg for FieldElement<C>
    where
        C: WeierstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1> + Shl<B1>,
        DoubleWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        FieldElement::zero() - self
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.words.zeroize();
    }
}
