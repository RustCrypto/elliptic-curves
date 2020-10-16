use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Neg};
use core::{fmt, mem};
use core::convert::TryInto;
use subtle::{ConditionallySelectable, Choice, ConstantTimeEq, CtOption};
use generic_array::ArrayLength;
use generic_array::typenum::{U1, Unsigned};

use super::{
    WeirstrassCurve, Word, WordWidth, Words, WordsLen,
    WideWordsLen, WideWords,
    WordsBytesLen, WordsBytes,
    WordsP1Len, WordsP1,
};
use crate::utils::{adc, sbb, mac};

#[derive(Default, Copy, Clone, Debug, Eq)]
pub struct Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    pub(crate) words: Words<C>,
}

impl<C> Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    /// Returns the zero scalar (additive identity).
    pub fn zero() -> Self {
        Self::default()
    }

    /// Returns the multiplicative identity.
    pub fn one() -> Self {
        let mut t = Self::default();
        t.words[0] = 1;
        t
    }

    /// Parses the given byte array as a scalar.
    ///
    /// Subtracts the modulus when the byte array is larger than the modulus.
    pub fn from_bytes_reduced(bytes: &WordsBytes<C>) -> Self {
        let mut words = WordsP1::<C>::default();
        let m = mem::size_of::<Word>();
        let iter = words.iter_mut().zip(bytes.chunks_exact(m).rev());
        for (w, chunk) in iter {
            *w = Word::from_be_bytes(chunk.try_into().unwrap());
        }
        let modulus = Self { words: C::MODULUS_Q };
        let mut res = Self::sub_inner(words, modulus);
        for _ in 1..C::MODULUS_Q_REDUCE_N {
            res -= modulus;
        }
        res
    }

    /// Returns the SEC1 encoding of this scalar.
    pub fn to_bytes(&self) -> WordsBytes<C> {
        let mut buf = WordsBytes::<C>::default();
        let m = mem::size_of::<Word>();
        let iter = buf.chunks_exact_mut(m).zip(self.words.iter().rev());
        for (chunk, w) in iter {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        buf
    }

    /// Determine if this `Scalar` is zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Scalar::zero())
    }

    /// Returns self + rhs mod n
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
        // Attempt to subtract the MODULUS_Q, to ensure the result is in the field.
        Self::sub_inner(t, Self { words: C::MODULUS_Q })
    }

    /// Returns 2*self.
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Returns self - rhs mod n
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
        // MODULUS_Q.
        let mut carry = Word::default();
        for (wb, &wm) in b.words.iter_mut().zip(C::MODULUS_Q.iter()) {
            let t = adc(*wb, wm & borrow, carry);
            *wb = t.0;
            carry = t.1;
        }
        b
    }

    /// Barrett Reduction
    ///
    /// The general algorithm is:
    /// ```text
    /// p = n = order of group
    /// b = 2^64 = 64bit machine word
    /// k = 4
    /// a \in [0, 2^512]
    /// mu := floor(b^{2k} / p)
    /// q1 := floor(a / b^{k - 1})
    /// q2 := q1 * mu
    /// q3 := <- floor(a / b^{k - 1})
    /// r1 := a mod b^{k + 1}
    /// r2 := q3 * m mod b^{k + 1}
    /// r := r1 - r2
    ///
    /// if r < 0: r := r + b^{k + 1}
    /// while r >= p: do r := r - p (at most twice)
    /// ```
    ///
    /// References:
    /// - Handbook of Applied Cryptography, Chapter 14
    ///   Algorithm 14.42
    ///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn barrett_reduce(a: WideWords<C>) -> Self {
        // `WideWords` length is always multiple of 2
        let k = a.len() / 2;
        let mut q1 = WordsP1::<C>::default();
        q1.copy_from_slice(&a[k-1..]);

        let mut q3 = WordsP1::<C>::default();
        let n = q3.len();
        // Schoolbook multiplication + take last `n` words
        for i in 0..n {
            let (_, mut carry) = mac(q3[0], q1[i], C::MU[0], 0);
            for j in 1..n {
                let t = mac(q3[j], q1[i], C::MU[j], carry);
                q3[j - 1] = t.0;
                carry = t.1;
            }
            q3[n - 1] = carry;
        }

        let mut r1 = WordsP1::<C>::default();
        r1.copy_from_slice(&a[..k+1]);

        let mut r2 = WordsP1::<C>::default();
        // Schoolbook multiplication + take first `n` words
        for i in 0..n {
            let mut carry = Word::default();
            for j in 0..(n - i) {
                let wm = C::MODULUS_Q.get(j).cloned().unwrap_or(0);
                let t = mac(r2[i + j], q3[i], wm, carry);
                r2[i + j] = t.0;
                carry = t.1;
            }
        }

        // If underflow occurred on the final word - don't care (= add b^{k+1}).
        let mut borrow = Word::default();
        for (w1, &w2) in r1.iter_mut().zip(r2.iter()) {
            let t = sbb(*w1, w2, borrow);
            *w1 = t.0;
            borrow = t.1;
        }
        let mut r = r1;

        fn sub_mod_if_necessary<C>(r: &mut WordsP1<C>)
            where
                C: WeirstrassCurve,
                WordsLen<C>: ArrayLength<Word> + Add<U1>,
                WideWordsLen<C>: ArrayLength<Word>,
                WordsP1Len<C>: ArrayLength<Word>,
                WordsBytesLen<C>: ArrayLength<u8>,
                Words<C>: Copy,
        {
            let mut borrow = Word::default();
            let n = r.len();
            for (wr, &wm) in r.iter_mut().zip(C::MODULUS_Q.iter()) {
                let t = sbb(*wr, wm, borrow);
                *wr = t.0;
                borrow = t.1;
            }
            let t = sbb(r[n - 1], 0, borrow);
            r[n - 1] = t.0;
            borrow = t.1;

            // If underflow occurred on the final limb, borrow = 0xfff...fff,
            // otherwise borrow = 0x000...000. Thus, we use it as a mask to
            // conditionally add the modulus.
            let mut carry = Word::default();
            for (wr, &wm) in r.iter_mut().zip(C::MODULUS_Q.iter()) {
                let t = adc(*wr, wm & borrow, carry);
                *wr = t.0;
                carry = t.1;
            }
            r[n - 1] = adc(r[n - 1], 0, carry).0;
        }

        // Result is in range (0, 3*n - 1),
        // and 90% of the time, no subtraction will be needed.
        sub_mod_if_necessary::<C>(&mut r);
        sub_mod_if_necessary::<C>(&mut r);
        
        let mut res = Self::default();
        res.words.copy_from_slice(&r[..k]);
        res
    }

    /// Returns self * rhs mod n
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut w = WideWords::<C>::default();
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
        Self::barrett_reduce(w)
    }

    /// Returns self * self mod p
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Returns `self^by`, where `by` is a little-endian integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.**
    /// If the exponent is fixed, this operation is effectively constant time.
    pub fn pow_vartime(&self, by: &Words<C>) -> Self {
        let mut res = Self::one();
        let n = WordWidth::USIZE;
        for e in by.iter().rev() {
            for i in (0..n).rev() {
                res = res.square();
                if ((*e >> i) & 1) == 1 {
                    res *= *self;
                }
            }
        }
        res
    }

    /// Returns the multiplicative inverse of self, if self is non-zero
    pub fn invert(&self) -> CtOption<Self> {
        // We need to find b such that b * a ≡ 1 mod p. As we are in a prime
        // field, we can apply Fermat's Little Theorem:
        //
        //    a^p         ≡ a mod p
        //    a^(p-1)     ≡ 1 mod p
        //    a^(p-2) * a ≡ 1 mod p
        //
        // Thus inversion can be implemented with a single exponentiation.
        //
        // This is `n - 2`, so the top right two digits are `4f` instead of `51`.
        let inverse = self.pow_vartime(&C::MODULUS_Q_M2);
        CtOption::new(inverse, !self.is_zero())
    }

    /// Is integer representing equivalence class odd
    pub fn is_odd(&self) -> Choice {
        ((self.words[0] & 1) as u8).into()
    }

    /// Is integer representing equivalence class even
    pub fn is_even(&self) -> Choice {
        !self.is_odd()
    }

    // fn shr1(&mut self) {
    //     todo!();
    // }

    /// Faster inversion using Stein's algorithm
    pub fn invert_vartime(&self) -> CtOption<Self> {
        // https://link.springer.com/article/10.1007/s13389-016-0135-4
        todo!();
    }

    pub fn from_repr(bytes: WordsBytes<C>) -> Option<Self> {
        let mut words = Words::<C>::default();
        let n = mem::size_of::<Word>();
        let iter = words.iter_mut().rev().zip(bytes.chunks_exact(n));
        for (wm, chunk) in iter {
            *wm = Word::from_be_bytes(chunk.try_into().unwrap());
        }

        // If w is in the range [0, n) then w - n will overflow, resulting
        // in a borrow value of 2^64 - 1.
        let mut borrow = Word::default();
        for (&w, &wm) in words.iter().zip(C::MODULUS_Q.iter()) {
            borrow = sbb(w, wm, borrow).1;
        }
        let is_some = (borrow as u8) & 1;

        CtOption::new(Self { words }, Choice::from(is_some)).into()
    }
}


impl<C> fmt::UpperHex for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
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

impl<C> ConditionallySelectable for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
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

impl<C> ConstantTimeEq for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
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

impl<C> PartialEq for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C> Add<Scalar<C>> for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        Scalar::add(&self, &other)
    }
}

impl<C> AddAssign<Scalar<C>> for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = Scalar::add(self, &other);
    }
}

impl<C> Sub<Scalar<C>> for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        Scalar::subtract(&self, &other)
    }
}

impl<C> SubAssign<Scalar<C>> for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        *self = Scalar::subtract(self, &other);
    }
}


impl<C> Mul<Scalar<C>> for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        Scalar::mul(&self, &other)
    }
}

impl<C> MulAssign<Scalar<C>> for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = Scalar::mul(self, &other);
    }
}

impl<C> Neg for Scalar<C>
    where
        C: WeirstrassCurve,
        WordsLen<C>: ArrayLength<Word> + Add<U1>,
        WideWordsLen<C>: ArrayLength<Word>,
        WordsP1Len<C>: ArrayLength<Word>,
        WordsBytesLen<C>: ArrayLength<u8>,
        Words<C>: Copy,
{
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Scalar::zero() - self
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.words.zeroize();
    }
}
