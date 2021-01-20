use crate::{DoubleWord, Word, WordWidth, WORD_WIDTH_BITS};
use byteorder::{ByteOrder, BigEndian, LittleEndian};
use generic_array::{GenericArray, ArrayLength, typenum::{Unsigned, Quot}};
use core::ops::Div;
use core::mem;
use core::convert::TryInto;

/// Computes `a + b + carry`, returning the result along with the new carry.
#[inline(always)]
pub(crate) const fn adc(a: Word, b: Word, carry: Word) -> (Word, Word) {
    let ret = (a as DoubleWord) + (b as DoubleWord) + (carry as DoubleWord);
    (ret as Word, (ret >> WORD_WIDTH_BITS) as Word)
}

/// Computes `a - (b + borrow)`, returning the result along with the new borrow.
#[inline(always)]
pub(crate) const fn sbb(a: Word, b: Word, borrow: Word) -> (Word, Word) {
    let (a, b) = (a as DoubleWord, b as DoubleWord);
    let t = (borrow >> (WORD_WIDTH_BITS - 1)) as DoubleWord;
    let ret = a.wrapping_sub(b + t);
    (ret as Word, (ret >> WORD_WIDTH_BITS) as Word)
}

/// Computes `a + (b * c) + carry`, returning the result along with the new carry.
#[inline(always)]
pub(crate) const fn mac(a: Word, b: Word, c: Word, carry: Word) -> (Word, Word) {
    let (a, b, c) = (a as DoubleWord, b as DoubleWord, c as DoubleWord);
    let ret = a + b * c + (carry as DoubleWord);
    (ret as Word, (ret >> WORD_WIDTH_BITS) as Word)
}

/// Extension of the `ByteOrder` trait for biguint <-> bytes conversion.
pub trait BigUintExt: ByteOrder {
    fn bytes2biguint<N>(bytes: &GenericArray<u8, N>) -> Words<N>
    where
        N: Unsigned + ArrayLength<u8> + Div<WordWidth>,
        Quot<N, WordWidth>: ArrayLength<Word>;

    fn biguint2bytes<N>(words: &Words<N>) -> GenericArray<u8, N>
    where
        N: Unsigned + ArrayLength<u8> + Div<WordWidth>,
        Quot<N, WordWidth>: ArrayLength<Word>;
}

type Words<N> = GenericArray<Word, Quot<N, WordWidth>>;

impl BigUintExt for BigEndian {
    fn bytes2biguint<N>(bytes: &GenericArray<u8, N>) -> Words<N>
    where
        N: Unsigned + ArrayLength<u8> + Div<WordWidth>,
        Quot<N, WordWidth>: ArrayLength<Word>
    {
        let mut words = Words::<N>::default();
        let m = mem::size_of::<Word>();
        let iter = words.iter_mut().zip(bytes.chunks_exact(m).rev());
        for (w, chunk) in iter {
            *w = Word::from_be_bytes(chunk.try_into().unwrap());
        }
        words
    }

    fn biguint2bytes<N>(words: &Words<N>) -> GenericArray<u8, N>
    where
        N: Unsigned + ArrayLength<u8> + Div<WordWidth>,
        Quot<N, WordWidth>: ArrayLength<Word>
    {
        let mut buf = GenericArray::<u8, N>::default();
        let m = mem::size_of::<Word>();
        let iter = buf.chunks_exact_mut(m).zip(words.iter().rev());
        for (chunk, w) in iter {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        buf
    }
}

impl BigUintExt for LittleEndian {
    fn bytes2biguint<N>(bytes: &GenericArray<u8, N>) -> Words<N>
    where
        N: Unsigned + ArrayLength<u8> + Div<WordWidth>,
        Quot<N, WordWidth>: ArrayLength<Word>
    {
        let mut words = Words::<N>::default();
        let n = mem::size_of::<Word>();
        let iter = words.iter_mut().zip(bytes.chunks_exact(n));
        for (wm, chunk) in iter {
            *wm = Word::from_le_bytes(chunk.try_into().unwrap());
        }
        words
    }

    fn biguint2bytes<N>(words: &Words<N>) -> GenericArray<u8, N>
    where
        N: Unsigned + ArrayLength<u8> + Div<WordWidth>,
        Quot<N, WordWidth>: ArrayLength<Word>
    {
        let mut buf = GenericArray::<u8, N>::default();
        let m = mem::size_of::<Word>();
        let iter = buf.chunks_exact_mut(m).zip(words.iter());
        for (chunk, w) in iter {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        buf
    }
}
