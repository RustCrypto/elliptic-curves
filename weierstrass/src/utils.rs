use generic_array::typenum::Unsigned;
use crate::{DoubleWord, Word, WordWidth};

/// Computes `a + b + carry`, returning the result along with the new carry.
#[inline(always)]
pub(crate) const fn adc(a: Word, b: Word, carry: Word) -> (Word, Word) {
    let ret = (a as DoubleWord) + (b as DoubleWord) + (carry as DoubleWord);
    (ret as Word, (ret >> WordWidth::USIZE) as Word)
}

/// Computes `a - (b + borrow)`, returning the result along with the new borrow.
#[inline(always)]
pub(crate) const fn sbb(a: Word, b: Word, borrow: Word) -> (Word, Word) {
    let (a, b) = (a as DoubleWord, b as DoubleWord);
    let t = (borrow >> (WordWidth::USIZE - 1)) as DoubleWord;
    let ret = a.wrapping_sub(b + t);
    (ret as Word, (ret >> WordWidth::USIZE) as Word)
}

/// Computes `a + (b * c) + carry`, returning the result along with the new carry.
#[inline(always)]
pub(crate) const fn mac(a: Word, b: Word, c: Word, carry: Word) -> (Word, Word) {
    let (a, b, c) = (a as DoubleWord, b as DoubleWord, c as DoubleWord);
    let ret = a + b * c + (carry as DoubleWord);
    (ret as Word, (ret >> WordWidth::USIZE) as Word)
}
