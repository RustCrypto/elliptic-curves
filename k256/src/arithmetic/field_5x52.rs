use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use super::util::{verify_bits, verify_bits_128};

#[cfg(feature = "getrandom")]
use getrandom::getrandom;


#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(crate) [u64; 5]);


impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &FieldElement, b: &FieldElement, choice: Choice) -> FieldElement {
        FieldElement([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
        ])
    }
}


impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
            & self.0[4].ct_eq(&other.0[4])
    }
}


impl FieldElement {
    /// Returns the zero element.
    pub const fn zero() -> FieldElement {
        FieldElement([0, 0, 0, 0, 0])
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> FieldElement {
        FieldElement([1, 0, 0, 0, 0])
    }

    /// Returns a uniformly-random element within the field.
    /// TODO: implement
    /*#[cfg(feature = "getrandom")]
    pub fn generate() -> Self {
        // We reduce a random 512-bit value into a 256-bit field, which results in a
        // negligible bias from the uniform distribution.
        let mut buf = [0; 64];
        getrandom(&mut buf).unwrap();
        FieldElement::from_bytes_wide(buf)
    }*/

    /// Attempts to parse the given byte array as an SEC-1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        let mut w = [0u64; 5];

        w[0] =
            (bytes[31] as u64)
            | ((bytes[30] as u64) << 8)
            | ((bytes[29] as u64) << 16)
            | ((bytes[28] as u64) << 24)
            | ((bytes[27] as u64) << 32)
            | ((bytes[26] as u64) << 40)
            | (((bytes[25] & 0xFu8) as u64) << 48);

        w[1] =
            ((bytes[25] >> 4) as u64)
            | ((bytes[24] as u64) << 4)
            | ((bytes[23] as u64) << 12)
            | ((bytes[22] as u64) << 20)
            | ((bytes[21] as u64) << 28)
            | ((bytes[20] as u64) << 36)
            | ((bytes[19] as u64) << 44);

        w[2] =
            (bytes[18] as u64)
            | ((bytes[17] as u64) << 8)
            | ((bytes[16] as u64) << 16)
            | ((bytes[15] as u64) << 24)
            | ((bytes[14] as u64) << 32)
            | ((bytes[13] as u64) << 40)
            | (((bytes[12] & 0xFu8) as u64) << 48);

        w[3] =
            ((bytes[12] >> 4) as u64)
            | ((bytes[11] as u64) << 4)
            | ((bytes[10] as u64) << 12)
            | ((bytes[9] as u64) << 20)
            | ((bytes[8] as u64) << 28)
            | ((bytes[7] as u64) << 36)
            | ((bytes[6] as u64) << 44);

        w[4] =
            (bytes[5] as u64)
            | ((bytes[4] as u64) << 8)
            | ((bytes[3] as u64) << 16)
            | ((bytes[2] as u64) << 24)
            | ((bytes[1] as u64) << 32)
            | ((bytes[0] as u64) << 40);

        // Alternatively we can subtract modulus and check if we end up with a nonzero borrow,
        // like in the previous version. Check which if faster.
        let overflow =
            w[4].ct_eq(&0x0FFFFFFFFFFFFu64)
            & (w[3] & w[2] & w[1]).ct_eq(&0xFFFFFFFFFFFFFu64)
            & Choice::from(if w[0] >= 0xFFFFEFFFFFC2Fu64 { 1u8 } else { 0u8 }); // FIXME: make constant time

        CtOption::new(FieldElement(w), !overflow)
    }

    /// Returns the SEC-1 encoding of this field element.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        ret[0] = (self.0[4] >> 40) as u8;
        ret[1] = (self.0[4] >> 32) as u8;
        ret[2] = (self.0[4] >> 24) as u8;
        ret[3] = (self.0[4] >> 16) as u8;
        ret[4] = (self.0[4] >> 8) as u8;
        ret[5] = self.0[4] as u8;
        ret[6] = (self.0[3] >> 44) as u8;
        ret[7] = (self.0[3] >> 36) as u8;
        ret[8] = (self.0[3] >> 28) as u8;
        ret[9] = (self.0[3] >> 20) as u8;
        ret[10] = (self.0[3] >> 12) as u8;
        ret[11] = (self.0[3] >> 4) as u8;
        ret[12] = ((self.0[2] >> 48) as u8 & 0xFu8) | ((self.0[3] as u8 & 0xFu8) << 4);
        ret[13] = (self.0[2] >> 40) as u8;
        ret[14] = (self.0[2] >> 32) as u8;
        ret[15] = (self.0[2] >> 24) as u8;
        ret[16] = (self.0[2] >> 16) as u8;
        ret[17] = (self.0[2] >> 8) as u8;
        ret[18] = self.0[2] as u8;
        ret[19] = (self.0[1] >> 44) as u8;
        ret[20] = (self.0[1] >> 36) as u8;
        ret[21] = (self.0[1] >> 28) as u8;
        ret[22] = (self.0[1] >> 20) as u8;
        ret[23] = (self.0[1] >> 12) as u8;
        ret[24] = (self.0[1] >> 4) as u8;
        ret[25] = ((self.0[0] >> 48) as u8 & 0xFu8) | ((self.0[1] as u8 & 0xFu8) << 4);
        ret[26] = (self.0[0] >> 40) as u8;
        ret[27] = (self.0[0] >> 32) as u8;
        ret[28] = (self.0[0] >> 24) as u8;
        ret[29] = (self.0[0] >> 16) as u8;
        ret[30] = (self.0[0] >> 8) as u8;
        ret[31] = self.0[0] as u8;
        ret
    }

    pub fn normalize_weak(&self) -> Self {

        let mut t0 = self.0[0];
        let mut t1 = self.0[1];
        let mut t2 = self.0[2];
        let mut t3 = self.0[3];
        let mut t4 = self.0[4];

        // Reduce t4 at the start so there will be at most a single carry from the first pass
        let x = t4 >> 48;
        t4 &= 0x0FFFFFFFFFFFFu64;

        // The first pass ensures the magnitude is 1, ...
        t0 += x * 0x1000003D1u64;
        t1 += t0 >> 52; t0 &= 0xFFFFFFFFFFFFFu64;
        t2 += t1 >> 52; t1 &= 0xFFFFFFFFFFFFFu64;
        t3 += t2 >> 52; t2 &= 0xFFFFFFFFFFFFFu64;
        t4 += t3 >> 52; t3 &= 0xFFFFFFFFFFFFFu64;

        // ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element)
        debug_assert!(t4 >> 49 == 0);

        FieldElement([t0, t1, t2, t3, t4])
    }

    pub fn normalize(&self) -> Self {

        // TODO: the first part is the same as normalize_weak()

        let mut t0 = self.0[0];
        let mut t1 = self.0[1];
        let mut t2 = self.0[2];
        let mut t3 = self.0[3];
        let mut t4 = self.0[4];

        // Reduce t4 at the start so there will be at most a single carry from the first pass
        let x = t4 >> 48;
        t4 &= 0x0FFFFFFFFFFFFu64;

        // The first pass ensures the magnitude is 1, ...
        t0 += x * 0x1000003D1u64;
        t1 += t0 >> 52; t0 &= 0xFFFFFFFFFFFFFu64;
        t2 += t1 >> 52; t1 &= 0xFFFFFFFFFFFFFu64; let mut m = t1;
        t3 += t2 >> 52; t2 &= 0xFFFFFFFFFFFFFu64; m &= t2;
        t4 += t3 >> 52; t3 &= 0xFFFFFFFFFFFFFu64; m &= t3;

        // ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element)
        debug_assert!(t4 >> 49 == 0);

        // At most a single final reduction is needed; check if the value is >= the field characteristic
        let x = (t4 >> 48 != 0) | (
                (t4 == 0x0FFFFFFFFFFFFu64)
                & (m == 0xFFFFFFFFFFFFFu64)
                & (t0 >= 0xFFFFEFFFFFC2Fu64));

        // Apply the final reduction (for constant-time behaviour, we do it always)
        // FIXME: ensure constant time here
        t0 += (x as u64) * 0x1000003D1u64;
        t1 += t0 >> 52; t0 &= 0xFFFFFFFFFFFFFu64;
        t2 += t1 >> 52; t1 &= 0xFFFFFFFFFFFFFu64;
        t3 += t2 >> 52; t2 &= 0xFFFFFFFFFFFFFu64;
        t4 += t3 >> 52; t3 &= 0xFFFFFFFFFFFFFu64;

        // If t4 didn't carry to bit 48 already, then it should have after any final reduction
        debug_assert!(t4 >> 48 == x as u64);

        // Mask off the possible multiple of 2^256 from the final reduction
        t4 &= 0x0FFFFFFFFFFFFu64;

        FieldElement([t0, t1, t2, t3, t4])
    }

    pub fn to_words(&self) -> [u64; 4] {
        let mut ret = [0u64; 4];
        let x = self.normalize();

        debug_assert!(verify_bits(x.0[0], 52));
        debug_assert!(verify_bits(x.0[1], 52));
        debug_assert!(verify_bits(x.0[2], 52));
        debug_assert!(verify_bits(x.0[3], 52));
        debug_assert!(verify_bits(x.0[4], 48));

        ret[0] = x.0[0] | (x.0[1] << 52);
        ret[1] = (x.0[1] >> 12) | (x.0[2] << 40);
        ret[2] = (x.0[2] >> 24) | (x.0[3] << 28);
        ret[3] = (x.0[3] >> 36) | (x.0[4] << 16);
        ret
    }

    pub fn from_words(words: [u64; 4]) -> CtOption<Self> {
        let mut w = [0u64; 5];

        w[0] = words[0] & 0xFFFFFFFFFFFFFu64;
        w[1] = (words[0] >> 52) | ((words[1] & 0xFFFFFFFFFFu64) << 12);
        w[2] = (words[1] >> 40) | ((words[2] & 0xFFFFFFFu64) << 24);
        w[3] = (words[2] >> 28) | ((words[3] & 0xFFFFu64) << 36);
        w[4] = words[3] >> 16;

        // Alternatively we can subtract modulus and check if we end up with a nonzero borrow,
        // like in the previous version. Check which if faster.
        let overflow =
            w[4].ct_eq(&0x0FFFFFFFFFFFFu64)
            & (w[3] & w[2] & w[1]).ct_eq(&0xFFFFFFFFFFFFFu64)
            & Choice::from(if w[0] >= 0xFFFFEFFFFFC2Fu64 { 1u8 } else { 0u8 }); // FIXME: make constant time

        debug_assert!(verify_bits(w[0], 52));
        debug_assert!(verify_bits(w[1], 52));
        debug_assert!(verify_bits(w[2], 52));
        debug_assert!(verify_bits(w[3], 52));
        debug_assert!(verify_bits(w[4], 48));

        CtOption::new(FieldElement(w), !overflow)
    }

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&FieldElement::zero())
    }

    /// Determine if this `FieldElement` is odd in the SEC-1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        (self.0[0] as u8 & 1).into()
    }

    pub const fn negate(&self, magnitude: u64) -> Self {
        let r0 = 0xFFFFEFFFFFC2Fu64 * 2 * (magnitude + 1) - self.0[0];
        let r1 = 0xFFFFFFFFFFFFFu64 * 2 * (magnitude + 1) - self.0[1];
        let r2 = 0xFFFFFFFFFFFFFu64 * 2 * (magnitude + 1) - self.0[2];
        let r3 = 0xFFFFFFFFFFFFFu64 * 2 * (magnitude + 1) - self.0[3];
        let r4 = 0x0FFFFFFFFFFFFu64 * 2 * (magnitude + 1) - self.0[4];
        FieldElement([r0, r1, r2, r3, r4])
    }

    /// Returns self + rhs mod p
    pub const fn add(&self, rhs: &Self) -> Self {
        FieldElement([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
            ])
    }

    /// Returns 2*self.
    pub const fn double(&self) -> Self {
        self.add(self)
    }

    pub const fn mul_single(&self, rhs: u64) -> Self {
        FieldElement([
            self.0[0] * rhs,
            self.0[1] * rhs,
            self.0[2] * rhs,
            self.0[3] * rhs,
            self.0[4] * rhs,
            ])
    }

    /// Returns self * rhs mod p
    pub const fn mul(&self, rhs: &Self) -> Self {
        let a0 = self.0[0] as u128;
        let a1 = self.0[1] as u128;
        let a2 = self.0[2] as u128;
        let a3 = self.0[3] as u128;
        let a4 = self.0[4] as u128;
        let b0 = rhs.0[0] as u128;
        let b1 = rhs.0[1] as u128;
        let b2 = rhs.0[2] as u128;
        let b3 = rhs.0[3] as u128;
        let b4 = rhs.0[4] as u128;
        let m = 0xFFFFFFFFFFFFFu64 as u128;
        let r = 0x1000003D10u64 as u128;

        // TODO: go through the algorithm and see where temporary variables dip under 64 bits,
        // so that we can truncate them to u64 and cast back to u128,
        // making sure compiler uses faster multiplication instructions.

        //debug_assert!(verify_bits(a0, 56));
        //debug_assert!(verify_bits(a1, 56));
        //debug_assert!(verify_bits(a2, 56));
        //debug_assert!(verify_bits(a3, 56));
        //debug_assert!(verify_bits(a4, 52));

        //debug_assert!(verify_bits(b0, 56));
        //debug_assert!(verify_bits(b1, 56));
        //debug_assert!(verify_bits(b2, 56));
        //debug_assert!(verify_bits(b3, 56));
        //debug_assert!(verify_bits(b4, 52));

        // [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
        // for 0 <= x <= 4, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
        // for 4 <= x <= 8, px is a shorthand for sum(a[i]*b[x-i], i=(x-4)..4)
        // Note that [x 0 0 0 0 0] = [x*r].

        let mut d = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
        //debug_assert!(verify_bits(d, 114));
        // [d 0 0 0] = [p3 0 0 0]
        let mut c = a4 * b4;
        //debug_assert!(verify_bits(c, 112));
        // [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0]
        d += (c & m) * r; c >>= 52;
        //debug_assert!(verify_bits(d, 115));
        //debug_assert!(verify_bits(c, 60));
        // [c 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0]
        let t3 = d & m; d >>= 52;
        //debug_assert!(verify_bits(t3, 52));
        //debug_assert!(verify_bits(d, 63));
        // [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0]

        d += a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
        //debug_assert!(verify_bits(d, 115));
        // [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
        d += c * r;
        //debug_assert!(verify_bits(d, 116));
        // [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
        let mut t4 = d & m; d >>= 52;
        //debug_assert!(verify_bits(t4, 52));
        //debug_assert!(verify_bits(d, 64));
        // [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
        let tx = t4 >> 48; t4 &= m >> 4;
        //debug_assert!(verify_bits(tx, 4));
        //debug_assert!(verify_bits(t4, 48));
        // [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]

        c = a0 * b0;
        //debug_assert!(verify_bits(c, 112));
        // [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0]
        d += a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1;
        //debug_assert!(verify_bits(d, 115));
        // [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        let mut u0 = d & m; d >>= 52;
        //debug_assert!(verify_bits(u0, 52));
        //debug_assert!(verify_bits(d, 63));
        // [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        // [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        u0 = (u0 << 4) | tx;
        //debug_assert!(verify_bits(u0, 56));
        // [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        c += u0 * (r >> 4);
        //debug_assert!(verify_bits(c, 115));
        // [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        let r0 = c & m; c >>= 52;
        //debug_assert!(verify_bits(r0, 52));
        //debug_assert!(verify_bits(c, 61));
        // [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0]

        c += a0 * b1 + a1 * b0;
        //debug_assert!(verify_bits(c, 114));
        // [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0]
        d += a2 * b4 + a3 * b3 + a4 * b2;
        //debug_assert!(verify_bits(d, 114));
        // [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]
        c += (d & m) * r; d >>= 52;
        //debug_assert!(verify_bits(c, 115));
        //debug_assert!(verify_bits(d, 62));
        // [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]
        let r1 = c & m; c >>= 52;
        //debug_assert!(verify_bits(r1, 52));
        //debug_assert!(verify_bits(c, 63));
        // [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]

        c += a0 * b2 + a1 * b1 + a2 * b0;
        //debug_assert!(verify_bits(c, 114));
        // [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0]
        d += a3 * b4 + a4 * b3;
        //debug_assert!(verify_bits(d, 114));
        // [d 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        c += (d & m) * r; d >>= 52;
        //debug_assert!(verify_bits(c, 115));
        //debug_assert!(verify_bits(d, 62));
        // [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]

        // [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        let r2 = c & m; c >>= 52;
        //debug_assert!(verify_bits(r2, 52));
        //debug_assert!(verify_bits(c, 63));
        // [d 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        c += d * r + t3;
        //debug_assert!(verify_bits(c, 100));
        // [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        let r3 = c & m; c >>= 52;
        //debug_assert!(verify_bits(r3, 52));
        //debug_assert!(verify_bits(c, 48));
        // [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        c += t4;
        //debug_assert!(verify_bits(c, 49));
        // [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        let r4 = c;
        //debug_assert!(verify_bits(r4, 49));
        // [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]

        FieldElement([r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64])
    }

    /// Returns self * self mod p
    pub fn square(&self) -> Self {

        let mut a0 = self.0[0] as u128;
        let a1 = self.0[1] as u128;
        let a2 = self.0[2] as u128;
        let a3 = self.0[3] as u128;
        let mut a4 = self.0[4] as u128;
        let m = 0xFFFFFFFFFFFFFu64 as u128;
        let r = 0x1000003D10u64 as u128;

        // TODO: go through the algorithm and see where temporary variables dip under 64 bits,
        // so that we can truncate them to u64 and cast back to u128,
        // making sure compiler uses faster multiplication instructions.
        // Also check that multiplications by 2 are resolved as shifts.

        debug_assert!(verify_bits_128(a0, 56));
        debug_assert!(verify_bits_128(a1, 56));
        debug_assert!(verify_bits_128(a2, 56));
        debug_assert!(verify_bits_128(a3, 56));
        debug_assert!(verify_bits_128(a4, 52));

        // [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
        // px is a shorthand for sum(a[i]*a[x-i], i=0..x).
        // Note that [x 0 0 0 0 0] = [x*r].

        let mut d = (a0*2) * a3 + (a1*2) * a2;
        debug_assert!(verify_bits_128(d, 114));
        // [d 0 0 0] = [p3 0 0 0]
        let mut c = a4 * a4;
        debug_assert!(verify_bits_128(c, 112));
        // [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0]
        d += (c & m) * r; c >>= 52;
        debug_assert!(verify_bits_128(d, 115));
        debug_assert!(verify_bits_128(c, 60));
        // [c 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0]
        let t3 = d & m; d >>= 52;
        debug_assert!(verify_bits_128(t3, 52));
        debug_assert!(verify_bits_128(d, 63));
        // [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0]

        a4 *= 2;
        d += a0 * a4 + (a1*2) * a3 + a2 * a2;
        debug_assert!(verify_bits_128(d, 115));
        // [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
        d += c * r;
        debug_assert!(verify_bits_128(d, 116));
        // [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
        let mut t4 = d & m; d >>= 52;
        debug_assert!(verify_bits_128(t4, 52));
        debug_assert!(verify_bits_128(d, 64));
        // [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
        let tx = t4 >> 48; t4 &= m >> 4;
        debug_assert!(verify_bits_128(tx, 4));
        debug_assert!(verify_bits_128(t4, 48));
        // [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]

        c = a0 * a0;
        debug_assert!(verify_bits_128(c, 112));
        // [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0]
        d += a1 * a4 + (a2*2) * a3;
        debug_assert!(verify_bits_128(d, 114));
        // [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        let mut u0 = d & m; d >>= 52;
        debug_assert!(verify_bits_128(u0, 52));
        debug_assert!(verify_bits_128(d, 62));
        // [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        // [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        u0 = (u0 << 4) | tx;
        debug_assert!(verify_bits_128(u0, 56));
        // [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        c += u0 * (r >> 4);
        debug_assert!(verify_bits_128(c, 113));
        // [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
        let r0 = c & m; c >>= 52;
        debug_assert!(verify_bits_128(r0, 52));
        debug_assert!(verify_bits_128(c, 61));
        // [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0]

        a0 *= 2;
        c += a0 * a1;
        debug_assert!(verify_bits_128(c, 114));
        // [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0]
        d += a2 * a4 + a3 * a3;
        debug_assert!(verify_bits_128(d, 114));
        // [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]
        c += (d & m) * r; d >>= 52;
        debug_assert!(verify_bits_128(c, 115));
        debug_assert!(verify_bits_128(d, 62));
        // [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]
        let r1 = c & m; c >>= 52;
        debug_assert!(verify_bits_128(r1, 52));
        debug_assert!(verify_bits_128(c, 63));
        // [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]

        c += a0 * a2 + a1 * a1;
        debug_assert!(verify_bits_128(c, 114));
        // [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0]
        d += a3 * a4;
        debug_assert!(verify_bits_128(d, 114));
        // [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        c += (d & m) * r; d >>= 52;
        debug_assert!(verify_bits_128(c, 115));
        debug_assert!(verify_bits_128(d, 62));
        // [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        let r2 = c & m; c >>= 52;
        debug_assert!(verify_bits_128(r2, 52));
        debug_assert!(verify_bits_128(c, 63));
        // [d 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]

        c += d * r + t3;
        debug_assert!(verify_bits_128(c, 100));
        // [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        let r3 = c & m; c >>= 52;
        debug_assert!(verify_bits_128(r3, 52));
        debug_assert!(verify_bits_128(c, 48));
        // [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        c += t4;
        debug_assert!(verify_bits_128(c, 49));
        // [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
        let r4 = c;
        debug_assert!(verify_bits_128(r4, 49));
        // [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]

        FieldElement([r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64])
    }
}
