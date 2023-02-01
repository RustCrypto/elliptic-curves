/// Implement field element inversion.
macro_rules! impl_field_invert {
    (
        $a:expr,
        $one:expr,
        $word_bits:expr,
        $nlimbs:expr,
        $mul:ident,
        $neg:ident,
        $divstep_precomp:ident,
        $divstep:ident,
        $msat:ident,
        $selectznz:ident,
    ) => {{
        const ITERATIONS: usize = (49 * $nlimbs * $word_bits + 57) / 17;

        let mut d = 1;
        let mut f = $msat();
        let mut g = [0; $nlimbs + 1];
        let mut v = [0; $nlimbs];
        let mut r = $one;
        let mut i = 0;
        let mut j = 0;

        while j < $nlimbs {
            g[j] = $a[j];
            j += 1;
        }

        while i < ITERATIONS - ITERATIONS % 2 {
            let (out1, out2, out3, out4, out5) = $divstep(d, &f, &g, &v, &r);
            let (out1, out2, out3, out4, out5) = $divstep(out1, &out2, &out3, &out4, &out5);
            d = out1;
            f = out2;
            g = out3;
            v = out4;
            r = out5;
            i += 2;
        }

        if ITERATIONS % 2 != 0 {
            let (_out1, out2, _out3, out4, _out5) = $divstep(d, &f, &g, &v, &r);
            v = out4;
            f = out2;
        }

        let s = ((f[f.len() - 1] >> $word_bits - 1) & 1) as u8;
        let v = $selectznz(s, &v, &$neg(&v));
        $mul(&v, &$divstep_precomp())
    }};
}
