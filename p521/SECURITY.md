# Security

## Security-hardening fork

This crate is a **security-hardening fork** of the RustCrypto **p521** implementation. It is maintained by sadco-io and consumed by **Veritru** (via the sad-p521 wrapper).

- **Upstream:** [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves) (p521 subtree).
- **Fork focus:** Improve constant-time and side-channel resistance for P-521 operations so that ECDSA signing and verification do not leak secret material through timing or branching. The public API and existing tests are preserved.

## Hardening applied

- **Constant-time scalar and field operations:** Operations on secret scalars (e.g. in ECDSA signing and scalar multiplication) avoid branching or indexing on secret data. The crate uses the `subtle` crate (and re-exports from `elliptic_curve` / primefield) for:
  - **Comparisons:** `ConstantTimeEq` / `ct_eq` for any comparison involving secret or partially secret material.
  - **Selection:** `ConditionallySelectable` / `conditional_select` instead of `if` on secret values.
  - **Optional values:** `CtOption` where failure must not leak.
- **Scalar multiplication:** Carried out in the **primeorder** crate with a constant-time, fixed-window approach (lookup table + conditional selection). No secret-dependent control flow in the scalar-mul path used by p521.
- **Secret comparisons:** No plain `==` or early returns on secret material in p521 code paths; constant-time equality is used where values may be secret.
- **Documentation:** Module- and function-level comments in p521 describe constant-time vs variable-time intent. Variable-time helpers (e.g. `pow_vartime`, `invert_vartime`) are documented and must not be used with secret exponents or divisors when constant-time is required.

See **[HARDENING.md](HARDENING.md)** for the full audit and checklist.

## Caveats

- **Not independently audited:** This implementation has not been formally audited. Use at your own risk.
- **Upstream dependency:** ECDSA and ECDH logic live in the `ecdsa` and `elliptic-curve` crates; scalar multiplication is in `primeorder`. Hardening in this repo focuses on the p521 crate’s own code and documentation.
- **Variable-time code:** Some helpers (e.g. `pow_vartime`, `sqn_vartime`, `invert_vartime`) are variable-time by design; they are only safe for non-secret or fixed inputs. See HARDENING.md.

## Reporting issues

Security-sensitive issues can be reported to the maintainers of this fork (sadco-io). For upstream RustCrypto code, consider also reporting to the [RustCrypto maintainers](https://github.com/RustCrypto/elliptic-curves).
