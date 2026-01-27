# P-521 Security Hardening Checklist

This document records the security hardening audit and changes applied to the **p521** crate in this fork. The goal is constant-time and side-channel resistance for operations on secret scalars, private keys, and ECDSA intermediates (NIST SP 800-186, RFC 6979).

## Scope

- **In scope:** Only code under `p521/` (Cargo.toml, src/, tests/, docs). Public API is unchanged.
- **Out of scope:** No changes to workspace crates `primefield`, `primeorder`, or upstream `elliptic-curve` / `ecdsa` unless strictly necessary and documented.
- **Consumer:** Veritru uses p521 via the sad-p521 wrapper with the `ecdsa` feature.

## Audit: Modules and Functions Touching Secret or Partially Secret Data

### 1. `p521/src/arithmetic/scalar.rs`

| Area | Secret data | Constant-time? | Notes |
|------|-------------|----------------|-------|
| `Scalar` type | Scalar field elements (e.g. private key, nonce) | Yes | From `primefield` monty macros: uses `ConditionallySelectable`, `ConstantTimeEq`, constant-time ops. |
| `Reduce<Uint>` | Reduced integer (may be secret) | Yes | Uses `Uint::conditional_select` for reduction result; no branch on secret. |
| `Reduce<FieldBytes>` | Decoded bytes | Yes | Delegates to `Reduce<Uint>`. |
| `IsHigh` | Canonical scalar | Yes | Uses `ct_gt` for high-half check. |
| `from_uint_unchecked` | Input uint | N/A | Used with already-valid or constant inputs in this crate. |

**Vartime usage:** `MODULUS_SHR1` uses `shr_vartime` on the **constant** curve order; not secret-dependent.

**Hardening:** No code changes required. Module-level comment added to state constant-time intent.

---

### 2. `p521/src/arithmetic/field.rs`

| Area | Secret data | Constant-time? | Notes |
|------|-------------|----------------|-------|
| `FieldElement` comparison | May be secret (e.g. coordinates) | Yes | `ConstantTimeEq::ct_eq`, `PartialEq` implemented via `ct_eq`. |
| `ConditionallySelectable` | Selection mask | Yes | Limb-wise `conditional_select`. |
| `from_bytes` / `from_uint` | Decoded value | Yes | `CtOption`; validity uses `uint.ct_lt(&MODULUS)`. |
| `invert` | Divisor | Yes | Uses constant-time `invert_odd_mod` from crypto-bigint. |
| `sqrt` | Radicand | Yes | Uses `ct_eq` for verification; `sqn(519)` with fixed exponent. |
| `is_zero`, `is_odd` | Possibly secret | Yes | `is_zero` uses `ct_eq`; `is_odd` uses low-bit mask (no branch). |
| `pow_vartime` | Exponent | **Variable-time** | Branches on exponent bits. **Not used with secret exponents** in p521 (only `sqn` with constant 519). Documented. |
| `sqn_vartime` | Exponent `n` | **Variable-time** | Fixed iteration when `n` is constant (e.g. 519 in `sqrt`). Documented. |
| `invert_vartime` | Divisor | **Variable-time** | Explicitly vartime; for non-secret or compatibility. |

**Hardening:** No change to behavior. Comments added for constant-time vs variable-time intent. Callers must not use `pow_vartime`/`sqn_vartime` with secret exponents.

---

### 3. `p521/src/arithmetic/field/loose.rs`

| Area | Secret data | Constant-time? | Notes |
|------|-------------|----------------|-------|
| `LooseFieldElement` | Intermediate field values | N/A | No comparisons or branches on values; fiat-crypto carry/mul are data-independent. |

**Hardening:** No changes.

---

### 4. `p521/src/arithmetic/hash2curve.rs`

| Area | Secret data | Constant-time? | Notes |
|------|-------------|----------------|-------|
| `Reduce<Array<u8, U98>>` for `Scalar` | Output scalar (may be key material) | Yes | Uses `Scalar::reduce` and fixed constant `F_2_392` (`from_hex_vartime` on constant). |
| `Reduce` for `FieldElement` | Output field element | Yes | No secret-dependent control flow. |
| OPRF / map_to_curve | Uses field/scalar types | As in field/scalar | No additional branches on secrets in this file. |

**Test code (line ~312):** `if !bool::from(scalar.is_zero())` in test vector loop — test-only; scalar is derived from test data, not a long-term secret. Acceptable.

**Hardening:** No production code changes. Optional: document that constant-time scalar reduction is used for hash-to-scalar.

---

### 5. `p521/src/ecdsa.rs` and `p521/src/ecdh.rs`

| Area | Secret data | Constant-time? | Notes |
|------|-------------|----------------|-------|
| ECDSA | SigningKey, nonce, intermediates | In **ecdsa** crate | p521 only re-exports types and implements `EcdsaCurve` (e.g. `NORMALIZE_S`, digest). No p521-specific logic on secrets. |
| ECDH | EphemeralSecret, shared secret | In **elliptic-curve** crate | Type aliases only. |

**Hardening:** Document in SECURITY.md that ECDSA/ECDH constant-time behavior depends on upstream `ecdsa` and `elliptic-curve` (and that scalar multiplication is in `primeorder`, see below).

---

### 6. Scalar multiplication and point operations

Scalar multiplication (e.g. for ECDSA signing and ECDH) is implemented in the **primeorder** crate (used by p521 via `PrimeCurveParams`):

- **Implementation:** Fixed-window scalar multiplication with a 16-point lookup table and `ConditionallySelectable::conditional_assign` for table indexing. Loop count is fixed (based on `Scalar::NUM_BITS`). No branch on scalar bits in the hot path.
- **Assessment:** Constant-time with respect to the scalar for the primeorder implementation in this workspace.
- **Scope:** We do not modify primeorder in this hardening pass; p521 documents reliance on it.

---

## Summary of Hardening Changes Applied

1. **Documentation**
   - Added this `HARDENING.md` with the audit and checklist.
   - Added `SECURITY.md` describing the fork and hardening scope.
   - Updated `README.md` with a short security-hardening fork notice.
   - Added module- and function-level comments in `arithmetic/scalar.rs` and `arithmetic/field.rs` stating constant-time (or variable-time) intent where relevant.

2. **Code**
   - No changes required to scalar or field arithmetic for constant-time correctness; existing use of `subtle` and constant-time patterns was already appropriate.
   - Confirmed: no secret-dependent `==` or early returns in p521 production code paths; comparisons use `ct_eq` or `CtOption`.

3. **Tests**
   - Added tests to ensure `ConstantTimeEq` (`ct_eq`) behaves correctly for `Scalar` and `FieldElement` (same value → true, different → false), to guard against accidental API changes.
   - Timing-based constant-time tests (e.g. measuring that equal vs different inputs take similar time) are not run in CI: they are environment-sensitive and can be flaky. Manual review and the use of constant-time primitives (`ct_eq`, `conditional_select`, fixed-loop scalar mul in primeorder) are documented instead.

4. **CI**
   - p521 workflow already runs `cargo test -p p521` (and full feature matrix). Added `cargo clippy -p p521 -- -D warnings` to the p521 workflow so hardening-related code stays lint-clean.

5. **Changelog / NOTICE**
   - Recorded upstream base and hardening date in `CHANGELOG.md` and optionally in README/SECURITY.

## Remaining Caveats

- **No formal audit:** The implementation has not been formally audited for constant-time or other cryptographic safety.
- **Upstream dependency:** ECDSA signing/verification and ECDH logic live in `ecdsa` and `elliptic-curve`; scalar multiplication lives in `primeorder`. This fork’s hardening focus is the p521 crate’s own code and documentation.
- **Variable-time helpers:** `pow_vartime`, `sqn_vartime`, and `invert_vartime` remain for fixed or non-secret use; callers must not pass secret exponents or secret divisors when constant-time is required.
