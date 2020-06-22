#[cfg(feature = "arithmetic")]
use p256::arithmetic::Scalar;

#[cfg(not(feature = "arithmetic"))]
fn main() {}

#[cfg(feature = "arithmetic")]
fn main() {
    let secret_seed = [1u8; 32];
    let secret_maybe_scalar = Scalar::from_bytes(secret_seed);
    let secret_scalar = secret_maybe_scalar.unwrap();

    let ephemeral_seed = [2u8; 32];
    let ephemeral_maybe_scalar = Scalar::from_bytes(ephemeral_seed);
    let ephemeral_scalar = ephemeral_maybe_scalar.unwrap();

    let hashed_msg = [3u8; 32];

    let masking_seed = [4u8; 32];
    let masking_maybe_scalar = Scalar::from_bytes(masking_seed);
    let masking_scalar = masking_maybe_scalar.unwrap();

    let signature = secret_scalar
        .try_sign_prehashed(ephemeral_scalar, Some(masking_scalar), &hashed_msg)
        .unwrap();

    println!("signature: {:02x?}", signature.as_ref());
}
