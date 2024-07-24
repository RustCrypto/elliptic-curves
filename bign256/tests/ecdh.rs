#![cfg(feature = "ecdh")]
#[test]
fn ecdh() {
    use bign256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
    use rand_core::OsRng; // requires 'getrandom' feature

    // Alice
    let alice_secret = EphemeralSecret::random(&mut OsRng);
    let alice_pk_bytes = EncodedPoint::from(alice_secret.public_key());

    // Bob
    let bob_secret = EphemeralSecret::random(&mut OsRng);
    let bob_pk_bytes = EncodedPoint::from(bob_secret.public_key());

    // Alice decodes Bob's serialized public key and computes a shared secret from it
    let bob_public =
        PublicKey::from_encoded_point(bob_pk_bytes).expect("bob's public key is invalid!"); // In real usage, don't panic, handle this!

    let alice_shared = alice_secret.diffie_hellman(&bob_public);

    // Bob decodes Alice's serialized public key and computes the same shared secret
    let alice_public =
        PublicKey::from_encoded_point(alice_pk_bytes).expect("alice's public key is invalid!"); // In real usage, don't panic, handle this!

    let bob_shared = bob_secret.diffie_hellman(&alice_public);

    // Both participants arrive on the same shared secret
    assert_eq!(
        alice_shared.raw_secret_bytes(),
        bob_shared.raw_secret_bytes()
    );
}
