//! Wycheproof `ed448_test.json` (C2SP/wycheproof `testvectors_v1`).
//! Every `valid` case must verify and every `invalid` case must be refused.

#![cfg(feature = "signing")]

use ed448_goldilocks::{Signature, VerifyingKey};
use serde_json::Value;

const VECTORS: &str = include_str!("ed448_test.json");

#[test]
fn wycheproof_ed448_verify() {
    let root: Value = serde_json::from_str(VECTORS).unwrap();
    let mut run = 0;
    let mut saw_encoding_cases = 0;
    for group in root["testGroups"].as_array().unwrap() {
        let pk = hex::decode(group["publicKey"]["pk"].as_str().unwrap()).unwrap();
        let key = pk
            .as_slice()
            .try_into()
            .ok()
            .and_then(|bytes| VerifyingKey::from_bytes(bytes).ok());
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex::decode(test["msg"].as_str().unwrap()).unwrap();
            let sig = hex::decode(test["sig"].as_str().unwrap()).unwrap();
            let accepted = match (&key, Signature::try_from(sig.as_slice())) {
                (Some(key), Ok(sig)) => key.verify_raw(&sig, &msg).is_ok(),
                _ => false,
            };
            match test["result"].as_str().unwrap() {
                "valid" => assert!(accepted, "tcId {tc_id}: valid case refused"),
                "invalid" => assert!(!accepted, "tcId {tc_id}: invalid case accepted"),
                other => panic!("tcId {tc_id}: unexpected result {other}"),
            }
            if (63..=65).contains(&tc_id) {
                saw_encoding_cases += 1;
            }
            run += 1;
        }
    }
    assert_eq!(run, root["numberOfTests"].as_u64().unwrap());
    assert_eq!(saw_encoding_cases, 3, "tcIds 63 to 65 must be present");
}
