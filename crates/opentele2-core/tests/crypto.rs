//! Golden-vector tests for `crypto` and `kdf` against the 1.5.0 outputs in
//! `tests/vectors/crypto.json`, plus the length and cap failure paths.

use std::fs;
use std::path::Path;

use opentele2_core::Error;
use opentele2_core::crypto::{
    self, AuthKey, aes_ige_decrypt, aes_ige_encrypt, decrypt_local, encrypt_local,
    encrypt_local_random, prepare_aes_oldmtp,
};
use opentele2_core::kdf;
use serde_json::Value;

fn vectors() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/crypto.json");
    let text = fs::read_to_string(&path).expect("read crypto.json");
    serde_json::from_str(&text).expect("parse crypto.json")
}

fn cases<'v>(vectors: &'v Value, key: &str) -> &'v [Value] {
    let cases = vectors[key].as_array().expect("vector array");
    assert!(!cases.is_empty(), "{key} has no cases");
    cases
}

fn text<'v>(case: &'v Value, key: &str) -> &'v str {
    case[key].as_str().expect("string field")
}

fn unhex(case: &Value, key: &str) -> Vec<u8> {
    hex::decode(text(case, key)).expect("hex field")
}

fn uint(case: &Value, key: &str) -> u32 {
    u32::try_from(case[key].as_u64().expect("integer field")).expect("u32 field")
}

fn auth_key(case: &Value, key: &str) -> AuthKey {
    AuthKey::from_slice(&unhex(case, key)).expect("256-byte key")
}

fn assert_bad_length<T: std::fmt::Debug>(result: Result<T, Error>, what: &str) {
    match result {
        Err(Error::BadLength { what: got, .. }) => assert_eq!(got, what),
        other => panic!("expected BadLength for {what}, got {other:?}"),
    }
}

#[test]
fn key_id_vectors() {
    for (i, case) in cases(&vectors(), "key_id").iter().enumerate() {
        let key = auth_key(case, "auth_key");
        let expected: u64 = text(case, "key_id").parse().expect("decimal key_id");
        assert_eq!(key.key_id(), expected, "key_id case {i}");
        assert_eq!(
            hex::encode(key.key_id().to_le_bytes()),
            text(case, "key_id_le"),
            "key_id_le case {i}"
        );
    }
}

#[test]
fn prepare_aes_oldmtp_vectors() {
    let vectors = vectors();
    let all = cases(&vectors, "prepare_aes_oldmtp");
    assert!(all.iter().any(|c| c["send"] == true) && all.iter().any(|c| c["send"] == false));
    for (i, case) in all.iter().enumerate() {
        let key = auth_key(case, "auth_key");
        let msg_key: [u8; 16] = unhex(case, "msg_key").try_into().expect("16-byte msg_key");
        let send = case["send"].as_bool().expect("send flag");
        let (aes_key, aes_iv) = prepare_aes_oldmtp(&key, &msg_key, send);
        assert_eq!(
            hex::encode(aes_key),
            text(case, "aes_key"),
            "aes_key case {i}"
        );
        assert_eq!(hex::encode(aes_iv), text(case, "aes_iv"), "aes_iv case {i}");
    }
}

#[test]
fn encrypt_local_vectors() {
    for (i, case) in cases(&vectors(), "encrypt_local").iter().enumerate() {
        let key = auth_key(case, "local_key");
        let payload = unhex(case, "payload");
        let padding = unhex(case, "padding");
        let decrypted = unhex(case, "decrypted");
        let encrypted = unhex(case, "encrypted");

        // `decrypted` is the 1.5.0 descriptor: LE u32 real length, then payload.
        let real_len = u32::try_from(payload.len() + 4).expect("u32 length");
        assert_eq!(decrypted[..4], real_len.to_le_bytes(), "header case {i}");
        assert_eq!(decrypted[4..], payload[..], "descriptor case {i}");
        assert_eq!(crypto::local_padding_len(payload.len()), padding.len());

        let out = encrypt_local(&payload, &key, |len| {
            assert_eq!(len, padding.len(), "padding request case {i}");
            padding.clone()
        })
        .expect("encrypt_local");
        assert_eq!(
            hex::encode(&out),
            text(case, "encrypted"),
            "encrypted case {i}"
        );
        assert_eq!(
            hex::encode(&out[..16]),
            text(case, "msg_key"),
            "msg_key case {i}"
        );

        assert_eq!(
            decrypt_local(&encrypted, &key).expect("decrypt_local"),
            payload
        );

        // Raw IGE of the body reproduces descriptor plus padding.
        let msg_key: [u8; 16] = encrypted[..16].try_into().expect("msg_key");
        let (aes_key, aes_iv) = prepare_aes_oldmtp(&key, &msg_key, false);
        let mut body = encrypted[16..].to_vec();
        aes_ige_decrypt(&mut body, &aes_key, &aes_iv).expect("ige decrypt");
        assert_eq!(body, [decrypted.as_slice(), padding.as_slice()].concat());
        aes_ige_encrypt(&mut body, &aes_key, &aes_iv).expect("ige encrypt");
        assert_eq!(body, encrypted[16..]);
    }
}

#[test]
fn create_local_key_vectors() {
    for (i, case) in cases(&vectors(), "create_local_key").iter().enumerate() {
        let key = kdf::create_local_key(text(case, "passcode").as_bytes(), &unhex(case, "salt"));
        assert_eq!(hex::encode(key.as_bytes()), text(case, "key"), "case {i}");
    }
}

#[test]
fn create_legacy_local_key_vectors() {
    for (i, case) in cases(&vectors(), "create_legacy_local_key")
        .iter()
        .enumerate()
    {
        let passcode = text(case, "passcode").as_bytes();
        let key = kdf::create_legacy_local_key(passcode, &unhex(case, "salt"));
        assert_eq!(hex::encode(key.as_bytes()), text(case, "key"), "case {i}");
    }
}

#[test]
fn argon2id_wrap_vector() {
    let vectors = vectors();
    let case = &vectors["argon2id_wrap"];
    assert_eq!(uint(case, "kind"), 1, "KDF_ARGON2ID");
    assert_eq!(uint(case, "argon2_version"), 0x13);

    let wrap = kdf::argon2id(
        text(case, "passcode").as_bytes(),
        &unhex(case, "salt"),
        uint(case, "memory_kib"),
        uint(case, "time"),
        uint(case, "lanes"),
    )
    .expect("argon2id");
    assert_eq!(hex::encode(wrap), text(case, "wrap_key"), "wrap_key");

    let wrap = AuthKey::new(wrap);
    let key_encrypted = unhex(case, "key_encrypted");
    let local_key = decrypt_local(&key_encrypted, &wrap).expect("unwrap local key");
    assert_eq!(
        hex::encode(&local_key),
        text(case, "local_key"),
        "local_key"
    );

    let padding = unhex(case, "padding");
    let rewrapped = encrypt_local(&local_key, &wrap, |_| padding).expect("rewrap");
    assert_eq!(rewrapped, key_encrypted, "key_encrypted");
}

#[test]
fn ige_bad_lengths_return_err_without_panicking() {
    let key = [7u8; 32];
    let iv = [9u8; 32];
    let mut short = [1u8; 15];
    assert_bad_length(aes_ige_encrypt(&mut short, &key, &iv), "AES-IGE buffer");
    assert_bad_length(aes_ige_decrypt(&mut short, &key, &iv), "AES-IGE buffer");
    assert_eq!(short, [1u8; 15], "buffer untouched on error");

    let mut block = [1u8; 16];
    assert_bad_length(aes_ige_encrypt(&mut block, &key[..31], &iv), "AES-IGE key");
    assert_bad_length(aes_ige_decrypt(&mut block, &key, &[0u8; 33]), "AES-IGE iv");
    assert_eq!(block, [1u8; 16], "buffer untouched on error");

    let mut empty: [u8; 0] = [];
    aes_ige_encrypt(&mut empty, &key, &iv).expect("empty buffer is whole blocks");
    assert_bad_length(AuthKey::from_slice(&[0u8; 255]), "auth key");
}

#[test]
fn local_round_trip_and_failures() {
    let key = AuthKey::new(core::array::from_fn(|i| u8::try_from(i).expect("byte")));
    let other = AuthKey::new([0x5a; 256]);

    for len in [0usize, 1, 11, 12, 13, 300] {
        let data = vec![0xc3; len];
        let encrypted = encrypt_local_random(&data, &key).expect("encrypt");
        assert_eq!(encrypted.len(), 16 + (len + 4).next_multiple_of(16));
        assert_eq!(decrypt_local(&encrypted, &key).expect("decrypt"), data);
        assert!(matches!(
            decrypt_local(&encrypted, &other),
            Err(Error::BadDecryptKey)
        ));
    }

    for size in [0usize, 15, 16, 33] {
        assert!(matches!(
            decrypt_local(&vec![0u8; size], &key),
            Err(Error::BadEncryptedDataSize { size: found }) if found == size
        ));
    }

    assert_bad_length(encrypt_local(b"abc", &key, |_| vec![0; 3]), "local padding");

    // A correctly keyed plaintext whose length header is too small.
    let mut plain = [0u8; 32];
    plain[..4].copy_from_slice(&2u32.to_le_bytes());
    let mut msg_key = [0u8; 16];
    msg_key.copy_from_slice(&sha1_prefix(&plain));
    let (aes_key, aes_iv) = prepare_aes_oldmtp(&key, &msg_key, false);
    aes_ige_encrypt(&mut plain, &aes_key, &aes_iv).expect("encrypt");
    let forged = [msg_key.as_slice(), plain.as_slice()].concat();
    assert!(matches!(
        decrypt_local(&forged, &key),
        Err(Error::BadDecryptedDataSize {
            encrypted_size: 48,
            full_len: 32,
            decrypted_size: 32
        })
    ));
}

/// `sha1(data)[..16]`, the local message key of a plaintext.
fn sha1_prefix(data: &[u8]) -> [u8; 16] {
    use sha1::{Digest, Sha1};
    let mut out = [0u8; 16];
    out.copy_from_slice(&Sha1::digest(data)[..16]);
    out
}

#[test]
fn auth_key_debug_hides_key_material() {
    let key = AuthKey::new([0xab; 256]);
    let shown = format!("{key:?}");
    assert!(shown.contains("key_id"));
    assert!(!shown.contains("abab"), "{shown}");
}

#[test]
fn argon2id_enforces_read_caps() {
    let salt = [1u8; 32];
    assert_bad_length(kdf::argon2id(b"", &salt, 64, 1, 1), "passcode");
    assert_bad_length(kdf::argon2id(b"pw", &salt[..7], 64, 1, 1), "passcode salt");
    assert_bad_length(
        kdf::argon2id(b"pw", &salt, kdf::ARGON2_MAX_MEMORY_KIB + 1, 1, 1),
        "Argon2id memory_kib",
    );
    assert_bad_length(kdf::argon2id(b"pw", &salt, 64, 65, 1), "Argon2id time");
    assert_bad_length(kdf::argon2id(b"pw", &salt, 256, 1, 17), "Argon2id lanes");
    for (memory, time, lanes) in [(64, 0, 1), (64, 1, 0), (15, 1, 2)] {
        assert!(matches!(
            kdf::argon2id(b"pw", &salt, memory, time, lanes),
            Err(Error::BadDecryptKey)
        ));
    }
    kdf::argon2id(b"pw", &salt, 16, 1, 2).expect("smallest valid cost");
}

#[test]
fn scrypt_matches_rfc7914_and_enforces_read_caps() {
    // RFC 7914 section 12, third vector; PBKDF2 output blocks are independent,
    // so the 256-byte key starts with the RFC's 64-byte key.
    let key = kdf::scrypt(b"pleaseletmein", b"SodiumChloride", 16384, 8, 1).expect("scrypt");
    assert_eq!(
        hex::encode(&key[..64]),
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2\
         d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
    );

    let salt = [2u8; 16];
    assert_bad_length(kdf::scrypt(b"", &salt, 1024, 8, 1), "passcode");
    assert_bad_length(kdf::scrypt(b"pw", &salt[..7], 1024, 8, 1), "passcode salt");
    assert_bad_length(kdf::scrypt(b"pw", &salt, 1 << 21, 1, 1), "scrypt N");
    assert_bad_length(kdf::scrypt(b"pw", &salt, 1024, 33, 1), "scrypt r");
    assert_bad_length(kdf::scrypt(b"pw", &salt, 1024, 8, 17), "scrypt p");
    for (n, r, p) in [
        (0, 8, 1),
        (1, 8, 1),
        (1000, 8, 1),
        (1024, 0, 1),
        (1024, 8, 0),
    ] {
        assert!(matches!(
            kdf::scrypt(b"pw", &salt, n, r, p),
            Err(Error::BadDecryptKey)
        ));
    }
    // Inside every cap but 1 GiB of memory: refused like hashlib's maxmem.
    assert!(matches!(
        kdf::scrypt(b"pw", &salt, 1 << 20, 8, 1),
        Err(Error::BadDecryptKey)
    ));
}
