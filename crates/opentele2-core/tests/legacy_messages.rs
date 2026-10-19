//! `Error::legacy_message` against the messages 1.5.0 raised on the same
//! inputs.
//!
//! Every expected string was captured by running the 1.5.0 sources under
//! `src/` (with `OPENTELE_NO_FETCH=1` set before `import src`) on the input
//! the test builds: `Storage.ReadFile`, `Storage.DecryptLocal`,
//! `MapData.read`, `Account._setMtpAuthorization`, `Account.FromTelethon`,
//! `read_key_data`, `create_passcode_key`, `TDesktop.__loadFromTData`,
//! `TDesktop.SaveTData`, `MTP.DcOptions.constructFromSerialized` and
//! `MTP.Config.FromSerialized`, reading the exception's `message`. Key
//! bytes are never printed.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use opentele2_core::crypto::{AuthKey, aes_ige_encrypt, decrypt_local, prepare_aes_oldmtp};
use opentele2_core::tdata::TData;
use opentele2_core::tdata::account::Account;
use opentele2_core::tdata::map::MapData;
use opentele2_core::tdf::{self, TdfFile};
use opentele2_core::{Error, MagicContext, MapReadFailure, Result};

/// A fresh, empty directory under the target tmp dir.
fn scratch(label: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "legacy_messages_{label}_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clear scratch");
    }
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

fn message<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("the call succeeded"),
        Err(error) => error.legacy_message(),
    }
}

/// The 256-byte key `bytes(range(256))` the captures used.
fn counting_key() -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| {
        u8::try_from(i).expect("index fits a byte")
    }))
}

#[test]
fn read_file_messages_match_1_5_0() {
    let dir = scratch("read_file");
    assert_eq!(message(tdf::read(&dir, "map")), "Could not open map");

    let with_magic = |name: &str, magic: &[u8]| {
        let mut data = magic.to_vec();
        data.extend_from_slice(&[0; 30]);
        fs::write(dir.join(name), data).expect("write file");
    };
    with_magic("mapss", b"ABCD");
    assert_eq!(
        message(tdf::read(&dir, "maps")),
        "Invalid magic b'ABCD' in file maps"
    );
    with_magic("q1s", b"T'\x00\xff");
    assert_eq!(
        message(tdf::read(&dir, "q1")),
        r#"Invalid magic b"T'\x00\xff" in file q1"#
    );
    with_magic("q2s", b"'\"\\\n");
    assert_eq!(
        message(tdf::read(&dir, "q2")),
        r#"Invalid magic b'\'"\\\n' in file q2"#
    );
    // The `1` suffix is read when `s` is absent.
    with_magic("q31", b"\t\r\x7f~");
    assert_eq!(
        message(tdf::read(&dir, "q3")),
        r"Invalid magic b'\t\r\x7f~' in file q3"
    );

    let mut data = b"TDF$".to_vec();
    data.extend_from_slice(&7_003_001u32.to_le_bytes());
    data.extend_from_slice(b"hello world");
    data.extend_from_slice(&[0; 16]);
    fs::write(dir.join("cks"), &data).expect("write file");
    let error = tdf::read(&dir, "ck").expect_err("bad checksum");
    assert_eq!(error.code(), "TDATA_INVALID_CHECKSUM");
    assert_eq!(
        error.legacy_message(),
        "Invalid checksum 78e20993e8b2d57b5f190eb51b1e8d63 in file ck"
    );
    fs::remove_dir_all(&dir).expect("clean scratch");
}

#[test]
fn parse_errors_carry_the_magic_and_checksum() {
    let error = TdfFile::parse(b"ABCD\0\0\0\0").expect_err("bad magic");
    assert!(matches!(
        error,
        Error::InvalidMagic {
            context: MagicContext::File { ref file, ref magic },
        } if file.is_empty() && magic == b"ABCD"
    ));
    let mut data = b"TDF$".to_vec();
    data.extend_from_slice(&7_003_001u32.to_le_bytes());
    data.extend_from_slice(b"hello world");
    data.extend_from_slice(&[0; 16]);
    assert_eq!(
        message(TdfFile::parse(&data)),
        "Invalid checksum 78e20993e8b2d57b5f190eb51b1e8d63 in file "
    );
}

#[test]
fn decrypt_local_messages_match_1_5_0() {
    let key = counting_key();
    assert_eq!(
        message(decrypt_local(&[0; 16], &key)),
        "Bad encrypted part size: 16"
    );
    assert_eq!(
        message(decrypt_local(&[0; 33], &key)),
        "Bad encrypted part size: 33"
    );
    assert_eq!(
        message(decrypt_local(&[0; 48], &key)),
        "Bad decrypt key, data not decrypted - incorrect password?"
    );

    // A correctly keyed plaintext whose length header says 2.
    let mut plain = [0u8; 32];
    plain[..4].copy_from_slice(&2u32.to_le_bytes());
    let mut msg_key = [0u8; 16];
    {
        use sha1::{Digest, Sha1};
        msg_key.copy_from_slice(&Sha1::digest(plain)[..16]);
    }
    let (aes_key, aes_iv) = prepare_aes_oldmtp(&key, &msg_key, false);
    aes_ige_encrypt(&mut plain, &aes_key, &aes_iv).expect("encrypt");
    let forged = [msg_key.as_slice(), plain.as_slice()].concat();
    assert_eq!(
        message(decrypt_local(&forged, &key)),
        "Bad decrypted part size: 48, fullLen: 32, decrypted size: 32"
    );
}

/// Writes a `maps` file holding `payload` into `dir`.
fn write_map(dir: &Path, payload: Vec<u8>) {
    tdf::write(
        dir,
        "map",
        &TdfFile {
            version: 7_003_001,
            payload,
        },
    )
    .expect("write maps");
}

/// A big-endian `QByteArray` of `bytes`.
fn qbytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(bytes.len())
        .expect("short array")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(bytes);
    out
}

#[test]
fn map_read_messages_match_1_5_0() {
    let dir = scratch("map");
    let key = counting_key();
    assert_eq!(
        message(MapData::read(&dir, &key)),
        "Could not read map data, file not found or couldn't be opened"
    );

    let mut payload = qbytes(&[0; 5]);
    payload.extend_from_slice(&u32::MAX.to_be_bytes());
    payload.extend_from_slice(&qbytes(&[0; 48]));
    write_map(&dir, payload);
    assert_eq!(
        message(MapData::read(&dir, &key)),
        "Could not decrypt map data"
    );

    let mut payload = 16u32.to_be_bytes().to_vec();
    payload.extend_from_slice(b"abc");
    write_map(&dir, payload);
    assert_eq!(
        message(MapData::read(&dir, &key)),
        "Could not stream data from mapData"
    );
    fs::remove_dir_all(&dir).expect("clean scratch");

    // The legacy-passcode read is 1.5.0's only; its messages are given
    // for bindings that implement it.
    let bad_salt = Error::ReadMapDataFailed {
        context: MapReadFailure::BadSalt { size: 5 },
    };
    assert_eq!(bad_salt.legacy_message(), "Bad salt in map file, size: 5");
    assert_eq!(bad_salt.code(), "TDATA_READ_MAP_DATA_FAILED");
    assert_eq!(
        Error::ReadMapDataIncorrectPasscode.legacy_message(),
        "Could not decrypt pass-protected key from map file, maybe bad password..."
    );
}

#[test]
fn mtp_authorization_messages_match_1_5_0() {
    assert_eq!(
        message(Account::parse_mtp_authorization(0, b"")),
        "Could not read main fields from mtp authorization."
    );
    assert_eq!(
        message(Account::parse_mtp_authorization(0, &[0; 8])),
        "Could not read keys count from mtp authorization."
    );
    assert_eq!(
        message(Account::parse_mtp_authorization(0, &[0; 16])),
        "Could not find the main authKey"
    );
    let error = Account::parse_mtp_authorization(0, &[0; 4]).expect_err("cut short");
    assert_eq!(error.code(), "QDATASTREAM_FAILED");
}

/// 1.5.0 skips an unknown MTP data block, so it never raised this; the text
/// is its `_readMtpData` format (`src/td/storage_account.py:122`).
#[test]
fn unknown_mtp_data_block_names_the_block_id() {
    let error = Account::parse_mtp_data(0, &0x1234_5678u32.to_be_bytes()).expect_err("unknown");
    assert_eq!(error.code(), "TDATA_INVALID_MAGIC");
    assert_eq!(
        error.legacy_message(),
        "Unsupported block id in MtpData: 305419896"
    );
}

#[test]
fn account_limit_message_matches_1_5_0() {
    let accounts = (0..6)
        .map(|index| {
            Account::new(index, 1, 2, vec![(2, AuthKey::new([0; AuthKey::SIZE]))]).expect("account")
        })
        .collect();
    let mut no_draw = |_: &mut [u8]| panic!("performance mode draws nothing");
    let mut tdata = TData::new(accounts, b"", true, &mut no_draw).expect("new");
    assert_eq!(
        message(tdata.add_account(1, 2, AuthKey::new([0; AuthKey::SIZE]))),
        "You can't have more than 6 accounts in one TDesktop client"
    );
}

/// Big-endian `u32`s.
fn be32(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

/// Big-endian `i32`s.
fn bei32(values: &[i32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

/// One trailer wrap: kind, generation, memory, time, parallelism, the salt
/// and a 48-byte wrapped key.
fn wrap(kdf: [u32; 5], salt: &[u8]) -> Vec<u8> {
    [be32(&kdf), qbytes(salt), qbytes(&[0; 48])].concat()
}

/// The inputs `read_key_data` was run on in 1.5.0 (`src/td/key_data.py:213`),
/// with the message it raised for each.
#[test]
fn key_data_messages_match_1_5_0() {
    use opentele2_core::tdata::key_data::KeyData;

    let head = [qbytes(&[0; 32]), qbytes(&[0; 48]), qbytes(&[0; 48])].concat();
    let trailer = |blob: Vec<u8>| [head.clone(), qbytes(&blob)].concat();
    let header = |format: u32, count: u32| be32(&[0x4B44_3200, format, 1, count]);
    let argon2 = |generation: u32| wrap([1, generation, 65_536, 8, 1], &[0; 32]);
    let cases: [(&str, Vec<u8>, &str); 14] = [
        (
            "salt",
            [qbytes(&[0; 5]), qbytes(&[0; 48]), qbytes(&[0; 48])].concat(),
            "Bad salt in key data, size: 5",
        ),
        ("short", Vec::new(), "Could not stream the key data"),
        (
            "two blobs",
            [qbytes(&[0; 32]), qbytes(&[0; 48])].concat(),
            "Could not stream the key data",
        ),
        (
            "trailer short",
            [head.clone(), be32(&[16])].concat(),
            "Could not stream the key data trailer",
        ),
        (
            "header short",
            trailer(be32(&[0x4B44_3200, 2])),
            "Could not stream the key data trailer header",
        ),
        (
            "magic",
            trailer(be32(&[0, 2, 0, 0])),
            "Bad key data trailer magic",
        ),
        ("count", trailer(header(2, 3)), "Bad key data wrap count: 3"),
        (
            "count newer",
            trailer(be32(&[0x4B44_3200, 3, 0, 17])),
            "Bad key data wrap count: 17",
        ),
        (
            "kind 0",
            trailer([header(2, 1), wrap([0, 1, 0, 0, 0], &[0; 32])].concat()),
            "Bad key data KDF family: 0",
        ),
        (
            "scrypt N not a power of two",
            trailer([header(2, 1), wrap([2, 1, 3, 8, 1], &[0; 32])].concat()),
            "Bad key data KDF family: 2",
        ),
        (
            "wrap salt",
            trailer([header(2, 1), wrap([1, 1, 65_536, 8, 1], &[0; 7])].concat()),
            "Bad key data wrap salt size: 7",
        ),
        (
            "duplicate generation",
            trailer([header(2, 2), argon2(1), argon2(1)].concat()),
            "Duplicate key data wrap generation: 1",
        ),
        (
            "wrap short",
            trailer([header(2, 1), be32(&[1, 1, 65_536])].concat()),
            "Could not stream a key data wrap",
        ),
        (
            "8-byte wrap salt is enough",
            trailer([header(2, 1), wrap([1, 1, 65_536, 8, 1], &[0; 8])].concat()),
            "",
        ),
    ];
    for (name, payload, want) in cases {
        let result = KeyData::parse(&payload);
        if want.is_empty() {
            assert!(result.is_ok(), "{name}");
        } else {
            assert_eq!(message(result), want, "{name}");
        }
    }
}

#[test]
fn passcode_key_message_matches_1_5_0() {
    use opentele2_core::tdata::key_data::{PasscodeKdf, create_passcode_key};

    let cases = [
        (
            [1, 65_536, 8, 1],
            "Unusable passcode wrap parameters: PasscodeKdf(kind=1, memory=65536, time=8, parallel=1)",
        ),
        (
            [0, 0, 0, 0],
            "Unusable passcode wrap parameters: PasscodeKdf(kind=0, memory=0, time=0, parallel=0)",
        ),
        (
            [2, 3, 8, 1],
            "Unusable passcode wrap parameters: PasscodeKdf(kind=2, memory=3, time=8, parallel=1)",
        ),
    ];
    for ([kind, memory, time, parallelism], want) in cases {
        let kdf = PasscodeKdf {
            kind,
            generation: 1,
            memory,
            time,
            parallelism,
        };
        assert_eq!(message(create_passcode_key(b"", &[0; 32], &kdf)), want);
    }
}

/// Writes `key_datas` the way the 1.5.0 capture did: a zero open salt, the
/// counting local key wrapped under the open key, and the accounts info
/// `[count, 0]` encrypted under `info_key`.
fn write_key_file(dir: &Path, count: i32, info_key: &AuthKey) {
    use opentele2_core::crypto::encrypt_local;
    use opentele2_core::kdf::create_local_key;
    use opentele2_core::tdata::key_data::{KeyData, wrap_local_key};

    let salt = vec![0; 32];
    let open_key = create_local_key(&[], &salt);
    let data = KeyData {
        key_encrypted: Some(wrap_local_key(&counting_key(), &open_key, &[0; 12]).expect("wrap")),
        salt,
        info_encrypted: encrypt_local(&bei32(&[count, 0]), info_key, |len| vec![0; len])
            .expect("info"),
        trailer: None,
    };
    tdf::write(
        dir,
        "key_data",
        &TdfFile {
            version: 7_003_001,
            payload: data.encode().expect("encode"),
        },
    )
    .expect("write key file");
}

#[test]
fn accounts_info_messages_match_1_5_0() {
    let dir = scratch("accounts_info");
    let other = AuthKey::new(core::array::from_fn(|i| {
        255 - u8::try_from(i).expect("index fits a byte")
    }));
    write_key_file(&dir, 1, &other);
    let error = TData::load(&dir, b"", None).expect_err("wrong info key");
    assert_eq!(error.code(), "TDATA_KEY_DATA_INVALID");
    assert_eq!(
        error.legacy_message(),
        "Could not decrypt the accounts info"
    );
    for count in [0, -3] {
        write_key_file(&dir, count, &counting_key());
        assert_eq!(
            message(TData::load(&dir, b"", None)),
            format!("Bad accounts count {count}, the data might have been corrupted")
        );
    }
    fs::remove_dir_all(&dir).expect("clean scratch");
}

/// `DcOptions.constructFromSerialized` and `Config.FromSerialized`
/// (`src/td/mtp.py:105-150,388-418`) on the same bytes.
#[test]
fn mtp_config_stream_messages_match_1_5_0() {
    use opentele2_core::tdata::mtp_config::{DcOptions, MtpConfig};

    let cases = [
        (
            [bei32(&[-1, 1, 2, 0, 443, 7]), b"1.2".to_vec()].concat(),
            "Could not stream config data",
        ),
        (
            [bei32(&[-2, 0]), vec![0, 1]].concat(),
            "Could not stream CDN config data",
        ),
        (
            [bei32(&[-2, 0, 1, 2, 5]), b"ab".to_vec()].concat(),
            "Could not stream CDN public key",
        ),
    ];
    for (serialized, want) in cases {
        assert_eq!(message(DcOptions::parse(&serialized)), want);
    }
    assert_eq!(
        message(MtpConfig::parse(&bei32(&[1, 0, 0, 1]))),
        "Could not stream MtpData serialized"
    );
}

#[test]
fn save_failed_message_matches_1_5_0() {
    let mut no_draw = |_: &mut [u8]| panic!("performance mode draws nothing");
    let tdata = TData::new(Vec::new(), b"", true, &mut no_draw).expect("new");
    let dir = scratch("save_failed");
    let error = tdata.save_random(&dir).expect_err("no account");
    assert_eq!(error.code(), "TDATA_SAVE_FAILED");
    assert_eq!(
        error.legacy_message(),
        "Could not save tdata, something went wrong"
    );
    fs::remove_dir_all(&dir).expect("clean scratch");
}
