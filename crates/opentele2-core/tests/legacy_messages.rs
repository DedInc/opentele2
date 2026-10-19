//! `Error::legacy_message` against the messages 1.5.0 raised on the same
//! inputs.
//!
//! Every expected string was captured by running the 1.5.0 sources under
//! `src/` (with `OPENTELE_NO_FETCH=1` set before `import src`) on the input
//! the test builds: `Storage.ReadFile`, `Storage.DecryptLocal`,
//! `MapData.read`, `Account._setMtpAuthorization` and
//! `Account.FromTelethon`, reading the exception's `message`. Key bytes are
//! never printed.

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
