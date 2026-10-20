//! Golden-vector tests for `qt` and `tdf` against the encodings in
//! `tests/vectors/tdf.json`.

use std::fs;
use std::path::{Path, PathBuf};

use opentele2_core::Error;
use opentele2_core::qt::{QReader, QWriter};
use opentele2_core::tdf::{self, TdfFile};
use serde_json::Value;

fn vectors() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/tdf.json");
    let text = fs::read_to_string(&path).expect("read tdf.json");
    serde_json::from_str(&text).expect("parse tdf.json")
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

fn is_null(case: &Value) -> bool {
    case["null"].as_bool().expect("null flag")
}

/// Fresh, empty scratch directory unique to one test.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "opentele2-core-primitives-{}-{test}",
        std::process::id()
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clear scratch dir");
    }
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

#[test]
fn qint32_vectors_round_trip() {
    for case in cases(&vectors(), "qint32") {
        let value = i32::try_from(case["value"].as_i64().expect("int")).expect("i32");
        let encoded = unhex(case, "encoded");
        let mut writer = QWriter::new();
        writer.write_i32(value);
        assert_eq!(writer.as_bytes(), encoded, "write {value}");
        let mut reader = QReader::new(&encoded);
        assert_eq!(reader.read_i32().expect("read"), value);
        assert!(reader.is_empty());
        // The same four bytes read back as the unsigned bit pattern.
        let mut writer = QWriter::new();
        writer.write_u32(u32::from_be_bytes(encoded[..].try_into().expect("4 bytes")));
        assert_eq!(writer.into_bytes(), encoded);
        assert_eq!(
            QReader::new(&encoded)
                .read_u32()
                .expect("read u32")
                .to_be_bytes(),
            value.to_be_bytes()
        );
    }
}

#[test]
fn qint64_vectors_round_trip() {
    for case in cases(&vectors(), "qint64") {
        let value: i64 = text(case, "value").parse().expect("i64");
        let encoded = unhex(case, "encoded");
        let mut writer = QWriter::new();
        writer.write_i64(value);
        assert_eq!(writer.as_bytes(), encoded, "write {value}");
        let mut reader = QReader::new(&encoded);
        assert_eq!(reader.read_i64().expect("read"), value);
        assert!(reader.is_empty());
        let mut writer = QWriter::new();
        writer.write_u64(u64::from_be_bytes(encoded[..].try_into().expect("8 bytes")));
        assert_eq!(writer.into_bytes(), encoded);
        assert_eq!(
            QReader::new(&encoded)
                .read_u64()
                .expect("read u64")
                .to_be_bytes(),
            value.to_be_bytes()
        );
    }
}

#[test]
fn qbytearray_vectors_round_trip() {
    for case in cases(&vectors(), "qbytearray") {
        let value = (!is_null(case)).then(|| unhex(case, "value"));
        let encoded = unhex(case, "encoded");
        let mut writer = QWriter::new();
        writer.write_bytearray(value.as_deref()).expect("write");
        assert_eq!(writer.as_bytes(), encoded);
        let mut reader = QReader::new(&encoded);
        let read = reader.read_bytearray().expect("read");
        assert_eq!(read, value.as_deref());
        assert!(reader.is_empty());
        if let Some(bytes) = read {
            // Zero-copy: the slice points into the input buffer.
            assert_eq!(bytes.as_ptr(), encoded[4..].as_ptr());
        }
    }
}

#[test]
fn qstring_vectors_round_trip() {
    for case in cases(&vectors(), "qstring") {
        let value = (!is_null(case)).then(|| text(case, "value"));
        let encoded = unhex(case, "encoded");
        let mut writer = QWriter::new();
        writer.write_qstring(value).expect("write");
        assert_eq!(writer.as_bytes(), encoded, "write {value:?}");
        let mut reader = QReader::new(&encoded);
        assert_eq!(reader.read_qstring().expect("read").as_deref(), value);
        assert!(reader.is_empty());
    }
}

/// One read attempted on a reader, with its value discarded.
type Probe = fn(&mut QReader<'_>) -> Result<(), Error>;

#[test]
fn short_or_invalid_streams_fail() {
    let failing: [(&str, &[u8], Probe); 7] = [
        ("i32", &[0, 0, 1], |r| r.read_i32().map(drop)),
        ("i64", &[0; 7], |r| r.read_i64().map(drop)),
        ("bytearray body", &[0, 0, 0, 3, 1, 2], |r| {
            r.read_bytearray().map(drop)
        }),
        ("bytearray prefix", &[0, 0], |r| {
            r.read_bytearray().map(drop)
        }),
        ("odd qstring", &[0, 0, 0, 3, 0, 0x61, 0], |r| {
            r.read_qstring().map(drop)
        }),
        ("lone high surrogate", &[0, 0, 0, 2, 0xd8, 0x00], |r| {
            r.read_qstring().map(drop)
        }),
        ("lone low surrogate", &[0, 0, 0, 2, 0xdc, 0x00], |r| {
            r.read_qstring().map(drop)
        }),
    ];
    for (label, input, probe) in failing {
        let mut reader = QReader::new(input);
        let error = probe(&mut reader).expect_err(label);
        assert_eq!(error.code(), "QDATASTREAM_FAILED", "{label}");
        assert_eq!(reader.remaining(), input.len(), "{label} moved the cursor");
    }
}

/// The `tdf_file` vector: its JSON case, the file bytes, and the payload
/// rebuilt from its blobs.
fn tdf_vector() -> (Value, Vec<u8>, Vec<u8>) {
    let vectors = vectors();
    let case = vectors["tdf_file"].clone();
    let file = unhex(&case, "file");
    let mut payload = QWriter::new();
    for blob in case["blobs"].as_array().expect("blobs") {
        let value = (!is_null(blob)).then(|| unhex(blob, "value"));
        payload.write_bytearray(value.as_deref()).expect("blob");
    }
    (case, file, payload.into_bytes())
}

fn version_of(case: &Value) -> u32 {
    u32::try_from(case["version"].as_u64().expect("version")).expect("u32")
}

#[test]
fn tdf_vector_parses_and_encodes_exactly() {
    let (case, file, payload) = tdf_vector();
    assert_eq!(&file[..4], unhex(&case, "magic"));
    assert_eq!(&file[file.len() - 16..], unhex(&case, "md5"));
    let parsed = TdfFile::parse(&file).expect("parse");
    assert_eq!(parsed.version, version_of(&case));
    assert_eq!(parsed.payload, payload);
    assert_eq!(parsed.encode(), file);
    let built = TdfFile {
        version: version_of(&case),
        payload,
    };
    assert_eq!(built.encode(), file);
}

#[test]
fn tdf_parse_rejects_corrupt_files() {
    let (_, file, _) = tdf_vector();
    let mut bad_magic = file.clone();
    bad_magic[3] = b'#';
    assert!(matches!(
        TdfFile::parse(&bad_magic),
        Err(Error::InvalidMagic { .. })
    ));
    assert_eq!(
        TdfFile::parse(&bad_magic).unwrap_err().code(),
        "TDATA_INVALID_MAGIC"
    );

    let mut bad_md5 = file.clone();
    *bad_md5.last_mut().expect("non-empty") ^= 0x01;
    assert_eq!(
        TdfFile::parse(&bad_md5).unwrap_err().code(),
        "TDATA_INVALID_CHECKSUM"
    );

    let mut bad_payload = file.clone();
    bad_payload[10] ^= 0x80;
    assert_eq!(
        TdfFile::parse(&bad_payload).unwrap_err().code(),
        "TDATA_INVALID_CHECKSUM"
    );

    for len in [0, 3, 8, 23] {
        assert_eq!(
            TdfFile::parse(&file[..len]).unwrap_err().code(),
            "QDATASTREAM_FAILED",
            "truncated to {len}"
        );
    }
    // Cutting the file shifts the checksum window, so the MD5 no longer
    // matches.
    assert_eq!(
        TdfFile::parse(&file[..file.len() - 1]).unwrap_err().code(),
        "TDATA_INVALID_CHECKSUM"
    );
}

#[test]
fn tdf_write_uses_s_suffix_and_reads_back() {
    let (case, file, _) = tdf_vector();
    let dir = scratch("write");
    let parsed = TdfFile::parse(&file).expect("parse");
    tdf::write(&dir, text(&case, "name"), &parsed).expect("write");
    let written = dir.join(text(&case, "written_name"));
    assert_eq!(fs::read(&written).expect("written file"), file);
    assert_eq!(tdf::read(&dir, text(&case, "name")).expect("read"), parsed);

    let nested = dir.join("a").join("b");
    tdf::write(&nested, "key_data", &parsed).expect("write nested");
    assert!(nested.join("key_datas").is_file());
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn tdf_read_tries_suffixes_in_order() {
    let (_, file, _) = tdf_vector();
    let dir = scratch("suffixes");
    let other = TdfFile {
        version: 1,
        payload: b"fallback".to_vec(),
    };

    assert!(matches!(
        tdf::read(&dir, "map"),
        Err(Error::FileNotFound { .. })
    ));
    assert_eq!(
        tdf::read(&dir, "map").unwrap_err().code(),
        "TFILE_NOT_FOUND"
    );

    fs::write(dir.join("map0"), other.encode()).expect("map0");
    assert_eq!(tdf::read(&dir, "map").expect("map0").version, 1);

    fs::write(dir.join("map1"), &file).expect("map1");
    assert_eq!(tdf::read(&dir, "map").expect("map1").encode(), file);

    // A corrupt `s` file is skipped in favour of the next suffix.
    fs::write(dir.join("maps"), b"TDF?garbage-garbage-garbage").expect("maps");
    assert_eq!(tdf::read(&dir, "map").expect("map1 again").encode(), file);

    fs::write(dir.join("maps"), other.encode()).expect("maps valid");
    assert_eq!(tdf::read(&dir, "map").expect("maps").version, 1);

    // With every candidate corrupt, the last integrity failure is reported.
    fs::write(dir.join("bads"), b"TDF?").expect("bads");
    let mut flipped = file.clone();
    flipped[12] ^= 0xff;
    fs::write(dir.join("bad0"), &flipped).expect("bad0");
    assert_eq!(
        tdf::read(&dir, "bad").unwrap_err().code(),
        "TDATA_INVALID_CHECKSUM"
    );
    fs::remove_dir_all(&dir).expect("cleanup");
}
