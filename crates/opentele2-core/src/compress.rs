//! Gzip compression of `MTProto` payloads (`gzip_packed`), in pure Rust
//! through `flate2`'s `miniz_oxide` backend.

use std::io::{Read as _, Write as _};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

use crate::Result;

/// Input fed to the encoder between size checks, in bytes.
const CHUNK_SIZE: usize = 16 * 1024;

/// Gzips `data` at the default level (6, as zlib).
///
/// Returns `None` when the compressed output would be longer than
/// `max_size`; compression stops as soon as the limit is passed. With
/// `max_size` `None` the result is always `Some`: the encoder writes into
/// memory, which cannot fail.
#[must_use]
pub fn gzip(data: &[u8], max_size: Option<usize>) -> Option<Vec<u8>> {
    let limit = max_size.unwrap_or(usize::MAX);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    for chunk in data.chunks(CHUNK_SIZE) {
        encoder.write_all(chunk).ok()?;
        if encoder.get_ref().len() > limit {
            return None;
        }
    }
    let out = encoder.finish().ok()?;
    (out.len() <= limit).then_some(out)
}

/// Decompresses one gzip member.
///
/// # Errors
/// [`crate::Error::Io`] when `data` is not a gzip stream, is truncated, or
/// fails its CRC-32 or length check.
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    GzDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}
