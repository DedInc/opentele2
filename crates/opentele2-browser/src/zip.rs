//! A minimal reader for the single-entry zip archives of the datapoints.
//!
//! Only what the embedded archives use is supported: a plain (non-ZIP64,
//! unencrypted) archive whose entries are stored or DEFLATE-compressed.

use crate::{Error, Result};

const END_OF_CENTRAL_DIRECTORY: u32 = 0x0605_4b50;
const CENTRAL_DIRECTORY_ENTRY: u32 = 0x0201_4b50;
const LOCAL_FILE_HEADER: u32 = 0x0403_4b50;
const END_OF_CENTRAL_DIRECTORY_LEN: usize = 22;
const CENTRAL_DIRECTORY_ENTRY_LEN: usize = 46;
const LOCAL_FILE_HEADER_LEN: usize = 30;
const MAX_COMMENT_LEN: usize = 0xFFFF;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const FLAG_ENCRYPTED: u16 = 1;

fn malformed(what: &str) -> Error {
    Error::Zip(what.to_owned())
}

fn bytes_at(archive: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    offset
        .checked_add(len)
        .and_then(|end| archive.get(offset..end))
        .ok_or_else(|| malformed("truncated archive"))
}

fn u16_at(archive: &[u8], offset: usize) -> Result<u16> {
    let mut le = [0u8; 2];
    le.copy_from_slice(bytes_at(archive, offset, 2)?);
    Ok(u16::from_le_bytes(le))
}

fn u32_at(archive: &[u8], offset: usize) -> Result<u32> {
    let mut le = [0u8; 4];
    le.copy_from_slice(bytes_at(archive, offset, 4)?);
    Ok(u32::from_le_bytes(le))
}

fn usize_at(archive: &[u8], offset: usize) -> Result<usize> {
    usize::try_from(u32_at(archive, offset)?)
        .map_err(|_| malformed("size exceeds the address space"))
}

fn end_of_central_directory(archive: &[u8]) -> Result<usize> {
    let last = archive
        .len()
        .checked_sub(END_OF_CENTRAL_DIRECTORY_LEN)
        .ok_or_else(|| malformed("archive shorter than its trailer"))?;
    let first = last.saturating_sub(MAX_COMMENT_LEN);
    (first..=last)
        .rev()
        .find(|&offset| u32_at(archive, offset).is_ok_and(|sig| sig == END_OF_CENTRAL_DIRECTORY))
        .ok_or_else(|| malformed("no end of central directory record"))
}

/// Returns the decompressed bytes of the first entry whose name ends with
/// `.json`, the entry browserforge's `extract_json` reads.
pub(crate) fn first_json_entry(archive: &[u8]) -> Result<Vec<u8>> {
    let eocd = end_of_central_directory(archive)?;
    let entries = u16_at(archive, eocd + 10)?;
    let mut offset = usize_at(archive, eocd + 16)?;
    for _ in 0..entries {
        if u32_at(archive, offset)? != CENTRAL_DIRECTORY_ENTRY {
            return Err(malformed("bad central directory entry signature"));
        }
        let name_len = usize::from(u16_at(archive, offset + 28)?);
        let extra_len = usize::from(u16_at(archive, offset + 30)?);
        let comment_len = usize::from(u16_at(archive, offset + 32)?);
        let name = bytes_at(archive, offset + CENTRAL_DIRECTORY_ENTRY_LEN, name_len)?;
        if name.ends_with(b".json") {
            return read_entry(archive, offset);
        }
        offset += CENTRAL_DIRECTORY_ENTRY_LEN + name_len + extra_len + comment_len;
    }
    Err(malformed("no .json entry"))
}

fn read_entry(archive: &[u8], central: usize) -> Result<Vec<u8>> {
    let flags = u16_at(archive, central + 8)?;
    let method = u16_at(archive, central + 10)?;
    let crc = u32_at(archive, central + 16)?;
    let compressed_len = usize_at(archive, central + 20)?;
    let uncompressed_len = usize_at(archive, central + 24)?;
    let local = usize_at(archive, central + 42)?;
    if flags & FLAG_ENCRYPTED != 0 {
        return Err(malformed("encrypted entry"));
    }
    if compressed_len == 0xFFFF_FFFF || uncompressed_len == 0xFFFF_FFFF {
        return Err(malformed("ZIP64 entry"));
    }
    if u32_at(archive, local)? != LOCAL_FILE_HEADER {
        return Err(malformed("bad local file header signature"));
    }
    let data_start = local
        + LOCAL_FILE_HEADER_LEN
        + usize::from(u16_at(archive, local + 26)?)
        + usize::from(u16_at(archive, local + 28)?);
    let data = bytes_at(archive, data_start, compressed_len)?;
    let contents = match method {
        METHOD_STORED => data.to_vec(),
        METHOD_DEFLATE => {
            miniz_oxide::inflate::decompress_to_vec_with_limit(data, uncompressed_len)
                .map_err(|_| malformed("corrupt DEFLATE stream"))?
        }
        _ => return Err(malformed("unsupported compression method")),
    };
    if contents.len() != uncompressed_len {
        return Err(malformed("entry size mismatch"));
    }
    if crc32fast::hash(&contents) != crc {
        return Err(malformed("entry CRC-32 mismatch"));
    }
    Ok(contents)
}
