//! Big-endian `QDataStream` values as Telegram Desktop writes them.
//!
//! [`QReader`] borrows its input and hands out slices of it, so reading a
//! `QByteArray` copies nothing; [`QWriter`] appends to an owned buffer. Both
//! use Qt's encoding: integers are big-endian,
//! a `QByteArray` is a `u32` byte count followed by the bytes, a `QString` is
//! a `u32` byte count followed by UTF-16BE code units, and the count
//! `0xFFFF_FFFF` marks a null value.

use crate::{Error, Result};

/// Length prefix that marks a null `QByteArray` or `QString`.
pub const NULL_LENGTH: u32 = 0xFFFF_FFFF;

/// Zero-copy reader over a `QDataStream` byte buffer.
///
/// Every read advances the cursor; a failed read leaves the cursor where it
/// was and returns [`Error::QDataStreamFailed`].
#[derive(Debug, Clone)]
pub struct QReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> QReader<'a> {
    /// Starts a reader at the first byte of `data`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Number of bytes not read yet.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Whether every byte has been read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.data.len())
            .ok_or(Error::QDataStreamFailed { context: None })?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.take(N)?;
        // `take` returned exactly N bytes, so the conversion cannot fail.
        bytes
            .try_into()
            .map_err(|_| Error::QDataStreamFailed { context: None })
    }

    /// Reads a big-endian `qint32`.
    ///
    /// # Errors
    ///
    /// [`Error::QDataStreamFailed`] when fewer than 4 bytes remain.
    pub fn read_i32(&mut self) -> Result<i32> {
        self.take_array().map(i32::from_be_bytes)
    }

    /// Reads a big-endian `quint32`.
    ///
    /// # Errors
    ///
    /// [`Error::QDataStreamFailed`] when fewer than 4 bytes remain.
    pub fn read_u32(&mut self) -> Result<u32> {
        self.take_array().map(u32::from_be_bytes)
    }

    /// Reads a big-endian `qint64`.
    ///
    /// # Errors
    ///
    /// [`Error::QDataStreamFailed`] when fewer than 8 bytes remain.
    pub fn read_i64(&mut self) -> Result<i64> {
        self.take_array().map(i64::from_be_bytes)
    }

    /// Reads a big-endian `quint64`.
    ///
    /// # Errors
    ///
    /// [`Error::QDataStreamFailed`] when fewer than 8 bytes remain.
    pub fn read_u64(&mut self) -> Result<u64> {
        self.take_array().map(u64::from_be_bytes)
    }

    /// Reads one length-prefixed block; `None` for the null marker.
    fn read_block(&mut self) -> Result<Option<&'a [u8]>> {
        let start = self.pos;
        let len = self.read_u32()?;
        if len == NULL_LENGTH {
            return Ok(None);
        }
        let block = usize::try_from(len)
            .map_err(|_| Error::QDataStreamFailed { context: None })
            .and_then(|len| self.take(len));
        if block.is_err() {
            self.pos = start;
        }
        block.map(Some)
    }

    /// Reads a `QByteArray`, borrowing its bytes from the input.
    ///
    /// Returns `None` for a null array and `Some(&[])` for an empty one.
    ///
    /// # Errors
    ///
    /// [`Error::QDataStreamFailed`] when the length prefix or the bytes it
    /// announces are cut short.
    pub fn read_bytearray(&mut self) -> Result<Option<&'a [u8]>> {
        self.read_block()
    }

    /// Reads a `QString`, decoding its UTF-16BE code units.
    ///
    /// Returns `None` for a null string and `Some(String::new())` for an
    /// empty one.
    ///
    /// # Errors
    ///
    /// [`Error::QDataStreamFailed`] when the data is cut short, the byte
    /// count is odd, or the code units are not valid UTF-16.
    pub fn read_qstring(&mut self) -> Result<Option<String>> {
        let start = self.pos;
        let decoded = self
            .read_block()
            .and_then(|block| block.map(decode_utf16be).transpose());
        if decoded.is_err() {
            self.pos = start;
        }
        decoded
    }
}

fn decode_utf16be(bytes: &[u8]) -> Result<String> {
    let (units, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(Error::QDataStreamFailed { context: None });
    }
    char::decode_utf16(units.iter().map(|&unit| u16::from_be_bytes(unit)))
        .collect::<std::result::Result<String, _>>()
        .map_err(|_| Error::QDataStreamFailed { context: None })
}

/// Builder of a big-endian `QDataStream` byte buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QWriter {
    buf: Vec<u8>,
}

impl QWriter {
    /// Starts an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Finishes the buffer and returns its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Appends a big-endian `qint32`.
    pub fn write_i32(&mut self, value: i32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `quint32`.
    pub fn write_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `qint64`.
    pub fn write_i64(&mut self, value: i64) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `quint64`.
    pub fn write_u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends the length prefix for a block of `len` bytes.
    fn write_len(&mut self, len: usize) -> Result<()> {
        // The null marker is not a valid length, so the largest block is one
        // byte short of it.
        let len = u32::try_from(len)
            .ok()
            .filter(|&len| len != NULL_LENGTH)
            .ok_or(Error::QDataStreamFailed { context: None })?;
        self.write_u32(len);
        Ok(())
    }

    /// Appends a `QByteArray`; `None` writes the null marker.
    ///
    /// # Errors
    ///
    /// [`Error::QDataStreamFailed`] when the bytes do not fit a `u32` length
    /// prefix; nothing is written in that case.
    pub fn write_bytearray(&mut self, value: Option<&[u8]>) -> Result<()> {
        match value {
            None => self.write_u32(NULL_LENGTH),
            Some(bytes) => {
                self.write_len(bytes.len())?;
                self.buf.extend_from_slice(bytes);
            }
        }
        Ok(())
    }

    /// Appends a `QString` as UTF-16BE; `None` writes the null marker.
    ///
    /// # Errors
    ///
    /// [`Error::QDataStreamFailed`] when the encoded string does not fit a
    /// `u32` length prefix; nothing is written in that case.
    pub fn write_qstring(&mut self, value: Option<&str>) -> Result<()> {
        let Some(text) = value else {
            self.write_u32(NULL_LENGTH);
            return Ok(());
        };
        let byte_len = text
            .encode_utf16()
            .count()
            .checked_mul(2)
            .ok_or(Error::QDataStreamFailed { context: None })?;
        self.write_len(byte_len)?;
        self.buf.reserve(byte_len);
        for unit in text.encode_utf16() {
            self.buf.extend_from_slice(&unit.to_be_bytes());
        }
        Ok(())
    }
}
