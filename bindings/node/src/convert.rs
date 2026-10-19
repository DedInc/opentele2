//! Conversions of JavaScript arguments into owned Rust values.

use napi::bindgen_prelude::{BigInt, Either, Either3, Uint8Array};

use opentele2_core::crypto::AuthKey;

use crate::error::{Result, check, invalid_arg};

/// A passcode argument: a string or bytes.
pub(crate) type Passcode = Either<String, Uint8Array>;

/// A device seed argument: a string, a `number` or a `bigint`.
pub(crate) type Seed = Either3<String, f64, BigInt>;

/// A passcode: bytes as given, a string encoded as UTF-8, and a missing
/// passcode as empty.
pub(crate) fn to_passcode(value: Option<Passcode>) -> Vec<u8> {
    match value {
        None => Vec::new(),
        Some(Either::A(text)) => text.into_bytes(),
        Some(Either::B(bytes)) => bytes.to_vec(),
    }
}

/// A 256-byte auth key; a wrong length raises `OT_BAD_LENGTH`.
pub(crate) fn to_auth_key(bytes: &[u8]) -> Result<AuthKey> {
    check(AuthKey::from_slice(bytes))
}

/// A user id given as a `bigint` in `0..2**64`.
pub(crate) fn to_user_id(value: &BigInt) -> Result<u64> {
    let (negative, id, lossless) = value.get_u64();
    if negative || !lossless {
        return Err(invalid_arg("userId must be a bigint in 0..2**64"));
    }
    Ok(id)
}

/// A device seed: a string as given, and an integer `number` or a `bigint`
/// as its decimal text, the way 1.5.0 hashes an `int` seed.
pub(crate) fn to_seed(value: Option<Seed>) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(Either3::A(text)) => Ok(Some(text)),
        Some(Either3::B(number)) => {
            // 2**53, the first integer a `number` may have rounded onto.
            const UNSAFE: f64 = 9_007_199_254_740_992.0;
            if !number.is_finite() || number.fract() != 0.0 || number.abs() >= UNSAFE {
                return Err(invalid_arg(
                    "a number seed must be a safe integer; pass larger seeds as a bigint",
                ));
            }
            if number == 0.0 {
                // `-0` is the integer 0, not the text "-0".
                return Ok(Some("0".to_owned()));
            }
            // An integral f64 prints its exact digits with no fraction.
            Ok(Some(format!("{number:.0}")))
        }
        Some(Either3::C(big)) => {
            let (negative, magnitude, lossless) = big.get_u128();
            if !lossless {
                return Err(invalid_arg("a bigint seed must fit in 128 bits"));
            }
            let sign = if negative && magnitude != 0 { "-" } else { "" };
            Ok(Some(format!("{sign}{magnitude}")))
        }
    }
}
