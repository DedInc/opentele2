//! The random source of `TData.new`, `TData.save` and `TData.migrate`: the
//! OS random source, or, as a testing hook, a list of recorded draws that
//! is replayed in order (the `draws` argument).

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use opentele2_core::Error;

use crate::convert::owned_bytes;
use crate::error::core_error;

/// Why a run of draws failed.
pub(crate) enum DrawFailure {
    /// The OS random source failed.
    Random(getrandom::Error),
    /// The given draws did not match what the core drew.
    Replay(String),
}

impl DrawFailure {
    /// `CoreError` `IO` for a random source failure, `ValueError` for a
    /// replay mismatch.
    pub(crate) fn into_err(self, py: Python<'_>) -> PyErr {
        match self {
            Self::Random(error) => core_error(py, &Error::Io(std::io::Error::other(error))),
            Self::Replay(message) => PyValueError::new_err(format!("draws: {message}")),
        }
    }
}

/// Recorded draws served in order.
struct Replay {
    draws: Vec<Vec<u8>>,
    next: usize,
}

/// Where random bytes come from; the first failure is kept and every later
/// draw is zero-filled, so the caller discards whatever was built.
pub(crate) struct Draws {
    replay: Option<Replay>,
    failure: Option<DrawFailure>,
}

impl Draws {
    /// The OS random source, or the replay of `draws` when given.
    pub(crate) fn new(draws: Option<Vec<Vec<u8>>>) -> Self {
        Self {
            replay: draws.map(|draws| Replay { draws, next: 0 }),
            failure: None,
        }
    }

    /// Whether the draws are a replay rather than the OS random source.
    pub(crate) fn is_replay(&self) -> bool {
        self.replay.is_some()
    }

    /// Fills `buf` with the next draw.
    pub(crate) fn fill(&mut self, buf: &mut [u8]) {
        if self.failure.is_some() {
            buf.fill(0);
            return;
        }
        let Some(replay) = self.replay.as_mut() else {
            if let Err(error) = getrandom::fill(buf) {
                self.failure = Some(DrawFailure::Random(error));
            }
            return;
        };
        match replay.draws.get(replay.next) {
            Some(draw) if draw.len() == buf.len() => {
                buf.copy_from_slice(draw);
                replay.next += 1;
            }
            Some(draw) => {
                self.failure = Some(DrawFailure::Replay(format!(
                    "draw {} has {} bytes, but {} were drawn",
                    replay.next,
                    draw.len(),
                    buf.len()
                )));
                buf.fill(0);
            }
            None => {
                self.failure = Some(DrawFailure::Replay(format!(
                    "draw {} of {} bytes was not given ({} draws given)",
                    replay.next,
                    buf.len(),
                    replay.draws.len()
                )));
                buf.fill(0);
            }
        }
    }

    /// The first failure, else a replay whose draws were not all used.
    pub(crate) fn finish(self) -> Result<(), DrawFailure> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        match self.replay {
            Some(replay) if replay.next != replay.draws.len() => Err(DrawFailure::Replay(format!(
                "{} of {} draws were left unused",
                replay.draws.len() - replay.next,
                replay.draws.len()
            ))),
            _ => Ok(()),
        }
    }
}

/// A `draws` argument: `None`, or an iterable of `bytes`/`bytearray`.
pub(crate) fn to_draws(value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Vec<Vec<u8>>>> {
    let Some(value) = value.filter(|value| !value.is_none()) else {
        return Ok(None);
    };
    value
        .try_iter()?
        .map(|item| owned_bytes(&item?))
        .collect::<PyResult<Vec<_>>>()
        .map(Some)
}
