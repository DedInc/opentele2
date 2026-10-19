//! The random source of `newTdata`, `saveTdata` and `migrateTdata`: the OS
//! random source, or, as a testing hook, a list of recorded draws that is
//! replayed in order (the `draws` argument).

use opentele2_core::Error;

use crate::error::{CodedError, core_error, invalid_arg};

/// Why a task failed: in the core, or in replaying the given draws.
pub enum Failure {
    /// A core failure, including a failed OS random source.
    Core(Error),
    /// The given draws did not match what the core drew.
    Replay(String),
}

impl Failure {
    /// `OT_<CODE>` for a core failure, `ERR_INVALID_ARG_VALUE` for a replay
    /// mismatch.
    pub(crate) fn into_error(self) -> CodedError {
        match self {
            Self::Core(error) => core_error(&error),
            Self::Replay(message) => invalid_arg(format!("draws: {message}")),
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Core(error)
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
    failure: Option<Failure>,
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
                self.failure = Some(Failure::Core(Error::Io(std::io::Error::other(error))));
            }
            return;
        };
        match replay.draws.get(replay.next) {
            Some(draw) if draw.len() == buf.len() => {
                buf.copy_from_slice(draw);
                replay.next += 1;
            }
            Some(draw) => {
                self.failure = Some(Failure::Replay(format!(
                    "draw {} has {} bytes, but {} were drawn",
                    replay.next,
                    draw.len(),
                    buf.len()
                )));
                buf.fill(0);
            }
            None => {
                self.failure = Some(Failure::Replay(format!(
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
    pub(crate) fn finish(self) -> Result<(), Failure> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        match self.replay {
            Some(replay) if replay.next != replay.draws.len() => Err(Failure::Replay(format!(
                "{} of {} draws were left unused",
                replay.draws.len() - replay.next,
                replay.draws.len()
            ))),
            _ => Ok(()),
        }
    }
}
