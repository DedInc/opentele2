//! Batch entry points over independent tdata folders.
//!
//! [`load_many`] loads many folders and [`map_many`] applies a conversion to
//! many values, both returning results in input order. With the `parallel`
//! feature (on by default) each call builds its own rayon thread pool with
//! [`BatchOptions::thread_count`] threads and drops it before returning; the
//! global rayon pool is never used, so a host's own rayon work is not
//! affected. Without the feature both functions run sequentially on the
//! calling thread and return identical results.
//!
//! The expensive step of a load is the one passcode KDF per folder (Argon2id
//! with m=65536 KiB, t=8, p=1), which holds about 64 MiB while it runs. Peak
//! memory of a batch over passcode folders is therefore about
//! `threads x 64 MiB`; cap [`BatchOptions::threads`] to bound it.

use std::fmt;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use crate::Result;
use crate::tdata::TData;

/// Upper bound of the default thread count when [`BatchOptions::threads`] is
/// `None`; an explicit count is used as given.
pub const MAX_DEFAULT_THREADS: NonZeroUsize = NonZeroUsize::new(16).unwrap();

/// One folder to load: the arguments of [`TData::load`].
///
/// `Debug` prints the passcode length only, never the passcode.
#[derive(Clone, PartialEq, Eq)]
pub struct LoadRequest {
    /// The tdata folder.
    pub dir: PathBuf,
    /// The local passcode; empty when the folder has none.
    pub passcode: Vec<u8>,
    /// The key file data name; `None` means [`crate::tdata::key_data::DEFAULT_KEY_FILE`].
    pub key_file: Option<String>,
}

impl fmt::Debug for LoadRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadRequest")
            .field("dir", &self.dir)
            .field("passcode_len", &self.passcode.len())
            .field("key_file", &self.key_file)
            .finish()
    }
}

/// How a batch call runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchOptions {
    /// Worker threads of the per-call pool. `None` means
    /// `min(available_parallelism, MAX_DEFAULT_THREADS)`. Peak memory over
    /// passcode folders is about `threads x 64 MiB`. Ignored without the
    /// `parallel` feature.
    pub threads: Option<NonZeroUsize>,
}

impl BatchOptions {
    /// The thread count a parallel call uses: [`BatchOptions::threads`], or
    /// `min(available_parallelism, MAX_DEFAULT_THREADS)` when it is `None`
    /// (1 when the parallelism cannot be queried).
    #[must_use]
    pub fn thread_count(&self) -> NonZeroUsize {
        self.threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .unwrap_or(NonZeroUsize::MIN)
                .min(MAX_DEFAULT_THREADS)
        })
    }
}

fn load_one(request: &LoadRequest) -> Result<TData> {
    TData::load(&request.dir, &request.passcode, request.key_file.as_deref())
}

/// Loads every folder of `requests` with [`TData::load`].
///
/// The result at position `i` belongs to `requests[i]`; a failing folder
/// yields its own error and does not affect the others. If the thread pool
/// cannot be built, every item is [`crate::Error::Io`] with the pool error.
///
/// # Panics
/// Propagates a panic of [`TData::load`], as a sequential loop would.
#[must_use]
pub fn load_many(requests: &[LoadRequest], options: &BatchOptions) -> Vec<Result<TData>> {
    #[cfg(feature = "parallel")]
    {
        if requests.is_empty() {
            return Vec::new();
        }
        match pool::build(options.thread_count()) {
            Ok(pool) => pool::map(&pool, requests, load_one),
            Err(error) => requests
                .iter()
                .map(|_| Err(pool::to_error(&error)))
                .collect(),
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = options;
        requests.iter().map(load_one).collect()
    }
}

/// Applies `f` to every item of `items` and returns the outputs in input
/// order. Bindings use it to convert many accounts or folders at once; `f`
/// returns its own `Result` when a conversion can fail per item.
///
/// # Errors
/// [`crate::Error::Io`] when the thread pool cannot be built; `f` has not
/// run on any item then. Never fails without the `parallel` feature.
///
/// # Panics
/// Propagates a panic of `f`, as a sequential loop would.
pub fn map_many<T, R>(
    items: &[T],
    options: &BatchOptions,
    f: impl Fn(&T) -> R + Sync,
) -> Result<Vec<R>>
where
    T: Sync,
    R: Send,
{
    #[cfg(feature = "parallel")]
    {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let pool = pool::build(options.thread_count()).map_err(|error| pool::to_error(&error))?;
        Ok(pool::map(&pool, items, f))
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = options;
        Ok(items.iter().map(f).collect())
    }
}

#[cfg(feature = "parallel")]
mod pool {
    use std::num::NonZeroUsize;

    use rayon::prelude::*;
    use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};

    use crate::Error;

    /// A fresh pool for one call, never the global one.
    pub(super) fn build(threads: NonZeroUsize) -> Result<ThreadPool, ThreadPoolBuildError> {
        ThreadPoolBuilder::new()
            .num_threads(threads.get())
            .thread_name(|index| format!("opentele2-batch-{index}"))
            .build()
    }

    /// The pool error is not `Clone`, so each failed item gets its own copy.
    pub(super) fn to_error(error: &ThreadPoolBuildError) -> Error {
        Error::Io(std::io::Error::other(error.to_string()))
    }

    /// An indexed parallel map, whose `collect` keeps input order.
    pub(super) fn map<T, R>(pool: &ThreadPool, items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R>
    where
        T: Sync,
        R: Send,
    {
        pool.install(|| items.par_iter().map(&f).collect())
    }
}
