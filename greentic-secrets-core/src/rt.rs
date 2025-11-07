use once_cell::sync::Lazy;
use tokio::runtime::{self, Handle};

static RUNTIME: Lazy<runtime::Runtime> = Lazy::new(|| {
    runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("greentic-secrets-rt")
        .build()
        .expect("build greentic-secrets runtime")
});

/// Run a future to completion from synchronous code without nesting runtimes.
pub fn sync_await<F>(fut: F) -> F::Output
where
    F: std::future::Future,
{
    if let Ok(handle) = Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        RUNTIME.block_on(fut)
    }
}
