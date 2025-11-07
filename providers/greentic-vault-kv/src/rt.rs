use once_cell::sync::Lazy;
use tokio::runtime::{self, Handle};

static RUNTIME: Lazy<runtime::Runtime> = Lazy::new(|| {
    runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("vault-kv-rt")
        .build()
        .expect("build vault-kv runtime")
});

/// Run the provided future to completion regardless of the current context.
pub fn block_on<F>(fut: F) -> F::Output
where
    F: std::future::Future,
{
    if let Ok(handle) = Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        RUNTIME.block_on(fut)
    }
}
