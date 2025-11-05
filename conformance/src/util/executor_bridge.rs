use once_cell::sync::Lazy;
use std::future::Future;
use tokio::{
    runtime::{Builder, Handle},
    sync::oneshot,
};

/// Global Tokio runtime handle leaked for the lifetime of the process.
#[allow(dead_code)]
static RUNTIME_HANDLE: Lazy<&'static Handle> = Lazy::new(|| {
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name("secrets-exec")
        .build()
        .expect("build global tokio runtime");

    // Leak the runtime so it is never dropped (avoids shutdown panic inside blocking contexts).
    let leaked_rt: &'static tokio::runtime::Runtime = Box::leak(Box::new(runtime));
    let handle = leaked_rt.handle().clone();

    Box::leak(Box::new(handle))
});

/// Run a future on the global runtime from synchronous code.
/// If already inside Tokio, use the current handle; otherwise block on a oneshot.
#[allow(dead_code)]
pub fn run_blocking_on_executor<F, T>(fut: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    if let Ok(handle) = Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        let (tx, rx) = oneshot::channel();
        RUNTIME_HANDLE.spawn(async move {
            let result = fut.await;
            let _ = tx.send(result);
        });
        rx.blocking_recv().expect("executor bridge dropped")
    }
}

/// Run a future on the global runtime from async code that may not already be inside Tokio.
#[allow(dead_code)]
pub async fn run_async_on_executor<F, T>(fut: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    if Handle::try_current().is_ok() {
        fut.await
    } else {
        let (tx, rx) = oneshot::channel();
        RUNTIME_HANDLE.spawn(async move {
            let result = fut.await;
            let _ = tx.send(result);
        });
        tokio::task::spawn_blocking(move || rx.blocking_recv().expect("executor bridge dropped"))
            .await
            .expect("spawn_blocking join error")
    }
}
