//! Runs the web server (API and dashboard) on its own thread, with a small
//! async runtime. The rest of the daemon is plain threads.

use anyhow::{Context, Result, anyhow};
use flagman_api::ApiState;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::Notify;

pub struct ApiServer {
    handle: JoinHandle<Result<()>>,
}

/// Starts serving on `listener` until `shutdown` is notified.
pub fn start(
    listener: TcpListener,
    state: ApiState,
    ui_dir: Option<PathBuf>,
    shutdown: Arc<Notify>,
) -> Result<ApiServer> {
    let handle = std::thread::Builder::new()
        .name("web".to_string())
        .spawn(move || -> Result<()> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("web-worker")
                .enable_all()
                .build()
                .context("could not start the web server runtime")?;
            runtime.block_on(async move {
                let app = flagman_api::router(state, ui_dir.as_deref());
                flagman_api::serve(listener, app, async move { shutdown.notified().await }).await
            })?;
            Ok(())
        })
        .context("could not start the web server thread")?;
    Ok(ApiServer { handle })
}

impl ApiServer {
    /// Waits until the server has stopped.
    pub fn join(self) -> Result<()> {
        self.handle
            .join()
            .map_err(|_| anyhow!("the web server crashed"))?
    }
}

/// The dashboard folder, if it holds a built dashboard. Otherwise only the
/// API is served, and the log says how to build the dashboard.
pub fn usable_ui_dir(dir: &Path) -> Option<PathBuf> {
    if dir.as_os_str().is_empty() {
        return None;
    }
    if dir.join("index.html").is_file() {
        return Some(dir.to_path_buf());
    }
    tracing::warn!(
        "no dashboard files in {} (build them with `npm run build` in product/ui); \
         serving the API only",
        dir.display()
    );
    None
}

/// Binds the server's address now, so "address already in use" is reported
/// before anything else starts.
pub fn bind(addr: std::net::SocketAddr) -> Result<TcpListener> {
    let listener = TcpListener::bind(addr).with_context(|| {
        format!("could not listen on {addr} (is another flagmand already running?)")
    })?;
    if !addr.ip().is_loopback() {
        tracing::warn!(
            "the dashboard listens on {addr}: other devices on the network can reach it. \
             The token still protects it, but it travels unencrypted (no HTTPS yet)."
        );
    }
    Ok(listener)
}
