//! Shared cancellation, task ownership and process-wide resource budgets.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

pub const IO_TIMEOUT: Duration = Duration::from_secs(10);
pub const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_SESSIONS: usize = 128;
pub const MAX_STREAMS: usize = 128;
pub const MAX_ASSOCIATIONS: usize = 128;
pub const MAX_UDP_PAYLOAD: usize = 65_507;

#[derive(Clone)]
pub struct Shutdown(watch::Sender<bool>);

impl Shutdown {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self(tx)
    }

    pub fn cancel(&self) {
        self.0.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    pub async fn cancelled(&self) {
        let mut rx = self.0.subscribe();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Dropping a handle must cancel its task, not detach it. In particular this
/// also applies when an owning future is aborted or returns early with `?`.
pub struct Task<T>(JoinHandle<T>);

impl<T> Task<T> {
    pub fn spawn(future: impl Future<Output = T> + Send + 'static) -> Self
    where
        T: Send + 'static,
    {
        Self(tokio::spawn(future))
    }

    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    pub async fn stop(&mut self) {
        self.0.abort();
        let _ = (&mut self.0).await;
    }
}

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
pub struct Resources {
    sockets: Arc<Semaphore>,
    fragments: Arc<Semaphore>,
}

impl Resources {
    pub fn new() -> Self {
        Self {
            // Leave room below a common 1024 FD limit for listeners, endpoints,
            // logs, DNS and runtime infrastructure. Shared by every tunnel.
            sockets: Arc::new(Semaphore::new(512)),
            fragments: Arc::new(Semaphore::new(8 * 1024 * 1024)),
        }
    }

    pub fn socket(&self) -> anyhow::Result<OwnedSemaphorePermit> {
        self.sockets.clone().try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("process connection budget exhausted"))
    }

    pub fn fragment(&self, bytes: usize) -> Option<OwnedSemaphorePermit> {
        let bytes = u32::try_from(bytes).ok()?;
        self.fragments.clone().try_acquire_many_owned(bytes).ok()
    }
}

pub fn unspecified_for(remote: SocketAddr) -> SocketAddr {
    let ip = if remote.is_ipv6() {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    SocketAddr::new(ip, 0)
}

pub async fn resolve(remote: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let addrs = tokio::time::timeout(IO_TIMEOUT, tokio::net::lookup_host(remote))
        .await
        .map_err(|_| anyhow::anyhow!("DNS resolution timed out"))??;
    let mut result = Vec::new();
    for addr in addrs {
        if !result.contains(&addr) { result.push(addr); }
    }
    anyhow::ensure!(!result.is_empty(), "DNS resolved no addresses");
    Ok(result)
}

/// EOF shuts down only one direction. The other direction is allowed to
/// finish, but cannot retain a socket forever after its peer half-closes.
pub async fn relay_halves<U, D>(upload: U, download: D) -> anyhow::Result<()>
where
    U: Future<Output = anyhow::Result<()>>,
    D: Future<Output = anyhow::Result<()>>,
{
    tokio::pin!(upload, download);
    tokio::select! {
        result = &mut upload => {
            result?;
            tokio::time::timeout(HALF_CLOSE_TIMEOUT, &mut download)
                .await.map_err(|_| anyhow::anyhow!("half-close timed out"))?
        }
        result = &mut download => {
            result?;
            tokio::time::timeout(HALF_CLOSE_TIMEOUT, &mut upload)
                .await.map_err(|_| anyhow::anyhow!("half-close timed out"))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_is_latched_for_late_subscribers() {
        let shutdown = Shutdown::new();
        shutdown.cancel();
        assert!(shutdown.is_cancelled());
        tokio::time::timeout(Duration::from_millis(100), shutdown.cancelled()).await.unwrap();
    }

    #[tokio::test]
    async fn dropping_task_does_not_detach_it() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = Task::spawn(async move {
            let _sender = tx;
            std::future::pending::<()>().await;
        });
        drop(task);
        assert!(rx.await.is_err());
    }
}
