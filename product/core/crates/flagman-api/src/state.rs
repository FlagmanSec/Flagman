//! What every request handler can reach: the database, the sensor health,
//! the token and the clock.

use crate::error::ApiError;
use flagman_core::health::SensorHealth;
use flagman_store::{Store, StoreError};
use std::sync::{Arc, Mutex, RwLock};

/// What "now" means when the dashboard asks for "the last hour".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    /// The real time (live capture).
    Live,
    /// The newest data in the database (replay of an old capture).
    LatestData,
}

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Mutex<Store>>,
    pub health: Arc<RwLock<SensorHealth>>,
    pub token: Arc<str>,
    pub clock: Clock,
}

impl ApiState {
    /// Runs a database query on a blocking thread, so slow queries never
    /// stall the web server's async threads.
    pub(crate) async fn query<T, F>(&self, work: F) -> Result<T, ApiError>
    where
        F: FnOnce(&mut Store, Clock) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let store = Arc::clone(&self.store);
        let clock = self.clock;
        tokio::task::spawn_blocking(move || {
            let mut store = store
                .lock()
                .map_err(|_| ApiError::internal("the database lock is poisoned"))?;
            work(&mut store, clock).map_err(ApiError::from)
        })
        .await
        .map_err(|_| ApiError::internal("the query task stopped unexpectedly"))?
    }
}
