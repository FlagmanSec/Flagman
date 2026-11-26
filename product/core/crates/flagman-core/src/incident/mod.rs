//! Incidents: alerts grouped per source host into one readable story.

mod engine;
mod model;

pub use engine::IncidentEngine;
pub use model::{Incident, MAX_TARGETS};
