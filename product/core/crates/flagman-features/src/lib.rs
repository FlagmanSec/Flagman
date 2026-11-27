//! Flagman's per-flow features for machine learning.
//!
//! The flow table of `flagman-core` keeps a [`FeatureState`] next to each
//! flow (`FlowTable<FeatureState>`), updates it with every packet, and hands
//! out a [`FeatureFlow`] when the flow ends: its record, kept for labelling,
//! and its [`FlowFeatures`], the only values a model may learn from.
//!
//! The same code runs in the live sensor and when a capture file is
//! replayed, so a model is trained on exactly what it will see live (the
//! first lesson of the CS395 project). The README lists every feature,
//! every value left out on purpose and why, and the memory each flow costs.

pub mod direction;
pub mod features;
pub mod port_class;
pub mod schema;
pub mod state;
pub mod stats;

pub use features::{FeatureFlow, FlowFeatures, SideFeatures};
pub use port_class::PortClass;
pub use schema::{SCHEMA_VERSION, schema_json};
pub use state::FeatureState;
