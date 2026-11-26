//! Suricata integration: Flagman reads the alerts Suricata writes to its
//! EVE JSON log (one JSON object per line), and never links to Suricata's
//! code. Suricata runs as its own program, under its own licence (GPL-2.0).
//!
//! - [`parse_alert_line`] turns one EVE line into a [`SignatureHit`].
//! - [`EveTailer`] follows the log file as Suricata appends to it, like `tail -f`.

mod eve;
mod tail;

pub use eve::parse_alert_line;
pub use flagman_core::detect::SignatureHit;
pub use tail::EveTailer;
