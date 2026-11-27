//! What TCP flags a flow has shown so far, and what they say about the
//! handshake and the end of the connection.

use super::record::TcpOutcome;
use crate::packet::TcpFlags;

/// What TCP flags we have seen so far in a flow.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TcpProgress {
    syn_fwd: bool,
    syn_ack_rev: bool,
    ack_fwd: bool,
    fin_fwd: bool,
    fin_rev: bool,
    rst_fwd: bool,
    rst_rev: bool,
}

impl TcpProgress {
    pub(super) fn note(&mut self, forward: bool, flags: TcpFlags) {
        if forward {
            self.syn_fwd |= flags.is_connection_request();
            // A plain ACK from the initiator completes the handshake.
            self.ack_fwd |= flags.ack && !flags.syn && !flags.rst;
            self.fin_fwd |= flags.fin;
            self.rst_fwd |= flags.rst;
        } else {
            self.syn_ack_rev |= flags.syn && flags.ack;
            self.fin_rev |= flags.fin;
            self.rst_rev |= flags.rst;
        }
    }

    pub(super) fn is_closed(&self) -> bool {
        self.rst_fwd || self.rst_rev || (self.fin_fwd && self.fin_rev)
    }

    pub(super) fn outcome(&self) -> TcpOutcome {
        if !self.syn_fwd {
            TcpOutcome::Midstream
        } else if self.syn_ack_rev && self.ack_fwd {
            TcpOutcome::Established
        } else if self.syn_ack_rev {
            TcpOutcome::HalfOpen
        } else if self.rst_rev {
            TcpOutcome::Rejected
        } else {
            TcpOutcome::Unanswered
        }
    }
}
