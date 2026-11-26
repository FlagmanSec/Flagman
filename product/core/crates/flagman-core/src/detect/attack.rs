//! MITRE ATT&CK references used by the built-in detectors.
//! Tactics and techniques are listed at <https://attack.mitre.org/>.

use crate::alert::AttackRef;

fn reference(tactic_id: &str, tactic: &str, technique_id: &str, technique: &str) -> AttackRef {
    AttackRef {
        tactic_id: tactic_id.to_string(),
        tactic: tactic.to_string(),
        technique_id: technique_id.to_string(),
        technique: technique.to_string(),
    }
}

/// Port scans: looking for which services a machine offers.
pub fn network_service_discovery() -> AttackRef {
    reference("TA0007", "Discovery", "T1046", "Network Service Discovery")
}

/// Host sweeps: looking for which machines exist on the network.
pub fn remote_system_discovery() -> AttackRef {
    reference("TA0007", "Discovery", "T1018", "Remote System Discovery")
}

/// Repeated login attempts against a service.
pub fn brute_force() -> AttackRef {
    reference("TA0006", "Credential Access", "T1110", "Brute Force")
}
