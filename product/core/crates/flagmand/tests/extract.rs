//! `flagmand extract`, run as a real program: two separate runs on the same
//! capture must give byte-identical files.
//!
//! Each run is a new process, so the hash tables get new random seeds, as
//! they would on another day or another machine. Only built with
//! `--features parquet`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/pcap")
        .join(name)
}

fn extract(pcap: &Path, out: &Path) {
    let run = Command::new(env!("CARGO_BIN_EXE_flagmand"))
        .arg("extract")
        .arg(pcap)
        .arg("--out")
        .arg(out)
        .output()
        .expect("flagmand runs");
    assert!(
        run.status.success(),
        "flagmand extract failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn extracting_the_same_capture_twice_gives_byte_identical_files() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "lab-attack-chain.pcap",
        "lab-normal-traffic.pcap",
        "lab-ssh-logins.pcap",
    ] {
        let first = dir.path().join(format!("{name}.1.parquet"));
        let second = dir.path().join(format!("{name}.2.parquet"));
        extract(&fixture(name), &first);
        extract(&fixture(name), &second);
        let first = std::fs::read(first).unwrap();
        let second = std::fs::read(second).unwrap();
        assert!(!first.is_empty());
        assert!(first == second, "{name}: the two files differ");
    }
}
