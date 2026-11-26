//! The dashboard's access token.
//!
//! - 32 random bytes from the operating system, written as 64 hex characters.
//! - Stored in a file only the daemon's user can read (mode 0600).
//! - The dashboard link carries it after `#`, a part of the address that
//!   browsers never send to the server or to other sites.

use anyhow::{Context, Result, bail};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const TOKEN_BYTES: usize = 32;

/// A new random token.
pub fn generate() -> Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("no randomness: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Reads the token file, or creates it with a new token on first start.
pub fn load_or_create(path: &Path) -> Result<String> {
    if path.exists() {
        return load(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let token = generate()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("could not create the token file {}", path.display()))?;
    writeln!(file, "{token}")?;
    tracing::info!("created a new dashboard token in {}", path.display());
    Ok(token)
}

/// Reads an existing token file. Tightens its permissions if others can read it.
pub fn load(path: &Path) -> Result<String> {
    let mode = fs::metadata(path)
        .with_context(|| format!("could not read {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        tracing::warn!(
            "{} could be read by other users; restricting it to mode 0600",
            path.display()
        );
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let token = fs::read_to_string(path)
        .with_context(|| format!("could not read the token file {}", path.display()))?
        .trim()
        .to_string();
    if token.len() < 32 || !token.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!(
            "the token file {} is damaged; delete it and restart to create a new one",
            path.display()
        );
    }
    Ok(token)
}

/// The link to open in a browser. A server listening on every address
/// (0.0.0.0) is shown with this machine's loopback address.
pub fn dashboard_url(listen: SocketAddr, token: &str) -> String {
    let host = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    format!(
        "http://{}/#token={token}",
        SocketAddr::new(host, listen.port())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_long_random_and_hex() {
        let first = generate().unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, generate().unwrap());
    }

    #[test]
    fn the_token_file_is_created_once_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("api-token");
        let created = load_or_create(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(load_or_create(&path).unwrap(), created);
    }

    #[test]
    fn links_point_at_a_reachable_address() {
        let url = dashboard_url("0.0.0.0:8750".parse().unwrap(), "abc");
        assert_eq!(url, "http://127.0.0.1:8750/#token=abc");
        let url = dashboard_url("[::]:8750".parse().unwrap(), "abc");
        assert_eq!(url, "http://[::1]:8750/#token=abc");
    }
}
