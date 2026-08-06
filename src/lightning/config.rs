//! Configuration for connecting to a Lightning backend.

use std::path::PathBuf;

/// Default gRPC address of an `ldk-server` instance.
pub const DEFAULT_LDK_SERVER_URL: &str = "127.0.0.1:3536";

/// Default request timeout in seconds for unary backend calls.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Connection parameters for an LDK Server sidecar.
///
/// LDK Server authenticates requests with an HMAC over an API key and serves
/// gRPC exclusively over TLS with a self-signed certificate it generates on
/// first startup. Both credentials live in the server's data directory:
/// the certificate at `<data_dir>/tls.crt` and the API key at
/// `<data_dir>/<network>/api_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightningConfig {
    /// Address of the ldk-server gRPC endpoint as `host:port`, without a
    /// scheme (TLS is implied).
    pub base_url: String,
    /// Hex-encoded API key used for HMAC request authentication.
    pub api_key: String,
    /// Path to the server's TLS certificate (PEM). If `None`, the certificate
    /// is looked up at `tls.crt` inside the OS-specific default ldk-server
    /// data directory (see [`default_cert_path`]).
    pub tls_cert_path: Option<PathBuf>,
    /// Timeout in seconds applied to each unary backend call.
    pub timeout_secs: u64,
}

impl Default for LightningConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_LDK_SERVER_URL.to_string(),
            api_key: String::new(),
            tls_cert_path: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }
}

/// Returns the default path of the ldk-server TLS certificate
/// (`<default data dir>/tls.crt`), mirroring ldk-server's own OS-specific
/// data directory convention.
pub fn default_cert_path() -> Option<PathBuf> {
    default_data_dir().map(|dir| dir.join("tls.crt"))
}

/// Returns the OS-specific default data directory used by ldk-server.
fn default_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|home| home.join("Library/Application Support/ldk-server"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|appdata| PathBuf::from(appdata).join("ldk-server"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        dirs::home_dir().map(|home| home.join(".ldk-server"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config = LightningConfig::default();
        assert_eq!(config.base_url, DEFAULT_LDK_SERVER_URL);
        assert!(config.api_key.is_empty());
        assert_eq!(config.tls_cert_path, None);
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn default_cert_path_ends_with_tls_crt() {
        let path = default_cert_path().expect("home dir should resolve in tests");
        assert!(path.ends_with("tls.crt"));
    }
}
