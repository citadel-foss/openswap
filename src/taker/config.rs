//! Taker configuration. Controlling various behaviors.
//!
//! This module defines the configuration options for the Taker module, controlling various aspects
//! of the taker's behavior including network settings, connection preferences, and security settings.

use crate::{
    protocol::features::parse_require_features,
    utill::{get_taker_dir, parse_field, parse_toml},
};
use std::{io, io::Write, path::Path};

/// Taker configuration
///
/// This struct defines all configurable parameters for the Taker app, including all network ports and marketplace settings
#[derive(Debug, Clone, PartialEq)]
pub struct TakerConfig {
    /// Control port for Tor interface (default: 9051)
    pub control_port: u16,
    /// Socks port for Tor proxy (default: 9050)
    pub socks_port: u16,
    /// Authentication password for Tor interface
    pub tor_auth_password: String,
    /// Whether funding inputs should be checked against the address blocklist.
    pub check_blocklist: bool,
    /// Feature names every maker must support, each only in the swaps it applies to.
    pub require_features: Vec<String>,
    /// LDK Server gRPC address (`host:port`, no scheme) for Lightning swaps.
    pub ldk_server_url: Option<String>,
    /// Path to the LDK Server API key file.
    pub ldk_api_key_path: Option<String>,
    /// Path to the LDK Server TLS certificate.
    pub ldk_tls_cert_path: Option<String>,
}

impl Default for TakerConfig {
    fn default() -> Self {
        Self {
            control_port: 9051,
            socks_port: 9050,
            tor_auth_password: "".to_string(),
            check_blocklist: false,
            require_features: Vec::new(),
            ldk_server_url: None,
            ldk_api_key_path: None,
            ldk_tls_cert_path: None,
        }
    }
}

impl TakerConfig {
    /// Constructs a [`TakerConfig`] from a specified data directory. Or create default configs and load them.
    ///
    /// The maker(/taker).toml file should exist at the provided data-dir location.
    /// Or else, a new default-config will be loaded and created at the given data-dir location.
    /// If no data-dir is provided, a default config will be created at the default data-dir location.
    ///
    /// For reference of default config checkout `./taker.toml` in repo folder.
    ///
    /// Default data-dir for linux: `~/.openswap/taker`
    /// Default config locations: `~/.openswap/taker/config.toml`.
    pub fn new(config_path: Option<&Path>) -> io::Result<Self> {
        let default_config_path = get_taker_dir()?.join("config.toml");

        let config_path = config_path.unwrap_or(&default_config_path);

        let default_config = Self::default();

        if !config_path.exists() || std::fs::metadata(config_path)?.len() == 0 {
            log::warn!(
                "Taker config file not found, creating default config file at path: {}",
                config_path.display()
            );
            default_config.write_to_file(config_path)?;
        }

        let config_map = parse_toml(config_path)?;

        log::info!(
            "Successfully loaded config file from : {}",
            config_path.display()
        );

        Ok(TakerConfig {
            control_port: parse_field(config_map.get("control_port"), default_config.control_port),
            socks_port: parse_field(config_map.get("socks_port"), default_config.socks_port),
            tor_auth_password: parse_field(
                config_map.get("tor_auth_password"),
                default_config.tor_auth_password,
            ),
            check_blocklist: parse_field(
                config_map.get("check_blocklist"),
                default_config.check_blocklist,
            ),
            require_features: parse_require_features(config_map.get("require_features"))?,
            ldk_server_url: config_map.get("ldk_server_url").cloned(),
            ldk_api_key_path: config_map.get("ldk_api_key_path").cloned(),
            ldk_tls_cert_path: config_map.get("ldk_tls_cert_path").cloned(),
        })
    }

    /// This method serializes the TakerConfig into a TOML format and writes it to disk.
    /// It creates the parent directory if it doesn't exist.
    pub(crate) fn write_to_file(&self, path: &Path) -> std::io::Result<()> {
        let toml_data = format!(
            "# Taker Configuration File
# Control port for Tor control interface
control_port = {}
# Socks port for Tor proxy
socks_port = {}
# Authentication password for Tor control interface
tor_auth_password = {}
# Check funding inputs against the address blocklist
check_blocklist = {}
# Features every maker must support in the swaps they apply to, on one line, e.g. [\"taproot\"]
require_features = [{}]",
            self.control_port,
            self.socks_port,
            self.tor_auth_password,
            self.check_blocklist,
            self.require_features
                .iter()
                .map(|n| format!("\"{n}\""))
                .collect::<Vec<_>>()
                .join(", "),
        );
        let mut toml_data = toml_data;
        if let Some(url) = &self.ldk_server_url {
            toml_data.push_str(&format!(
                "\n# LDK Server gRPC address (host:port, no scheme) for Lightning swaps\nldk_server_url = {url}"
            ));
        }
        if let Some(path) = &self.ldk_api_key_path {
            toml_data.push_str(&format!(
                "\n# Path to the LDK Server API key file\nldk_api_key_path = {path}"
            ));
        }
        if let Some(path) = &self.ldk_tls_cert_path {
            toml_data.push_str(&format!(
                "\n# Path to the LDK Server TLS certificate\nldk_tls_cert_path = {path}"
            ));
        }

        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "config path has no parent directory",
            )
        })?;
        std::fs::create_dir_all(parent)?;
        let mut file = std::fs::File::create(path)?;
        file.write_all(toml_data.as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        maker::MakerServerConfig, taker::api::REFUND_LOCKTIME_BASE, wallet::MIN_FIDELITY_TIMELOCK,
    };

    use super::*;
    use std::{
        collections::HashMap,
        fs::{self, File},
        io::Write,
        path::PathBuf,
    };

    #[test]
    fn compat_v023_configs_keep_values_and_default_to_no_requirements() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Keys and string forms from the v0.2.3 config writers.
        let original = "control_port = 19051\nsocks_port = 19050\n\
            tor_auth_password = secret\ncheck_blocklist = true\n\
            network_port = 16102\nrpc_port = 16103\nbase_fee = 700\n\
            name = \"old-maker\"\nldk_server_url = localhost:3537\n\
            ldk_api_key_path = /tmp/ldk/api_key\nldk_tls_cert_path = /tmp/ldk/tls.crt\n";
        let original = &format!("{original}fidelity_timelock = {MIN_FIDELITY_TIMELOCK}\n");
        fs::write(&path, original).unwrap();
        let maker = MakerServerConfig::new(Some(&path)).unwrap();
        let taker = TakerConfig::new(Some(&path)).unwrap();
        assert!(maker.require_features.is_empty());
        assert!(taker.require_features.is_empty());
        assert_eq!(
            (maker.network_port, maker.rpc_port, maker.base_fee),
            (16102, 16103, 700)
        );
        assert_eq!(maker.name, "old-maker");
        assert_eq!((maker.control_port, maker.socks_port), (19051, 19050));
        assert_eq!((taker.control_port, taker.socks_port), (19051, 19050));
        assert_eq!(maker.tor_auth_password, "secret");
        assert_eq!(taker.tor_auth_password, "secret");
        assert!(maker.check_blocklist && taker.check_blocklist);
        assert_eq!(maker.ldk_server_url, taker.ldk_server_url);
        assert_eq!(maker.ldk_api_key_path, taker.ldk_api_key_path);
        assert_eq!(maker.ldk_tls_cert_path, taker.ldk_tls_cert_path);
        assert_eq!(taker.ldk_server_url.as_deref(), Some("localhost:3537"));
        assert_eq!(taker.ldk_api_key_path.as_deref(), Some("/tmp/ldk/api_key"));
        assert_eq!(taker.ldk_tls_cert_path.as_deref(), Some("/tmp/ldk/tls.crt"));
        assert_eq!(fs::read_to_string(&path).unwrap(), *original);
    }

    #[test]
    fn compat_configs_keep_unknown_requirements_and_keys() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "# future config\nfuture_key = { enabled = true }\n\
            require_features = [\"taproot\", \"future-v2\", \"ln-swap-out\"]\n";
        let original = &format!("{original}fidelity_timelock = {MIN_FIDELITY_TIMELOCK}\n");
        fs::write(&path, original).unwrap();
        let expected = ["taproot", "future-v2", "ln-swap-out"];
        assert_eq!(
            MakerServerConfig::new(Some(&path))
                .unwrap()
                .require_features,
            expected
        );
        assert_eq!(
            TakerConfig::new(Some(&path)).unwrap().require_features,
            expected
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), *original);
    }

    #[test]
    fn compat_configs_refuse_malformed_requirements_without_writing() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        for value in [
            "",
            "taproot",
            "[taproot]",
            "[\"taproot\",]",
            "[\"\"]",
            "[\"Taproot\"]",
            "[\"tap_root\"]",
            "[\"taproot\"] # note",
            "[\n\"taproot\"\n]",
            "[\"taproot\",\n\"legacy\"]",
            r#""["taproot",]""#,
            r#""["Taproot"]""#,
        ] {
            let original = format!("require_features = {value}\nfuture_key = keep\n");
            fs::write(&path, &original).unwrap();
            assert!(
                MakerServerConfig::new(Some(&path)).is_err(),
                "maker: {:?}",
                value
            );
            assert!(TakerConfig::new(Some(&path)).is_err(), "taker: {:?}", value);
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
        }
    }

    #[test]
    fn compat_configs_parse_quoted_requirement_lists_as_contents() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        for (value, expected) in [
            (r#""[]""#, vec![]),
            (
                r#""["taproot", "future-v2"]""#,
                vec!["taproot", "future-v2"],
            ),
        ] {
            let original = format!(
                "require_features = {value}\nfuture_key = keep\n\
                 fidelity_timelock = {MIN_FIDELITY_TIMELOCK}\n"
            );
            fs::write(&path, &original).unwrap();
            let maker = MakerServerConfig::new(Some(&path)).unwrap();
            let taker = TakerConfig::new(Some(&path)).unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
            assert_eq!(maker.require_features, expected, "maker: {value}");
            assert_eq!(taker.require_features, expected, "taker: {value}");
        }
    }

    #[test]
    fn compat_v023_readers_ignore_new_requirements() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let requires = vec!["future-v2".to_string(), "taproot".to_string()];
        let maker = MakerServerConfig {
            control_port: 19051,
            socks_port: 19050,
            tor_auth_password: "secret".to_string(),
            check_blocklist: true,
            require_features: requires.clone(),
            ..MakerServerConfig::default()
        };
        let taker = TakerConfig {
            control_port: 19051,
            socks_port: 19050,
            tor_auth_password: "secret".to_string(),
            check_blocklist: true,
            require_features: requires,
            ..TakerConfig::default()
        };
        for is_maker in [true, false] {
            if is_maker {
                maker.write_to_file(&path).unwrap();
            } else {
                taker.write_to_file(&path).unwrap();
            }
            // Frozen v0.2.3 line reader: old config constructors select only known keys.
            let mut old_map = HashMap::new();
            let content = fs::read_to_string(&path).unwrap();
            for line in content.lines().filter(|line| !line.is_empty()) {
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim();
                    let value = value
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(value);
                    old_map.insert(key.trim().to_string(), value.to_string());
                }
            }
            for (key, expected) in [
                ("control_port", "19051"),
                ("socks_port", "19050"),
                ("tor_auth_password", "secret"),
                ("check_blocklist", "true"),
            ] {
                assert_eq!(old_map.get(key).unwrap(), expected);
            }
        }
    }

    #[test]
    fn compat_requirements_round_trip_through_both_config_writers() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        for names in [vec![], vec!["legacy", "taproot", "future-v12"]] {
            let requires: Vec<String> = names.iter().map(|n| n.to_string()).collect();
            let maker = MakerServerConfig {
                require_features: requires.clone(),
                fidelity_timelock: MIN_FIDELITY_TIMELOCK,
                ..MakerServerConfig::default()
            };
            maker.write_to_file(&path).unwrap();
            assert_eq!(
                MakerServerConfig::new(Some(&path))
                    .unwrap()
                    .require_features,
                requires
            );
            let taker = TakerConfig {
                require_features: requires.clone(),
                ..TakerConfig::default()
            };
            taker.write_to_file(&path).unwrap();
            assert_eq!(TakerConfig::new(Some(&path)).unwrap(), taker);
        }
    }

    fn create_temp_config(contents: &str, file_name: &str) -> PathBuf {
        let file_path = PathBuf::from(file_name);
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "{contents}").unwrap();
        file_path
    }

    fn remove_temp_config(path: &Path) {
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_valid_config() {
        let contents = r#"
        control_port = 9051
        socks_port = 9050
        connection_type = "TOR"
        rpc_port = 8081
        "#;
        let config_path = create_temp_config(contents, "valid_taker_config.toml");
        let config = TakerConfig::new(Some(&config_path)).unwrap();
        remove_temp_config(&config_path);

        let default_config = TakerConfig::default();
        assert_eq!(config, default_config);
    }

    #[test]
    fn test_missing_fields() {
        let contents = r#"
            [taker_config]
            refund_locktime = 48
        "#;
        let config_path = create_temp_config(contents, "missing_fields_taker_config.toml");
        let config = TakerConfig::new(Some(&config_path)).unwrap();
        remove_temp_config(&config_path);

        #[cfg(not(feature = "integration-test"))]
        assert_eq!(REFUND_LOCKTIME_BASE, 20);
        #[cfg(feature = "integration-test")]
        assert_eq!(REFUND_LOCKTIME_BASE, 150);
        assert_eq!(config, TakerConfig::default());
    }

    #[test]
    fn test_incorrect_data_type() {
        let contents = r#"
            [taker_config]
            refund_locktime = "not_a_number"
        "#;
        let config_path = create_temp_config(contents, "incorrect_type_taker_config.toml");
        let config = TakerConfig::new(Some(&config_path)).unwrap();
        remove_temp_config(&config_path);

        assert_eq!(config, TakerConfig::default());
    }

    #[test]
    fn test_different_data() {
        let contents = r#"
            [taker_config]
            socks_port = 9050
            check_blocklist = true
        "#;
        let config_path = create_temp_config(contents, "different_data_taker_config.toml");
        let config = TakerConfig::new(Some(&config_path)).unwrap();
        remove_temp_config(&config_path);
        #[cfg(not(feature = "integration-test"))]
        assert_eq!(REFUND_LOCKTIME_BASE, 20);
        #[cfg(feature = "integration-test")]
        assert_eq!(REFUND_LOCKTIME_BASE, 150);
        assert_eq!(
            TakerConfig {
                socks_port: 9050,         // Configurable via TOML.
                check_blocklist: true,    // Explicitly enabled at runtime.
                ..TakerConfig::default()  // Use default for other values.
            },
            config
        );
    }

    #[test]
    fn test_missing_file() {
        let config_path = get_taker_dir().unwrap().join("taker.toml");
        let config = TakerConfig::new(Some(&config_path)).unwrap();
        remove_temp_config(&config_path);
        assert_eq!(config, TakerConfig::default());
    }

    /// The taker's Lightning settings must load and survive the rewrite, for
    /// the same reason as the maker's: a dropped field silently disables
    /// Lightning on the next start.
    #[test]
    fn lightning_settings_round_trip_through_the_config_file() {
        let contents = r#"
            control_port = 9051
            socks_port = 9050
            ldk_server_url = 127.0.0.1:3537
            ldk_api_key_path = /tmp/ldk2/api_key
            ldk_tls_cert_path = /tmp/ldk2/tls.crt
        "#;
        let path = create_temp_config(contents, "taker_ln_config.toml");
        let loaded = TakerConfig::new(Some(&path)).unwrap();
        assert_eq!(loaded.ldk_server_url.as_deref(), Some("127.0.0.1:3537"));
        assert_eq!(
            loaded.ldk_api_key_path.as_deref(),
            Some("/tmp/ldk2/api_key")
        );
        assert_eq!(
            loaded.ldk_tls_cert_path.as_deref(),
            Some("/tmp/ldk2/tls.crt")
        );

        let rewritten = PathBuf::from("taker_ln_config_rewritten.toml");
        loaded.write_to_file(&rewritten).unwrap();
        let reloaded = TakerConfig::new(Some(&rewritten)).unwrap();
        assert_eq!(reloaded, loaded);

        remove_temp_config(&path);
        remove_temp_config(&rewritten);
    }

    /// Absent keys stay absent rather than defaulting to a sidecar that is
    /// not there.
    #[test]
    fn lightning_settings_absent_by_default() {
        let path = create_temp_config("control_port = 9051\n", "taker_no_ln_config.toml");
        let loaded = TakerConfig::new(Some(&path)).unwrap();
        assert!(loaded.ldk_server_url.is_none());
        assert!(loaded.ldk_api_key_path.is_none());
        assert!(loaded.ldk_tls_cert_path.is_none());
        remove_temp_config(&path);
    }
}
