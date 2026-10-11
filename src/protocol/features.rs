//! Feature names: what peers offer and require, and what stored records need.
//!
//! Rules every later release must keep:
//! - Names are append-only. A name, its meaning, its reader and its recovery are
//!   never removed, and a supported name stays in `Hello` for reconnect checks.
//! - `x-v(N+1)` keeps every guarantee of `x-vN`; anything else is a new family.
//!   Requiring `x-vN` means "family `x` at version N or higher".
//! - An incompatible encryption or KDF change adds a format name and keeps the old reader.

use crate::utill::parse_list;
use std::io;

/// One entry of the feature registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feature {
    /// Wire and disk name, `[a-z0-9-]`.
    pub name: &'static str,
    /// Protocol flows this feature applies to. Nothing else in the code says which.
    pub flows: &'static [&'static str],
    /// Served only by builds with the `lightning` cargo feature.
    pub lightning: bool,
}

/// Every name this build recognizes.
pub const KNOWN: &[Feature] = &[
    Feature {
        name: "legacy",
        flows: &["legacy"],
        lightning: false,
    },
    Feature {
        name: "taproot",
        flows: &["taproot"],
        lightning: false,
    },
    Feature {
        name: "ln-swap-in",
        flows: &["ln-swap-in"],
        lightning: true,
    },
    Feature {
        name: "ln-swap-out",
        flows: &["ln-swap-out"],
        lightning: true,
    },
];

/// Names this build can serve.
pub fn supported() -> Vec<&'static str> {
    KNOWN
        .iter()
        .filter(|f| cfg!(feature = "lightning") || !f.lightning)
        .map(|f| f.name)
        .collect()
}

/// Splits `x-vN` into family `x` and version N. A name without a canonical
/// `-vN` suffix (no leading zero) is its own family at version 0.
pub fn family_and_version(name: &str) -> (&str, u32) {
    name.rsplit_once("-v")
        .filter(|(_, n)| !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|(family, n)| Some((family, n.parse().ok()?)))
        .unwrap_or((name, 0))
}

/// Whether `name` is a well-formed feature name.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Returns the required names that no offered name meets. An offered name meets
/// a required one when it is in the same family at the same or a higher version.
pub fn check_requires<R: AsRef<str>>(
    required: impl IntoIterator<Item = R>,
    offered: &[impl AsRef<str>],
) -> Result<(), Vec<String>> {
    let missing: Vec<String> = required
        .into_iter()
        .filter(|r| {
            let (family, version) = family_and_version(r.as_ref());
            !offered.iter().any(|o| {
                let (o_family, o_version) = family_and_version(o.as_ref());
                o_family == family && o_version >= version
            })
        })
        .map(|r| r.as_ref().to_string())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

/// Reads a `require_features` config value. A malformed list or name stops
/// startup; a name this build can't serve only warns, as requiring it is the user's choice.
pub(crate) fn parse_require_features(value: Option<&String>) -> io::Result<Vec<String>> {
    let names = parse_list(value)?;
    if let Some(bad) = names.iter().find(|n| !is_valid_name(n)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("require_features: invalid feature name {bad:?}"),
        ));
    }
    if let Err(unknown) = check_requires(&names, &supported()) {
        log::warn!("require_features lists names this build does not support: {unknown:?}");
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_split_only_on_a_canonical_suffix() {
        assert_eq!(family_and_version("taproot"), ("taproot", 0));
        assert_eq!(family_and_version("bip324-v1"), ("bip324", 1));
        assert_eq!(family_and_version("x-v12"), ("x", 12));
        for own_family in ["x-v", "x-v0", "x-v01", "x-v+1", "x-v1a", "x-v99999999999"] {
            assert_eq!(family_and_version(own_family), (own_family, 0));
        }
    }

    #[test]
    fn a_higher_version_meets_a_lower_requirement() {
        let offered = ["taproot", "x-v2"];
        assert_eq!(
            check_requires(["x-v1", "x-v2", "taproot"], &offered),
            Ok(())
        );
        assert_eq!(
            check_requires(["x-v3", "y-v1", "legacy"], &offered),
            Err(vec![
                "x-v3".to_string(),
                "y-v1".to_string(),
                "legacy".to_string()
            ])
        );
        assert_eq!(check_requires(["x"], &offered), Ok(()));
        assert_eq!(check_requires(Vec::<&str>::new(), &offered), Ok(()));
    }

    #[test]
    fn registry_names_are_valid_and_lightning_needs_the_cargo_feature() {
        assert!(KNOWN.iter().all(|f| is_valid_name(f.name)));
        assert!(!is_valid_name("") && !is_valid_name("Taproot") && !is_valid_name("a b"));
        assert_eq!(
            supported().contains(&"ln-swap-in"),
            cfg!(feature = "lightning")
        );
        assert!(supported().contains(&"taproot"));
    }

    #[test]
    fn require_features_fails_closed_on_bad_names() {
        let read = |v: &str| parse_require_features(Some(&v.to_string()));
        assert_eq!(
            read(r#"["taproot", "future-v1"]"#).unwrap(),
            ["taproot", "future-v1"]
        );
        assert!(read(r#"["Taproot"]"#).is_err());
        assert!(read(r#"[""]"#).is_err());
        assert!(parse_require_features(None).unwrap().is_empty());
    }
}
