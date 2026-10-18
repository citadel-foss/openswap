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

/// Protocol features this build recognizes. Disk format names are listed in
/// `crate::security::FORMAT_NAMES` and included by [`supported`].
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
        .chain(crate::security::FORMAT_NAMES.iter().copied())
        .collect()
}

/// Most names a peer's feature list may hold.
pub const MAX_FEATURES: usize = 128;
/// Longest feature name a peer may send.
pub const MAX_FEATURE_NAME_LEN: usize = 64;

/// Refuses a list with too many names or an overlong one.
pub fn check_bounds(names: &[String]) -> Result<(), String> {
    if names.len() > MAX_FEATURES {
        return Err(format!("more than {MAX_FEATURES} feature names"));
    }
    if names.iter().any(|n| n.len() > MAX_FEATURE_NAME_LEN) {
        return Err(format!(
            "a feature name is longer than {MAX_FEATURE_NAME_LEN} bytes"
        ));
    }
    Ok(())
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

/// Picks a swap's pins for `flow`: per family that changes the flow, the highest
/// version both sides list. Pins are exact names, unlike requirements.
pub fn choose_pins(flow: &str, theirs: &[String]) -> Vec<String> {
    let ours = supported();
    let mut pins: Vec<&str> = Vec::new();
    for feature in KNOWN.iter().filter(|f| {
        f.flows.contains(&flow) && ours.contains(&f.name) && theirs.iter().any(|t| t == f.name)
    }) {
        let (family, version) = family_and_version(feature.name);
        match pins
            .iter_mut()
            .find(|pin| family_and_version(pin).0 == family)
        {
            Some(pin) if family_and_version(pin).1 < version => *pin = feature.name,
            Some(_) => {}
            None => pins.push(feature.name),
        }
    }
    pins.into_iter().map(String::from).collect()
}

/// Whether a requirement constrains `flow`. A family this build doesn't know
/// always does, so an unknown requirement refuses the swap instead of passing it.
fn applies_to(required: &str, flow: &str) -> bool {
    let family = family_and_version(required).0;
    let mut known = KNOWN
        .iter()
        .filter(|f| family_and_version(f.name).0 == family)
        .peekable();
    known.peek().is_none() || known.any(|f| f.flows.contains(&flow))
}

/// The requirements the Hello can already judge: families this build doesn't
/// know apply to every flow. Known families wait for the swap's pins.
pub fn unmet_at_hello(required: &[String], offered: &[String]) -> Result<(), Vec<String>> {
    check_requires(
        required.iter().filter(|r| {
            let family = family_and_version(r).0;
            !KNOWN.iter().any(|f| family_and_version(f.name).0 == family)
        }),
        offered,
    )
}

/// The requirements a swap on `flow` leaves unmet with these pins.
pub fn unmet_for_flow(required: &[String], pins: &[String], flow: &str) -> Result<(), Vec<String>> {
    check_requires(required.iter().filter(|r| applies_to(r, flow)), pins)
}

/// Checks a peer's pins for one swap and returns its flow. Every pin must be a
/// name we serve that changes that one flow, at most one per family, and our
/// requirements for the flow must be met.
pub fn check_pins(pins: &[String], required: &[String]) -> Result<&'static str, String> {
    check_bounds(pins)?;
    let ours = supported();
    let flows: Vec<&'static str> = ours
        .iter()
        .copied()
        .filter(|name| {
            pins.iter().any(|p| p == name) && KNOWN.iter().any(|f| f.flows.contains(name))
        })
        .collect();
    let [flow] = flows[..] else {
        return Err(format!("pins {pins:?} must name exactly one flow"));
    };
    if let Some(stray) = pins.iter().find(|p| {
        !KNOWN
            .iter()
            .any(|f| f.name == p.as_str() && ours.contains(&f.name) && f.flows.contains(&flow))
    }) {
        return Err(format!("pin {stray:?} is not served for {flow}"));
    }
    for (i, pin) in pins.iter().enumerate() {
        let family = family_and_version(pin).0;
        if pins[..i].iter().any(|p| family_and_version(p).0 == family) {
            return Err(format!("more than one pin in family {family:?}"));
        }
    }
    unmet_for_flow(required, pins, flow)
        .map_err(|missing| format!("pins leave required features unmet: {missing:?}"))?;
    Ok(flow)
}

/// Reads a `require_features` config value. A malformed list or name stops
/// startup; a name this build can't serve only warns, as requiring it is the user's choice.
pub(crate) fn parse_require_features(value: Option<&String>) -> io::Result<Vec<String>> {
    let names = parse_list(value)?;
    check_bounds(&names).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("require_features: {e}"))
    })?;
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
    fn compat_registry_keeps_names_flows_and_build_support() {
        for (name, flow, lightning) in [
            ("legacy", "legacy", false),
            ("taproot", "taproot", false),
            ("ln-swap-in", "ln-swap-in", true),
            ("ln-swap-out", "ln-swap-out", true),
        ] {
            let entries: Vec<_> = KNOWN.iter().filter(|f| f.name == name).collect();
            assert_eq!(entries.len(), 1, "{name}");
            assert!(entries[0].flows.contains(&flow), "{}", name);
            assert_eq!(entries[0].lightning, lightning, "{name}");
            assert_eq!(
                supported().contains(&name),
                !lightning || cfg!(feature = "lightning")
            );
        }
        for (i, feature) in KNOWN.iter().enumerate() {
            assert!(!feature.flows.is_empty());
            assert!(!KNOWN[..i].iter().any(|f| f.name == feature.name));
        }
    }

    #[test]
    fn compat_requirement_versions_do_not_cross_families() {
        for (required, offered, met) in [
            ("x-v2", "x-v1", false),
            ("x-v2", "x-v2", true),
            ("x-v2", "x-v3", true),
            ("x-v2", "y-v3", false),
            ("x-v2", "x", false),
            ("x", "x-v1", true),
            ("x-v01", "x-v1", false),
            ("x-v01", "x-v01", true),
            ("x-v4294967295", "x-v4294967295", true),
            ("ln-swap-in", "ln-swap-out", false),
        ] {
            assert_eq!(
                check_requires([required], &[offered]).is_ok(),
                met,
                "{required}, {offered}"
            );
        }
        assert_eq!(
            check_requires(["future-v1"], &[] as &[&str]),
            Err(vec!["future-v1".to_string()])
        );
    }

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
    fn feature_lists_are_bounded() {
        let names = |n: usize| vec!["a".to_string(); n];
        assert!(check_bounds(&names(MAX_FEATURES)).is_ok());
        assert!(check_bounds(&names(MAX_FEATURES + 1)).is_err());
        assert!(check_bounds(&["a".repeat(MAX_FEATURE_NAME_LEN + 1)]).is_err());
        assert!(check_pins(&names(MAX_FEATURES + 1), &[]).is_err());
    }

    #[test]
    fn hello_defers_known_families_to_pins() {
        let required = vec!["ln-swap-out".to_string(), "x-v1".to_string()];
        assert_eq!(
            unmet_at_hello(&required, &[]),
            Err(vec!["x-v1".to_string()])
        );
        assert_eq!(unmet_at_hello(&required, &["x-v1".to_string()]), Ok(()));
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

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn pins_take_only_mutual_names_for_the_flow() {
        let theirs = names(&["legacy", "taproot", "future-v9"]);
        assert_eq!(choose_pins("taproot", &theirs), ["taproot"]);
        assert_eq!(choose_pins("legacy", &theirs), ["legacy"]);
        assert!(choose_pins("taproot", &names(&["legacy"])).is_empty());
    }

    #[test]
    fn pins_are_checked_for_one_served_flow() {
        assert_eq!(check_pins(&names(&["taproot"]), &[]), Ok("taproot"));
        for bad in [
            names(&[]),
            names(&["legacy", "taproot"]),
            names(&["taproot", "taproot"]),
            names(&["taproot", "future-v1"]),
        ] {
            assert!(check_pins(&bad, &[]).is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn requirements_bind_only_their_own_flows_but_unknown_ones_bind_all() {
        let taproot = names(&["taproot"]);
        // `legacy` changes only the legacy flow, so a taproot swap meets it.
        assert_eq!(
            unmet_for_flow(&names(&["legacy"]), &taproot, "taproot"),
            Ok(())
        );
        assert!(unmet_for_flow(&names(&["future-v1"]), &taproot, "taproot").is_err());
        assert!(check_pins(&taproot, &names(&["future-v1"])).is_err());
    }

    #[test]
    fn compat_pins_obey_flow_requirements_and_build_support() {
        let theirs = KNOWN.iter().map(|f| f.name.to_string()).collect::<Vec<_>>();
        for flow in ["legacy", "taproot", "ln-swap-in", "ln-swap-out"] {
            let pins = choose_pins(flow, &theirs);
            let served = supported().contains(&flow);
            assert_eq!(pins, if served { names(&[flow]) } else { vec![] });
            assert_eq!(check_pins(&names(&[flow]), &[]).is_ok(), served);
            assert!(check_pins(&names(&[flow, flow]), &[]).is_err());
            assert!(check_pins(&names(&[flow]), &names(&["future-v1"])).is_err());
            assert!(check_pins(&names(&[flow]), &names(&[&format!("{flow}-v1")])).is_err());
        }
        assert_eq!(
            unmet_for_flow(&names(&["ln-swap-in-v1"]), &names(&["taproot"]), "taproot"),
            Ok(())
        );
    }
}
