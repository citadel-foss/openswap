// Insert inside src/blocklist.rs::tests in the v0.2.3 tag source.

    #[test]
    fn generate_v023_blocklist_fixture() {
        let output = std::path::PathBuf::from(std::env::var_os("OPENSWAP_COMPAT_FIXTURES").unwrap());
        let file = BlocklistFile { entries: vec![
            BlocklistEntry::new(test_address(1, Network::Regtest).to_string(), Some("funding source".into())),
            BlocklistEntry::new(test_address(2, Network::Regtest).to_string(), None),
        ] };
        std::fs::write(output.join("blocklist-entries.cbor"), serde_cbor::to_vec(&file).unwrap()).unwrap();
    }
