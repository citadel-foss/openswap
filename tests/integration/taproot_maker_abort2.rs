use openswap::protocol::common_messages::ProtocolVersion;

use super::scenarios::maker_abort::{MakerAbort, MakerAbortExpect};

use super::test_framework::*;

/// Test: Maker drops at private key handover phase (Taproot). Recovery via timelock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtPrivateKeyHandover],
    takers = [Normal],
)]
fn test_taproot_maker_abort2(world: &mut World) {
    let abort = MakerAbort::fail_swap(
        world,
        ProtocolVersion::Taproot,
        "Swap should fail due to Maker2 closing at private key handover",
    );

    // Retrying finalization must resume at the failing maker. Replaying the
    // completed prefix sends a duplicate handover to Maker1 after it has
    // removed its live state, which then produces the misleading
    // Legacy-vs-Taproot error seen in the original failure.
    let log = std::fs::read_to_string(abort.world().taker_log_path()).unwrap();
    assert_eq!(
        log.matches("Sending privkey to maker 0 and awaiting response")
            .count(),
        1,
        "a completed maker must not receive finalization again"
    );
    assert_eq!(
        log.matches("Sending privkey to maker 1 and awaiting response")
            .count(),
        2,
        "only the failing maker should consume both integration-test attempts"
    );
    assert!(
        !log.contains(
            "UnexpectedMessage { expected: \"Legacy protocol message\", got: \"Taproot protocol message\" }"
        ),
        "retry replayed a Taproot handover into a completed maker's default Legacy state"
    );

    abort.recover();
    abort.assert_recovered(&MakerAbortExpect {
        taker_regular: 14499538,
        taker_swap: 496660,
        taker_loss: 3802,
        maker_regular: [14500751, 14502170],
        maker_swap: [499664, 498079],
        maker_spendable: Some([15000415, 15000249]),
    });
}
