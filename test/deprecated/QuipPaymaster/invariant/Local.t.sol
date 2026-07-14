// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterInvariantBase} from "./InvariantBase.sol";
import {QuipPaymasterInvariantHandler} from "./Handler.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @title QuipPaymaster — Local Invariant Suite (verifier lifecycle)
/// @dev Stateful fuzz over the verifier-lifecycle surface:
///        - setPqVerifier
///        - removePqVerifier
///        - validatePaymasterUserOp (full WOTS+ signing path)
///        - attempted re-registration of historical keys
///
///      Maps the audit-finding invariants to a mix of global state checks
///      and post-call assertions tracked via handler counters. The four
///      counters (`crossWalletDriftCount`, `successDidNotAdvanceCount`,
///      `improperRebindSuccessCount`, `noVerifierSponsorshipBugCount`)
///      MUST stay zero across the entire campaign — they capture
///      properties that can only be checked at the moment of mutation
///      (e.g. "no other wallet's verifier changed across this call")
///      and can't be reconstructed from a final-state snapshot.
///
///      Budget: WOTS+ sign + verify dominate per-call cost, but the
///      suite inherits `foundry.toml`'s invariant defaults rather than
///      scoping down — the project-wide settings are the authoritative
///      knob. Override for overnight stress via
///      `FOUNDRY_INVARIANT_RUNS=...` / `FOUNDRY_INVARIANT_DEPTH=...`.
contract QuipPaymaster_Local_Invariant is QuipPaymasterInvariantBase {
    function setUp() public override {
        super.setUp();
        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = QuipPaymasterInvariantHandler.fuzzSetPqVerifier.selector;
        selectors[1] = QuipPaymasterInvariantHandler.fuzzRemovePqVerifier.selector;
        selectors[2] = QuipPaymasterInvariantHandler.fuzzValidatePaymasterUserOp.selector;
        selectors[3] = QuipPaymasterInvariantHandler.fuzzAttemptRebindUsedKey.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /*══════════════ counter-backed handler-side invariants ══════════════*/

    /// @dev Audit finding — "once a verifier hash is marked used, it can
    ///      never be rebound to any wallet." The handler attempts
    ///      historical re-registrations via `fuzzAttemptRebindUsedKey`;
    ///      every non-no-op call MUST revert `VerifierKeyInUse`. A
    ///      success is recorded as a violation.
    function invariant_monotonicOccupancyHolds() public view {
        assertEq(handler.improperRebindSuccessCount(), 0, "a used verifier hash was successfully re-bound");
    }

    /// @dev Audit finding — "a wallet with no registered verifier can
    ///      never validate sponsorship." Tracked at the call site
    ///      because `validatePaymasterUserOp` is state-changing and
    ///      can't be invoked from a `view` invariant.
    function invariant_noVerifierMeansNoSponsorship() public view {
        assertEq(handler.noVerifierSponsorshipBugCount(), 0, "validation succeeded for a wallet with no verifier");
    }

    /// @dev Audit finding — "successful sponsored operations always
    ///      advance the stored verifier key." On every `vd == 0` exit
    ///      the handler asserts the stored verifier equals the
    ///      `nextVerifier` arg; a mismatch increments the counter.
    function invariant_successAlwaysAdvancesVerifier() public view {
        assertEq(handler.successDidNotAdvanceCount(), 0, "successful validation failed to rotate the verifier");
    }

    /// @dev Audit finding — "rotating one wallet's verifier can never
    ///      affect another wallet's verifier state." The handler
    ///      snapshots every non-target wallet's verifier hash before
    ///      every set/remove/validate/rebind call and re-checks
    ///      afterwards; any drift increments the counter.
    function invariant_crossWalletIsolation() public view {
        assertEq(handler.crossWalletDriftCount(), 0, "a non-target wallet's verifier changed across a call");
    }

    /*══════════════════ global state invariants ═════════════════════════*/

    /// @dev Stronger consequence of monotonic occupancy: at every
    ///      boundary, any two wallets in the pool with non-zero
    ///      verifiers must hold distinct hashes. Cross-wallet reuse
    ///      would let a single revealed WOTS+ signature burn both
    ///      wallets' verifiers.
    function invariant_walletsHaveDistinctVerifiers() public view {
        uint256 n = handler.walletCount();
        for (uint256 i = 0; i < n; i++) {
            WOTSPlus.WinternitzAddress memory vi = paymaster.getPqVerifier(handler.walletAt(i));
            if (vi.publicSeed == bytes32(0)) continue;
            for (uint256 j = i + 1; j < n; j++) {
                WOTSPlus.WinternitzAddress memory vj = paymaster.getPqVerifier(handler.walletAt(j));
                if (vj.publicSeed == bytes32(0)) continue;
                assertFalse(
                    vi.publicSeed == vj.publicSeed && vi.publicKeyHash == vj.publicKeyHash,
                    "two pool wallets share a verifier"
                );
            }
        }
    }

    /// @dev Every wallet's current non-zero verifier must have been
    ///      legitimately installed via the handler — i.e. its hash
    ///      appears in `everUsedPubs`. A wallet holding a verifier the
    ///      handler never wrote would indicate a corrupt storage write
    ///      bypassing the legitimate paths.
    function invariant_currentVerifierHashesInMirror() public view {
        uint256 n = handler.walletCount();
        for (uint256 i = 0; i < n; i++) {
            WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(handler.walletAt(i));
            if (v.publicSeed == bytes32(0)) continue;
            bytes32 h = keccak256(abi.encodePacked(v.publicSeed, v.publicKeyHash));
            bool found;
            uint256 m = handler.everUsedCount();
            for (uint256 j = 0; j < m; j++) {
                WOTSPlus.WinternitzAddress memory e = handler.everUsedAt(j);
                if (keccak256(abi.encodePacked(e.publicSeed, e.publicKeyHash)) == h) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "live verifier hash not in handler mirror");
        }
    }

    /// @dev Paymaster ownership is set in setUp and untouched by any
    ///      fuzz selector. A drift would indicate a broken `onlyOwner`
    ///      gate.
    function invariant_paymasterOwnerStable() public view {
        assertEq(paymaster.owner(), address(handler), "paymaster owner drifted");
    }
}
