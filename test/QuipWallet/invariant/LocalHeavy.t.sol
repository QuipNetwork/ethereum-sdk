// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletInvariantBase} from "./InvariantBase.sol";
import {QuipWalletInvariantHandler} from "./Handler.t.sol";

/// @title QuipWallet — Heavy Invariant Suite (catastrophic-reset & upgrade ops)
/// @dev Targets the 4 expensive fuzz selectors:
///        - fuzzSaveWallet         (~32k keccaks/call — 31 fresh keypairs)
///        - fuzzTransferOwnership  (~32k keccaks/call — 31 fresh keypairs)
///        - fuzzUpgradeToAndCall   (~3k keccaks/call — 2 fresh keypairs)
///        - fuzzRecoveryUpgrade    (~3k keccaks/call — 2 fresh keypairs)
///
///      Pairs with `Local.t.sol` (the light suite). Invariants are
///      declared on `QuipWalletInvariantBase` and inherited by both
///      suites, so a property violation triggered ONLY by saveWallet
///      etc. fails this suite while the light suite stays green —
///      pinpointing the offending op class.
///
///      Budget is scoped down via `forge-config` annotations: at ~15× the
///      per-call cost of the light suite, this campaign uses runs = 10 ×
///      depth = 50 = 500 calls. Override for CI overnight runs via env
///      (`FOUNDRY_INVARIANT_RUNS=...`).
/// forge-config: default.invariant.runs = 10
/// forge-config: default.invariant.depth = 50
contract QuipWallet_LocalHeavy_Invariant is QuipWalletInvariantBase {
    function setUp() public override {
        super.setUp();
        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = QuipWalletInvariantHandler.fuzzSaveWallet.selector;
        selectors[1] = QuipWalletInvariantHandler
            .fuzzTransferOwnership
            .selector;
        selectors[2] = QuipWalletInvariantHandler
            .fuzzUpgradeToAndCall
            .selector;
        selectors[3] = QuipWalletInvariantHandler.fuzzRecoveryUpgrade.selector;
        targetSelector(
            FuzzSelector({addr: address(handler), selectors: selectors})
        );
    }
}
