// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationInvariantBase} from "./InvariantBase.sol";
import {WOTSPlusImplementationInvariantHandler} from "./Handler.t.sol";

/// @title WOTSPlusImplementation — Light Invariant Suite (high-frequency rotation ops)
/// @dev Targets the cheap + mid-cost fuzz selectors on the shared Handler:
///        - execute, withdrawDepositTo (1 fresh key per call)
///        - resetKeyset[Txn|Rec|Ver] (11 fresh keys per call)
///        - replaceKeys * 6 variants (≤4 fresh keys per call)
///
///      Pairs with `LocalHeavy.t.sol` (saveWallet / transferOwnership /
///      upgrades — 30+ fresh keys per call). Invariants are declared
///      once on `WOTSPlusImplementationInvariantBase` and inherited by both suites,
///      so a property violation triggered by any selector in either
///      partition surfaces in the matching suite.
///
///      Budget: inherits foundry.toml defaults (runs = 20, depth = 200).
contract WOTSPlusImplementation_Local_Invariant is WOTSPlusImplementationInvariantBase {
    function setUp() public override {
        super.setUp();
        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](11);
        selectors[0] = WOTSPlusImplementationInvariantHandler.fuzzExecute.selector;
        selectors[1] = WOTSPlusImplementationInvariantHandler.fuzzWithdrawDepositTo.selector;
        selectors[2] = WOTSPlusImplementationInvariantHandler
            .fuzzResetKeysetTransaction_recoverySigned
            .selector;
        selectors[3] = WOTSPlusImplementationInvariantHandler
            .fuzzResetKeysetRecovery_txSigned
            .selector;
        selectors[4] = WOTSPlusImplementationInvariantHandler
            .fuzzResetKeysetVerification_txSigned
            .selector;
        selectors[5] = WOTSPlusImplementationInvariantHandler.fuzzReplaceTxnInTxn.selector;
        selectors[6] = WOTSPlusImplementationInvariantHandler.fuzzReplaceRecInTxn.selector;
        selectors[7] = WOTSPlusImplementationInvariantHandler.fuzzReplaceVerInTxn.selector;
        selectors[8] = WOTSPlusImplementationInvariantHandler.fuzzReplaceTxnInRec.selector;
        selectors[9] = WOTSPlusImplementationInvariantHandler.fuzzReplaceRecInRec.selector;
        selectors[10] = WOTSPlusImplementationInvariantHandler.fuzzReplaceVerInRec.selector;
        targetSelector(
            FuzzSelector({addr: address(handler), selectors: selectors})
        );
    }
}
