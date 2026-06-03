// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletInvariantBase} from "./InvariantBase.sol";
import {QuipWalletInvariantHandler} from "./Handler.t.sol";

/// @title QuipWallet — Light Invariant Suite (high-frequency rotation ops)
/// @dev Targets the cheap + mid-cost fuzz selectors on the shared Handler:
///        - execute, withdrawDepositTo (1 fresh key per call)
///        - resetKeyset[Txn|Rec|Ver] (11 fresh keys per call)
///        - replaceKeys * 6 variants (≤4 fresh keys per call)
///
///      Pairs with `LocalHeavy.t.sol` (saveWallet / transferOwnership /
///      upgrades — 30+ fresh keys per call). Invariants are declared
///      once on `QuipWalletInvariantBase` and inherited by both suites,
///      so a property violation triggered by any selector in either
///      partition surfaces in the matching suite.
///
///      Budget: inherits foundry.toml defaults (runs = 20, depth = 200).
contract QuipWallet_Local_Invariant is QuipWalletInvariantBase {
    function setUp() public override {
        super.setUp();
        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](11);
        selectors[0] = QuipWalletInvariantHandler.fuzzExecute.selector;
        selectors[1] = QuipWalletInvariantHandler.fuzzWithdrawDepositTo.selector;
        selectors[2] = QuipWalletInvariantHandler
            .fuzzResetKeysetTransaction_recoverySigned
            .selector;
        selectors[3] = QuipWalletInvariantHandler
            .fuzzResetKeysetRecovery_txSigned
            .selector;
        selectors[4] = QuipWalletInvariantHandler
            .fuzzResetKeysetVerification_txSigned
            .selector;
        selectors[5] = QuipWalletInvariantHandler.fuzzReplaceTxnInTxn.selector;
        selectors[6] = QuipWalletInvariantHandler.fuzzReplaceRecInTxn.selector;
        selectors[7] = QuipWalletInvariantHandler.fuzzReplaceVerInTxn.selector;
        selectors[8] = QuipWalletInvariantHandler.fuzzReplaceTxnInRec.selector;
        selectors[9] = QuipWalletInvariantHandler.fuzzReplaceRecInRec.selector;
        selectors[10] = QuipWalletInvariantHandler.fuzzReplaceVerInRec.selector;
        targetSelector(
            FuzzSelector({addr: address(handler), selectors: selectors})
        );
    }
}
