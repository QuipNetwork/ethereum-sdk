// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";

contract WOTSPlusImplementation_keyCount is WOTSPlusImplementationTest {
    function test_keyCount_transactionTenAfterInit() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
    }

    function test_keyCount_recoveryTenAfterInit() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_keyCount_verificationTenAfterInit() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
    }

    function test_keyCount_verificationTracksResetKeyset() public {
        // `_seedVerificationKeys` always wipes-and-reinstalls 10 fresh keys
        // via `resetKeyset(Verification, signingKind=Transaction)`. The count
        // stays at 10 because verification is full at init too.
        _seedVerificationKeys(3);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
    }
}
