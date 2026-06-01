// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

contract QuipWallet_keyCount is QuipWalletTest {
    function test_keyCount_transactionFiveAfterInit() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 5);
    }

    function test_keyCount_recoveryTenAfterInit() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_keyCount_verificationZeroWhenEmpty() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 0);
    }

    function test_keyCount_verificationTracksResetKeyset() public {
        // `_seedVerificationKeys` installs exactly MAX_KEYS=10 via resetKeyset
        // regardless of the requested `n`. A second call wipes-and-reinstalls
        // another 10. Either way the count after seeding is 10.
        _seedVerificationKeys(3);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
    }
}
