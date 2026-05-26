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

    function test_keyCount_verificationTracksAddsAndRefreshes() public {
        _seedVerificationKeys(3);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);

        // Refresh with 5 fresh keys.
        WOTSPlus.WinternitzAddress[]
            memory fresh = new WOTSPlus.WinternitzAddress[](5);
        for (uint256 i = 0; i < 5; i++) {
            (fresh[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked("count-refresh", i))
            );
        }
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "count-refresh-next"
        );
        bytes32 msgHash = _buildReplenishVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            fresh
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );
        vm.prank(ALICE);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, fresh)
        );

        assertEq(wallet.keyCount(Codec.KeyType.Verification), 5);
    }
}
