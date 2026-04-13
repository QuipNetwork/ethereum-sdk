// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

contract QuipWallet_getVerificationKeyCount is QuipWalletTest {
    function test_getVerificationKeyCount_zeroWhenEmpty() public view {
        assertEq(wallet.getVerificationKeyCount(), 0);
    }

    function test_getVerificationKeyCount_tracksAddsAndRefreshes() public {
        _seedVerificationKeyset(3);
        assertEq(wallet.getVerificationKeyCount(), 3);

        // Refresh with 5 fresh keys.
        WOTSPlus.WinternitzAddress[] memory fresh = new WOTSPlus.WinternitzAddress[](5);
        for (uint256 i = 0; i < 5; i++) {
            (fresh[i],) = _generateKeyPair(keccak256(abi.encodePacked("count-refresh", i)));
        }
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("count-refresh-next");
        bytes32 msgHash = _buildVerificationKeysetMessageHash(
            address(wallet), alicePubkey, nextPq, fresh
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);
        vm.prank(ALICE);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, sig, fresh));

        assertEq(wallet.getVerificationKeyCount(), 5);
    }
}
