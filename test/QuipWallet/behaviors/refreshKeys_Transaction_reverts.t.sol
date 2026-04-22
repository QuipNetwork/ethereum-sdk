// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

contract QuipWallet_refreshKeys_Transaction_reverts is QuipWalletTest {
    function test_refreshKeys_Transaction_reverts() public {
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](1);
        (keys[0], ) = _generateKeyPair("refresh-tx-forbidden-key");
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "refresh-tx-forbidden-next"
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            keccak256("irrelevant")
        );

        bytes memory payload = Codec.encodeKeyManagement(
            Codec.KeyType.Transaction,
            alicePubkey,
            nextPq,
            sig,
            keys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.RefreshTransactionForbidden.selector);
        wallet.refreshKeys(payload);
    }
}
