// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_changePqOwner is QuipWalletTest {
    function test_changePqOwner_updatesPqOwner() public {
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-pq-owner");

        bytes32 msgHash = _buildChangePqOwnerMessageHash(alicePubkey, newPubkey);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.changePqOwner(newPubkey, sig);

        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, newPubkey.publicSeed);
        assertEq(publicKeyHash, newPubkey.publicKeyHash);
    }

    function test_changePqOwner_revertsWhen_callerNotOwner() public {
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-pq-owner");

        bytes32 msgHash = _buildChangePqOwnerMessageHash(alicePubkey, newPubkey);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, BOB));
        wallet.changePqOwner(newPubkey, sig);
    }

    function test_changePqOwner_revertsWhen_invalidSignature() public {
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-pq-owner");

        // Sign wrong message
        bytes32 wrongMsgHash = keccak256("wrong message");
        WOTSPlus.WinternitzElements memory badSig = _sign(alicePrivateKey, wrongMsgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.changePqOwner(newPubkey, badSig);
    }
}
