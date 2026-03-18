// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {Initializable} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/utils/Initializable.sol";

contract QuipWallet_initialize is QuipWalletTest {
    function test_initialize_revertsWhen_alreadyInitialized() public {
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-seed");

        vm.prank(ALICE);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        wallet.initialize(newPubkey);
    }

    function test_initialize_revertsWhen_callerNotOwnerOrFactory() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)), payable(ALICE));
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-seed");

        vm.prank(BOB);
        vm.expectRevert(IQuipWallet.UnauthorizedInitializer.selector);
        freshWallet.initialize(newPubkey);
    }

    function test_initialize_revertsWhen_publicSeedEmpty() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)), payable(ALICE));
        WOTSPlus.WinternitzAddress memory emptyPubkey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidPqOwner.selector);
        freshWallet.initialize(emptyPubkey);
    }

    function test_initialize_revertsWhen_publicKeyHashEmpty() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)), payable(ALICE));
        WOTSPlus.WinternitzAddress memory emptyPubkey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidPqOwner.selector);
        freshWallet.initialize(emptyPubkey);
    }
}
