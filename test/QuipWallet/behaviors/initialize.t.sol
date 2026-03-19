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
        WOTSPlus.WinternitzAddress[] memory noRecovery = new WOTSPlus.WinternitzAddress[](0);

        vm.prank(ALICE);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        wallet.initialize(newPubkey, noRecovery);
    }

    function test_initialize_revertsWhen_callerNotOwnerOrFactory() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)), payable(ALICE));
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-seed");
        WOTSPlus.WinternitzAddress[] memory noRecovery = new WOTSPlus.WinternitzAddress[](0);

        vm.prank(BOB);
        vm.expectRevert(IQuipWallet.UnauthorizedInitializer.selector);
        freshWallet.initialize(newPubkey, noRecovery);
    }

    function test_initialize_revertsWhen_publicSeedEmpty() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)), payable(ALICE));
        WOTSPlus.WinternitzAddress memory emptyPubkey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        WOTSPlus.WinternitzAddress[] memory noRecovery = new WOTSPlus.WinternitzAddress[](0);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidPqOwner.selector);
        freshWallet.initialize(emptyPubkey, noRecovery);
    }

    function test_initialize_revertsWhen_publicKeyHashEmpty() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)), payable(ALICE));
        WOTSPlus.WinternitzAddress memory emptyPubkey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzAddress[] memory noRecovery = new WOTSPlus.WinternitzAddress[](0);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidPqOwner.selector);
        freshWallet.initialize(emptyPubkey, noRecovery);
    }

    function test_initialize_revertsWhen_recoveryKeyHasZeroSeed() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)), payable(ALICE));
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-seed");

        WOTSPlus.WinternitzAddress[] memory badRecovery = new WOTSPlus.WinternitzAddress[](1);
        badRecovery[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidPqOwner.selector);
        freshWallet.initialize(newPubkey, badRecovery);
    }

    function test_initialize_revertsWhen_tooManyRecoveryKeys() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)), payable(ALICE));
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-seed");
        (WOTSPlus.WinternitzAddress[] memory tooMany,) = _generateRecoveryKeys("overflow", 11);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.RecoveryKeyLimitExceeded.selector);
        freshWallet.initialize(newPubkey, tooMany);
    }
}
