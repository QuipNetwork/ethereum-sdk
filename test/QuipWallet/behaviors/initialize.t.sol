// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";

contract QuipWallet_initialize is QuipWalletTest {
    /// @dev Encode init payload: [0:64) pqOwner + [64:704) recoveryKeys
    function _encodeInitPayload(
        WOTSPlus.WinternitzAddress memory owner,
        WOTSPlus.WinternitzAddress[] memory keys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(owner.publicSeed, owner.publicKeyHash);
        for (uint256 i = 0; i < keys.length; i++) {
            payload = abi.encodePacked(payload, keys[i].publicSeed, keys[i].publicKeyHash);
        }
        return payload;
    }

    function test_initialize_revertsWhen_alreadyInitialized() public {
        (WOTSPlus.WinternitzAddress memory newPubkey, bytes32 newPrivKey) = _generateKeyPair("new-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(newPrivKey, 10);
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        wallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_callerNotFactory() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)));
        (WOTSPlus.WinternitzAddress memory newPubkey, bytes32 newPrivKey) = _generateKeyPair("new-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(newPrivKey, 10);
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidFactory.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_publicSeedEmpty() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)));
        WOTSPlus.WinternitzAddress memory emptyPubkey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        (, bytes32 privKey) = _generateKeyPair("dummy");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privKey, 10);
        bytes memory payload = _encodeInitPayload(emptyPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_publicKeyHashEmpty() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)));
        WOTSPlus.WinternitzAddress memory emptyPubkey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        (, bytes32 privKey) = _generateKeyPair("dummy");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privKey, 10);
        bytes memory payload = _encodeInitPayload(emptyPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_recoveryKeyHasZeroSeed() public {
        QuipWallet freshWallet = new QuipWallet(payable(address(factory)));
        (WOTSPlus.WinternitzAddress memory newPubkey, bytes32 newPrivKey) = _generateKeyPair("new-seed");

        WOTSPlus.WinternitzAddress[] memory badRecovery = _generateRecoveryKeys(newPrivKey, 10);
        badRecovery[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        bytes memory payload = _encodeInitPayload(newPubkey, badRecovery);

        vm.prank(address(factory));
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }
}
