// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev `storageStore` is permanently disabled (a raw slot write could clear consumed-leaf bits in
///      the bitmap and re-enable one-time-signature replay). It reverts for ALL callers.
contract ShrincsWallet_storageStore is ShrincsWalletTest {
    function test_storageStore_revertsForStranger() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(IShrincsWallet.StorageStoreDisabled.selector);
        wallet.storageStore(bytes32(uint256(1)), bytes32(uint256(2)));
    }

    function test_storageStore_revertsForOwner() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StorageStoreDisabled.selector);
        wallet.storageStore(bytes32(uint256(1)), bytes32(uint256(2)));
    }

    function test_storageStore_revertsForEntryPoint() public {
        vm.prank(ENTRY_POINT);
        vm.expectRevert(IShrincsWallet.StorageStoreDisabled.selector);
        wallet.storageStore(bytes32(0), bytes32(0));
    }
}
