// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";

/// @dev Behaviour tests for `WalletFactory.updateWalletOwner(newOwner)`. This
///      callback is the load-bearing primitive for the registry-vs-wallet-
///      owner consistency invariant (see INVARIANTS.md §"Registry
///      consistency"). The gates are layered so that exactly one call site —
///      the tail of `transferOwnership(bytes)` on a registered wallet — can
///      succeed. The wallet does not pass `oldOwner`: the factory reads it
///      from its own `walletOwner[msg.sender]` source of truth.
contract WalletFactory_updateWalletOwner is WalletFactoryTest {
    /// @dev Returns the address of a fresh wallet deployed by ALICE. The
    ///      factory writes `vaultIdOf[wallet] = vaultId`,
    ///      `walletOwner[wallet] = owner`, and `_vaultIds[owner].add(vaultId)`
    ///      during `_deployProxy`.
    function _deployWalletFor(bytes32 seed, address owner) internal returns (address wallet) {
        (wallet,,,) = _createWalletFull(owner, seed, 0);
    }

    /// @dev Calls from any EOA / contract that wasn't deployed by this factory
    ///      have `vaultIdOf[msg.sender] == 0` and fail the first gate.
    function test_updateWalletOwner_revertsWhen_callerNotAWallet() public {
        vm.expectRevert(IWalletFactory.OnlyWallet.selector);
        vm.prank(BOB);
        factory.updateWalletOwner(BOB);
    }

    /// @dev Even another factory's wallet can't notify THIS factory — its
    ///      vaultIdOf entry lives in the other factory's storage. Reproduced
    ///      here with a synthetic contract address: vaultIdOf lookup returns 0.
    function test_updateWalletOwner_revertsWhen_callerIsRandomContract() public {
        address stranger = makeAddr("stranger-contract");
        vm.etch(stranger, hex"00"); // give it some code so it's not an EOA
        vm.expectRevert(IWalletFactory.OnlyWallet.selector);
        vm.prank(stranger);
        factory.updateWalletOwner(BOB);
    }

    function test_updateWalletOwner_revertsWhen_newOwnerZero() public {
        address wallet = _deployWalletFor(bytes32(uint256(0xA1)), ALICE);
        vm.expectRevert(IWalletFactory.ZeroAddressOwner.selector);
        vm.prank(wallet);
        factory.updateWalletOwner(address(0));
    }

    function test_updateWalletOwner_revertsWhen_sameOwner() public {
        address wallet = _deployWalletFor(bytes32(uint256(0xA2)), ALICE);
        // Wallet's currently-registered owner is ALICE (set at deploy time);
        // calling with newOwner == ALICE is a no-op transfer.
        vm.expectRevert(IWalletFactory.SameOwner.selector);
        vm.prank(wallet);
        factory.updateWalletOwner(ALICE);
    }

    /// @dev The wallet's on-chain `owner()` is still ALICE at this point —
    ///      we're spoofing a notify with `newOwner = BOB` BEFORE the wallet
    ///      has actually transferred. The owner-state-pin catches this and
    ///      blocks the registry mutation, which is the load-bearing property
    ///      preventing `execute`/`delegateExecute`-routed bypass attacks.
    function test_updateWalletOwner_revertsWhen_ownerStateMismatch() public {
        address wallet = _deployWalletFor(bytes32(uint256(0xA3)), ALICE);
        vm.expectRevert(IWalletFactory.OwnerStateMismatch.selector);
        vm.prank(wallet);
        factory.updateWalletOwner(BOB);
    }

    /// @dev Sanity check on the post-deploy registry state — the precondition
    ///      every `updateWalletOwner` call relies on. Mirrors the invariant
    ///      documented in INVARIANTS.md §"Registry consistency".
    function test_updateWalletOwner_setUpRegistryIsConsistent() public {
        bytes32 seed = bytes32(uint256(0xA5));
        address wallet = _deployWalletFor(seed, ALICE);
        bytes32 vaultId = keccak256(abi.encodePacked(seed));
        assertEq(factory.vaultIdOf(wallet), vaultId);
        assertEq(factory.wallets(_salt(vaultId)), wallet);
        assertEq(factory.walletOwner(wallet), ALICE);
        assertNotEq(factory.getVaultIdIndex(ALICE, _salt(vaultId)), type(uint256).max);
        assertEq(factory.getVaultIdIndex(BOB, _salt(vaultId)), type(uint256).max);
        assertEq(factory.getVaultIdCount(ALICE), 1);
    }
}
