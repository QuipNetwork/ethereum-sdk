// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster_removePqVerifier is QuipPaymasterTest {
    /// @dev ERC-7201 namespace slot for `QuipPaymasterStorage.Layout`. Mirrors
    ///      the constant in the storage library so the half-zero corruption
    ///      tests below can derive `verifiers[wallet]`'s storage location
    ///      without touching contract code.
    bytes32 private constant _PAYMASTER_STORAGE_SLOT =
        0x8926ce57d385a1d96a00d5ce1618d3e300ce201cbf2177f181835ec0ca228b00;

    function test_removePqVerifier_deletesVerifierKey() public {
        vm.prank(ADMIN);
        paymaster.removePqVerifier(WALLET);

        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, bytes32(0));
        assertEq(v.publicKeyHash, bytes32(0));
    }

    function test_removePqVerifier_emitsPqVerifierRemoved() public {
        vm.prank(ADMIN);
        vm.expectEmit(true, false, false, false);
        emit IQuipPaymaster.PqVerifierRemoved(WALLET);
        paymaster.removePqVerifier(WALLET);
    }

    function test_removePqVerifier_allowsResetting() public {
        vm.startPrank(ADMIN);
        paymaster.removePqVerifier(WALLET);

        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("new-key");
        paymaster.setPqVerifier(WALLET, newKey);
        vm.stopPrank();

        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, newKey.publicSeed);
        assertEq(v.publicKeyHash, newKey.publicKeyHash);
    }

    function test_removePqVerifier_revertsWhen_notOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.removePqVerifier(WALLET);
    }

    function test_removePqVerifier_revertsWhen_notRegistered() public {
        address wallet2 = makeAddr("wallet2");

        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.PqVerifierNotRegistered.selector);
        paymaster.removePqVerifier(wallet2);
    }

    /// @dev Removing a wallet's verifier MUST NOT release the global occupancy
    ///      hash. WOTS+ is one-time-use: a registered verifier may already
    ///      have signed and revealed its key chain on-chain, and the index
    ///      cannot distinguish "registered but unused" from "registered and
    ///      used" — so the conservative invariant is that any key ever
    ///      registered stays permanently locked, even after retirement.
    function test_removePqVerifier_keepsKeyLocked() public {
        // WALLET initially holds `verifierPubkey` (from base setUp).
        vm.prank(ADMIN);
        paymaster.removePqVerifier(WALLET);

        // The verifier is no longer bound to WALLET — `getPqVerifier(WALLET)`
        // returns zero — but the hash is still locked in the index.
        address wallet2 = makeAddr("wallet2-reuse-after-remove");
        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.VerifierKeyInUse.selector);
        paymaster.setPqVerifier(wallet2, verifierPubkey);
    }

    /// @dev Even WALLET itself cannot re-adopt its own removed verifier — the
    ///      occupancy index is fully monotonic, with no exception for
    ///      "the wallet that originally held it." Once removed, gone for good.
    function test_removePqVerifier_cannotReAdoptForOriginalWallet() public {
        vm.prank(ADMIN);
        paymaster.removePqVerifier(WALLET);

        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.VerifierKeyInUse.selector);
        paymaster.setPqVerifier(WALLET, verifierPubkey);
    }

    /// @dev Half-zero corruption regression: `setPqVerifier` enforces "both
    ///      fields non-zero" so any registered entry is fully populated. If
    ///      storage ever ends up half-zero (publicSeed cleared, publicKeyHash
    ///      retained) — e.g. from a malformed upgrade, slot collision, or
    ///      unexpected delegatecall — `removePqVerifier` MUST surface the
    ///      corruption as `PqVerifierNotRegistered` rather than silently
    ///      delete. Forces the corruption via `vm.store` because the path
    ///      isn't naturally reachable through public APIs.
    function test_removePqVerifier_revertsWhen_storageHalfZero_seedCleared() public {
        bytes32 root = keccak256(abi.encode(WALLET, _PAYMASTER_STORAGE_SLOT));
        // root + 0 = publicSeed; clearing it leaves publicKeyHash populated.
        vm.store(address(paymaster), root, bytes32(0));

        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.PqVerifierNotRegistered.selector);
        paymaster.removePqVerifier(WALLET);
    }

    function test_removePqVerifier_revertsWhen_storageHalfZero_hashCleared() public {
        bytes32 root = keccak256(abi.encode(WALLET, _PAYMASTER_STORAGE_SLOT));
        // root + 1 = publicKeyHash; clearing it leaves publicSeed populated.
        bytes32 hashSlot = bytes32(uint256(root) + 1);
        vm.store(address(paymaster), hashSlot, bytes32(0));

        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.PqVerifierNotRegistered.selector);
        paymaster.removePqVerifier(WALLET);
    }
}
