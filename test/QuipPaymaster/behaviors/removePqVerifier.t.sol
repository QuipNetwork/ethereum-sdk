// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster_removePqVerifier is QuipPaymasterTest {
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

        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "new-key"
        );
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
}
