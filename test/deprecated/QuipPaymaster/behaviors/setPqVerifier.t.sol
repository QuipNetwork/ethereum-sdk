// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../../contracts/deprecated/interfaces/IQuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster_setPqVerifier is QuipPaymasterTest {
    function test_setPqVerifier_setsVerifierKey() public {
        address wallet2 = makeAddr("wallet2");
        (WOTSPlus.WinternitzAddress memory key,) = _generateKeyPair("wallet2-verifier");

        vm.prank(ADMIN);
        paymaster.setPqVerifier(wallet2, key);

        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(wallet2);
        assertEq(v.publicSeed, key.publicSeed);
        assertEq(v.publicKeyHash, key.publicKeyHash);
    }

    function test_setPqVerifier_overwritesExistingKey() public {
        // WALLET already has a verifier from setUp — overwrite it
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("overwrite-key");

        vm.prank(ADMIN);
        paymaster.setPqVerifier(WALLET, newKey);

        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, newKey.publicSeed);
        assertEq(v.publicKeyHash, newKey.publicKeyHash);
    }

    function test_setPqVerifier_emitsPqVerifierSet() public {
        address wallet2 = makeAddr("wallet2");
        (WOTSPlus.WinternitzAddress memory key,) = _generateKeyPair("wallet2-verifier");

        // Fresh registration: oldVerifier is the zero address-pair so
        // off-chain consumers can distinguish first-set from hot-swap.
        WOTSPlus.WinternitzAddress memory zeroVerifier =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});

        vm.prank(ADMIN);
        vm.expectEmit(true, false, false, true);
        emit IQuipPaymaster.PqVerifierSet(wallet2, zeroVerifier, key);
        paymaster.setPqVerifier(wallet2, key);
    }

    /// @dev Hot-swap branch: when the wallet already has a verifier and
    ///      `setPqVerifier` is called with a different key, `oldVerifier`
    ///      carries the prior key (not zero) so off-chain consumers can
    ///      identify admin overrides directly from the event.
    function test_setPqVerifier_emitsPriorVerifierOnHotSwap() public {
        // WALLET already holds `verifierPubkey` from base setUp.
        (WOTSPlus.WinternitzAddress memory replacement,) = _generateKeyPair("hot-swap-replacement");

        vm.prank(ADMIN);
        vm.expectEmit(true, false, false, true);
        emit IQuipPaymaster.PqVerifierSet(WALLET, verifierPubkey, replacement);
        paymaster.setPqVerifier(WALLET, replacement);
    }

    function test_setPqVerifier_revertsWhen_notOwner() public {
        address wallet2 = makeAddr("wallet2");
        (WOTSPlus.WinternitzAddress memory key,) = _generateKeyPair("wallet2-verifier");

        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.setPqVerifier(wallet2, key);
    }

    function test_setPqVerifier_revertsWhen_zeroPublicSeed() public {
        address wallet2 = makeAddr("wallet2");
        WOTSPlus.WinternitzAddress memory key =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(uint256(1))});

        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.ZeroValuePqVerifierKey.selector);
        paymaster.setPqVerifier(wallet2, key);
    }

    function test_setPqVerifier_revertsWhen_zeroPublicKeyHash() public {
        address wallet2 = makeAddr("wallet2");
        WOTSPlus.WinternitzAddress memory key =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(0)});

        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.ZeroValuePqVerifierKey.selector);
        paymaster.setPqVerifier(wallet2, key);
    }

    /// @dev Cross-wallet collision: assigning the same WOTS+ verifier to a
    ///      second wallet must revert. WOTS+ is one-time-use — letting two
    ///      wallets back onto the same key would let a single revealed
    ///      signature burn both verifiers simultaneously.
    function test_setPqVerifier_revertsWhen_keyAlreadyAssignedToAnotherWallet() public {
        address wallet2 = makeAddr("wallet2-collision");

        // The base setUp already registered `verifierPubkey` for WALLET.
        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.VerifierKeyInUse.selector);
        paymaster.setPqVerifier(wallet2, verifierPubkey);
    }

    /// @dev Overwriting a wallet's verifier with a fresh key must NOT release
    ///      the old key's occupancy slot. The occupancy index is monotonic:
    ///      once a key has been registered as a paymaster verifier, it is
    ///      permanently locked even if it never signed, because the on-chain
    ///      mapping can't distinguish "registered but unused" from "registered
    ///      and used" — and a used key has revealed its WOTS+ chain.
    function test_setPqVerifier_overwriteKeepsPriorKeyLocked() public {
        // WALLET initially holds `verifierPubkey` (from base setUp).
        // Step 1: overwrite WALLET's verifier with a fresh key.
        (WOTSPlus.WinternitzAddress memory replacement,) = _generateKeyPair("wallet-replacement-key");
        vm.prank(ADMIN);
        paymaster.setPqVerifier(WALLET, replacement);

        // Step 2: another wallet must NOT be able to adopt the original
        // `verifierPubkey` — its hash stays locked in the index.
        address wallet2 = makeAddr("wallet2-reuse-after-overwrite");
        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.VerifierKeyInUse.selector);
        paymaster.setPqVerifier(wallet2, verifierPubkey);
    }

    /// @dev If a wallet already holds verifier K and the owner re-sets the
    ///      SAME K, the call must succeed as a no-op. The same-key short-
    ///      circuit at the top of `setPqVerifier` skips the in-use check
    ///      (which would otherwise fire on K's own existing entry).
    function test_setPqVerifier_canResetSameKeyOnSameWallet() public {
        vm.prank(ADMIN);
        paymaster.setPqVerifier(WALLET, verifierPubkey);

        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, verifierPubkey.publicSeed);
        assertEq(v.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    /// @dev Re-setting the same key on the same wallet still emits
    ///      `PqVerifierSet` for symmetry with the fresh-set path. Both
    ///      `oldVerifier` and `newVerifier` carry the same key — the no-op
    ///      semantics flow through to the event, so off-chain consumers can
    ///      detect "old == new" and treat it as an idempotent re-bind.
    function test_setPqVerifier_reSettingSameKeyEmitsEvent() public {
        vm.prank(ADMIN);
        vm.expectEmit(true, false, false, true);
        emit IQuipPaymaster.PqVerifierSet(WALLET, verifierPubkey, verifierPubkey);
        paymaster.setPqVerifier(WALLET, verifierPubkey);
    }
}
