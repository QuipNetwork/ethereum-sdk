// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.2.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the ERC-4337 `_validateSignature` stateful path, driven by live-signed
///      erc4337-context signatures.
contract ShrincsWallet__validateSignature is ShrincsWalletTest {
    /// @dev A userOp signed at `leaf` over a synthetic-but-fixed userOpHash.
    function _erc4337Op(uint32 leaf) internal view returns (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) {
        userOpHash = keccak256(abi.encodePacked("erc4337-userop", leaf));
        ShrincsTypes.StatefulSignature memory sig = _signErc4337(userOpHash, leaf);
        op = _makeUserOp(abi.encode(_mainPk(), sig));
    }

    // NOTE: every signature binds the LIVE wrapper nonce, so consuming any signature supersedes
    // all outstanding ones — ops are strictly serialized by signing order. The used-leaf bitmap
    // remains the OTS-reuse guard; leaf indices themselves may still be consumed in any order
    // (see `test_validateSignature_outOfOrderLeaves`).

    function test_validateSignature_validLeafOne() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        uint256 result = wallet.exposed_validateSignature(op, userOpHash);
        assertEq(result, 0, "valid leaf-1 signature should pass");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 marked consumed");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
        assertEq(wallet.actionNonce(), 1, "consumed signature advances the wrapper nonce");
    }

    function test_validateSignature_revertsWhen_replayConsumedLeaf() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0, "first use passes");
        // Re-presenting the same consumed leaf is rejected by the bitmap (anti-replay).
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "replayed leaf must be rejected");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter unchanged on rejection");
    }

    function test_validateSignature_revertsWhen_leafAlreadyUsed() public {
        // Pre-mark leaf 1 consumed; an otherwise-valid leaf-1 op must then be rejected.
        wallet.harness_markLeafUsed(1);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "already-consumed leaf must be rejected");
    }

    function test_validateSignature_revertsWhen_wrongUserOpHash() public {
        (ERC4337.PackedUserOperation memory op,) = _erc4337Op(1);
        uint256 result = wallet.exposed_validateSignature(op, keccak256("not-the-signed-hash"));
        assertEq(result, 1, "wrong message must be rejected");
        assertFalse(wallet.isStatefulLeafUsed(1), "leaf not consumed on rejection");
    }

    function test_validateSignature_revertsWhen_badSignatureLength() public {
        ERC4337.PackedUserOperation memory op = _makeUserOp(hex"1234");
        uint256 result = wallet.exposed_validateSignature(op, keccak256("x"));
        assertEq(result, 1, "short signature must be rejected");
    }

    /* ─────────────── rejection-reason discrimination (UserOpValidationRejected) ─────────────── */

    /// @dev Returns the `reason` of the first `UserOpValidationRejected` event in the recorded logs.
    function _lastRejectionReason() internal returns (uint256) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IShrincsWallet.UserOpValidationRejected.selector) {
                return uint256(logs[i].topics[1]);
            }
        }
        revert("no UserOpValidationRejected emitted");
    }

    function test_validateSignature_reason_badSignatureLength() public {
        vm.recordLogs();
        wallet.exposed_validateSignature(_makeUserOp(hex"1234"), keccak256("x"));
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.BadSignatureLength));
    }

    function test_validateSignature_reason_leafZero() public {
        ERC4337.PackedUserOperation memory op = _makeUserOp(abi.encode(_mainPk(), _statefulSigWithLeaf(0)));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, keccak256("x")), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.StatefulBudgetExhausted));
    }

    function test_validateSignature_reason_leafOverBudget() public {
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(abi.encode(_mainPk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1)));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, keccak256("x")), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.StatefulBudgetExhausted));
    }

    function test_validateSignature_reason_staleLeaf() public {
        wallet.harness_markLeafUsed(1);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.StaleStatefulLeaf));
    }

    function test_validateSignature_reason_invalidSignature() public {
        (ERC4337.PackedUserOperation memory op,) = _erc4337Op(1);
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, keccak256("not-the-signed-hash")), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidSignature));
    }

    function test_validateSignature_success_advancesActionNonce() public {
        assertEq(wallet.actionNonce(), 0);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0);
        assertEq(wallet.actionNonce(), 1, "consumed signature advances the action nonce");
    }

    function test_validateSignature_outOfOrderLeaves() public {
        // Leaf indices carry no ordering constraint: a higher leaf (3) may be consumed before a
        // lower one (2). Each op is signed against the live nonce AFTER the previous one landed —
        // leaf order is independent of nonce order, but signing order is strict.
        (ERC4337.PackedUserOperation memory op3, bytes32 h3) = _erc4337Op(3);
        assertEq(wallet.exposed_validateSignature(op3, h3), 0, "higher leaf lands first");
        (ERC4337.PackedUserOperation memory op2, bytes32 h2) = _erc4337Op(2);
        assertEq(wallet.exposed_validateSignature(op2, h2), 0, "lower leaf accepted after");
        assertTrue(wallet.isStatefulLeafUsed(3), "leaf 3 consumed");
        assertTrue(wallet.isStatefulLeafUsed(2), "leaf 2 consumed");
        assertEq(wallet.statefulLeavesUsed(), 2, "two leaves consumed");
    }

    /* ─────────────── ERC-7562: validation is fee-independent and call-free ─────────────── */

    /// @dev The digest no longer binds the factory fee: a fee change AFTER signing must not
    ///      affect validation (the signer's ceiling lives in `callData` under userOpHash, and is
    ///      enforced in the execution phase instead).
    function test_validateSignature_unaffectedByFeeChange() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        factory.setExecuteFee(123456789); // moved between signing and validation
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0, "fee change cannot break validation");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf consumed normally");
    }

    /// @dev THE regression guard for ERC-7562 finding F-1: the validation frame must perform no
    ///      factory call at all. `executeFee()` is mocked to revert — if validation ever regains
    ///      a `getExecuteFee()` read (an STO-033 violation conformant bundlers reject), this test
    ///      fails loudly instead of the violation resurfacing at bundler rollout.
    function test_validateSignature_noFactoryRead() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        vm.mockCallRevert(
            address(factory),
            abi.encodeWithSignature("executeFee()"),
            "factory read during validation"
        );
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0, "validation must not touch the factory");
        vm.clearMockedCalls();
    }

    function test_validateSignature_rejectsStaleNonce() public {
        // Both ops signed against the SAME live nonce (0); after the first lands, the second is
        // superseded — rejected as InvalidSignature with its leaf NOT consumed.
        (ERC4337.PackedUserOperation memory op1, bytes32 h1) = _erc4337Op(1);
        (ERC4337.PackedUserOperation memory op2, bytes32 h2) = _erc4337Op(2);
        assertEq(wallet.exposed_validateSignature(op1, h1), 0, "first op lands");

        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op2, h2), 1, "stale-nonce op rejected");
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidSignature));
        assertFalse(wallet.isStatefulLeafUsed(2), "superseded op's leaf not consumed");
        assertEq(wallet.actionNonce(), 1, "nonce unchanged by the rejection");
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev A synthetic signature (correct `authPath.length`, no real crypto) can never verify, so
    ///      `_validateSignature` must return 1 (reject) for ANY leaf and userOpHash — never 0 — and
    ///      must never consume a leaf. Exercises the guard + verify-fail branches without a real sig.
    function testFuzz_validateSignature_rejectsSyntheticSignature(uint256 leaf, bytes32 userOpHash) public {
        leaf = bound(leaf, 0, 512); // `_statefulSigWithLeaf` allocates `new bytes32[](leaf)`
        ERC4337.PackedUserOperation memory op = _makeUserOp(abi.encode(_mainPk(), _statefulSigWithLeaf(leaf)));

        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "synthetic signature always rejected");
        assertEq(wallet.statefulLeavesUsed(), 0, "no leaf consumed on rejection");
        if (leaf >= 1 && leaf <= MAX_SIG) {
            assertFalse(wallet.isStatefulLeafUsed(leaf), "in-budget leaf not consumed on verify-fail");
        }
    }
}
