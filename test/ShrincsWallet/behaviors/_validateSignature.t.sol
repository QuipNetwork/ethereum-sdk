// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the ERC-4337 `_validateSignature` stateful path, driven by the
///      Rust-generated wallet vectors.
contract ShrincsWallet__validateSignature is ShrincsWalletTest {
    function _erc4337Op(uint256 i) internal view returns (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) {
        string memory base = string.concat(".cases.erc4337[", vm.toString(i), "]");
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(string.concat(base, ".signature"));
        op = _makeUserOp(abi.encode(pk, sig));
        userOpHash = _bytes32(string.concat(base, ".userOpHash"));
    }

    // NOTE: under the no-nonce + bitmap scheme every erc4337 leaf binds `nonce = 0`, so all three
    // committed vectors (`erc4337[0..2]`) verify and may be applied in any order — the used-leaf
    // bitmap is the sole anti-replay (see `test_validateSignature_outOfOrderLeaves`).

    function test_validateSignature_validLeafOne() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(0);
        uint256 result = wallet.exposed_validateSignature(op, userOpHash);
        assertEq(result, 0, "valid leaf-1 signature should pass");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 marked consumed");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
        assertEq(wallet.actionNonce(), 0, "stateful path does not advance the wrapper nonce");
    }

    function test_validateSignature_revertsWhen_replayConsumedLeaf() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(0);
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0, "first use passes");
        // Re-presenting the same consumed leaf is rejected by the bitmap (anti-replay).
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "replayed leaf must be rejected");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter unchanged on rejection");
    }

    function test_validateSignature_revertsWhen_leafAlreadyUsed() public {
        // Pre-mark leaf 1 consumed; an otherwise-valid leaf-1 op must then be rejected.
        wallet.harness_markLeafUsed(1);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(0);
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "already-consumed leaf must be rejected");
    }

    function test_validateSignature_revertsWhen_wrongUserOpHash() public {
        (ERC4337.PackedUserOperation memory op,) = _erc4337Op(0);
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
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        ERC4337.PackedUserOperation memory op = _makeUserOp(abi.encode(pk, _statefulSigWithLeaf(0)));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, keccak256("x")), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.StatefulBudgetExhausted));
    }

    function test_validateSignature_reason_leafOverBudget() public {
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        ERC4337.PackedUserOperation memory op = _makeUserOp(abi.encode(pk, _statefulSigWithLeaf(uint256(MAX_SIG) + 1)));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, keccak256("x")), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.StatefulBudgetExhausted));
    }

    function test_validateSignature_reason_staleLeaf() public {
        wallet.harness_markLeafUsed(1);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(0);
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.StaleStatefulLeaf));
    }

    function test_validateSignature_reason_invalidSignature() public {
        (ERC4337.PackedUserOperation memory op,) = _erc4337Op(0);
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, keccak256("not-the-signed-hash")), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidSignature));
    }

    function test_validateSignature_success_doesNotTouchActionNonce() public {
        assertEq(wallet.actionNonce(), 0);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(0);
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0);
        assertEq(wallet.actionNonce(), 0, "stateful path leaves the action nonce untouched");
    }

    function test_validateSignature_outOfOrderLeaves() public {
        // No-nonce + bitmap: a higher leaf (3) may land before a lower one (2), both accepted.
        (ERC4337.PackedUserOperation memory op3, bytes32 h3) = _erc4337Op(2);
        (ERC4337.PackedUserOperation memory op2, bytes32 h2) = _erc4337Op(1);
        assertEq(wallet.exposed_validateSignature(op3, h3), 0, "higher leaf lands first");
        assertEq(wallet.exposed_validateSignature(op2, h2), 0, "lower leaf still accepted out of order");
        assertTrue(wallet.isStatefulLeafUsed(3), "leaf 3 consumed");
        assertTrue(wallet.isStatefulLeafUsed(2), "leaf 2 consumed");
        assertEq(wallet.statefulLeavesUsed(), 2, "two leaves consumed");
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev A synthetic signature (correct `authPath.length`, no real crypto) can never verify, so
    ///      `_validateSignature` must return 1 (reject) for ANY leaf and userOpHash — never 0 — and
    ///      must never consume a leaf. Exercises the guard + verify-fail branches without a vector.
    function testFuzz_validateSignature_rejectsSyntheticSignature(uint256 leaf, bytes32 userOpHash) public {
        leaf = bound(leaf, 0, 512); // `_statefulSigWithLeaf` allocates `new bytes32[](leaf)`
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        ERC4337.PackedUserOperation memory op = _makeUserOp(abi.encode(pk, _statefulSigWithLeaf(leaf)));

        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "synthetic signature always rejected");
        assertEq(wallet.statefulLeavesUsed(), 0, "no leaf consumed on rejection");
        if (leaf >= 1 && leaf <= MAX_SIG) {
            assertFalse(wallet.isStatefulLeafUsed(leaf), "in-budget leaf not consumed on verify-fail");
        }
    }
}
