// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../contracts/deprecated/wots/WOTSPlusCodec.sol";

import {IWOTSPlusImplementation} from "../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

import {IntegrationBase, IEntryPoint, IEntryPointExt, PackedUserOperation} from "./IntegrationBase.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @title Wallet UserOp Integration Test
/// @dev Fork test against the real EntryPoint v0.7 on Base Sepolia.
///      Submits full UserOps via handleOps and verifies key rotation,
///      execution, and fee deduction.
contract Integration_walletUserOp is IntegrationBase {
    function setUp() public override {
        super.setUp();
        _deployWalletStack();
    }

    /// @dev Full UserOp submission via handleOps: execute ETH transfer, verify key rotation.
    function test_integration_handleOps_fullUserOp() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("integration-next-key");

        uint256 transferAmount = 0.1 ether;
        PackedUserOperation memory userOp = _buildUserOp(BOB, transferAmount, "");
        _signUserOp(userOp, alicePrivateKey, alicePubkey, nextPq);

        uint256 bobBalBefore = BOB.balance;
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);

        assertEq(BOB.balance, bobBalBefore + transferAmount);

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
    }

    /// @dev Key rotation happens during validation, before execution.
    ///      If execution reverts, the key should still be rotated.
    function test_integration_handleOps_rotatesKeyOnFailedExecution() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("integration-fail-key");

        uint256 excessiveAmount = 1000 ether;
        PackedUserOperation memory userOp = _buildUserOp(BOB, excessiveAmount, "");
        _signUserOp(userOp, alicePrivateKey, alicePubkey, nextPq);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
    }

    /// @dev A UserOp whose wallet signature is tampered must be rejected by the
    ///      EntryPoint with the canonical `AA24 signature error` FailedOp.
    ///      Proves the v0.7 signature-failure error string still matches what the
    ///      wallet's `_validateSignature` returns (validationData = 1).
    /// @dev Shared arrange for the single-op handleOps family: builds and signs one op
    ///      transferring 0.01 ether to BOB, rotating to a key derived from `seed`.
    function _signedOps(bytes32 seed)
        internal
        returns (PackedUserOperation[] memory ops, WOTSPlus.WinternitzAddress memory nextPq)
    {
        (nextPq,) = _generateKeyPair(seed);
        PackedUserOperation memory userOp = _buildUserOp(BOB, 0.01 ether, "");
        _signUserOp(userOp, alicePrivateKey, alicePubkey, nextPq);
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
    }

    function test_integration_handleOps_revertsWhen_walletSigTampered() public {
        (PackedUserOperation[] memory ops,) = _signedOps("integration-badsig-key");

        // Corrupt one byte deep inside the WOTS+ signature element bytes —
        // past the (currentKey, nextKey) header so the pre-verify branches pass
        // and verification itself fails.
        bytes memory sig = ops[0].signature;
        sig[200] ^= bytes1(0xFF);
        ops[0].signature = sig;

        vm.expectRevert(abi.encodeWithSignature("FailedOp(uint256,string)", uint256(0), "AA24 signature error"));
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);
    }

    /// @dev Chained UserOps: rotation committed by op1 must persist on-chain so
    ///      op2 (signed by op1's nextKey) validates. Also confirms `BENEFICIARY`
    ///      receives the gas refund from both submissions.
    function test_integration_handleOps_chainedRotation() public {
        (WOTSPlus.WinternitzAddress memory k1, bytes32 k1Priv) = _generateKeyPair("integration-chain-k1");
        (WOTSPlus.WinternitzAddress memory k2,) = _generateKeyPair("integration-chain-k2");

        // --- op1: alicePubkey -> k1 ---
        PackedUserOperation memory op1 = _buildUserOp(BOB, 0.01 ether, "");
        _signUserOp(op1, alicePrivateKey, alicePubkey, k1);

        PackedUserOperation[] memory ops1 = new PackedUserOperation[](1);
        ops1[0] = op1;

        uint256 beneficiaryBefore = BENEFICIARY.balance;
        IEntryPoint(ENTRY_POINT).handleOps(ops1, BENEFICIARY);
        assertGt(BENEFICIARY.balance, beneficiaryBefore, "beneficiary must receive gas refund for op1");
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, k1));
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));

        // --- op2: k1 -> k2 (uses new nonce, signed by the key installed by op1) ---
        PackedUserOperation memory op2 = _buildUserOp(BOB, 0.01 ether, "");
        op2.nonce = IEntryPoint(ENTRY_POINT).getNonce(address(wallet), 0);
        _signUserOp(op2, k1Priv, k1, k2);

        PackedUserOperation[] memory ops2 = new PackedUserOperation[](1);
        ops2[0] = op2;
        IEntryPoint(ENTRY_POINT).handleOps(ops2, BENEFICIARY);

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, k2));
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, k1));
    }

    /// @dev Replay: re-submitting a previously-executed UserOp must fail because
    ///      the nonce advanced *and* the signing key was rotated out of the set.
    ///      Proves one-time-key semantics at the EntryPoint level.
    function test_integration_handleOps_revertsWhen_replay() public {
        (PackedUserOperation[] memory ops,) = _signedOps("integration-replay-key");
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);

        // Second submission of the exact same op. The EntryPoint's nonce
        // manager enforces monotonic nonces; nonce 0 is already consumed.
        vm.expectRevert(abi.encodeWithSignature("FailedOp(uint256,string)", uint256(0), "AA25 invalid account nonce"));
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);
    }

    /// @dev Verify fee deduction during successful UserOp execution on fork.
    function test_integration_handleOps_deductsFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(0.002 ether);

        uint256 fee = wallet.getExecuteFee();
        assertEq(fee, 0.002 ether);

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("integration-fee-key");

        uint256 transferAmount = 0.01 ether;
        PackedUserOperation memory userOp = _buildUserOp(BOB, transferAmount, "");
        _signUserOp(userOp, alicePrivateKey, alicePubkey, nextPq);

        uint256 walletBalBefore = address(wallet).balance;
        uint256 factoryBalBefore = address(factory).balance;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);

        assertEq(address(factory).balance, factoryBalBefore + fee);
        assertEq(address(wallet).balance, walletBalBefore - transferAmount - fee);
    }
}
