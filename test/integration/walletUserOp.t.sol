// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IntegrationBase, IEntryPoint, PackedUserOperation} from "./IntegrationBase.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

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
        (bytes32 seedBefore,) = wallet.pqOwner();
        assertEq(seedBefore, alicePubkey.publicSeed);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);

        assertEq(BOB.balance, bobBalBefore + transferAmount);

        (bytes32 seedAfter, bytes32 hashAfter) = wallet.pqOwner();
        assertEq(seedAfter, nextPq.publicSeed);
        assertEq(hashAfter, nextPq.publicKeyHash);
        assertTrue(seedAfter != seedBefore);
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

        (bytes32 seedAfter, bytes32 hashAfter) = wallet.pqOwner();
        assertEq(seedAfter, nextPq.publicSeed);
        assertEq(hashAfter, nextPq.publicKeyHash);
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
