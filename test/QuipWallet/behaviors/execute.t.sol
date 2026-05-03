// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";

contract QuipWallet_execute is QuipWalletTest {
    DummyContract public dummy;

    function setUp() public override {
        super.setUp();
        dummy = new DummyContract();
    }

    // ── Pure ETH transfers (empty data) ─────────────────────────────

    function test_execute_transfersFunds() public {
        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "transfer-next"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            transferAmount,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        uint256 bobBalBefore = BOB.balance;
        uint256 walletBalBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                transferAmount,
                ""
            )
        );

        assertEq(BOB.balance, bobBalBefore + transferAmount);
        assertEq(address(wallet).balance, walletBalBefore - transferAmount);
    }

    function test_execute_emitsKeyRotatedAndExecutionSucceeded() public {
        uint256 transferAmount = 0.3 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "event-next"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            transferAmount,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                transferAmount,
                ""
            )
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool foundRotated = false;
        bool foundSucceeded = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.KeyRotated.selector) {
                foundRotated = true;
            }
            if (logs[i].topics[0] == IQuipWallet.ExecutionSucceeded.selector) {
                foundSucceeded = true;
            }
        }
        assertTrue(foundRotated, "KeyRotated event not emitted");
        assertTrue(foundSucceeded, "ExecutionSucceeded event not emitted");
    }

    // Empty execute (value == 0 && data.length == 0): the signature is still
    // consumed and the key still rotates, but the no-op must surface as
    // `KeyRotationOnly`, not `ExecutionSucceeded`. The fee still collects.
    function test_execute_emitsKeyRotationOnlyForEmptyExecute() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "empty-exec-next"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            0,
            "",
            EXECUTE_FEE
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        uint256 walletBalBefore = address(wallet).balance;
        uint256 factoryBalBefore = address(factory).balance;
        uint256 bobBalBefore = BOB.balance;

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.execute(
            Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, 0, "")
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool foundRotationOnly = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].topics[0] == IQuipWallet.KeyRotationOnly.selector &&
                logs[i].emitter == address(wallet)
            ) {
                foundRotationOnly = true;
            }
            // ExecutionSucceeded must NOT appear for the zero/zero case.
            assertTrue(
                logs[i].topics[0] != IQuipWallet.ExecutionSucceeded.selector ||
                    logs[i].emitter != address(wallet),
                "ExecutionSucceeded must not fire for empty execute"
            );
        }
        assertTrue(foundRotationOnly, "KeyRotationOnly event not emitted");

        // Key still rotated.
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));

        // Fee still collected; nothing else moved.
        assertEq(address(wallet).balance, walletBalBefore - EXECUTE_FEE);
        assertEq(address(factory).balance, factoryBalBefore + EXECUTE_FEE);
        assertEq(BOB.balance, bobBalBefore);
    }

    function test_execute_collectsFees() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 transferAmount = 0.3 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "fee-next"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            transferAmount,
            "",
            EXECUTE_FEE
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        uint256 factoryBalBefore = address(factory).balance;

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                transferAmount,
                ""
            )
        );

        assertEq(address(factory).balance, factoryBalBefore + EXECUTE_FEE);
    }

    function test_execute_rotatesKey() public {
        (
            WOTSPlus.WinternitzAddress memory nextPubkey,
            bytes32 nextPrivKey
        ) = _generateKeyPair("rotate-next");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            0.1 ether,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                0.1 ether,
                ""
            )
        );

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));

        // Old key should no longer work
        (WOTSPlus.WinternitzAddress memory anotherPubkey, ) = _generateKeyPair(
            "another-next"
        );
        bytes32 oldMsgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            anotherPubkey,
            BOB,
            0.1 ether,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory oldSig = _sign(
            alicePrivateKey,
            oldMsgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                anotherPubkey,
                oldSig,
                BOB,
                0.1 ether,
                ""
            )
        );
    }

    function test_execute_zeroValueTransfer() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "zero-val-next"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            0,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        uint256 walletBalBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, 0, "")
        );

        // Balance unchanged (no fee set)
        assertEq(address(wallet).balance, walletBalBefore);

        // Key still rotated
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));
    }

    function test_execute_transferToSelf() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 transferAmount = 0.3 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "self-transfer"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(wallet),
            transferAmount,
            "",
            EXECUTE_FEE
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        uint256 walletBalBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(wallet),
                transferAmount,
                ""
            )
        );

        // Only the fee should be deducted (transfer to self is a no-op on balance)
        assertEq(address(wallet).balance, walletBalBefore - EXECUTE_FEE);
    }

    function test_execute_transferEntireBalance() public {
        // No fee for this test
        assertEq(factory.executeFee(), 0);

        uint256 walletBal = address(wallet).balance;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "entire-bal"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            walletBal,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                walletBal,
                ""
            )
        );

        assertEq(address(wallet).balance, 0);
    }

    function test_execute_walletToWalletTransfer() public {
        (address bobWalletAddr, , , ) = _createWallet(
            BOB,
            "bob-wallet",
            INITIAL_DEPOSIT
        );

        uint256 transferAmount = 0.3 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "w2w-next"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            bobWalletAddr,
            transferAmount,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        uint256 bobWalletBalBefore = bobWalletAddr.balance;

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                bobWalletAddr,
                transferAmount,
                ""
            )
        );

        assertEq(bobWalletAddr.balance, bobWalletBalBefore + transferAmount);
    }

    // ── Contract calls (non-empty data) ─────────────────────────────

    function test_execute_executesCall() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValue.selector,
            42
        );
        uint256 requiredEth = 0.01 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "exec-call"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(dummy),
            requiredEth,
            callData,
            EXECUTE_FEE
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(dummy),
                requiredEth,
                callData
            )
        );

        assertEq(dummy.value(), 42);
    }

    function test_execute_forwardsValueToTarget() public {
        uint256 forwardAmount = 0.05 ether;
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValue.selector,
            99
        );
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "fwd-val"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(dummy),
            forwardAmount,
            callData,
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        uint256 dummyBalBefore = address(dummy).balance;

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(dummy),
                forwardAmount,
                callData
            )
        );

        assertEq(address(dummy).balance, dummyBalBefore + forwardAmount);
    }

    function test_execute_returnsCallData() public {
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            77
        );
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "ret-data"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(dummy),
            0,
            callData,
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        bytes memory result = wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(dummy),
                0,
                callData
            )
        );

        // setValueNoFee returns nothing, so result should be empty
        assertEq(result.length, 0);
        assertEq(dummy.value(), 77);
    }

    function test_execute_revertsWhen_targetReverts() public {
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.failingFunction.selector
        );
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "target-revert"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(dummy),
            0,
            callData,
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(DummyContract.AlwaysFails.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(dummy),
                0,
                callData
            )
        );
    }

    // ── Shared validation (reverts) ─────────────────────────────────

    function test_execute_revertsWhen_insufficientBalance() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 tooMuch = address(wallet).balance + 1;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "insuff-bal"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            tooMuch,
            "",
            EXECUTE_FEE
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        // Fee is collected successfully (balance >= fee), then the inner
        // ETH transfer of `tooMuch` to BOB reverts via SafeTransferLib.
        vm.expectRevert(SafeTransferLib.ETHTransferFailed.selector);
        wallet.execute(
            Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, tooMuch, "")
        );
    }

    function test_execute_revertsWhen_callerNotOwner() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "not-owner"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            0.1 ether,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                0.1 ether,
                ""
            )
        );
    }

    function test_execute_revertsWhen_invalidSignature() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "invalid-sig"
        );
        (, bytes32 wrongPrivKey) = _generateKeyPair("wrong-key");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            0.1 ether,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory badSig = _sign(
            wrongPrivKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                badSig,
                BOB,
                0.1 ether,
                ""
            )
        );
    }

    function test_execute_revertsWhen_nextKeySeedIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(uint256(1))
        });
        WOTSPlus.WinternitzElements memory fakeSig;

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                zeroPq,
                fakeSig,
                BOB,
                0.1 ether,
                ""
            )
        );
    }

    function test_execute_revertsWhen_nextKeyHashIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzElements memory fakeSig;

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                zeroPq,
                fakeSig,
                BOB,
                0.1 ether,
                ""
            )
        );
    }

    function test_execute_revertsWhen_nextKeyAlreadyInUse() public {
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            alicePubkey,
            BOB,
            0.1 ether,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.SameKey.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                alicePubkey,
                sig,
                BOB,
                0.1 ether,
                ""
            )
        );
    }
}
