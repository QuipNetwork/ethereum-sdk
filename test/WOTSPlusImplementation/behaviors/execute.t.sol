// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/wots/WOTSPlusImplementation.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/wots/EnumerableWinternitzAddressSet.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";

/// @dev Contract-owner test harness for reentrancy testing of `execute(bytes)`.
///      `execute(bytes)` is `onlyOwner`, so a malicious target's re-entry can
///      only reach `_verifyAndRotate` if the caller-of-the-re-entry IS the
///      wallet's owner. We sidestep the EOA-owner case by making this contract
///      itself the owner: `fire()` is the outer call (msg.sender to wallet =
///      this contract = owner ✓), and `attack()` is invoked by the wallet
///      mid-execute and re-enters `wallet.execute(savedPayload)` (msg.sender
///      to wallet on the re-entry = this contract = owner ✓). The rotation
///      that committed before the wallet's outer external call is what
///      prevents the re-entry from succeeding.
contract ReentrantReplayer {
    address public wallet;
    bytes public storedPayload;

    function setup(address _wallet, bytes calldata _payload) external {
        wallet = _wallet;
        storedPayload = _payload;
    }

    function fire() external payable {
        IWOTSPlusImplementation(wallet).execute(storedPayload);
    }

    /// @dev Called by the wallet during the outer `execute(P)`. Re-enters
    ///      `execute(P)` with the same payload — the rotation invariant
    ///      should make the inner `_verifyAndRotate` revert with `UnknownKey`,
    ///      which bubbles up and reverts the outer call.
    function attack() external payable {
        IWOTSPlusImplementation(wallet).execute(storedPayload);
    }

    receive() external payable {}
}

contract WOTSPlusImplementation_execute is WOTSPlusImplementationTest {
    DummyContract public dummy;

    function setUp() public override {
        super.setUp();
        dummy = new DummyContract();
    }

    // ── Pure ETH transfers (empty data) ─────────────────────────────

    function test_execute_transfersFunds() public {
        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("transfer-next");

        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, transferAmount, "", 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 bobBalBefore = BOB.balance;
        uint256 walletBalBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, transferAmount, ""));

        assertEq(BOB.balance, bobBalBefore + transferAmount);
        assertEq(address(wallet).balance, walletBalBefore - transferAmount);
    }

    function test_execute_emitsKeyRotatedAndExecutionSucceeded() public {
        uint256 transferAmount = 0.3 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("event-next");

        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, transferAmount, "", 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, transferAmount, ""));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool foundRotated = false;
        bool foundSucceeded = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IWOTSPlusImplementation.KeyRotated.selector) {
                foundRotated = true;
            }
            if (logs[i].topics[0] == IWOTSPlusImplementation.ExecutionSucceeded.selector) {
                foundSucceeded = true;
            }
        }
        assertTrue(foundRotated, "KeyRotated event not emitted");
        assertTrue(foundSucceeded, "ExecutionSucceeded event not emitted");
    }

    // CEI / reentrancy regression: a malicious target that the wallet calls
    // into during `execute(P)` cannot succeed in re-entering `execute(P)`
    // with the same signed payload. The mechanism is the rotation:
    // `_verifyAndRotate` removes `currentKey` from `transactionKeys` BEFORE
    // the external call runs, so the re-entered inner `_verifyAndRotate`
    // reverts at `_enforceContained` with `UnknownKey`. The inner revert
    // bubbles through `LibCall.callContract` and reverts the outer call —
    // the wallet's state is fully rolled back and no funds move.
    //
    // This test exercises the actual reentrancy code path the SECURITY
    // comments warn about. A future refactor that moves any of the
    // Interactions before the rotation would let the inner call's
    // `_verifyAndRotate` find `currentKey` still present and the re-entry
    // would succeed — this test would fail.
    //
    // Setup uses a contract-owner pattern so the inner re-entered call's
    // `onlyOwner` gate passes; an EOA owner cannot be impersonated by a
    // malicious target, so this is the only way to exercise the rotation
    // invariant in isolation.
    function test_execute_revertsWhen_targetReentersWithSamePayload() public {
        ReentrantReplayer replayer = new ReentrantReplayer();
        vm.deal(address(replayer), 1 ether);

        // Deploy a fresh wallet whose owner is the malicious replayer.
        (address rWalletAddr, WOTSPlus.WinternitzAddress memory rPubkey, bytes32 rPrivKey,) =
            _createWallet(address(replayer), keccak256("reentrant"), INITIAL_DEPOSIT);
        WOTSPlusImplementation rWallet = WOTSPlusImplementation(payable(rWalletAddr));

        // Build a signed payload P targeting the replayer with data =
        // attack-selector. When the wallet executes P it will call
        // replayer.attack(), which re-enters wallet.execute(P).
        bytes memory callData = abi.encodeWithSelector(ReentrantReplayer.attack.selector);
        (WOTSPlus.WinternitzAddress memory rNextKey,) = _generateKeyPair("reentrant-next");
        bytes32 msgHash = _buildExecuteMessageHash(rWalletAddr, rPubkey, rNextKey, address(replayer), 0, callData, 0);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);
        bytes memory payload = Codec.encodeExecute(rPubkey, rNextKey, sig, address(replayer), 0, callData);

        replayer.setup(rWalletAddr, payload);

        // Outer flow:
        //   replayer.fire() -> wallet.execute(P)
        //     wallet rotates rPubkey -> rNextKey (Effect)
        //     wallet calls replayer.attack() (Interaction)
        //       replayer.attack() calls wallet.execute(P) (re-entry)
        //         wallet's _verifyAndRotate fails at _enforceContained
        //         because rPubkey was just rotated out -> UnknownKey
        //       inner revert bubbles up
        //     replayer.attack() reverts
        //   LibCall.callContract bubbles the inner revert
        //   outer wallet.execute reverts with UnknownKey
        //   replayer.fire() reverts
        //   ALL state rolls back
        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        replayer.fire();

        // State must be unchanged: rPubkey still present, rNextKey not.
        assertTrue(rWallet.isKey(Codec.KeyType.Transaction, rPubkey));
        assertFalse(rWallet.isKey(Codec.KeyType.Transaction, rNextKey));
    }

    // CEI / replay-protection regression: a second `execute(P)` with the same
    // signed payload must revert because `_verifyAndRotate` already removed
    // `alicePubkey` from `transactionKeys` on the first call. Pins the
    // rotate-before-external-call invariant called out in the SECURITY
    // comment block in `WOTSPlusImplementation.execute(bytes)` — a future refactor that
    // moves rotation after the external call would let a malicious target
    // re-enter `execute(P)` with the same payload and drain the wallet.
    function test_execute_revertsWhen_payloadReplayedAfterRotation() public {
        uint256 transferAmount = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("replay-next");

        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, transferAmount, "", 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);
        bytes memory payload = Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, transferAmount, "");

        // First call: consumes alicePubkey, rotates to nextPubkey.
        vm.prank(ALICE);
        wallet.execute(payload);

        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));

        // Replay: alicePubkey is no longer in transactionKeys, so
        // `_verifyAndRotate` reverts at `_enforceContained` with `UnknownKey`.
        // This is the rotation invariant doing its job.
        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        wallet.execute(payload);
    }

    // Empty execute (value == 0 && data.length == 0): the signature is still
    // consumed and the key still rotates, but the no-op must surface as
    // `KeyRotationOnly`, not `ExecutionSucceeded`. The fee still collects.
    function test_execute_emitsKeyRotationOnlyForEmptyExecute() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("empty-exec-next");

        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, 0, "", EXECUTE_FEE);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 walletBalBefore = address(wallet).balance;
        uint256 factoryBalBefore = address(factory).balance;
        uint256 bobBalBefore = BOB.balance;

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, 0, ""));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool foundRotationOnly = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].topics[0] == IWOTSPlusImplementation.KeyRotationOnly.selector
                    && logs[i].emitter == address(wallet)
            ) {
                foundRotationOnly = true;
            }
            // ExecutionSucceeded must NOT appear for the zero/zero case.
            assertTrue(
                logs[i].topics[0] != IWOTSPlusImplementation.ExecutionSucceeded.selector
                    || logs[i].emitter != address(wallet),
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
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("fee-next");

        bytes32 msgHash =
            _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, transferAmount, "", EXECUTE_FEE);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 factoryBalBefore = address(factory).balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, transferAmount, ""));

        assertEq(address(factory).balance, factoryBalBefore + EXECUTE_FEE);
    }

    function test_execute_rotatesKey() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey, bytes32 nextPrivKey) = _generateKeyPair("rotate-next");

        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, 0.1 ether, "", 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, 0.1 ether, ""));

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));

        // Old key should no longer work
        (WOTSPlus.WinternitzAddress memory anotherPubkey,) = _generateKeyPair("another-next");
        bytes32 oldMsgHash =
            _buildExecuteMessageHash(address(wallet), alicePubkey, anotherPubkey, BOB, 0.1 ether, "", 0);
        WOTSPlus.WinternitzElements memory oldSig = _sign(alicePrivateKey, oldMsgHash);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        wallet.execute(Codec.encodeExecute(alicePubkey, anotherPubkey, oldSig, BOB, 0.1 ether, ""));
    }

    function test_execute_zeroValueTransfer() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("zero-val-next");

        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, 0, "", 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 walletBalBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, 0, ""));

        // Balance unchanged (no fee set)
        assertEq(address(wallet).balance, walletBalBefore);

        // Key still rotated
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));
    }

    function test_execute_transferToSelf() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 transferAmount = 0.3 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("self-transfer");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(wallet), transferAmount, "", EXECUTE_FEE
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 walletBalBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, address(wallet), transferAmount, ""));

        // Only the fee should be deducted (transfer to self is a no-op on balance)
        assertEq(address(wallet).balance, walletBalBefore - EXECUTE_FEE);
    }

    function test_execute_transferEntireBalance() public {
        // No fee for this test
        assertEq(factory.executeFee(), 0);

        uint256 walletBal = address(wallet).balance;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("entire-bal");

        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, walletBal, "", 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, walletBal, ""));

        assertEq(address(wallet).balance, 0);
    }

    function test_execute_walletToWalletTransfer() public {
        (address bobWalletAddr,,,) = _createWallet(BOB, "bob-wallet", INITIAL_DEPOSIT);

        uint256 transferAmount = 0.3 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("w2w-next");

        bytes32 msgHash =
            _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, bobWalletAddr, transferAmount, "", 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 bobWalletBalBefore = bobWalletAddr.balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, bobWalletAddr, transferAmount, ""));

        assertEq(bobWalletAddr.balance, bobWalletBalBefore + transferAmount);
    }

    // ── Contract calls (non-empty data) ─────────────────────────────

    function test_execute_executesCall() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(DummyContract.setValue.selector, 42);
        uint256 requiredEth = 0.01 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("exec-call");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), requiredEth, callData, EXECUTE_FEE
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, address(dummy), requiredEth, callData));

        assertEq(dummy.value(), 42);
    }

    function test_execute_forwardsValueToTarget() public {
        uint256 forwardAmount = 0.05 ether;
        bytes memory callData = abi.encodeWithSelector(DummyContract.setValue.selector, 99);
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("fwd-val");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), forwardAmount, callData, 0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 dummyBalBefore = address(dummy).balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, address(dummy), forwardAmount, callData));

        assertEq(address(dummy).balance, dummyBalBefore + forwardAmount);
    }

    function test_execute_returnsCallData() public {
        bytes memory callData = abi.encodeWithSelector(DummyContract.setValueNoFee.selector, 77);
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("ret-data");

        bytes32 msgHash =
            _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, address(dummy), 0, callData, 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        bytes memory result =
            wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, address(dummy), 0, callData));

        // setValueNoFee returns nothing, so result should be empty
        assertEq(result.length, 0);
        assertEq(dummy.value(), 77);
    }

    function test_execute_revertsWhen_targetReverts() public {
        bytes memory callData = abi.encodeWithSelector(DummyContract.failingFunction.selector);
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("target-revert");

        bytes32 msgHash =
            _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, address(dummy), 0, callData, 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(DummyContract.AlwaysFails.selector);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, address(dummy), 0, callData));
    }

    // ── Shared validation (reverts) ─────────────────────────────────

    function test_execute_revertsWhen_insufficientBalance() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 tooMuch = address(wallet).balance + 1;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("insuff-bal");

        bytes32 msgHash =
            _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, tooMuch, "", EXECUTE_FEE);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        // Fee is collected successfully (balance >= fee), then the inner
        // ETH transfer of `tooMuch` to BOB reverts via SafeTransferLib.
        vm.expectRevert(SafeTransferLib.ETHTransferFailed.selector);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, tooMuch, ""));
    }

    function test_execute_revertsWhen_callerNotOwner() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("not-owner");

        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, 0.1 ether, "", 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, 0.1 ether, ""));
    }

    function test_execute_revertsWhen_invalidSignature() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("invalid-sig");
        (, bytes32 wrongPrivKey) = _generateKeyPair("wrong-key");

        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, 0.1 ether, "", 0);
        WOTSPlus.WinternitzElements memory badSig = _sign(wrongPrivKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, badSig, BOB, 0.1 ether, ""));
    }

    function test_execute_revertsWhen_nextKeySeedIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(uint256(1))});
        WOTSPlus.WinternitzElements memory fakeSig;

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.execute(Codec.encodeExecute(alicePubkey, zeroPq, fakeSig, BOB, 0.1 ether, ""));
    }

    function test_execute_revertsWhen_nextKeyHashIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(0)});
        WOTSPlus.WinternitzElements memory fakeSig;

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.execute(Codec.encodeExecute(alicePubkey, zeroPq, fakeSig, BOB, 0.1 ether, ""));
    }

    function test_execute_revertsWhen_nextKeyAlreadyInUse() public {
        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), alicePubkey, alicePubkey, BOB, 0.1 ether, "", 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        wallet.execute(Codec.encodeExecute(alicePubkey, alicePubkey, sig, BOB, 0.1 ether, ""));
    }
}
