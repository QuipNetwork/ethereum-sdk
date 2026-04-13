// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

/// @title Multi-Operation Key Chain Scenario Test
/// @dev Verifies an unbroken WOTS+ key chain across 7 different operation
///      types: execute (transfer) → execute (call) → changePqOwner →
///      addRecoveryKeys → execute → transferOwnership → completeOwnershipHandover.
///      Each operation rotates the PQ key; the next uses the rotated key.
contract QuipWallet_multiOperationKeyChain is QuipWalletTest {
    DummyContract public dummy;

    WOTSPlus.WinternitzAddress internal currentPq;
    bytes32 internal currentPrivKey;

    function setUp() public override {
        super.setUp();
        dummy = new DummyContract();
    }

    /// @dev Rotate key, return new private key.
    function _advance(bytes32 seed)
        internal
        returns (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPrivKey)
    {
        (nextPq, nextPrivKey) = _generateKeyPair(seed);
    }

    /// @dev 7-operation key chain across different op types.
    function test_simulation_multiOperationKeyChain() public {
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // ── Op 1: execute (ETH transfer) ────────────────────────────
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
                _advance("chain-1-execute-transfer");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet), currentPq, nextPq, BOB, 0.05 ether, "", fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            uint256 bobBal = BOB.balance;
            vm.prank(ALICE);
            wallet.execute(Codec.encodeExecute(nextPq, sig, BOB, 0.05 ether, ""));
            assertEq(BOB.balance, bobBal + 0.05 ether);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 2: execute (contract call) ───────────────────────────
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
                _advance("chain-2-execute-call");
            bytes memory callData = abi.encodeWithSelector(DummyContract.setValueNoFee.selector, 99);
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet), currentPq, nextPq, address(dummy), 0, callData, fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.execute(Codec.encodeExecute(nextPq, sig, address(dummy), 0, callData));
            assertEq(dummy.value(), 99);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 3: changePqOwner ─────────────────────────────────────
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
                _advance("chain-3-rotate");
            bytes32 msgHash = _buildChangePqOwnerMessageHash(
                address(wallet), currentPq, nextPq
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.changePqOwner(Codec.encodeChangePqOwner(nextPq, sig));

            (bytes32 s, bytes32 h) = wallet.pqOwner();
            assertEq(s, nextPq.publicSeed);
            assertEq(h, nextPq.publicKeyHash);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 4: replenishRecoveryKeys (keyManagement digest domain) ──
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
                _advance("chain-4-replenish");
            bytes32 recBase = keccak256("chain-4-recovery-keys");
            WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(recBase, 10);

            bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
                address(wallet), currentPq, nextPq, newKeys
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.replenishRecoveryKeys(Codec.encodeKeyManagement(nextPq, sig, newKeys));
            assertEq(wallet.getRecoveryKeyCount(), 10);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 5: execute (another transfer) ────────────────────────
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
                _advance("chain-5-execute");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet), currentPq, nextPq, BOB, 0.01 ether, "", fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.execute(Codec.encodeExecute(nextPq, sig, BOB, 0.01 ether, ""));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 6: transferOwnership to BOB ──────────────────────────
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
                _advance("chain-6-transfer-ownership");
            bytes32 msgHash = _buildTransferOwnershipMessageHash(
                address(wallet), currentPq, nextPq, BOB
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.transferOwnership(Codec.encodeOwnershipTransfer(nextPq, sig, BOB));
            assertEq(wallet.owner(), BOB);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 7: BOB operates with the chained key ────────────────
        {
            (WOTSPlus.WinternitzAddress memory nextPq,) = _advance("chain-7-bob-exec");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet), currentPq, nextPq, BOB, 0.01 ether, "", fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            uint256 bobBal = BOB.balance;
            vm.prank(BOB);
            wallet.execute(Codec.encodeExecute(nextPq, sig, BOB, 0.01 ether, ""));
            assertEq(BOB.balance, bobBal + 0.01 ether);
        }
    }
}
