// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @title Disaster Recovery Scenario
/// @dev End-to-end flow for the last-resort rescue path. Models a wallet whose
///      transaction and recovery keysets are both considered compromised: the
///      operator still controls the disaster key (held offline / cold) and
///      uses `saveWallet` to reset both keysets and install a fresh disaster
///      key, then resumes normal operation and replenishes.
contract QuipWallet_disasterRecovery is QuipWalletTest {
    WOTSPlus.WinternitzAddress internal disasterPub;
    bytes32 internal disasterPriv;

    /// @dev Fresh replacements written by saveWallet.
    WOTSPlus.WinternitzAddress[5] internal freshTxn;
    bytes32[5] internal freshTxnPrivs;
    WOTSPlus.WinternitzAddress[10] internal freshRec;

    WOTSPlus.WinternitzAddress internal nextDisasterPub;
    bytes32 internal nextDisasterPriv;

    function setUp() public override {
        super.setUp();
        (disasterPub, disasterPriv) = _generateDisasterRecoveryKey(VAULT_SEED);
        (nextDisasterPub, nextDisasterPriv) = _generateKeyPair(
            keccak256(abi.encodePacked(VAULT_SEED, "next-disaster"))
        );
        for (uint256 i = 0; i < 5; i++) {
            (freshTxn[i], freshTxnPrivs[i]) = _generateKeyPair(
                keccak256(abi.encodePacked(VAULT_SEED, "fresh-txn", i))
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            (freshRec[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked(VAULT_SEED, "fresh-rec", i))
            );
        }
    }

    function _buildSaveWalletPayload() internal view returns (bytes memory) {
        bytes32 keysHash = keccak256(abi.encode(freshTxn, freshRec));
        bytes32 digest = Codec.saveWalletDigest(
            address(wallet),
            block.chainid,
            disasterPub.publicSeed,
            disasterPub.publicKeyHash,
            nextDisasterPub.publicSeed,
            nextDisasterPub.publicKeyHash,
            keysHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);
        return
            Codec.encodeSaveWallet(
                disasterPub,
                nextDisasterPub,
                sig,
                freshTxn,
                freshRec
            );
    }

    /// @dev Precondition: original PQ keysets populated as set up by factory.
    function _assertPreSaveInvariants() internal view {
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[0]));
    }

    /// @dev Full disaster path — saveWallet → operate → recover via a fresh
    ///      recovery key → operate again.
    function test_simulation_disasterRecovery() public {
        _assertPreSaveInvariants();

        uint256 balBefore = address(wallet).balance;
        address ownerBefore = wallet.owner();

        // Step 1: Operator invokes saveWallet with the cold-held disaster key.
        //         Anyone can send the tx (no onlyOwner), the key-gate is the
        //         WOTS+ sig against the stored disasterRecoveryKey.
        address relayer = makeAddr("saveWalletRelayer");
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        wallet.saveWallet(_buildSaveWalletPayload());

        // Step 2: Invariants after rescue — both keysets swapped, owner + balance
        //         + verificationKeys (not touched by saveWallet) all intact.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        for (uint256 i = 0; i < 5; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[i])
            );
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, freshTxn[i]));
        }
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i])
            );
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, freshRec[i]));
        }
        assertEq(wallet.owner(), ownerBefore);
        assertEq(address(wallet).balance, balBefore);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 0);

        // Step 3: The disaster key rotated to `nextDisasterPub`. The old
        //         disaster-sig cannot be replayed — the stored key no longer
        //         matches.
        {
            bytes memory replay = _buildSaveWalletPayload();
            vm.prank(relayer);
            vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
            wallet.saveWallet(replay);
        }

        // Step 4: Resume operation with one of the freshly installed txn keys.
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,

            ) = _generateKeyPair("disaster-recovery-post-exec");
            uint256 fee = wallet.getExecuteFee();
            bytes32 execHash = _buildExecuteMessageHash(
                address(wallet),
                freshTxn[0],
                nextPq,
                BOB,
                0.05 ether,
                "",
                fee
            );
            WOTSPlus.WinternitzElements memory execSig = _sign(
                freshTxnPrivs[0],
                execHash
            );

            uint256 bobBal = BOB.balance;
            vm.prank(ALICE);
            wallet.execute(
                Codec.encodeExecute(
                    freshTxn[0],
                    nextPq,
                    execSig,
                    BOB,
                    0.05 ether,
                    ""
                )
            );
            assertEq(BOB.balance, bobBal + 0.05 ether);
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, freshTxn[0]));
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
        }

        // Step 5: Exercise the new recovery keyset — resetKeyset(Tx,
        //         signingKind=Recovery) with the first fresh recovery key
        //         proves it signs validly against the post-saveWallet stored
        //         keyset.
        {
            bytes32 freshRecPriv = _freshRecoveryPriv(0);
            WOTSPlus.WinternitzAddress[10] memory postRecoveryTx10;
            for (uint256 i = 0; i < 10; i++) {
                (postRecoveryTx10[i], ) = _generateKeyPair(
                    keccak256(abi.encodePacked("disaster-post-recovery-tx", i))
                );
            }
            (
                WOTSPlus.WinternitzAddress memory postRecoveryRk,
            ) = _generateKeyPair("disaster-post-recovery-rk");

            bytes32 recHash = _buildResetKeysetMessageHash(
                Codec.KeyType.Transaction,
                Codec.KeyType.Recovery,
                address(wallet),
                freshRec[0],
                postRecoveryRk,
                postRecoveryTx10
            );
            WOTSPlus.WinternitzElements memory recSig = _sign(
                freshRecPriv,
                recHash
            );

            vm.prank(ALICE);
            wallet.resetKeyset(
                Codec.encodeResetKeyset(
                    Codec.KeyType.Transaction,
                    Codec.KeyType.Recovery,
                    freshRec[0],
                    postRecoveryRk,
                    recSig,
                    postRecoveryTx10
                )
            );

            // resetKeyset clears the txn set and installs the 10 fresh keys.
            assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
            for (uint256 i = 0; i < 10; i++) {
                assertTrue(
                    wallet.isKey(Codec.KeyType.Transaction, postRecoveryTx10[i])
                );
            }
            // Consumed recovery key rotated in-place: original gone, replacement
            // installed, pool size preserved at 10.
            assertFalse(wallet.isKey(Codec.KeyType.Recovery, freshRec[0]));
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, postRecoveryRk));
            assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        }
    }

    /// @dev Mirrors the per-index derivation used by the setUp loop.
    function _freshRecoveryPriv(uint256 i) internal view returns (bytes32) {
        (, bytes32 priv) = WOTSPlus.generateKeyPair(
            keccak256(abi.encodePacked(VAULT_SEED, "fresh-rec", i))
        );
        return priv;
    }
}
