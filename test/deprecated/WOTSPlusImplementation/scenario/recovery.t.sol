// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/WOTSPlusTestSigner.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

/// @title WOTSPlusImplementation Recovery Scenario Tests
/// @dev Recovery flows under the unified `resetKeyset(Tx, signingKind=Recovery)`
///      surface: a recovery key authorizes a wholesale reset of the transaction
///      keyset, rotating the signing recovery key in-place (size-preserving)
///      and installing 10 fresh transaction keys.
contract WOTSPlusImplementation_recovery is WOTSPlusImplementationTest {
    /// @dev Tracks the current PQ owner key across recovery steps.
    WOTSPlus.WinternitzAddress internal currentPq;
    bytes32 internal currentPrivKey;

    /// @dev Generate 10 fresh transaction keys derived from `seed`. Returns the
    ///      packed `[10]` array (codec input) plus a parallel `[10]` of private
    ///      keys so callers can sign with any of them post-install.
    function _freshTx10(bytes32 seed)
        internal
        view
        returns (WOTSPlus.WinternitzAddress[10] memory pubs, bytes32[10] memory privs)
    {
        for (uint256 i = 0; i < 10; i++) {
            (pubs[i], privs[i]) = _generateKeyPair(keccak256(abi.encodePacked(seed, "tx", i)));
        }
    }

    /// @dev Recover wallet using the given recovery key index: signs a
    ///      `resetKeyset(Tx, signingKind=Recovery)` with the recovery key,
    ///      installing 10 fresh transaction keys and rotating the consumed
    ///      recovery key to `newRecoveryKey`.
    function _recoverWith(
        uint256 keyIndex,
        WOTSPlus.WinternitzAddress[] memory rPubkeys,
        bytes32 rBaseSeed,
        bytes32 newTxSeed
    ) internal returns (bytes32 newPrivKey, WOTSPlus.WinternitzAddress memory newRecoveryKey) {
        (WOTSPlus.WinternitzAddress[10] memory newTx10, bytes32[10] memory newTx10Priv) = _freshTx10(newTxSeed);
        (newRecoveryKey,) = _generateKeyPair(keccak256(abi.encodePacked(newTxSeed, "recovery-replacement")));

        WOTSPlus.WinternitzAddress memory rKey = rPubkeys[keyIndex];
        bytes32 rKeyPriv = _recoverySigningKeyFromBase(rBaseSeed, keyIndex);

        bytes32 msgHash = _buildResetKeysetMessageHash(
            Codec.KeyType.Transaction, Codec.KeyType.Recovery, address(wallet), rKey, newRecoveryKey, newTx10
        );
        WOTSPlus.WinternitzElements memory sig = _sign(rKeyPriv, msgHash);

        vm.prank(wallet.owner());
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                Codec.KeyType.Transaction, Codec.KeyType.Recovery, rKey, newRecoveryKey, sig, newTx10
            )
        );

        // `resetKeyset(Tx, signingKind=Recovery)` clears the tx set and installs
        // the new 10; the consumed recovery key rotates in-place to
        // `newRecoveryKey`. Pin both invariants in the helper.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10, "resetKeyset(Tx) did not install exactly 10 txn keys");
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, newTx10[i]), "installed tx key missing");
        }
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, rKey), "burned recovery key should be removed");
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, newRecoveryKey), "replacement recovery key should be installed");
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

        currentPq = newTx10[0];
        currentPrivKey = newTx10Priv[0];
        newPrivKey = newTx10Priv[0];
    }

    /// @dev Recovery-key seed derivation that mirrors `_generateRecoveryKeys(base, n)`
    ///      so a test that originally generated a recovery batch from `base` can
    ///      sign with the i-th key by recomputing the same per-key seed.
    function _recoverySigningKeyFromBase(bytes32 base, uint256 index) internal pure returns (bytes32 priv) {
        bytes32 keySeed = keccak256(abi.encodePacked(base, "recovery", index));
        (, priv) = WOTSPlusTestSigner.generateKeyPair(keySeed);
    }

    /// @dev Replenish recovery keys using the current PQ key. Uses
    ///      `resetKeyset(Recovery)` tx-signed by the active transaction key.
    function _replenishKeys(bytes32 newRecoverySeed) internal returns (WOTSPlus.WinternitzAddress[] memory newKeys) {
        WOTSPlus.WinternitzAddress memory nextPq;
        bytes32 nextPrivKey;
        (nextPq, nextPrivKey) = _generateKeyPair(keccak256(abi.encodePacked(newRecoverySeed, "next-pq")));

        WOTSPlus.WinternitzAddress[10] memory newKeys10;
        WOTSPlus.WinternitzAddress[] memory genKeys = _generateRecoveryKeys(newRecoverySeed, 10);
        for (uint256 i = 0; i < 10; i++) {
            newKeys10[i] = genKeys[i];
        }
        newKeys = genKeys;

        bytes32 digest = _buildResetKeysetMessageHash(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, address(wallet), currentPq, nextPq, newKeys10
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, digest);

        vm.prank(wallet.owner());
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                Codec.KeyType.Recovery, Codec.KeyType.Transaction, currentPq, nextPq, sig, newKeys10
            )
        );

        currentPq = nextPq;
        currentPrivKey = nextPrivKey;
    }

    /// @dev Lose primary key, recover via recovery key, resume operations.
    function test_simulation_recoveryFlow() public {
        (WOTSPlus.WinternitzAddress[10] memory newTx10, bytes32[10] memory newTx10Priv) = _freshTx10("recovery-new-tx");
        (WOTSPlus.WinternitzAddress memory newRk,) = _generateKeyPair("recovery-new-rk");

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 recoverySigningKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildResetKeysetMessageHash(
            Codec.KeyType.Transaction, Codec.KeyType.Recovery, address(wallet), rKey, newRk, newTx10
        );
        WOTSPlus.WinternitzElements memory sig = _sign(recoverySigningKey, msgHash);

        vm.prank(ALICE);
        wallet.resetKeyset(
            Codec.encodeResetKeyset(Codec.KeyType.Transaction, Codec.KeyType.Recovery, rKey, newRk, sig, newTx10)
        );

        // Verify tx keyset wholesale-replaced and recovery keyset rotated.
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, newTx10[i]));
        }
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, rKey));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, newRk));
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

        // Resume operations with one of the newly-installed tx keys
        currentPq = newTx10[0];
        currentPrivKey = newTx10Priv[0];

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("post-recovery-key");
        uint256 fee = wallet.getExecuteFee();
        bytes32 execHash = _buildExecuteMessageHash(address(wallet), currentPq, nextPq, BOB, 0.05 ether, "", fee);
        WOTSPlus.WinternitzElements memory execSig = _sign(currentPrivKey, execHash);

        uint256 bobBalBefore = BOB.balance;
        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(currentPq, nextPq, execSig, BOB, 0.05 ether, ""));
        assertEq(BOB.balance, bobBalBefore + 0.05 ether);
    }

    /// @dev Rotate one recovery key, replenish all keys, recover with a new key.
    function test_simulation_replenishAndRecover() public {
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // Step 1: Rotate recovery key 0 (size preserved).
        _recoverWith(0, recoveryPubkeys, alicePrivateKey, "replenish-pq-1");
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

        // Step 2: Replenish with fresh 10 recovery keys via resetKeyset.
        bytes32 newRecoverySeed = keccak256("new-recovery-seed");
        WOTSPlus.WinternitzAddress[] memory newKeys = _replenishKeys(newRecoverySeed);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

        // Step 3: Recover with one of the new keys.
        _recoverWith(0, newKeys, newRecoverySeed, "replenish-pq-3");
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    /// @dev Rotate all 10 original recovery keys. After this, none of the
    ///      original keys are still in the active set, even though the set
    ///      size remains 10. Verify a further recovery attempt with one of
    ///      the burned originals fails. Then refresh and recover again.
    function test_simulation_recoveryExhaustion() public {
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // Rotate all 10 original recovery keys. After each rotation the set
        // size is preserved (the burned key is replaced in-place).
        for (uint256 i = 0; i < 10; i++) {
            _recoverWith(i, recoveryPubkeys, alicePrivateKey, bytes32(keccak256(abi.encodePacked("exhaust-pq-", i))));
            assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        }

        // All original recovery keys are burned; the set still has 10 entries
        // (the replacements installed during each rotation).
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }

        // Further recovery attempt with one of the burned originals fails —
        // `_verifyAndRotate` on the recoveryKeys set sees the burned key is
        // no longer a member and reverts with `UnknownKey`.
        (WOTSPlus.WinternitzAddress[10] memory fakeTx10,) = _freshTx10("fake-tx");
        (WOTSPlus.WinternitzAddress memory fakeRk,) = _generateKeyPair("fake-rk");
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);
        bytes32 msgHash = _buildResetKeysetMessageHash(
            Codec.KeyType.Transaction, Codec.KeyType.Recovery, address(wallet), rKey, fakeRk, fakeTx10
        );
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        wallet.resetKeyset(
            Codec.encodeResetKeyset(Codec.KeyType.Transaction, Codec.KeyType.Recovery, rKey, fakeRk, sig, fakeTx10)
        );

        // Replenish with fresh keys (clears the rotated set, installs 10 new).
        bytes32 freshSeed = keccak256("fresh-recovery-seed");
        WOTSPlus.WinternitzAddress[] memory freshKeys = _replenishKeys(freshSeed);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

        // Recover with a fresh key.
        _recoverWith(0, freshKeys, freshSeed, "post-exhaust-pq");
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }
}
