// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @title QuipWallet Recovery Scenario Tests
/// @dev Recovery flows: single recovery, replenish + recover, and full
///      rotation of all 10 original recovery keys followed by replenishment.
///
///      Note: `recoverWallet` rotates the consumed recovery key with a fresh
///      replacement (size-preserving), and clears+reseeds the transaction
///      keyset. The recovery set's *size* never changes via recovery, but the
///      *membership* rotates.
contract QuipWallet_recovery is QuipWalletTest {
    /// @dev Tracks the current PQ owner key across recovery steps.
    WOTSPlus.WinternitzAddress internal currentPq;
    bytes32 internal currentPrivKey;

    /// @dev Recover wallet using the given recovery key index, setting a new PQ
    ///      owner and rotating the recovery key to a fresh replacement.
    function _recoverWith(
        uint256 keyIndex,
        WOTSPlus.WinternitzAddress[] memory rPubkeys,
        bytes32 rBaseSeed,
        bytes32 newPqSeed
    )
        internal
        returns (
            bytes32 newPrivKey,
            WOTSPlus.WinternitzAddress memory newRecoveryKey
        )
    {
        WOTSPlus.WinternitzAddress memory newPqOwner;
        (newPqOwner, newPrivKey) = _generateKeyPair(newPqSeed);
        (newRecoveryKey, ) = _generateKeyPair(
            keccak256(abi.encodePacked(newPqSeed, "recovery-replacement"))
        );

        WOTSPlus.WinternitzAddress memory rKey = rPubkeys[keyIndex];
        bytes32 rKeySeed = keccak256(
            abi.encodePacked(rBaseSeed, "recovery", keyIndex)
        );
        (, bytes32 rKeyPriv) = WOTSPlus.generateKeyPair(rKeySeed);

        bytes32 msgHash = _buildRecoverWalletMessageHash(
            address(wallet),
            rKey,
            newRecoveryKey,
            newPqOwner
        );
        WOTSPlus.WinternitzElements memory sig = _sign(rKeyPriv, msgHash);

        vm.prank(wallet.owner());
        wallet.recoverWallet(
            Codec.encodeRecoverWallet(rKey, newRecoveryKey, newPqOwner, sig)
        );

        // `recoverWallet` drains the transaction keyset and installs exactly
        // one replacement, and rotates the consumed recovery key in-place
        // (size-preserving). Pin both invariants in the helper.
        assertEq(
            wallet.keyCount(Codec.KeyType.Transaction),
            1,
            "recoverWallet did not drain+install exactly one txn key"
        );
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, newPqOwner));
        assertFalse(
            wallet.isKey(Codec.KeyType.Recovery, rKey),
            "burned recovery key should be removed"
        );
        assertTrue(
            wallet.isKey(Codec.KeyType.Recovery, newRecoveryKey),
            "replacement recovery key should be installed"
        );

        currentPq = newPqOwner;
        currentPrivKey = newPrivKey;
    }

    /// @dev Replenish recovery keys using the current PQ key. Uses
    ///      `resetKeyset(Recovery)` tx-signed by the active transaction key.
    function _replenishKeys(
        bytes32 newRecoverySeed
    ) internal returns (WOTSPlus.WinternitzAddress[] memory newKeys) {
        WOTSPlus.WinternitzAddress memory nextPq;
        bytes32 nextPrivKey;
        (nextPq, nextPrivKey) = _generateKeyPair(
            keccak256(abi.encodePacked(newRecoverySeed, "next-pq"))
        );

        WOTSPlus.WinternitzAddress[10] memory newKeys10;
        WOTSPlus.WinternitzAddress[]
            memory genKeys = _generateRecoveryKeys(newRecoverySeed, 10);
        for (uint256 i = 0; i < 10; i++) {
            newKeys10[i] = genKeys[i];
        }
        newKeys = genKeys;

        bytes32 digest = _buildResetKeysetMessageHash(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            address(wallet),
            currentPq,
            nextPq,
            newKeys10
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, digest);

        vm.prank(wallet.owner());
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                Codec.KeyType.Recovery,
                Codec.KeyType.Transaction,
                currentPq,
                nextPq,
                sig,
                newKeys10
            )
        );

        currentPq = nextPq;
        currentPrivKey = nextPrivKey;
    }

    /// @dev Lose primary key, recover via recovery key, resume operations.
    function test_simulation_recoveryFlow() public {
        (
            WOTSPlus.WinternitzAddress memory newPqOwner,
            bytes32 newPqPrivKey
        ) = _generateKeyPair("recovery-new-pq");
        (
            WOTSPlus.WinternitzAddress memory newRk,
        ) = _generateKeyPair("recovery-new-rk");

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 recoverySigningKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoverWalletMessageHash(
            address(wallet),
            rKey,
            newRk,
            newPqOwner
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            recoverySigningKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.recoverWallet(
            Codec.encodeRecoverWallet(rKey, newRk, newPqOwner, sig)
        );

        // Verify pqOwner changed, txn keyset drained+seeded, and recovery
        // keyset rotated (size preserved).
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, newPqOwner));
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 1);
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, rKey));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, newRk));
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

        // Resume operations with new key
        currentPq = newPqOwner;
        currentPrivKey = newPqPrivKey;

        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "post-recovery-key"
        );
        uint256 fee = wallet.getExecuteFee();
        bytes32 execHash = _buildExecuteMessageHash(
            address(wallet),
            currentPq,
            nextPq,
            BOB,
            0.05 ether,
            "",
            fee
        );
        WOTSPlus.WinternitzElements memory execSig = _sign(
            currentPrivKey,
            execHash
        );

        uint256 bobBalBefore = BOB.balance;
        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                newPqOwner,
                nextPq,
                execSig,
                BOB,
                0.05 ether,
                ""
            )
        );
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
        WOTSPlus.WinternitzAddress[] memory newKeys = _replenishKeys(
            newRecoverySeed
        );
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
            _recoverWith(
                i,
                recoveryPubkeys,
                alicePrivateKey,
                bytes32(keccak256(abi.encodePacked("exhaust-pq-", i)))
            );
            assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        }

        // All original recovery keys are burned; the set still has 10 entries
        // (the replacements installed during each rotation).
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i])
            );
        }

        // Further recovery attempt with one of the burned originals fails.
        (WOTSPlus.WinternitzAddress memory fakePq, ) = _generateKeyPair(
            "fake-pq"
        );
        (
            WOTSPlus.WinternitzAddress memory fakeRk,
        ) = _generateKeyPair("fake-rk");
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);
        bytes32 msgHash = _buildRecoverWalletMessageHash(
            address(wallet),
            rKey,
            fakeRk,
            fakePq
        );
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.recoverWallet(
            Codec.encodeRecoverWallet(rKey, fakeRk, fakePq, sig)
        );

        // Replenish with fresh keys (clears the rotated set, installs 10 new).
        bytes32 freshSeed = keccak256("fresh-recovery-seed");
        WOTSPlus.WinternitzAddress[] memory freshKeys = _replenishKeys(
            freshSeed
        );
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

        // Recover with a fresh key.
        _recoverWith(0, freshKeys, freshSeed, "post-exhaust-pq");
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }
}
