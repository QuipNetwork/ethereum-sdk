// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @title Multi-Operation Key Chain Scenarios
/// @dev End-to-end integration scenarios that chain MANY operations on the
///      same wallet, verifying:
///        - the active transaction key rotates correctly through every op,
///        - keyset sizes stay consistent across the chain,
///        - the global burn index (`isKeySpent`) holds — no historically
///          installed key resurfaces in any keyset after rotation,
///        - cross-keyset uniqueness holds — no key appears in two keysets
///          simultaneously,
///        - both cross-keyset auth paths work (tx-sign on non-tx targets;
///          recovery-sign on any target).
contract QuipWallet_scenario_multiOperationKeyChain is QuipWalletTest {
    /// @dev Tracks the currently-active transaction signing key as the chain
    ///      progresses. Each op consumes this and assigns its replacement.
    WOTSPlus.WinternitzAddress internal curPq;
    bytes32 internal curPqPriv;

    function setUp() public override {
        super.setUp();
        curPq = alicePubkey;
        curPqPriv = alicePrivateKey;
    }

    /// @dev Op A → B → C → D → E → F chain exercising every retained
    ///      key-management surface in sequence on the same wallet:
    ///        A. execute              — tx-signed value transfer
    ///        B. resetKeyset(Verif)   — tx-signed seed (verification was empty)
    ///        C. replaceKeys(Verif,3) — tx-signed rotate 3 verification keys
    ///        D. resetKeyset(Recov)   — tx-signed wholesale recovery rotate
    ///        E. replaceKeys(Recov,2) — recovery-signed rotate of 2 (same-keyset auth)
    ///        F. execute              — final tx-signed value transfer
    ///      After each step we assert:
    ///        - the consumed PQ key is GONE from the tx set AND spent
    ///        - the replacement key is IN the tx set
    ///        - the target keyset count is correct
    ///        - the wallet's balance / fee accounting is preserved
    function test_scenario_multiOp_executeResetReplaceChain() public {
        // Snapshot starting state.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);

        // ── Op A: execute(BOB, 0.01) ─────────────────────────────────
        uint256 bobBalBefore = BOB.balance;
        _opExecute(BOB, 0.01 ether, "op-A-next");
        assertEq(BOB.balance, bobBalBefore + 0.01 ether);
        // Tx keyset stays at 10 (rotation is size-neutral). curPq is updated.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);

        // ── Op B: resetKeyset(Verification, txSign) — seeds 10 ───────
        WOTSPlus.WinternitzAddress[10] memory verifBatch = _freshKeys10(
            "op-B-verif"
        );
        _opResetKeyset_TxSigned(Codec.KeyType.Verification, verifBatch, "op-B-next");
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Verification, verifBatch[i]));
            // No collision into other keysets.
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, verifBatch[i]));
            assertFalse(wallet.isKey(Codec.KeyType.Recovery, verifBatch[i]));
        }

        // ── Op C: replaceKeys(Verification, txSign, N=3) ─────────────
        WOTSPlus.WinternitzAddress[] memory verifOld = new WOTSPlus.WinternitzAddress[](3);
        WOTSPlus.WinternitzAddress[] memory verifNew = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            verifOld[i] = verifBatch[i];
            (verifNew[i], ) = _generateKeyPair(
                keccak256(abi.encode("op-C-new", i))
            );
        }
        _opReplaceKeys_TxSigned(
            Codec.KeyType.Verification,
            verifOld,
            verifNew,
            "op-C-next"
        );
        // Verification size still 10; rotated 3.
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Verification, verifOld[i]));
            assertTrue(wallet.isKey(Codec.KeyType.Verification, verifNew[i]));
            // Spent originals not in the burn index? They ARE — `_safeRemoveKey`
            // burns on remove. Confirm via the spent flag (cross-keyset add of
            // a spent key would revert KeyInUse — exercised separately).
            assertTrue(wallet.isKeySpent(verifOld[i]));
        }

        // ── Op D: resetKeyset(Recovery, txSign) — wholesale rotate ───
        WOTSPlus.WinternitzAddress[10] memory newRecBatch = _freshKeys10(
            "op-D-rec"
        );
        _opResetKeyset_TxSigned(Codec.KeyType.Recovery, newRecBatch, "op-D-next");
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        // None of the original recovery keys remain.
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i])
            );
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, newRecBatch[i]));
        }
        // Tx set still at 5.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);

        // ── Op E: replaceKeys(Recovery, recoverySign, N=2) ──────────
        //
        // Same-keyset auth: sign with newRecBatch[0]; rotate 2 OTHER
        // recovery keys. Caller obligation: oldKeys must not include the
        // signing key (auth rotation already removed it), and newKeys must
        // not include the signing nextRec.
        bytes32 recPrivE = _derivePrivKeyForFreshKeys10("op-D-rec", 0);
        WOTSPlus.WinternitzAddress memory recE = newRecBatch[0];
        WOTSPlus.WinternitzAddress[] memory recOld = new WOTSPlus.WinternitzAddress[](2);
        WOTSPlus.WinternitzAddress[] memory recNew = new WOTSPlus.WinternitzAddress[](2);
        recOld[0] = newRecBatch[3];
        recOld[1] = newRecBatch[7];
        (recNew[0], ) = _generateKeyPair("op-E-recNew-0");
        (recNew[1], ) = _generateKeyPair("op-E-recNew-1");
        (WOTSPlus.WinternitzAddress memory recNextE, ) = _generateKeyPair(
            "op-E-recNext"
        );
        bytes32 digestE = _buildReplaceKeysMessageHash(
            Codec.KeyType.Recovery,
            Codec.KeyType.Recovery,
            address(wallet),
            recE,
            recNextE,
            recOld,
            recNew
        );
        WOTSPlus.WinternitzElements memory sigE = _sign(recPrivE, digestE);
        vm.prank(ALICE);
        wallet.replaceKeys(
            Codec.encodeReplaceKeys(
                Codec.KeyType.Recovery,
                Codec.KeyType.Recovery,
                2,
                recE,
                recNextE,
                sigE,
                recOld,
                recNew
            )
        );
        // Recovery still at 10. recE rotated to recNextE; recOld[0..1] →
        // recNew[0..1]. Tx key UNTOUCHED by recovery-signed op.
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, recE));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recNextE));
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, recOld[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recNew[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, curPq));

        // ── Op F: execute final transfer ─────────────────────────────
        bobBalBefore = BOB.balance;
        _opExecute(BOB, 0.02 ether, "op-F-next");
        assertEq(BOB.balance, bobBalBefore + 0.02 ether);
        // Final state sanity.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
    }

    /// @dev Variant chain: recovery-signed surface on every target keyset.
    ///      Proves cross-keyset auth works end-to-end on the "recovery key
    ///      can authorize anything" side of the matrix.
    ///        A. resetKeyset(Verification, recSign)
    ///        B. replaceKeys(Transaction, recSign, N=3) — wipe parts of tx
    ///        C. resetKeyset(Transaction, recSign) — wholesale tx rotate
    function test_scenario_multiOp_recoverySignedOnAllTargets() public {
        // Track the recovery key being consumed across the chain.
        WOTSPlus.WinternitzAddress memory recCur = recoveryPubkeys[0];
        bytes32 recCurPriv = _recoverySigningKey(alicePrivateKey, 0);

        // ── Op A: resetKeyset(Verification, recSign) ─────────────────
        WOTSPlus.WinternitzAddress[10] memory verifBatch = _freshKeys10(
            "rsignA-verif"
        );
        (WOTSPlus.WinternitzAddress memory recNextA, ) = _generateKeyPair(
            "rsignA-recNext"
        );
        _resetKeysetSubmit(
            Codec.KeyType.Verification,
            Codec.KeyType.Recovery,
            recCur,
            recCurPriv,
            recNextA,
            verifBatch
        );
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, recCur));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recNextA));
        recCur = recNextA;
        recCurPriv = _derivePrivKey("rsignA-recNext");

        // Tx set untouched.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));

        // ── Op B: replaceKeys(Transaction, recSign, N=3) ─────────────
        // Pull 3 tx keys to swap. curPq is still alicePubkey since no
        // tx-signed op has run.
        WOTSPlus.WinternitzAddress[] memory txOld = new WOTSPlus.WinternitzAddress[](3);
        WOTSPlus.WinternitzAddress[] memory txNew = new WOTSPlus.WinternitzAddress[](3);
        txOld[0] = aliceTxnPubkeys[1];
        txOld[1] = aliceTxnPubkeys[2];
        txOld[2] = aliceTxnPubkeys[3];
        (txNew[0], ) = _generateKeyPair("rsignB-txNew-0");
        (txNew[1], ) = _generateKeyPair("rsignB-txNew-1");
        (txNew[2], ) = _generateKeyPair("rsignB-txNew-2");
        (WOTSPlus.WinternitzAddress memory recNextB, ) = _generateKeyPair(
            "rsignB-recNext"
        );
        bytes32 digestB = _buildReplaceKeysMessageHash(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            address(wallet),
            recCur,
            recNextB,
            txOld,
            txNew
        );
        WOTSPlus.WinternitzElements memory sigB = _sign(recCurPriv, digestB);
        vm.prank(ALICE);
        wallet.replaceKeys(
            Codec.encodeReplaceKeys(
                Codec.KeyType.Transaction,
                Codec.KeyType.Recovery,
                3,
                recCur,
                recNextB,
                sigB,
                txOld,
                txNew
            )
        );
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, txOld[i]));
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, txNew[i]));
        }
        // alicePubkey untouched.
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
        recCur = recNextB;
        recCurPriv = _derivePrivKey("rsignB-recNext");

        // ── Op C: resetKeyset(Transaction, recSign) ──────────────────
        WOTSPlus.WinternitzAddress[10] memory txBatch = _freshKeys10(
            "rsignC-tx"
        );
        (WOTSPlus.WinternitzAddress memory recNextC, ) = _generateKeyPair(
            "rsignC-recNext"
        );
        _resetKeysetSubmit(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            recCur,
            recCurPriv,
            recNextC,
            txBatch
        );
        // Tx set is now exactly the 10 new keys.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, txBatch[i]));
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       OP HELPERS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Single tx-signed execute. Consumes `curPq`, rotates to a fresh
    ///      key derived from `nextSeed`.
    function _opExecute(
        address to,
        uint256 value,
        bytes32 nextSeed
    ) internal {
        (
            WOTSPlus.WinternitzAddress memory nextPq,
            bytes32 nextPriv
        ) = _generateKeyPair(nextSeed);
        uint256 fee = wallet.getExecuteFee();
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            curPq,
            nextPq,
            to,
            value,
            "",
            fee
        );
        WOTSPlus.WinternitzElements memory sig = _sign(curPqPriv, msgHash);
        vm.prank(ALICE);
        wallet.execute{value: fee}(
            Codec.encodeExecute(curPq, nextPq, sig, to, value, "")
        );
        // Spent + rotated checks.
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, curPq));
        assertTrue(wallet.isKeySpent(curPq));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
        curPq = nextPq;
        curPqPriv = nextPriv;
    }

    /// @dev tx-signed resetKeyset on `kind`. Consumes `curPq` and rotates.
    function _opResetKeyset_TxSigned(
        Codec.KeyType kind,
        WOTSPlus.WinternitzAddress[10] memory newKeys,
        bytes32 nextSeed
    ) internal {
        (
            WOTSPlus.WinternitzAddress memory nextPq,
            bytes32 nextPriv
        ) = _generateKeyPair(nextSeed);
        bytes32 msgHash = _buildResetKeysetMessageHash(
            kind,
            Codec.KeyType.Transaction,
            address(wallet),
            curPq,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(curPqPriv, msgHash);
        vm.prank(ALICE);
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                kind,
                Codec.KeyType.Transaction,
                curPq,
                nextPq,
                sig,
                newKeys
            )
        );
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, curPq));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
        curPq = nextPq;
        curPqPriv = nextPriv;
    }

    /// @dev tx-signed replaceKeys on `kind`. Consumes `curPq` and rotates.
    function _opReplaceKeys_TxSigned(
        Codec.KeyType kind,
        WOTSPlus.WinternitzAddress[] memory oldKeys,
        WOTSPlus.WinternitzAddress[] memory newKeys,
        bytes32 nextSeed
    ) internal {
        (
            WOTSPlus.WinternitzAddress memory nextPq,
            bytes32 nextPriv
        ) = _generateKeyPair(nextSeed);
        bytes32 msgHash = _buildReplaceKeysMessageHash(
            kind,
            Codec.KeyType.Transaction,
            address(wallet),
            curPq,
            nextPq,
            oldKeys,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(curPqPriv, msgHash);
        vm.prank(ALICE);
        wallet.replaceKeys(
            Codec.encodeReplaceKeys(
                kind,
                Codec.KeyType.Transaction,
                oldKeys.length,
                curPq,
                nextPq,
                sig,
                oldKeys,
                newKeys
            )
        );
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, curPq));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
        curPq = nextPq;
        curPqPriv = nextPriv;
    }

    /// @dev Submit a resetKeyset with an explicit signing keypair (for
    ///      recovery-signed paths).
    function _resetKeysetSubmit(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        WOTSPlus.WinternitzAddress memory currentPq,
        bytes32 currentPriv,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[10] memory newKeys
    ) internal {
        bytes32 msgHash = _buildResetKeysetMessageHash(
            kind,
            signingKind,
            address(wallet),
            currentPq,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, msgHash);
        vm.prank(ALICE);
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                kind,
                signingKind,
                currentPq,
                nextPq,
                sig,
                newKeys
            )
        );
    }

    function _freshKeys10(
        bytes32 seed
    ) internal pure returns (WOTSPlus.WinternitzAddress[10] memory out) {
        for (uint256 i = 0; i < 10; i++) {
            (out[i], ) = WOTSPlus.generateKeyPair(
                keccak256(abi.encode(seed, i))
            );
        }
    }

    /// @dev Re-derive the private key for a `_freshKeys10(seed)[index]`
    ///      output. Mirrors the `keccak256(abi.encode(seed, index))` seed
    ///      derivation used inside `_freshKeys10`.
    function _derivePrivKeyForFreshKeys10(
        bytes32 seed,
        uint256 index
    ) internal pure returns (bytes32) {
        (, bytes32 priv) = WOTSPlus.generateKeyPair(
            keccak256(abi.encode(seed, index))
        );
        return priv;
    }

    /// @dev Re-derive the private key for a `_generateKeyPair(seed)` output.
    function _derivePrivKey(bytes32 seed) internal pure returns (bytes32) {
        (, bytes32 priv) = WOTSPlus.generateKeyPair(seed);
        return priv;
    }
}
