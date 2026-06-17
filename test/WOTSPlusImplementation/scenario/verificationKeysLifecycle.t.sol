// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";

/// @title Verification Keyset Lifecycle Scenario
/// @dev End-to-end lifecycle of the verification keyset under the new
///      function pair (`resetKeyset` + `replaceKeys`):
///        1. starts empty,
///        2. is seeded via `resetKeyset(Verification, signingKind=Tx)`,
///        3. one verifier authorizes an ERC-1271 message,
///        4. that verifier rotates out via `replaceKeys(Verification, N=1)`,
///        5. the rotated-out key's ERC-1271 sig is no longer valid,
///        6. the whole keyset wipes-and-reinstalls via
///           `resetKeyset(Verification, signingKind=Recovery)`,
///        7. cross-keyset uniqueness: a verification install that collides
///           with a tx or recovery key reverts `KeyInUse`.
contract WOTSPlusImplementation_scenario_verificationKeysLifecycle is WOTSPlusImplementationTest {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;

    /// @dev Captures alicePrivateKey at deploy time so the recovery-signing
    ///      derivation works across the test even after we rotate alicePubkey
    ///      / alicePrivateKey through tx-signed ops.
    bytes32 internal _OG_ALICE_PRIVATE;

    /// @dev Mid-test shared state (storage rather than stack to keep the
    ///      lifecycle test frame within the stack-too-deep budget).
    WOTSPlus.WinternitzAddress[10] internal verifBatch1;
    bytes32[10] internal verifBatch1Priv;
    WOTSPlus.WinternitzAddress internal rotatedInVerifier;
    bytes32 internal rotatedInVerifierPriv;

    function setUp() public override {
        super.setUp();
        _OG_ALICE_PRIVATE = alicePrivateKey;
    }

    function _ecdsaSign(
        uint256 privKey,
        bytes32 hash
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function _freshKeys10WithPriv(
        bytes32 seed
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress[10] memory keys,
            bytes32[10] memory privs
        )
    {
        for (uint256 i = 0; i < 10; i++) {
            (keys[i], privs[i]) = WOTSPlus.generateKeyPair(
                keccak256(abi.encode(seed, i))
            );
        }
    }

    /// @dev Full lifecycle in one chain. Each step is its own internal
    ///      function so locals don't pile up in a single stack frame.
    function test_simulation_verificationKeysLifecycle() public {
        // Step 1: full at init (always-10 invariant).
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);

        // Step 2: wholesale-reset to a known batch via tx-signed resetKeyset.
        _seedInitialVerifierBatch();
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);

        // Step 3 + 4 + 5: verify, rotate that verifier out, verify the
        // rotated-out key is no longer valid.
        _verifyAndRotateOneVerifier();

        // Step 6: wholesale reset via recovery-signed resetKeyset.
        _wholesaleResetViaRecoverySig();

        // Final invariants.
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
    }

    /// @dev Step 2 — seed.
    function _seedInitialVerifierBatch() internal {
        (
            WOTSPlus.WinternitzAddress[10] memory keys,
            bytes32[10] memory privs
        ) = _freshKeys10WithPriv("verif-life-batch-1");
        for (uint256 i = 0; i < 10; i++) {
            verifBatch1[i] = keys[i];
            verifBatch1Priv[i] = privs[i];
        }

        (
            WOTSPlus.WinternitzAddress memory nextTx,
            bytes32 nextTxPriv
        ) = _generateKeyPair("verif-life-next-1");
        bytes32 digest = _buildResetKeysetMessageHash(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            address(wallet),
            alicePubkey,
            nextTx,
            keys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            digest
        );
        vm.prank(ALICE);
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                Codec.KeyType.Verification,
                Codec.KeyType.Transaction,
                alicePubkey,
                nextTx,
                sig,
                keys
            )
        );
        alicePubkey = nextTx;
        alicePrivateKey = nextTxPriv;
    }

    /// @dev Steps 3–5 — use a verifier, rotate it, confirm the rotated-out
    ///      key no longer validates while the replacement does.
    function _verifyAndRotateOneVerifier() internal {
        WOTSPlus.WinternitzAddress memory targetVerifier = verifBatch1[2];
        bytes32 targetPriv = verifBatch1Priv[2];

        // ERC-1271 valid via the in-set verifier.
        bytes32 msgHash = keccak256("verif-life-msg");
        bytes memory inSetSig = _encodeErc1271(
            targetVerifier,
            targetPriv,
            msgHash
        );
        assertEq(wallet.isValidSignature(msgHash, inSetSig), MAGIC);

        // Rotate that verifier out via tx-signed replaceKeys(N=1).
        (
            WOTSPlus.WinternitzAddress memory newVerif,
            bytes32 newVerifPriv
        ) = _generateKeyPair("verif-life-rot-2");
        _rotateOneVerifier(targetVerifier, newVerif);
        rotatedInVerifier = newVerif;
        rotatedInVerifierPriv = newVerifPriv;

        // Rotated-out verifier's ERC-1271 sig no longer validates (UnknownVerifier → FAIL).
        assertEq(wallet.isValidSignature(msgHash, inSetSig), FAIL);

        // Replacement verifier on a fresh message returns MAGIC.
        bytes32 msgHash2 = keccak256("verif-life-msg2");
        bytes memory replacementSig = _encodeErc1271(
            newVerif,
            newVerifPriv,
            msgHash2
        );
        assertEq(wallet.isValidSignature(msgHash2, replacementSig), MAGIC);
    }

    /// @dev Step 4 helper — submit a replaceKeys(Verification, N=1) for one
    ///      slot. Rotates the tx auth key.
    function _rotateOneVerifier(
        WOTSPlus.WinternitzAddress memory oldVerifier,
        WOTSPlus.WinternitzAddress memory newVerifier
    ) internal {
        WOTSPlus.WinternitzAddress[]
            memory oldArr = new WOTSPlus.WinternitzAddress[](1);
        WOTSPlus.WinternitzAddress[]
            memory newArr = new WOTSPlus.WinternitzAddress[](1);
        oldArr[0] = oldVerifier;
        newArr[0] = newVerifier;
        (
            WOTSPlus.WinternitzAddress memory nextTx,
            bytes32 nextTxPriv
        ) = _generateKeyPair("verif-life-rot-next");

        bytes32 digest = _buildReplaceKeysMessageHash(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            address(wallet),
            alicePubkey,
            nextTx,
            oldArr,
            newArr
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            digest
        );
        vm.prank(ALICE);
        wallet.replaceKeys(
            Codec.encodeReplaceKeys(
                Codec.KeyType.Verification,
                Codec.KeyType.Transaction,
                1,
                alicePubkey,
                nextTx,
                sig,
                oldArr,
                newArr
            )
        );
        alicePubkey = nextTx;
        alicePrivateKey = nextTxPriv;
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
    }

    /// @dev Step 6 — wholesale reset of the verification keyset signed by
    ///      a recovery key.
    function _wholesaleResetViaRecoverySig() internal {
        bytes32 recPriv = _recoverySigningKey(_OG_ALICE_PRIVATE, 0);
        WOTSPlus.WinternitzAddress memory recCur = recoveryPubkeys[0];
        (WOTSPlus.WinternitzAddress memory recNext, ) = _generateKeyPair(
            "verif-life-recNext"
        );
        (
            WOTSPlus.WinternitzAddress[10] memory batch2,

        ) = _freshKeys10WithPriv("verif-life-batch-2");

        bytes32 digest = _buildResetKeysetMessageHash(
            Codec.KeyType.Verification,
            Codec.KeyType.Recovery,
            address(wallet),
            recCur,
            recNext,
            batch2
        );
        WOTSPlus.WinternitzElements memory sig = _sign(recPriv, digest);
        vm.prank(ALICE);
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                Codec.KeyType.Verification,
                Codec.KeyType.Recovery,
                recCur,
                recNext,
                sig,
                batch2
            )
        );

        // None of batch1 remains; the rotated-in replacement is also wiped
        // by the wholesale reset.
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Verification, verifBatch1[i])
            );
            assertTrue(wallet.isKey(Codec.KeyType.Verification, batch2[i]));
        }
        assertFalse(
            wallet.isKey(Codec.KeyType.Verification, rotatedInVerifier)
        );
        // Recovery rotation committed.
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, recCur));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recNext));
    }

    function _encodeErc1271(
        WOTSPlus.WinternitzAddress memory verifier,
        bytes32 verifierPriv,
        bytes32 msgHash
    ) internal view returns (bytes memory) {
        bytes32 digest = _buildErc1271MessageHash(
            address(wallet),
            verifier,
            msgHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(verifierPriv, digest);
        bytes memory ecdsa = _ecdsaSign(
            ALICE_KEY,
            _buildErc1271EcdsaTarget(address(wallet), msgHash)
        );
        return Codec.encodeErc1271Signature(verifier, sig, ecdsa);
    }

    /// @dev Cross-keyset uniqueness: attempting to seed verification with a
    ///      batch that includes a key currently active in the tx keyset
    ///      reverts `KeyInUse`.
    function test_simulation_verificationCrossKeysetUniqueness_revertsOnTxKeyCollision()
        public
    {
        WOTSPlus.WinternitzAddress[10] memory batch;
        for (uint256 i = 0; i < 10; i++) {
            (batch[i], ) = _generateKeyPair(
                keccak256(abi.encode("verif-crossuniq", i))
            );
        }
        batch[4] = aliceTxnPubkeys[2]; // plant tx key in verification batch
        _expectKeyInUseOnResetVerification(batch, "verif-crossuniq-next");
        // Verification set unchanged from its init-full state.
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
    }

    /// @dev Mirror — collision against a recovery key reverts `KeyInUse`.
    function test_simulation_verificationCrossKeysetUniqueness_revertsOnRecoveryKeyCollision()
        public
    {
        WOTSPlus.WinternitzAddress[10] memory batch;
        for (uint256 i = 0; i < 10; i++) {
            (batch[i], ) = _generateKeyPair(
                keccak256(abi.encode("verif-crossuniq-rec", i))
            );
        }
        batch[0] = recoveryPubkeys[5];
        _expectKeyInUseOnResetVerification(batch, "verif-crossuniq-rec-next");
    }

    function _expectKeyInUseOnResetVerification(
        WOTSPlus.WinternitzAddress[10] memory batch,
        bytes32 nextSeed
    ) internal {
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            nextSeed
        );
        bytes32 digest = _buildResetKeysetMessageHash(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            address(wallet),
            alicePubkey,
            nextPq,
            batch
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            digest
        );
        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                Codec.KeyType.Verification,
                Codec.KeyType.Transaction,
                alicePubkey,
                nextPq,
                sig,
                batch
            )
        );
    }
}
