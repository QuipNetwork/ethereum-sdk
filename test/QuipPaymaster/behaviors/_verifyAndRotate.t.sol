// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {QuipPaymasterHarness} from "../../harness/QuipPaymasterHarness.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipPaymaster__verifyAndRotate is QuipPaymasterTest {
    /// @dev Domain tag for paymaster approval digests (must match QuipPaymaster._PAYMASTER_APPROVE_TAG).
    bytes32 private constant _PAYMASTER_APPROVE_TAG =
        keccak256("quip.digest.paymasterApprove");

    function test_exposed_verifyAndRotate_returnsTrueAndRotates() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        bytes32 opCommitment = EfficientHashLib.hash(
            bytes32(uint256(uint160(WALLET))),
            bytes32(uint256(0)),
            EfficientHashLib.hash(bytes(""))
        );

        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(harness)))),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            opCommitment
        );

        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            digest
        );

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            "",
            paymasterData
        );
        assertTrue(valid);

        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(
            WALLET
        );
        assertEq(stored.publicSeed, nextPubkey.publicSeed);
        assertEq(stored.publicKeyHash, nextPubkey.publicKeyHash);
    }

    function test_exposed_verifyAndRotate_emitsPqVerifierRotated() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        bytes32 opCommitment = EfficientHashLib.hash(
            bytes32(uint256(uint160(WALLET))),
            bytes32(uint256(0)),
            EfficientHashLib.hash(bytes(""))
        );

        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(harness)))),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            opCommitment
        );

        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            digest
        );

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            sig.elements
        );

        vm.recordLogs();
        harness.exposed_verifyAndRotate(WALLET, 0, "", paymasterData);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], IQuipPaymaster.PqVerifierRotated.selector);
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(WALLET))));
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_zeroNextVerifierSeed()
        public
    {
        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            bytes32(0), // zero publicSeed
            verifierPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            "",
            paymasterData
        );
        assertFalse(valid);

        // Verifier unchanged
        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(
            WALLET
        );
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
        assertEq(stored.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_zeroNextVerifierHash()
        public
    {
        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            verifierPubkey.publicSeed,
            bytes32(0), // zero publicKeyHash
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            "",
            paymasterData
        );
        assertFalse(valid);

        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(
            WALLET
        );
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
        assertEq(stored.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_noVerifier() public {
        address unregistered = makeAddr("unregistered");

        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "verifier-seed-2"
        );

        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(
            unregistered,
            0,
            "",
            paymasterData
        );
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_keyReuse() public {
        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            "",
            paymasterData
        );
        assertFalse(valid);

        // Verifier unchanged
        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(
            WALLET
        );
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
        assertEq(stored.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_invalidSignature()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "verifier-seed-invalid"
        );

        // Sign with a wrong key (not the installed verifier's private key)
        (, bytes32 wrongPrivateKey) = _generateKeyPair("wrong-key");

        bytes32 opCommitment = EfficientHashLib.hash(
            bytes32(uint256(uint160(WALLET))),
            bytes32(uint256(0)),
            EfficientHashLib.hash(bytes(""))
        );

        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(harness)))),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            opCommitment
        );

        WOTSPlus.WinternitzElements memory sig = _sign(wrongPrivateKey, digest);

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            "",
            paymasterData
        );
        assertFalse(valid);

        // Verifier unchanged
        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(
            WALLET
        );
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
        assertEq(stored.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    /*─────────────────── digest-binding invariants ──────────────────────*/
    //
    // The digest preimage includes `sender`, `nonce`, and `keccak(callData)`
    // via the `opCommitment`. These tests confirm that a signature committing
    // to one tuple does not verify against a different tuple — locking in the
    // intended replay-protection properties rather than relying on them as
    // implicit side-effects of the invalid-sig branch.

    /// @dev Helper to sign the paymaster-approve digest for a specific bundle.
    function _buildPaymasterDataForTuple(
        address sender_,
        uint256 nonce_,
        bytes memory callData_,
        WOTSPlus.WinternitzAddress memory currentPub,
        bytes32 currentPriv,
        WOTSPlus.WinternitzAddress memory nextPub
    ) internal view returns (bytes memory) {
        bytes32 opCommitment = EfficientHashLib.hash(
            bytes32(uint256(uint160(sender_))),
            bytes32(nonce_),
            EfficientHashLib.hash(callData_)
        );
        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(harness)))),
            currentPub.publicSeed,
            currentPub.publicKeyHash,
            nextPub.publicSeed,
            nextPub.publicKeyHash,
            opCommitment
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);
        return
            abi.encodePacked(
                uint48(block.timestamp + 1 hours),
                uint48(0),
                nextPub.publicSeed,
                nextPub.publicKeyHash,
                sig.elements
            );
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_senderMismatch()
        public
    {
        // Register a second wallet with a DIFFERENT verifier — the global
        // `verifierKeyUsed` check forbids two wallets from sharing a verifier,
        // so we use distinct keys. The sender-binding property is still
        // exercised: the paymaster rebuilds the digest from sender=WALLET_B,
        // and that digest no longer matches the signature WALLET signed.
        address WALLET_B = makeAddr("wallet-b-binding");
        (
            WOTSPlus.WinternitzAddress memory verifierBPubkey,

        ) = _generateKeyPair("verifier-seed-b");
        vm.prank(ADMIN);
        harness.setPqVerifier(WALLET_B, verifierBPubkey);

        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "sender-binding-next"
        );

        // Sign for sender=WALLET using WALLET's verifier privkey...
        bytes memory paymasterData = _buildPaymasterDataForTuple(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );

        // ...but submit as sender=WALLET_B. Inside `_verifyAndRotate` the
        // digest is rebuilt with (sender=WALLET_B, currentVerifier=WALLET_B's
        // stored verifier), so the WOTS+ verify against the supplied sig fails.
        bool valid = harness.exposed_verifyAndRotate(
            WALLET_B,
            0,
            "",
            paymasterData
        );
        assertFalse(valid);

        // Neither wallet's verifier rotated.
        assertEq(
            harness.getPqVerifier(WALLET).publicSeed,
            verifierPubkey.publicSeed
        );
        assertEq(
            harness.getPqVerifier(WALLET_B).publicSeed,
            verifierBPubkey.publicSeed
        );
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_nonceMismatch()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "nonce-binding-next"
        );

        // Sign for nonce=7...
        bytes memory paymasterData = _buildPaymasterDataForTuple(
            WALLET,
            7,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );

        // ...but submit with nonce=8.
        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            8,
            "",
            paymasterData
        );
        assertFalse(valid);

        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(
            WALLET
        );
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_callDataMismatch()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "calldata-binding-next"
        );

        // Sign for callData = hex"a1a1a1a1"...
        bytes memory paymasterData = _buildPaymasterDataForTuple(
            WALLET,
            0,
            hex"a1a1a1a1",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );

        // ...but submit with a different callData.
        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            hex"b2b2b2b2",
            paymasterData
        );
        assertFalse(valid);

        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(
            WALLET
        );
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
    }

    /*──────────────────── event non-emission on failure ─────────────────*/

    /// @dev The rotation event MUST NOT fire on any failure path — a reorder
    ///      bug (emit before verify, for example) would silently alter the
    ///      observer stream even though state is preserved. Exercise via the
    ///      invalid-sig branch; the other failure branches all share the
    ///      same "no emit + no rotate" contract.
    function test_exposed_verifyAndRotate_noEventEmittedWhen_invalidSignature()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "no-event-next"
        );
        (, bytes32 wrongPrivateKey) = _generateKeyPair("no-event-wrong");

        bytes32 opCommitment = EfficientHashLib.hash(
            bytes32(uint256(uint160(WALLET))),
            bytes32(uint256(0)),
            EfficientHashLib.hash(bytes(""))
        );
        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(harness)))),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            opCommitment
        );
        WOTSPlus.WinternitzElements memory sig = _sign(wrongPrivateKey, digest);
        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            sig.elements
        );

        vm.recordLogs();
        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            "",
            paymasterData
        );
        assertFalse(valid);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 rotated = IQuipPaymaster.PqVerifierRotated.selector;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0) {
                assertTrue(
                    logs[i].topics[0] != rotated,
                    "PqVerifierRotated emitted on failure path"
                );
            }
        }
    }

    function test_exposed_verifyAndRotate_noEventEmittedWhen_keyReuse() public {
        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );
        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            sig.elements
        );

        vm.recordLogs();
        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            "",
            paymasterData
        );
        assertFalse(valid);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 rotated = IQuipPaymaster.PqVerifierRotated.selector;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0) {
                assertTrue(
                    logs[i].topics[0] != rotated,
                    "PqVerifierRotated emitted on failure path"
                );
            }
        }
    }

    /// @dev Cross-wallet collision via the rotation path: WALLET attempts to
    ///      rotate its verifier to a key already registered for WALLET_B.
    ///      `_verifyAndRotate` must reject before the WOTS+ verify and before
    ///      touching state, emitting the typed `NextVerifierKeyInUse` reason.
    ///      Locks down the runtime side of the same invariant `setPqVerifier`
    ///      enforces at admin time.
    function test_exposed_verifyAndRotate_returnsFalseWhen_nextKeyInUseElsewhere()
        public
    {
        // Register a second wallet with its own verifier so its hash is
        // present in the global occupancy index.
        address WALLET_B = makeAddr("wallet-b-collision");
        (
            WOTSPlus.WinternitzAddress memory walletBVerifier,

        ) = _generateKeyPair("verifier-seed-b-collision");
        vm.prank(ADMIN);
        harness.setPqVerifier(WALLET_B, walletBVerifier);

        // WALLET tries to rotate its own verifier to WALLET_B's verifier.
        bytes memory paymasterData = _buildPaymasterDataForTuple(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            walletBVerifier
        );

        vm.expectEmit(address(harness));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET,
            IQuipPaymaster.PaymasterValidationFailure.NextVerifierKeyInUse
        );
        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            "",
            paymasterData
        );
        assertFalse(valid);

        // Neither wallet's verifier rotated; index still has both entries.
        WOTSPlus.WinternitzAddress memory storedA = harness.getPqVerifier(
            WALLET
        );
        assertEq(storedA.publicSeed, verifierPubkey.publicSeed);
        assertEq(storedA.publicKeyHash, verifierPubkey.publicKeyHash);
        WOTSPlus.WinternitzAddress memory storedB = harness.getPqVerifier(
            WALLET_B
        );
        assertEq(storedB.publicSeed, walletBVerifier.publicSeed);
        assertEq(storedB.publicKeyHash, walletBVerifier.publicKeyHash);
    }

    /// @dev After rotation the SPENT verifier (which just produced an on-chain
    ///      WOTS+ signature) must remain permanently locked in the occupancy
    ///      index. WOTS+ reveals key-chain material every time it signs, so
    ///      the public key is forever forgeable from that moment on; allowing
    ///      it to be re-bound elsewhere would let an observer of the original
    ///      rotation forge sigs against the rebind target. This is the most
    ///      load-bearing test of the monotonic-index invariant.
    function test_exposed_verifyAndRotate_spentKeyStaysLockedAfterRotation()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "spent-key-locked-next"
        );

        bytes memory paymasterData = _buildPaymasterDataForTuple(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );

        bool valid = harness.exposed_verifyAndRotate(
            WALLET,
            0,
            "",
            paymasterData
        );
        assertTrue(valid);

        // The original `verifierPubkey` JUST signed the rotation digest — its
        // WOTS+ chain is revealed on-chain. Re-binding it to ANY wallet
        // (including the original) must revert.
        address wallet2 = makeAddr("wallet2-after-rotation");
        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.VerifierKeyInUse.selector);
        harness.setPqVerifier(wallet2, verifierPubkey);

        // Even the original WALLET cannot re-adopt the spent key.
        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.VerifierKeyInUse.selector);
        harness.setPqVerifier(WALLET, verifierPubkey);
    }

    /// @dev A rotation cannot re-target a previously-spent verifier. Wallet B
    ///      rotates K_b → K_b'; later, wallet A's userOp tries to rotate to
    ///      K_b' (which is now spent). Must reject with `NextVerifierKeyInUse`.
    ///      Combined with the test above, this proves the post-rotation lock
    ///      protects every entry path: admin set, wallet self-rebind, and
    ///      cross-wallet rotation.
    function test_exposed_verifyAndRotate_revertsWhen_nextEqualsSpentKey()
        public
    {
        // Wallet B starts with its own verifier and rotates once.
        address WALLET_B = makeAddr("wallet-b-spent");
        (
            WOTSPlus.WinternitzAddress memory bCurr,
            bytes32 bCurrPriv
        ) = _generateKeyPair("wallet-b-curr");
        vm.prank(ADMIN);
        harness.setPqVerifier(WALLET_B, bCurr);

        (WOTSPlus.WinternitzAddress memory bNext, ) = _generateKeyPair(
            "wallet-b-next"
        );
        bytes memory bData = _buildPaymasterDataForTuple(
            WALLET_B,
            0,
            "",
            bCurr,
            bCurrPriv,
            bNext
        );
        assertTrue(harness.exposed_verifyAndRotate(WALLET_B, 0, "", bData));

        // Wallet A now tries to rotate to wallet B's NEW (now-current) key —
        // also blocked, but via the standard "key registered for B" path.
        bytes memory aDataToBNext = _buildPaymasterDataForTuple(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            bNext
        );
        vm.expectEmit(address(harness));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET,
            IQuipPaymaster.PaymasterValidationFailure.NextVerifierKeyInUse
        );
        assertFalse(
            harness.exposed_verifyAndRotate(WALLET, 0, "", aDataToBNext)
        );

        // Now the more pointed case: wallet A tries to rotate to wallet B's
        // SPENT old key. This is the regression test for "spent keys must
        // stay locked even after the wallet that spent them rotated away."
        bytes memory aDataToBSpent = _buildPaymasterDataForTuple(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            bCurr
        );
        vm.expectEmit(address(harness));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET,
            IQuipPaymaster.PaymasterValidationFailure.NextVerifierKeyInUse
        );
        assertFalse(
            harness.exposed_verifyAndRotate(WALLET, 0, "", aDataToBSpent)
        );
    }
}
