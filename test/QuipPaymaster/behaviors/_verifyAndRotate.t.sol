// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {QuipPaymasterHarness} from "../../harness/QuipPaymasterHarness.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

contract QuipPaymaster__verifyAndRotate is QuipPaymasterTest {
    /// @dev ERC-7201 namespace slot for `QuipPaymasterStorage.Layout`. Used
    ///      by the half-zero corruption regression tests below.
    bytes32 private constant _PAYMASTER_STORAGE_SLOT =
        0x8926ce57d385a1d96a00d5ce1618d3e300ce201cbf2177f181835ec0ca228b00;

    /*─────────────────────────── helpers ───────────────────────────────*/

    /// @dev Build a signed userOp targeting the harness. The signed
    ///      digest commits to the full userOp envelope (per the
    ///      userOpBindingHash contract); mutating any envelope field after
    ///      this call will invalidate the signature, which is what the
    ///      binding-invariant tests exploit.
    function _harnessUserOp(
        address sender_,
        uint256 nonce_,
        bytes memory callData_,
        WOTSPlus.WinternitzAddress memory currentPub,
        bytes32 currentPriv,
        WOTSPlus.WinternitzAddress memory nextPub
    ) internal view returns (PackedUserOperation memory) {
        PackedUserOperation memory userOp = _mockUserOp("", sender_);
        userOp.nonce = nonce_;
        userOp.callData = callData_;
        return
            _signPaymasterApproval(
                userOp,
                address(harness),
                _DEFAULT_PM_VERIFICATION_GAS,
                _DEFAULT_PM_POSTOP_GAS,
                uint48(block.timestamp + 1 hours),
                uint48(0),
                currentPub,
                currentPriv,
                nextPub
            );
    }

    /// @dev Build a userOp with an arbitrary WOTS+ signature (not necessarily
    ///      valid for the bound digest). Used for failure-path tests where the
    ///      signature is wrong but the rest of the envelope is well-formed.
    function _userOpWithRawSig(
        address sender_,
        uint256 nonce_,
        bytes memory callData_,
        WOTSPlus.WinternitzAddress memory nextPub,
        WOTSPlus.WinternitzElements memory sig
    ) internal view returns (PackedUserOperation memory) {
        bytes memory prefix = _paymasterAndDataPrefix(
            address(harness),
            _DEFAULT_PM_VERIFICATION_GAS,
            _DEFAULT_PM_POSTOP_GAS,
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPub
        );

        PackedUserOperation memory userOp = _mockUserOp(
            abi.encodePacked(prefix, sig.elements),
            sender_
        );
        userOp.nonce = nonce_;
        userOp.callData = callData_;
        return userOp;
    }

    /*──────────────────────── happy-path tests ─────────────────────────*/

    function test_exposed_verifyAndRotate_returnsTrueAndRotates() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );

        bool valid = harness.exposed_verifyAndRotate(userOp);
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

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );

        vm.recordLogs();
        harness.exposed_verifyAndRotate(userOp);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], IQuipPaymaster.PqVerifierRotated.selector);
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(WALLET))));
    }

    /*──────────────────── zero-value / missing checks ──────────────────*/

    function test_exposed_verifyAndRotate_returnsFalseWhen_zeroNextVerifierSeed()
        public
    {
        // nextVerifier with zero seed; signature value doesn't matter — the
        // zero-check fires before the WOTS+ verify.
        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );
        PackedUserOperation memory userOp = _userOpWithRawSig(
            WALLET,
            0,
            "",
            WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(0),
                publicKeyHash: verifierPubkey.publicKeyHash
            }),
            sig
        );

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);

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
        PackedUserOperation memory userOp = _userOpWithRawSig(
            WALLET,
            0,
            "",
            WOTSPlus.WinternitzAddress({
                publicSeed: verifierPubkey.publicSeed,
                publicKeyHash: bytes32(0)
            }),
            sig
        );

        bool valid = harness.exposed_verifyAndRotate(userOp);
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
        PackedUserOperation memory userOp = _userOpWithRawSig(
            unregistered,
            0,
            "",
            nextPubkey,
            sig
        );

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_keyReuse() public {
        // next == current: caught before WOTS+ verify, so any sig works.
        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );
        PackedUserOperation memory userOp = _userOpWithRawSig(
            WALLET,
            0,
            "",
            verifierPubkey,
            sig
        );

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);

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

        // Sign with a wrong key (not the installed verifier's private key).
        (, bytes32 wrongPrivateKey) = _generateKeyPair("wrong-key");

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            wrongPrivateKey,
            nextPubkey
        );

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);

        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(
            WALLET
        );
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
        assertEq(stored.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    /*─────────────── digest-binding invariants (envelope mutation) ────────
    //
    // userOpBindingHash binds the full envelope. These tests confirm that a
    // signature committing to one envelope does not verify against any
    // mutation — the auditor's "regression tests that mutate each excluded
    // field" recommendation, now applied to the complete envelope.
    ──────────────────────────────────────────────────────────────────────*/

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

        // Sign for sender=WALLET...
        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        // ...but submit as sender=WALLET_B.
        userOp.sender = WALLET_B;

        bool valid = harness.exposed_verifyAndRotate(userOp);
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

        // Sign for nonce=7, submit with nonce=8.
        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            7,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        userOp.nonce = 8;

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);

        assertEq(
            harness.getPqVerifier(WALLET).publicSeed,
            verifierPubkey.publicSeed
        );
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_callDataMismatch()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "calldata-binding-next"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            hex"a1a1a1a1",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        userOp.callData = hex"b2b2b2b2";

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);

        assertEq(
            harness.getPqVerifier(WALLET).publicSeed,
            verifierPubkey.publicSeed
        );
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_initCodeMutated()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "initcode-binding-next"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        userOp.initCode = hex"deadbeef";

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_accountGasLimitsMutated()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "accgas-binding-next"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        // Inflate verificationGasLimit (the upper 16 bytes).
        userOp.accountGasLimits = bytes32(
            (uint256(999_999) << 128) | uint256(100_000)
        );

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_preVerificationGasMutated()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "pvg-binding-next"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        // preVerificationGas amplification is the most concrete cost-extraction
        // vector — it's claimed in full by the bundler regardless of usage.
        userOp.preVerificationGas = 9_999_999;

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_gasFeesMutated()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "gasfees-binding-next"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        // Inflate maxPriorityFeePerGas (upper 16 bytes), the extracted portion.
        userOp.gasFees = bytes32(
            (uint256(1_000 gwei) << 128) | uint256(10 gwei)
        );

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_validUntilMutated()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "validuntil-binding-next"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        // validUntil lives at paymasterAndData[52:58] (uint48). Overwrite
        // those bytes with a different value; the binding hash sees the new
        // bytes via paymasterAndData[:128].
        bytes memory pmd = userOp.paymasterAndData;
        bytes6 newValidUntil = bytes6(uint48(block.timestamp + 9999 hours));
        assembly {
            // pmd: 32 bytes length, then data. Offset 52 → data ptr + 52.
            let dataPtr := add(pmd, 0x20)
            mstore(add(dataPtr, 52), or(
                and(mload(add(dataPtr, 52)), not(shl(208, 0xffffffffffff))),
                shl(208, shr(208, newValidUntil))
            ))
        }
        userOp.paymasterAndData = pmd;

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_validAfterMutated()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "validafter-binding-next"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        // validAfter at paymasterAndData[58:64].
        bytes memory pmd = userOp.paymasterAndData;
        bytes6 newValidAfter = bytes6(uint48(block.timestamp + 1 hours));
        assembly {
            let dataPtr := add(pmd, 0x20)
            mstore(add(dataPtr, 58), or(
                and(mload(add(dataPtr, 58)), not(shl(208, 0xffffffffffff))),
                shl(208, shr(208, newValidAfter))
            ))
        }
        userOp.paymasterAndData = pmd;

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_paymasterVerificationGasLimitMutated()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "pmvgas-binding-next"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        // paymasterVerificationGasLimit at paymasterAndData[20:36] (uint128).
        bytes memory pmd = userOp.paymasterAndData;
        bytes16 newLimit = bytes16(uint128(999_999));
        assembly {
            let dataPtr := add(pmd, 0x20)
            mstore(add(dataPtr, 20), or(
                and(mload(add(dataPtr, 20)), not(shl(128, sub(shl(128, 1), 1)))),
                shl(128, shr(128, newLimit))
            ))
        }
        userOp.paymasterAndData = pmd;

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_paymasterPostOpGasLimitMutated()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "pmopgas-binding-next"
        );

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );
        // paymasterPostOpGasLimit at paymasterAndData[36:52] (uint128).
        bytes memory pmd = userOp.paymasterAndData;
        bytes16 newLimit = bytes16(uint128(999_999));
        assembly {
            let dataPtr := add(pmd, 0x20)
            mstore(add(dataPtr, 36), or(
                and(mload(add(dataPtr, 36)), not(shl(128, sub(shl(128, 1), 1)))),
                shl(128, shr(128, newLimit))
            ))
        }
        userOp.paymasterAndData = pmd;

        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
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

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            wrongPrivateKey,
            nextPubkey
        );

        vm.recordLogs();
        bool valid = harness.exposed_verifyAndRotate(userOp);
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
        PackedUserOperation memory userOp = _userOpWithRawSig(
            WALLET,
            0,
            "",
            verifierPubkey,
            sig
        );

        vm.recordLogs();
        bool valid = harness.exposed_verifyAndRotate(userOp);
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
        PackedUserOperation memory userOp = _harnessUserOp(
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
        bool valid = harness.exposed_verifyAndRotate(userOp);
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

        PackedUserOperation memory userOp = _harnessUserOp(
            WALLET,
            0,
            "",
            verifierPubkey,
            verifierPrivateKey,
            nextPubkey
        );

        bool valid = harness.exposed_verifyAndRotate(userOp);
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

    /// @dev Half-zero corruption regression for the validation path. If
    ///      `verifiers[wallet]` is half-zero (one field cleared, one set) —
    ///      e.g. from a malformed upgrade, slot collision, or unexpected
    ///      delegatecall — `_verifyAndRotate` MUST short-circuit at the
    ///      "no verifier registered" check rather than progress to WOTS+
    ///      verify against garbage. The `||` check (mirroring
    ///      `setPqVerifier`'s zero invariant) is what makes this happen;
    ///      `&&` would slip through and continue to digest construction.
    function test_exposed_verifyAndRotate_returnsFalseWhen_storageHalfZero_seedCleared()
        public
    {
        bytes32 root = keccak256(
            abi.encode(WALLET, _PAYMASTER_STORAGE_SLOT)
        );
        vm.store(address(harness), root, bytes32(0));

        // Build any well-formed paymasterData (digest/sig don't matter — we
        // expect rejection BEFORE WOTS+ verify).
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "half-zero-seed-cleared-next"
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );
        PackedUserOperation memory userOp = _userOpWithRawSig(
            WALLET,
            0,
            "",
            nextPubkey,
            sig
        );

        vm.expectEmit(address(harness));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET,
            IQuipPaymaster.PaymasterValidationFailure.NoVerifierRegistered
        );
        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_storageHalfZero_hashCleared()
        public
    {
        bytes32 root = keccak256(
            abi.encode(WALLET, _PAYMASTER_STORAGE_SLOT)
        );
        bytes32 hashSlot = bytes32(uint256(root) + 1);
        vm.store(address(harness), hashSlot, bytes32(0));

        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "half-zero-hash-cleared-next"
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );
        PackedUserOperation memory userOp = _userOpWithRawSig(
            WALLET,
            0,
            "",
            nextPubkey,
            sig
        );

        vm.expectEmit(address(harness));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET,
            IQuipPaymaster.PaymasterValidationFailure.NoVerifierRegistered
        );
        bool valid = harness.exposed_verifyAndRotate(userOp);
        assertFalse(valid);
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
        PackedUserOperation memory bOp = _harnessUserOp(
            WALLET_B,
            0,
            "",
            bCurr,
            bCurrPriv,
            bNext
        );
        assertTrue(harness.exposed_verifyAndRotate(bOp));

        // Wallet A now tries to rotate to wallet B's NEW (now-current) key —
        // also blocked, but via the standard "key registered for B" path.
        PackedUserOperation memory aOpToBNext = _harnessUserOp(
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
        assertFalse(harness.exposed_verifyAndRotate(aOpToBNext));

        // Now the more pointed case: wallet A tries to rotate to wallet B's
        // SPENT old key. This is the regression test for "spent keys must
        // stay locked even after the wallet that spent them rotated away."
        PackedUserOperation memory aOpToBSpent = _harnessUserOp(
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
        assertFalse(harness.exposed_verifyAndRotate(aOpToBSpent));
    }
}
