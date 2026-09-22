// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the ERC-4337 `_validateSignature` stateful path, driven by live-signed
///      erc4337-context signatures.
contract ShrincsWallet__validateSignature is ShrincsWalletTest {
    /// @dev A userOp signed at `leaf` over a synthetic-but-fixed userOpHash, with the owner's
    ///      ECDSA co-signature over the same hash (the hybrid blob).
    function _erc4337Op(uint32 leaf) internal view returns (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) {
        userOpHash = keccak256(abi.encodePacked("erc4337-userop", leaf));
        SHRINCS.Signature memory sig = _signErc4337(userOpHash, leaf);
        op = _makeUserOp(_userOpBlob(sig, userOpHash));
    }

    // NOTE: every signature binds the LIVE wrapper nonce, so consuming any signature supersedes
    // all outstanding ones — ops are strictly serialized by signing order. The used-leaf bitmap
    // remains the OTS-reuse guard; leaf indices themselves may still be consumed in any order
    // (see `test_validateSignature_outOfOrderLeaves`).

    function test_validateSignature_validLeafOne() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        uint256 result = wallet.exposed_validateSignature(op, userOpHash);
        assertEq(result, 0, "valid leaf-1 signature should pass");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 marked consumed");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
        assertEq(wallet.actionNonce(), 1, "consumed signature advances the wrapper nonce");
    }

    /// @dev The real EntryPoint path end to end: `validateUserOp` (not just the exposed
    ///      internal core) must accept a valid op. This is the only coverage of the envelope
    ///      plumbing — the try/catch decode whose result feeds verification.
    function test_validateSignature_entrypointAcceptsValidOp() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, userOpHash, 0);
        assertEq(result, 0, "entrypoint validation accepts a valid op");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 marked consumed");
    }

    function test_validateSignature_revertsWhen_replayConsumedLeaf() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0, "first use passes");
        // Re-presenting the same consumed leaf is rejected by the bitmap (anti-replay).
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "replayed leaf must be rejected");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter unchanged on rejection");
    }

    function test_validateSignature_revertsWhen_leafAlreadyUsed() public {
        // Pre-mark leaf 1 consumed; an otherwise-valid leaf-1 op must then be rejected.
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "already-consumed leaf must be rejected");
    }

    function test_validateSignature_revertsWhen_wrongUserOpHash() public {
        // Both halves signed over the op's own hash, validated against a different one:
        // rejected at the ECDSA gate (it runs first), leaf untouched.
        (ERC4337.PackedUserOperation memory op,) = _erc4337Op(1);
        uint256 result = wallet.exposed_validateSignature(op, keccak256("not-the-signed-hash"));
        assertEq(result, 1, "wrong message must be rejected");
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed on rejection");
    }

    function test_validateSignature_revertsWhen_badSignatureLength() public {
        ERC4337.PackedUserOperation memory op = _makeUserOp(hex"1234");
        uint256 result = wallet.exposed_validateSignature(op, keccak256("x"));
        assertEq(result, 1, "short signature must be rejected");
    }

    /* ─────────────── rejection-reason discrimination (UserOpValidationRejected) ─────────────── */

    /// @dev Returns the `reason` of the first `UserOpValidationRejected` event in the recorded logs.
    function _lastRejectionReason() internal returns (uint256) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IShrincsWallet.UserOpValidationRejected.selector) {
                return uint256(logs[i].topics[1]);
            }
        }
        revert("no UserOpValidationRejected emitted");
    }

    function test_validateSignature_reason_badSignatureLength() public {
        vm.recordLogs();
        wallet.exposed_validateSignature(_makeUserOp(hex"1234"), keccak256("x"));
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.BadSignatureLength));
    }

    function test_validateSignature_reason_leafZero() public {
        // Valid co-signature so the op clears the ECDSA gate and reaches the leaf guard.
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(_userOpBlob(_statefulSigWithLeaf(0), keccak256("x")));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, keccak256("x")), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.StatefulBudgetExhausted));
    }

    function test_validateSignature_reason_leafOverBudget() public {
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(_userOpBlob(_statefulSigWithLeaf(uint256(MAX_SIG) + 1), keccak256("x")));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, keccak256("x")), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.StatefulBudgetExhausted));
    }

    function test_validateSignature_reason_staleLeaf() public {
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.StaleStatefulLeaf));
    }

    function test_validateSignature_reason_invalidSignature() public {
        // Co-sign the VALIDATED hash but SHRINCS-sign a different one: the ECDSA gate passes
        // and the SHRINCS verify is what fails.
        bytes32 validatedHash = keccak256("not-the-signed-hash");
        SHRINCS.Signature memory sig = _signErc4337(keccak256("some-other-hash"), 1);
        ERC4337.PackedUserOperation memory op = _makeUserOp(_userOpBlob(sig, validatedHash));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, validatedHash), 1);
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidSignature));
    }

    /* ─────────────── hybrid gate: the owner ECDSA co-signature (matrix) ─────────────── */

    function test_validateSignature_reason_invalidEcdsa_wrongSigner() public {
        // A perfectly valid SHRINCS signature co-signed by a NON-owner key must be rejected
        // BEFORE any SHRINCS work: leaf unconsumed, nonce unchanged. This is the hybrid gate —
        // a stolen SHRINCS key alone cannot pass validation.
        bytes32 userOpHash = keccak256("wrong-signer-op");
        (, uint256 malloryPk) = makeAddrAndKey("mallory");
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(malloryPk, wallet.quipUserOpHashEcdsaTarget(userOpHash));
        ERC4337.PackedUserOperation memory op = _makeUserOp(
            abi.encode(_mainPk(), _signErc4337(userOpHash, 1), abi.encodePacked(r, s, v))
        );
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "non-owner co-signer rejected");
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidEcdsaSignature));
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed on ECDSA rejection");
        assertEq(wallet.actionNonce(), 0, "nonce unchanged on ECDSA rejection");
    }

    function test_validateSignature_reason_invalidEcdsa_missing() public {
        // An empty co-signature decodes cleanly but recovers address(0).
        bytes32 userOpHash = keccak256("missing-cosig-op");
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(abi.encode(_mainPk(), _signErc4337(userOpHash, 1), bytes("")));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "missing co-signature rejected");
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidEcdsaSignature));
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed");
    }

    function test_validateSignature_reason_invalidEcdsa_malformed() public {
        // 65 garbage bytes: tryRecover yields address(0) or a non-owner address.
        bytes32 userOpHash = keccak256("malformed-cosig-op");
        bytes memory garbage = new bytes(65);
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(abi.encode(_mainPk(), _signErc4337(userOpHash, 1), garbage));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "malformed co-signature rejected");
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidEcdsaSignature));
    }

    function test_validateSignature_reason_invalidEcdsa_erc1271DomainSignature() public {
        // THE domain-separation property: the owner's ERC-1271 message signature over the same
        // 32 bytes must NOT double as the userOp co-signature — the two EIP-712 typehashes are
        // deliberately distinct, so a dApp-harvested `QuipSignedHash` signature is useless here.
        bytes32 userOpHash = keccak256("cross-domain-op");
        bytes memory erc1271Sig = _ownerEcdsa(userOpHash); // signs QuipSignedHash(hash), not QuipUserOpHash
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(abi.encode(_mainPk(), _signErc4337(userOpHash, 1), erc1271Sig));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "1271-domain signature rejected");
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidEcdsaSignature));
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed");
    }

    function test_validateSignature_legacyTwoTupleBlob_rejected() public {
        // The pre-co-signature blob shape `abi.encode(pk, sig)` passes the length floor but its
        // third head word is struct-tail data, yielding a garbage ecdsaSig that cannot recover
        // the owner. Legacy blobs die at the ECDSA gate, never at the SHRINCS verify.
        bytes32 userOpHash = keccak256("legacy-blob-op");
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(abi.encode(_mainPk(), _signErc4337(userOpHash, 1)));
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "legacy 2-tuple blob rejected");
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidEcdsaSignature));
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed");
    }

    function test_validateSignature_success_advancesActionNonce() public {
        assertEq(wallet.actionNonce(), 0);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0);
        assertEq(wallet.actionNonce(), 1, "consumed signature advances the action nonce");
    }

    function test_validateSignature_outOfOrderLeaves() public {
        // Leaf indices carry no ordering constraint: a higher leaf (3) may be consumed before a
        // lower one (2). Each op is signed against the live nonce AFTER the previous one landed —
        // leaf order is independent of nonce order, but signing order is strict.
        (ERC4337.PackedUserOperation memory op3, bytes32 h3) = _erc4337Op(3);
        assertEq(wallet.exposed_validateSignature(op3, h3), 0, "higher leaf lands first");
        (ERC4337.PackedUserOperation memory op2, bytes32 h2) = _erc4337Op(2);
        assertEq(wallet.exposed_validateSignature(op2, h2), 0, "lower leaf accepted after");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 3), "leaf 3 consumed");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 2), "leaf 2 consumed");
        assertEq(wallet.statefulLeavesUsed(), 2, "two leaves consumed");
    }

    /* ─────────────── ERC-7562: validation is fee-independent and call-free ─────────────── */

    /// @dev The digest no longer binds the factory fee: a fee change AFTER signing must not
    ///      affect validation (the signer's ceiling lives in `callData` under userOpHash, and is
    ///      enforced in the execution phase instead).
    function test_validateSignature_unaffectedByFeeChange() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        _setExecuteFee(123456789); // moved between signing and validation
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0, "fee change cannot break validation");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf consumed normally");
    }

    /// @dev THE regression guard for ERC-7562 finding F-1: the validation frame must perform no
    ///      factory call at all. `executeFee()` is mocked to revert — if validation ever regains
    ///      a `getExecuteFee()` read (an STO-033 violation conformant bundlers reject), this test
    ///      fails loudly instead of the violation resurfacing at bundler rollout.
    function test_validateSignature_noFactoryRead() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        vm.mockCallRevert(
            address(factory),
            abi.encodeWithSignature("executeFee()"),
            "factory read during validation"
        );
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0, "validation must not touch the factory");
        vm.clearMockedCalls();
    }

    function test_validateSignature_rejectsStaleNonce() public {
        // Both ops signed against the SAME live nonce (0); after the first lands, the second is
        // superseded — rejected as InvalidSignature with its leaf NOT consumed.
        (ERC4337.PackedUserOperation memory op1, bytes32 h1) = _erc4337Op(1);
        (ERC4337.PackedUserOperation memory op2, bytes32 h2) = _erc4337Op(2);
        assertEq(wallet.exposed_validateSignature(op1, h1), 0, "first op lands");

        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op2, h2), 1, "stale-nonce op rejected");
        assertEq(_lastRejectionReason(), uint256(IShrincsWallet.UserOpValidationFailure.InvalidSignature));
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 2), "superseded op's leaf not consumed");
        assertEq(wallet.actionNonce(), 1, "nonce unchanged by the rejection");
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev A synthetic signature (correct `authPath.length`, no real crypto) can never verify, so
    ///      `_validateSignature` must return 1 (reject) for ANY leaf and userOpHash — never 0 — and
    ///      must never consume a leaf. Exercises the guard + verify-fail branches without a real sig.
    function testFuzz_validateSignature_rejectsSyntheticSignature(uint256 leaf, bytes32 userOpHash) public {
        leaf = bound(leaf, 0, 512); // `_statefulSigWithLeaf` allocates `new bytes32[](leaf)`
        // Valid co-signature: the rejection must come from the leaf guards / SHRINCS verify.
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(_userOpBlob(_statefulSigWithLeaf(leaf), userOpHash));

        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "synthetic signature always rejected");
        assertEq(wallet.statefulLeavesUsed(), 0, "no leaf consumed on rejection");
        if (leaf >= 1 && leaf <= MAX_SIG) {
            assertFalse(wallet.isStatefulLeafUsed(leaf), "in-budget leaf not consumed on verify-fail");
        }
    }


    /* ───────────────────── NESTED ABI FRAMING (never-revert) ───────────────────── */

    /// @dev The codec bounds-checks only a blob's TOP-LEVEL tail offsets; a NESTED offset (inside
    ///      the PublicKey / Signature tails) that runs past calldatasize trips Solidity's own
    ///      calldata bounds check at `_leafIndex` / `abi.encode(pk, sig)`. Both reads run behind
    ///      the `userOpEnvelope` self-staticcall, so the revert maps to `validationData == 1` +
    ///      `MalformedSignature` like every other rejection (INVARIANTS §19). Reachable by
    ///      replaying a legit blob (the owner co-signature bytes are reusable) with its internals
    ///      corrupted; nothing is consumed.
    function test_validateSignature_softFails_onCorruptedNestedOffset() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        bytes memory legit = op.signature;
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0, "legit op passes");
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "untouched replay soft-fails");

        uint256 pkOff = _word(legit, 0x00);
        uint256 sigOff = _word(legit, 0x20);

        // Signature tail, 4th head word: `authPath` offset -> would revert at `_leafIndex`.
        op.signature = _clone(legit);
        _setWord(op.signature, sigOff + 0x60, 1 << 64);
        _assertMalformed(op, userOpHash, "authPath offset 2^64");

        // PublicKey tail, 1st head word: `statefulPublicKey` offset -> would revert in the
        // re-encode. Framing is checked before the leaf guards, so even on the consumed op this
        // reports MalformedSignature rather than being masked by the stale-leaf branch.
        op.signature = _clone(legit);
        _setWord(op.signature, pkOff, 1 << 64);
        _assertMalformed(op, userOpHash, "pk offset 2^64");

        // Exact edge: inside the self-call the blob is the whole calldata, so an offset whose
        // length word starts one byte past the blob is one byte past calldatasize.
        op.signature = _clone(legit);
        _setWord(op.signature, pkOff, legit.length - pkOff - 0x20 + 1);
        _assertMalformed(op, userOpHash, "pk offset 1 byte past blob");

        // Same corruption on a FRESH (unconsumed, e.g. mempool-observed) op: still a soft fail,
        // and the fresh leaf stays untouched.
        (ERC4337.PackedUserOperation memory fresh, bytes32 freshHash) = _erc4337Op(2);
        _setWord(fresh.signature, _word(fresh.signature, 0x00), 1 << 64);
        _assertMalformed(fresh, freshHash, "fresh op pk offset 2^64");

        assertEq(wallet.statefulLeavesUsed(), 1, "only the legit op consumed a leaf");
        assertEq(wallet.actionNonce(), 1, "only the legit op advanced the nonce");
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 2), "fresh op's leaf untouched");
    }

    /// @dev Framing precedes the ECDSA gate: a corrupted nested offset is reported as
    ///      `MalformedSignature` even when the co-signature is garbage too.
    function test_validateSignature_corruptedNestedOffset_reportedBeforeEcdsa() public {
        bytes32 userOpHash = keccak256("no-cosig");
        bytes memory blob = abi.encode(_mainPk(), _signErc4337(userOpHash, 1), new bytes(65));
        _setWord(blob, _word(blob, 0x20) + 0x60, 1 << 64);
        ERC4337.PackedUserOperation memory op = _makeUserOp(blob);
        _assertMalformed(op, userOpHash, "malformed before ecdsa");
        assertEq(wallet.statefulLeavesUsed(), 0, "nothing consumed");
    }

    /// @dev A TOP-LEVEL offset past the blob (the codec's own `MalformedPayload` revert) is
    ///      contained by the same self-staticcall: soft fail, not a hard revert.
    function test_validateSignature_softFails_onCorruptedTopLevelOffset() public {
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        _setWord(op.signature, 0x00, 1 << 64);
        _assertMalformed(op, userOpHash, "top-level pk offset 2^64");
        assertEq(wallet.statefulLeavesUsed(), 0, "nothing consumed");
    }

    /// @dev Never-revert over the whole nested head-word space: ANY value in ANY of the six nested
    ///      head words (four PublicKey `bytes` offsets, the Signature `chains` / `authPath`
    ///      offsets) yields a return, never a revert. An in-range garbage offset decodes a
    ///      different struct and fails verification; an out-of-range one is `MalformedSignature`.
    function testFuzz_validateSignature_neverReverts_onAnyNestedHeadWord(uint8 slot, uint256 value) public {
        slot = uint8(bound(slot, 0, 5));
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        (uint256 at, ) = _nestedHeadWord(op.signature, slot);
        uint256 original = _word(op.signature, at);
        _setWord(op.signature, at, value);

        uint256 result = wallet.exposed_validateSignature(op, userOpHash);
        if (value == original) {
            assertEq(result, 0, "unchanged blob still validates");
        } else {
            assertEq(result, 1, "any corrupted nested head word soft-fails");
            assertEq(wallet.statefulLeavesUsed(), 0, "nothing consumed");
            assertEq(wallet.actionNonce(), 0, "nonce untouched");
        }
    }

    /// @dev Auditor-requested case: an otherwise well-formed blob whose nested tail offset lands
    ///      anywhere past the blob's own end is handled gracefully as `MalformedSignature`.
    ///      Covers every offset solc treats as positive: its tail check is a SIGNED comparison
    ///      (`slt(offset, calldatasize - base - 31)`), so the reverting range is
    ///      (blob.length - base - 0x20, 2^255). See the `_onSignedNegativeNestedOffset` twin for
    ///      the upper half.
    function testFuzz_validateSignature_malformed_onNestedOffsetPastBlob(uint8 slot, uint256 overrun) public {
        slot = uint8(bound(slot, 0, 5));
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        (uint256 at, uint256 base) = _nestedHeadWord(op.signature, slot);
        // A head word `v` at struct base `base` points at a length word occupying
        // [base + v, base + v + 0x20); it is past the blob iff v > blob.length - base - 0x20.
        uint256 inRangeMax = op.signature.length - base - 0x20;
        overrun = bound(overrun, 1, (uint256(1) << 255) - 1 - inRangeMax);
        _setWord(op.signature, at, inRangeMax + overrun);

        _assertMalformed(op, userOpHash, "nested offset past blob end");
        assertEq(wallet.statefulLeavesUsed(), 0, "nothing consumed");
        assertEq(wallet.actionNonce(), 0, "nonce untouched");
    }

    /// @dev Offsets >= 2^255 read as NEGATIVE in solc's signed tail check, so they pass it and
    ///      `add(base, offset)` wraps to a BACKWARD pointer: the field decodes from earlier bytes
    ///      of the same calldata (or as empty, when the wrapped address is past calldatasize and
    ///      `calldataload` returns zeros). Inside the self-call that calldata is just the blob and
    ///      its 0x44-byte call prefix, so the alias is confined to bytes the submitter already
    ///      controls; the garbage struct then fails the leaf guards or verification. Pinned:
    ///      never a revert, never a consumed leaf, never a pass.
    function testFuzz_validateSignature_neverReverts_onSignedNegativeNestedOffset(uint8 slot, uint256 value) public {
        slot = uint8(bound(slot, 0, 5));
        value = bound(value, uint256(1) << 255, type(uint256).max);
        (ERC4337.PackedUserOperation memory op, bytes32 userOpHash) = _erc4337Op(1);
        (uint256 at, ) = _nestedHeadWord(op.signature, slot);
        _setWord(op.signature, at, value);

        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "rejected, never reverted");
        assertEq(wallet.statefulLeavesUsed(), 0, "nothing consumed");
        assertEq(wallet.actionNonce(), 0, "nonce untouched");
    }

    /// @dev Asserts a soft fail carrying the `MalformedSignature` reason.
    function _assertMalformed(
        ERC4337.PackedUserOperation memory op,
        bytes32 userOpHash,
        string memory name
    ) internal {
        vm.recordLogs();
        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, name);
        assertEq(
            _lastRejectionReason(),
            uint256(IShrincsWallet.UserOpValidationFailure.MalformedSignature),
            name
        );
    }

    /// @dev Blob position of the `slot`-th nested head word and the base of the struct it belongs
    ///      to: PublicKey `statefulPublicKey` / `publicKeyCommitment` / `pkSeed` / `hypertreeRoot`
    ///      offsets (slots 0..3, at pk + 0x00..0x60) and Signature `chains` / `authPath` offsets
    ///      (slots 4..5, at sig + 0x40 / 0x60, after `randomizer` and `counter`).
    function _nestedHeadWord(bytes memory blob, uint8 slot) internal pure returns (uint256 at, uint256 base) {
        uint256 pkOff = _word(blob, 0x00);
        uint256 sigOff = _word(blob, 0x20);
        if (slot < 4) return (pkOff + 0x20 * slot, pkOff);
        return (sigOff + 0x40 + 0x20 * (slot - 4), sigOff);
    }

    function _word(bytes memory b, uint256 at) internal pure returns (uint256 w) {
        assembly {
            w := mload(add(add(b, 0x20), at))
        }
    }

    function _setWord(bytes memory b, uint256 at, uint256 w) internal pure {
        assembly {
            mstore(add(add(b, 0x20), at), w)
        }
    }

    function _clone(bytes memory b) internal pure returns (bytes memory) {
        return abi.encodePacked(b);
    }
}
