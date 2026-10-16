// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for `validatePaymasterUserOp`. Covers every rejection branch (each precedes
///      `SHRINCS.verifyStateful`, plus the wrong-context `InvalidSignature`) and the sponsorship-
///      success path (including the non-zero validity-window packing) via the dedicated paymaster
///      vectors.
contract ShrincsPaymaster_validatePaymasterUserOp is ShrincsPaymasterTest {
    address internal constant SENDER = address(0xA11CE);

    /// @dev Validates and returns the single emitted `PaymasterValidationRejected` reason.
    function _rejectReason(
        PackedUserOperation memory op
    ) internal returns (uint256 reason, uint256 validationData) {
        vm.recordLogs();
        vm.prank(ENTRY_POINT);
        (, validationData) = paymaster.validatePaymasterUserOp(
            op,
            bytes32(0),
            1 ether
        );
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                IShrincsPaymaster.PaymasterValidationRejected.selector
            ) {
                return (abi.decode(logs[i].data, (uint256)), validationData);
            }
        }
        revert("no PaymasterValidationRejected emitted");
    }

    function test_validate_revertsWhen_notEntryPoint() public {
        PackedUserOperation memory op = _userOp(
            SENDER,
            _pmData(_pk(), _statefulSigWithLeaf(1))
        );
        vm.prank(makeAddr("notEntryPoint"));
        vm.expectRevert(IShrincsPaymaster.InvalidEntryPoint.selector);
        paymaster.validatePaymasterUserOp(op, bytes32(0), 1 ether);
    }

    function test_validate_rejectsMalformedShortPayload() public {
        PackedUserOperation memory op = _userOp(SENDER, new bytes(127)); // < 128 gate
        (uint256 reason, uint256 vd) = _rejectReason(op);
        assertEq(
            reason,
            uint256(
                IShrincsPaymaster.PaymasterValidationFailure.MalformedPayload
            )
        );
        assertEq(vd, 1, "validationData == 1");
    }

    function test_validate_rejectsLeafZero() public {
        PackedUserOperation memory op = _userOp(
            SENDER,
            _pmData(_pk(), _statefulSigWithLeaf(0))
        );
        (uint256 reason, uint256 vd) = _rejectReason(op);
        assertEq(
            reason,
            uint256(
                IShrincsPaymaster
                    .PaymasterValidationFailure
                    .StatefulBudgetExhausted
            )
        );
        assertEq(vd, 1);
        assertEq(paymaster.statefulLeavesUsed(), 0, "no leaf consumed");
    }

    function test_validate_rejectsLeafOverBudget() public {
        PackedUserOperation memory op = _userOp(
            SENDER,
            _pmData(_pk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1))
        );
        (uint256 reason, ) = _rejectReason(op);
        assertEq(
            reason,
            uint256(
                IShrincsPaymaster
                    .PaymasterValidationFailure
                    .StatefulBudgetExhausted
            )
        );
    }

    /// @dev Off-by-one boundary on the budget guard (`leaf > maxSignatures`): leaf == maxSignatures
    ///      is IN budget, so it must clear the budget + stale guards and reach `verifyStateful`. The
    ///      synthetic sig (empty `chains`) fails verification there, so the reason is `InvalidSignature`
    ///      — NOT `StatefulBudgetExhausted`. A `>=` regression would surface here.
    function test_validate_leafAtBudget_reachesVerify() public {
        PackedUserOperation memory op = _userOp(
            SENDER,
            _pmData(_pk(), _statefulSigWithLeaf(MAX_SIG))
        );
        (uint256 reason, uint256 vd) = _rejectReason(op);
        assertEq(
            reason,
            uint256(
                IShrincsPaymaster.PaymasterValidationFailure.InvalidSignature
            ),
            "leaf == maxSignatures passes the budget guard and reaches verify"
        );
        assertEq(vd, 1);
        assertEq(paymaster.statefulLeavesUsed(), 0, "no leaf consumed");
    }

    /// @dev The minimum-length payload that PASSES the `< 128` gate (52 header + 12 window + 0x40
    ///      ABI head). The codec then reads two offset words from an otherwise-empty blob; validation
    ///      must still reject gracefully (return `("", 1)`) rather than revert, and consume no leaf.
    function test_validate_exactly128Bytes_gracefulReject() public {
        PackedUserOperation memory op = _userOp(SENDER, new bytes(128));
        (bytes memory context, uint256 vd) = _validate(op);
        assertEq(vd, 1, "rejected, not authorized");
        assertEq(context.length, 0, "no context on rejection");
        assertEq(paymaster.statefulLeavesUsed(), 0, "no leaf consumed");
    }

    function test_validate_rejectsStaleLeaf() public {
        paymaster.harness_markLeafUsed(1);
        PackedUserOperation memory op = _userOp(
            SENDER,
            _pmData(_pk(), _statefulSigWithLeaf(1))
        );
        (uint256 reason, uint256 vd) = _rejectReason(op);
        assertEq(
            reason,
            uint256(
                IShrincsPaymaster.PaymasterValidationFailure.StaleStatefulLeaf
            )
        );
        assertEq(vd, 1);
    }

    function test_validate_rejectsInvalidSignature() public {
        // Leaf-1 wallet sig: in budget, unused, reaches verify, but bound to the wrong context.
        PackedUserOperation memory op = _userOp(
            SENDER,
            _pmData(_pk(), _wrongContextStatefulSig())
        );
        (uint256 reason, uint256 vd) = _rejectReason(op);
        assertEq(
            reason,
            uint256(
                IShrincsPaymaster.PaymasterValidationFailure.InvalidSignature
            )
        );
        assertEq(vd, 1);
        assertFalse(
            paymaster.isStatefulLeafUsed(1),
            "leaf not consumed on invalid signature"
        );
        assertEq(paymaster.statefulLeavesUsed(), 0, "counter untouched");
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev The budget guard partitions the leaf space exactly: `leaf == 0 || leaf > maxSignatures`
    ///      rejects with `StatefulBudgetExhausted` BEFORE reaching verify; every in-budget leaf clears
    ///      it and (with the synthetic, signature-less blob) fails at verify with `InvalidSignature`.
    ///      Either way validation returns `("", 1)` and consumes nothing.
    function testFuzz_validate_budgetGuardPartition(uint256 leaf) public {
        leaf = bound(leaf, 0, uint256(MAX_SIG) * 4); // span both sides of the boundary
        PackedUserOperation memory op = _userOp(
            SENDER,
            _pmData(_pk(), _statefulSigWithLeaf(leaf))
        );
        (uint256 reason, uint256 vd) = _rejectReason(op);
        if (leaf == 0 || leaf > MAX_SIG) {
            assertEq(
                reason,
                uint256(
                    IShrincsPaymaster
                        .PaymasterValidationFailure
                        .StatefulBudgetExhausted
                ),
                "out-of-budget leaf rejected before verify"
            );
        } else {
            assertEq(
                reason,
                uint256(
                    IShrincsPaymaster
                        .PaymasterValidationFailure
                        .InvalidSignature
                ),
                "in-budget leaf reaches verify"
            );
        }
        assertEq(vd, 1);
        assertEq(
            paymaster.statefulLeavesUsed(),
            0,
            "no leaf consumed on any rejection"
        );
    }

    /* ──────────────────────── sponsorship success ──────────────────────────── */

    function test_validate_succeeds() public {
        (PackedUserOperation memory op, uint32 leaf) = _sponsorUserOp(0);
        (bytes memory context, uint256 vd) = _validate(op);
        assertEq(vd, 0, "authorizer success, no validity window");
        assertEq(
            abi.decode(context, (address)),
            SPONSOR_SENDER,
            "context encodes sender"
        );
        assertTrue(paymaster.isStatefulLeafUsed(leaf), "leaf consumed");
        assertEq(paymaster.statefulLeavesUsed(), 1, "counter incremented");
    }

    function test_validate_succeeds_emitsSponsorshipVerified() public {
        (PackedUserOperation memory op, uint32 leaf) = _sponsorUserOp(0);
        vm.recordLogs();
        _validate(op);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                IShrincsPaymaster.SponsorshipVerified.selector
            ) {
                found = true;
                assertEq(
                    address(uint160(uint256(logs[i].topics[1]))),
                    SPONSOR_SENDER,
                    "wallet indexed"
                );
                (uint32 evLeaf, ) = abi.decode(logs[i].data, (uint32, uint256));
                assertEq(evLeaf, leaf, "leaf in event");
            }
        }
        assertTrue(found, "SponsorshipVerified emitted");
    }

    function test_validate_succeeds_replayRejected() public {
        // A consumed leaf cannot be reused (the bitmap blocks it).
        (PackedUserOperation memory op, ) = _sponsorUserOp(0);
        (, uint256 vd1) = _validate(op);
        assertEq(vd1, 0, "first use succeeds");
        (uint256 reason, uint256 vd2) = _rejectReason(op);
        assertEq(
            reason,
            uint256(
                IShrincsPaymaster.PaymasterValidationFailure.StaleStatefulLeaf
            )
        );
        assertEq(vd2, 1, "replay rejected");
    }

    /// @dev A sponsorship signed over a NON-ZERO validity window: `validationData` must pack
    ///      `(validUntil << 160) | (validAfter << 208)` with the authorizer (low 160 bits) zero. The
    ///      two bounds are distinct, so a transposed shift or swapped byte slice would diverge here.
    ///      This is the only path that exercises the window packing with non-zero values.
    function test_validate_succeeds_packsValidityWindow() public {
        (
            PackedUserOperation memory op,
            uint48 validUntil,
            uint48 validAfter,
            uint32 leaf
        ) = _sponsorWithWindowUserOp();
        assertTrue(validUntil != validAfter, "window bounds are distinct");

        (bytes memory context, uint256 vd) = _validate(op);

        uint256 expected = (uint256(validUntil) << 160) |
            (uint256(validAfter) << 208);
        assertEq(
            vd,
            expected,
            "validationData == validUntil<<160 | validAfter<<208"
        );
        assertEq(uint160(vd), 0, "authorizer (low 160 bits) is success/zero");
        assertEq(
            uint48(vd >> 160),
            validUntil,
            "validUntil decoded from bits [160:208)"
        );
        assertEq(
            uint48(vd >> 208),
            validAfter,
            "validAfter decoded from bits [208:256)"
        );
        assertEq(abi.decode(context, (address)), SPONSOR_SENDER);
        assertTrue(paymaster.isStatefulLeafUsed(leaf), "leaf consumed");
    }

    /* ───────────────────── NESTED ABI FRAMING (never-revert) ───────────────────── */

    /// @dev Bytes of `paymasterAndData` before the sponsorship blob: the 52-byte ERC-4337
    ///      header (paymaster, gas limits) plus `validUntil`/`validAfter` (mirrors the contract's
    ///      `_PAYMASTER_DATA_OFFSET + _CUSTOM_SIG_OFFSET`).
    uint256 internal constant BLOB_OFFSET = 52 + 12;

    /// @dev The codec bounds-checks only the blob's TOP-LEVEL tail offsets; a NESTED offset (inside
    ///      the PublicKey / Signature tails) that runs past calldatasize trips Solidity's own
    ///      calldata bounds check at `_leafIndex` / `abi.encode(pk, sig)`. Those reads run behind
    ///      the `sponsorshipEnvelope` self-staticcall, so the revert maps to `validationData == 1`
    ///      + `MalformedPayload` like every other rejection (INVARIANTS §19) — reachable by anyone
    ///      (no co-signature on the sponsorship blob). Inside the self-call the blob is the whole
    ///      calldata, so this also pins the tightened bound: an `authPath` offset whose length word
    ///      is the LAST word of the blob is still read (garbage leaf -> graceful
    ///      `StatefulBudgetExhausted`); one byte further is `MalformedPayload`, including the
    ///      offsets that previously resolved into the adjacent `userOp.signature` field.
    function test_validate_softFails_onCorruptedNestedOffset() public {
        bytes memory pmData = _pmData(_pk(), _statefulSigWithLeaf(1));
        PackedUserOperation memory op = _userOp(SENDER, pmData);
        bytes memory outer = abi.encodeCall(paymaster.validatePaymasterUserOp, (op, bytes32(0), 1 ether));

        // `paymasterAndData` is the second-to-last tail; the empty `signature` length word follows it.
        assertEq(pmData.length % 0x20, 0, "pmData word-aligned (layout assumption)");
        uint256 pmStart = outer.length - 0x20 - pmData.length;
        assertEq(keccak256(_slice(outer, pmStart, pmData.length)), keccak256(pmData), "located pmData");

        uint256 blobLen = pmData.length - BLOB_OFFSET;
        uint256 sigOff = _wordAt(pmData, BLOB_OFFSET + 0x20); // blob head word 1: Signature tail
        uint256 authPathWord = BLOB_OFFSET + sigOff + 0x60; // 4th head word of the Signature tail
        uint256 lastBlobWordRel = blobLen - sigOff - 0x20; // length word == last word of the blob
        uint256 lastOuterWordRel = outer.length - 0x20 - (pmStart + BLOB_OFFSET + sigOff); // last word of OUTER calldata

        // (a) length word == last word of the blob: read (it is authPath[0] == 0), graceful reject.
        _setWordAt(pmData, authPathWord, lastBlobWordRel);
        op.paymasterAndData = pmData;
        (uint256 reason, uint256 vd) = _rejectReason(op);
        assertEq(reason, uint256(IShrincsPaymaster.PaymasterValidationFailure.StatefulBudgetExhausted));
        assertEq(vd, 1);

        // (b) one byte past the blob: soft `MalformedPayload`.
        _setWordAt(pmData, authPathWord, lastBlobWordRel + 1);
        op.paymasterAndData = pmData;
        _assertMalformed(op, "one byte past blob");

        // (c) the last word of the OUTER calldata (the adjacent `userOp.signature` length word):
        // readable before the self-call boundary existed, `MalformedPayload` now.
        _setWordAt(pmData, authPathWord, lastOuterWordRel);
        op.paymasterAndData = pmData;
        _assertMalformed(op, "adjacent outer calldata no longer readable");

        // (d) far out of range, from any caller's blob.
        _setWordAt(pmData, authPathWord, 1 << 64);
        op.paymasterAndData = pmData;
        _assertMalformed(op, "offset 2^64");

        assertEq(paymaster.statefulLeavesUsed(), 0, "nothing consumed");
    }

    /// @dev A TOP-LEVEL offset past the blob (the codec's own `MalformedPayload` revert) is
    ///      contained by the same self-staticcall: soft fail, not a hard revert.
    function test_validate_softFails_onCorruptedTopLevelOffset() public {
        bytes memory pmData = _pmData(_pk(), _statefulSigWithLeaf(1));
        _setWordAt(pmData, BLOB_OFFSET, 1 << 64); // blob head word 0: PublicKey tail offset
        PackedUserOperation memory op = _userOp(SENDER, pmData);
        _assertMalformed(op, "top-level pk offset 2^64");
        assertEq(paymaster.statefulLeavesUsed(), 0, "nothing consumed");
    }

    /// @dev Never-revert over the whole nested head-word space: ANY value in ANY of the six nested
    ///      head words yields a return, never a revert (in-range garbage decodes a different
    ///      struct and fails verification; out-of-range is `MalformedPayload`).
    function testFuzz_validate_neverReverts_onAnyNestedHeadWord(uint8 slot, uint256 value) public {
        slot = uint8(bound(slot, 0, 5));
        bytes memory pmData = _pmData(_pk(), _statefulSigWithLeaf(1));
        (uint256 at, ) = _nestedHeadWord(pmData, slot);
        _setWordAt(pmData, at, value);
        PackedUserOperation memory op = _userOp(SENDER, pmData);

        (, uint256 vd) = _rejectReason(op);
        assertEq(vd, 1, "rejected, never reverted");
        assertEq(paymaster.statefulLeavesUsed(), 0, "nothing consumed");
    }

    /// @dev Auditor-requested case: an otherwise well-formed blob whose nested tail offset lands
    ///      anywhere past the blob's own end is handled gracefully as `MalformedPayload`.
    ///      Covers every offset solc treats as positive: its tail check is a SIGNED comparison
    ///      (`slt(offset, calldatasize - base - 31)`), so the reverting range is
    ///      (blobLen - base - 0x20, 2^255). See the `_onSignedNegativeNestedOffset` twin for the
    ///      upper half.
    function testFuzz_validate_malformed_onNestedOffsetPastBlob(uint8 slot, uint256 overrun) public {
        slot = uint8(bound(slot, 0, 5));
        bytes memory pmData = _pmData(_pk(), _statefulSigWithLeaf(1));
        (uint256 at, uint256 base) = _nestedHeadWord(pmData, slot);
        // A head word `v` at struct base `base` (blob-relative) points at a length word occupying
        // [base + v, base + v + 0x20); it is past the blob iff v > blobLen - base - 0x20.
        uint256 inRangeMax = (pmData.length - BLOB_OFFSET) - base - 0x20;
        overrun = bound(overrun, 1, (uint256(1) << 255) - 1 - inRangeMax);
        _setWordAt(pmData, at, inRangeMax + overrun);
        PackedUserOperation memory op = _userOp(SENDER, pmData);

        _assertMalformed(op, "nested offset past blob end");
        assertEq(paymaster.statefulLeavesUsed(), 0, "nothing consumed");
    }

    /// @dev Offsets >= 2^255 read as NEGATIVE in solc's signed tail check, so they pass it and
    ///      `add(base, offset)` wraps to a BACKWARD pointer: the field decodes from earlier bytes
    ///      of the same calldata (or as empty, when the wrapped address is past calldatasize and
    ///      `calldataload` returns zeros). Inside the self-call that calldata is just the blob and
    ///      its 0x44-byte call prefix, so the alias is confined to bytes the submitter already
    ///      controls; the garbage struct then fails the leaf guards or verification. Pinned:
    ///      never a revert, never a consumed leaf, never a pass.
    function testFuzz_validate_neverReverts_onSignedNegativeNestedOffset(uint8 slot, uint256 value) public {
        slot = uint8(bound(slot, 0, 5));
        value = bound(value, uint256(1) << 255, type(uint256).max);
        bytes memory pmData = _pmData(_pk(), _statefulSigWithLeaf(1));
        (uint256 at, ) = _nestedHeadWord(pmData, slot);
        _setWordAt(pmData, at, value);
        PackedUserOperation memory op = _userOp(SENDER, pmData);

        (, uint256 vd) = _rejectReason(op);
        assertEq(vd, 1, "rejected, never reverted");
        assertEq(paymaster.statefulLeavesUsed(), 0, "nothing consumed");
    }

    /// @dev Asserts a soft fail carrying the `MalformedPayload` reason.
    function _assertMalformed(PackedUserOperation memory op, string memory name) internal {
        (uint256 reason, uint256 vd) = _rejectReason(op);
        assertEq(reason, uint256(IShrincsPaymaster.PaymasterValidationFailure.MalformedPayload), name);
        assertEq(vd, 1, name);
    }

    /// @dev `paymasterAndData` position of the `slot`-th nested head word and the blob-relative
    ///      base of the struct it belongs to: PublicKey `statefulPublicKey` / `publicKeyCommitment`
    ///      / `pkSeed` / `hypertreeRoot` offsets (slots 0..3, at pk + 0x00..0x60) and Signature
    ///      `chains` / `authPath` offsets (slots 4..5, at sig + 0x40 / 0x60).
    function _nestedHeadWord(bytes memory pmData, uint8 slot) internal pure returns (uint256 at, uint256 base) {
        uint256 pkOff = _wordAt(pmData, BLOB_OFFSET);
        uint256 sigOff = _wordAt(pmData, BLOB_OFFSET + 0x20);
        if (slot < 4) return (BLOB_OFFSET + pkOff + 0x20 * slot, pkOff);
        return (BLOB_OFFSET + sigOff + 0x40 + 0x20 * (slot - 4), sigOff);
    }

    function _wordAt(bytes memory b, uint256 at) internal pure returns (uint256 w) {
        assembly {
            w := mload(add(add(b, 0x20), at))
        }
    }

    function _setWordAt(bytes memory b, uint256 at, uint256 w) internal pure {
        assembly {
            mstore(add(add(b, 0x20), at), w)
        }
    }

    function _slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) {
            out[i] = b[start + i];
        }
    }
}
