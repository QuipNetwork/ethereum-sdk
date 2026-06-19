// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

/// @title QuipPaymaster.validatePaymasterUserOp — length-gate regression
/// @dev Pins the protocol-layout length check that runs BEFORE
///      `_verifyAndRotate`. The assembly slices inside `_verifyAndRotate`
///      trust `paymasterAndData.length == _PAYMASTER_AND_DATA_LEN` —
///      under-length data would either revert with an opaque panic on
///      out-of-bounds calldata reads or, if the slice happens to align,
///      silently produce a wrong digest. The early-return path returning
///      `validationData = 1` with a `PaymasterValidationRejected(...,
///      MalformedPayload)` event is what keeps that gate honest.
///
///      Covers `_PAYMASTER_AND_DATA_LEN = 2272`.
contract QuipPaymaster_validatePaymasterUserOp_lengthGate is QuipPaymasterTest {
    uint256 private constant _PAYMASTER_AND_DATA_LEN = 2272;

    /// @dev Drive `validatePaymasterUserOp` with `paymasterAndData` of the
    ///      given length, asserting:
    ///        - the call does not revert (early-return path taken)
    ///        - `validationData == 1` (SIG_VALIDATION_FAILED sentinel)
    ///        - exactly one `PaymasterValidationRejected(sender,
    ///          MalformedPayload)` event was emitted
    function _assertRejectsLength(uint256 len) internal {
        bytes memory pmd = new bytes(len);
        // Prefix the paymaster address in slots [0:20) so the EntryPoint
        // would correctly route to this paymaster if the call happened —
        // the length gate is the only thing that should be observed.
        if (len >= 20) {
            address pm = address(paymaster);
            assembly {
                let dst := add(pmd, 32)
                let val := shl(96, pm)
                mstore(dst, or(and(mload(dst), not(shl(96, sub(shl(160, 1), 1)))), val))
            }
        }
        PackedUserOperation memory userOp = _mockUserOp(pmd);

        vm.recordLogs();
        vm.prank(ENTRY_POINT);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);

        assertEq(context.length, 0, "context must be empty on length reject");
        assertEq(validationData, 1, "validationData must be SIG_VALIDATION_FAILED");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        // Find a PaymasterValidationRejected event whose `reason` is
        // MalformedPayload (enum value 0). Other events emitted during
        // validation paths are not relevant here — but the rejection event
        // MUST be present exactly once.
        bytes32 rejectedTopic = IQuipPaymaster.PaymasterValidationRejected.selector;
        uint256 hits;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics.length == 0) continue;
            if (logs[i].topics[0] != rejectedTopic) continue;
            // topics[1] = wallet (indexed), topics[2] = reason (indexed enum)
            assertEq(
                uint256(logs[i].topics[2]),
                uint256(IQuipPaymaster.PaymasterValidationFailure.MalformedPayload),
                "reason must be MalformedPayload"
            );
            ++hits;
        }
        assertEq(hits, 1, "exactly one MalformedPayload rejection event");
    }

    /// Zero-length: there isn't even a paymaster address in the slice. The
    /// length gate must fire BEFORE any field is decoded. Without the gate,
    /// the downstream `paymasterAndData[_PAYMASTER_DATA_OFFSET:]` slice
    /// would revert with an OOB panic.
    function test_validatePaymasterUserOp_revertsWhen_lengthIsZero() public {
        _assertRejectsLength(0);
    }

    /// One under the data offset (52 bytes header). Decoder would still
    /// fail OOB if the gate were removed.
    function test_validatePaymasterUserOp_revertsWhen_lengthBelowDataOffset() public {
        _assertRejectsLength(51);
    }

    /// Exactly the data offset (no verifier, no sig). Decoder would slice
    /// an empty `paymasterData` and start reading garbage uint48s.
    function test_validatePaymasterUserOp_revertsWhen_lengthAtDataOffset() public {
        _assertRejectsLength(52);
    }

    /// One under the sig offset (verifier present, no signature). This is
    /// the most dangerous case — the structure looks almost right.
    function test_validatePaymasterUserOp_revertsWhen_lengthBelowSigOffset() public {
        _assertRejectsLength(127);
    }

    /// Exactly the sig offset (verifier present, zero-length sig). The
    /// WOTS+ verify would OOB without the gate.
    function test_validatePaymasterUserOp_revertsWhen_lengthAtSigOffset() public {
        _assertRejectsLength(128);
    }

    /// One byte under the canonical layout — the closest realistic
    /// "almost-valid" payload.
    function test_validatePaymasterUserOp_revertsWhen_lengthOneByteShort() public {
        _assertRejectsLength(_PAYMASTER_AND_DATA_LEN - 1);
    }

    /// One byte over — surplus bytes must be rejected, not silently
    /// truncated.
    function test_validatePaymasterUserOp_revertsWhen_lengthOneByteLong() public {
        _assertRejectsLength(_PAYMASTER_AND_DATA_LEN + 1);
    }

    /// Fuzz across the full forbidden range below the canonical length.
    /// Every value < `_PAYMASTER_AND_DATA_LEN` must hit the gate.
    function testFuzz_validatePaymasterUserOp_rejectsAnyShorterLength(uint16 raw) public {
        uint256 len = uint256(raw) % _PAYMASTER_AND_DATA_LEN;
        _assertRejectsLength(len);
    }
}
