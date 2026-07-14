// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {WOTSPlusCodecHarness} from "../../harness/WOTSPlusCodecHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @title WOTSPlusCodec — address-decoder mask regression
/// @dev `decodeExecute`, `decodeWithdrawDeposit`, and `decodeOwnershipTransfer`
///      load the 32-byte calldata word containing an address field and mask
///      it with `_ADDRESS_MASK = type(uint160).max`. The encoders right-pad
///      addresses with 12 leading zero bytes, so on legitimate calldata the
///      mask is a no-op. The mask exists as defence in depth — a future
///      "cleanup" pass might be tempted to drop it ("the encoder always
///      pads, so the upper bits are always zero"), at which point any
///      adversary-crafted payload with non-zero garbage in those upper bits
///      would leak straight through the decoder and either:
///        - shift downstream `keccak(...,address,...)` digests, or
///        - mismatch ownership/access checks elsewhere.
///
///      This file pins the masking behaviour by hand-crafting payloads with
///      non-zero garbage in the upper 12 bytes of each address slot and
///      asserting the decoder returns only the lower 20 bytes. Both static
///      and fuzz coverage included.
contract WOTSPlusCodec_addressMaskRegression is Test {
    WOTSPlusCodecHarness internal harness;

    function setUp() public {
        harness = new WOTSPlusCodecHarness();
    }

    /*─────────────────────────── helpers ───────────────────────────────*/

    /// Pack a 32-byte word as `garbage96 ‖ address160`. The encoder would
    /// produce `0 ‖ address160`; we deliberately stuff `garbage96` into the
    /// upper 96 bits to exercise the mask.
    function _stuffAddressWord(uint96 garbage, address addr) internal pure returns (bytes32 word) {
        word = bytes32((uint256(garbage) << 160) | uint256(uint160(addr)));
    }

    /// Build a minimal valid `decodeExecute` payload (2336 bytes) with
    /// `addressWord` placed at offset 2272 and `value` at offset 2304. All
    /// other bytes are zero — the decoder doesn't care about them for this
    /// regression. (Length and structural checks fire only on `< 2336`.)
    function _buildExecutePayload(bytes32 addressWord, uint256 value) internal pure returns (bytes memory payload) {
        payload = new bytes(2336);
        // Offset 2272 — address slot.
        for (uint256 i = 0; i < 32; ++i) {
            payload[2272 + i] = addressWord[i];
        }
        // Offset 2304 — value slot.
        bytes32 valueWord = bytes32(value);
        for (uint256 i = 0; i < 32; ++i) {
            payload[2304 + i] = valueWord[i];
        }
    }

    /// Same shape as `_buildExecutePayload` but for `decodeWithdrawDeposit`
    /// (identical layout — 2336 bytes, address at 2272, amount at 2304).
    function _buildWithdrawPayload(bytes32 addressWord, uint256 amount) internal pure returns (bytes memory payload) {
        return _buildExecutePayload(addressWord, amount);
    }

    /// Build a minimal valid `decodeOwnershipTransfer` payload (4288
    /// bytes) with `addressWord` at offset 2272 (the newOwner slot). The
    /// remainder is zero — the decoder reads the 10-of-each keysets via
    /// fixed-length calldata refs that the assembly accepts regardless of
    /// content.
    function _buildOwnershipTransferPayload(bytes32 addressWord) internal pure returns (bytes memory payload) {
        payload = new bytes(4288);
        for (uint256 i = 0; i < 32; ++i) {
            payload[2272 + i] = addressWord[i];
        }
    }

    /*─────────────────── decodeExecute coverage ────────────────────────*/

    /// Sanity: a legitimate encoder-style payload (upper bits zero) round-
    /// trips to the same address the test put in. Documents the
    /// no-garbage baseline so the masked-garbage tests have a control.
    function test_decodeExecute_returnsAddressForCleanWord() public view {
        address target = address(uint160(0xCAFE_BABE_DEAD_BEEF_1234));
        bytes memory payload = _buildExecutePayload(_stuffAddressWord(0, target), 42);
        (,,, address decoded, uint256 value,) = harness.exposed_decodeExecute(payload);
        assertEq(decoded, target);
        assertEq(value, 42);
    }

    /// All-ones in the upper 96 bits. If the mask were removed, the
    /// decoder would attempt to cast the full 256-bit word into an
    /// `address` — Solidity's `address` cast would truncate to 160 bits
    /// at the language level but any inline-assembly code path that
    /// `calldataload`s and hashes the raw word would diverge. This test
    /// pins the masked semantics regardless.
    function test_decodeExecute_masksUpper96BitsAllOnes() public view {
        address target = address(uint160(0xABCDEF_1234567890_ABCDEF_12345678));
        bytes memory payload = _buildExecutePayload(_stuffAddressWord(type(uint96).max, target), 7);
        (,,, address decoded,,) = harness.exposed_decodeExecute(payload);
        assertEq(decoded, target);
    }

    function test_decodeExecute_masksUpper96BitsSingleHighBit() public view {
        address target = address(uint160(0xDEAD_BEEF));
        uint96 garbage = uint96(1) << 95; // top bit of the upper 96
        bytes memory payload = _buildExecutePayload(_stuffAddressWord(garbage, target), 0);
        (,,, address decoded,,) = harness.exposed_decodeExecute(payload);
        assertEq(decoded, target);
    }

    /// Fuzz the upper-96 garbage bits across the entire `uint96` range
    /// against arbitrary addresses. Every draw must hit the masked branch.
    function testFuzz_decodeExecute_masksAnyUpperGarbage(uint96 garbage, address target, uint256 value) public view {
        bytes memory payload = _buildExecutePayload(_stuffAddressWord(garbage, target), value);
        (,,, address decoded, uint256 v,) = harness.exposed_decodeExecute(payload);
        assertEq(decoded, target, "address must equal lower-20-byte cast");
        assertEq(v, value, "value field must be unaffected");
    }

    /*────────────── decodeWithdrawDeposit coverage ─────────────────────*/

    function test_decodeWithdrawDeposit_masksUpper96BitsAllOnes() public view {
        address to = address(uint160(0x1111_2222_3333_4444_5555));
        bytes memory payload = _buildWithdrawPayload(_stuffAddressWord(type(uint96).max, to), 1_000_000);
        (,,, address decoded, uint256 amount) = harness.exposed_decodeWithdrawDeposit(payload);
        assertEq(decoded, to);
        assertEq(amount, 1_000_000);
    }

    function testFuzz_decodeWithdrawDeposit_masksAnyUpperGarbage(uint96 garbage, address to, uint256 amount)
        public
        view
    {
        bytes memory payload = _buildWithdrawPayload(_stuffAddressWord(garbage, to), amount);
        (,,, address decoded, uint256 a) = harness.exposed_decodeWithdrawDeposit(payload);
        assertEq(decoded, to);
        assertEq(a, amount);
    }

    /*────────────── decodeOwnershipTransfer coverage ───────────────────*/

    function test_decodeOwnershipTransfer_masksUpper96BitsAllOnes() public view {
        address newOwner = address(uint160(0xFEED_BEEF_C0DE_BABE));
        bytes memory payload = _buildOwnershipTransferPayload(_stuffAddressWord(type(uint96).max, newOwner));
        (,,, address decoded,,,,) = harness.exposed_decodeOwnershipTransfer(payload);
        assertEq(decoded, newOwner);
    }

    function testFuzz_decodeOwnershipTransfer_masksAnyUpperGarbage(uint96 garbage, address newOwner) public view {
        bytes memory payload = _buildOwnershipTransferPayload(_stuffAddressWord(garbage, newOwner));
        (,,, address decoded,,,,) = harness.exposed_decodeOwnershipTransfer(payload);
        assertEq(decoded, newOwner);
    }

    /*────────────────── invariant: lower-20 isolation ──────────────────*/

    /// Sentinel: regardless of what's in the upper 96 bits, the decoded
    /// address must equal the language-level `address(uint160(...))`
    /// truncation of the raw 256-bit word. This is the property the mask
    /// is supposed to enforce; the regression is "did anyone change the
    /// behaviour to leak upper bits."
    function testFuzz_decodeExecute_lowerTwentyBytesAreLoadBearing(uint256 fullWord, uint256 value) public view {
        // Build a payload whose address slot is the entire `fullWord`,
        // upper bits and all.
        bytes memory payload = new bytes(2336);
        bytes32 word = bytes32(fullWord);
        for (uint256 i = 0; i < 32; ++i) {
            payload[2272 + i] = word[i];
        }
        bytes32 valueWord = bytes32(value);
        for (uint256 i = 0; i < 32; ++i) {
            payload[2304 + i] = valueWord[i];
        }
        (,,, address decoded, uint256 v,) = harness.exposed_decodeExecute(payload);
        // The masked-out behaviour: decoded address == low-160-bit truncation.
        assertEq(decoded, address(uint160(fullWord)));
        assertEq(v, value);
    }
}
