// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for `sponsorshipEnvelope` — the self-call target `validatePaymasterUserOp`
///      uses to decode the sponsorship blob, derive the stateful leaf, and re-encode it into the
///      verifier envelope. Mirror of the wallet's `userOpEnvelope`: it exists to put a call
///      boundary around the nested-calldata reads (the codec bounds-checks only a blob's top-level
///      tail offsets), so its contract is: self-call only; `leaf == authPath.length`; envelope
///      byte-identical to `abi.encode(publicKey, signature)`; and it REVERTS (rather than
///      soft-fails) on every malformed input, because the caller's try/catch is the policy.
contract ShrincsPaymaster_sponsorshipEnvelope is ShrincsPaymasterTest {
    uint32 internal constant LEAF = 3;

    function _legit() internal view returns (bytes memory blob, bytes memory expectedEnvelope) {
        SHRINCS.Signature memory sig = _statefulSigWithLeaf(LEAF);
        blob = _blob(_pk(), sig);
        expectedEnvelope = abi.encode(_pk(), sig);
    }

    /* ─────────────────────────────── ACCESS ─────────────────────────────── */

    function test_sponsorshipEnvelope_revertsWhen_notSelf() public {
        (bytes memory blob,) = _legit();
        vm.expectRevert(IShrincsPaymaster.SelfCallOnly.selector);
        paymaster.sponsorshipEnvelope(blob);
    }

    function test_sponsorshipEnvelope_revertsWhen_owner() public {
        (bytes memory blob,) = _legit();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.SelfCallOnly.selector);
        paymaster.sponsorshipEnvelope(blob);
    }

    function test_sponsorshipEnvelope_revertsWhen_entryPoint() public {
        (bytes memory blob,) = _legit();
        vm.prank(ENTRY_POINT);
        vm.expectRevert(IShrincsPaymaster.SelfCallOnly.selector);
        paymaster.sponsorshipEnvelope(blob);
    }

    /* ─────────────────────────────── DECODING ─────────────────────────────── */

    function test_sponsorshipEnvelope_decodesLeafAndEnvelope() public {
        (bytes memory blob, bytes memory expectedEnvelope) = _legit();
        vm.prank(address(paymaster));
        (uint32 leaf, bytes memory envelope) = paymaster.sponsorshipEnvelope(blob);
        assertEq(leaf, LEAF, "leaf == authPath.length");
        assertEq(envelope, expectedEnvelope, "envelope == abi.encode(pk, sig)");
    }

    /// @dev `_verifyAndAdvance` calls it via `this.` from a non-view context, which compiles to a
    ///      STATICCALL; the function must be usable in a static context.
    function test_sponsorshipEnvelope_worksUnderStaticcall() public {
        (bytes memory blob, bytes memory expectedEnvelope) = _legit();
        vm.prank(address(paymaster));
        (bool ok, bytes memory ret) =
            address(paymaster).staticcall(abi.encodeCall(paymaster.sponsorshipEnvelope, (blob)));
        assertTrue(ok, "staticcall succeeds");
        (uint32 leaf, bytes memory envelope) = abi.decode(ret, (uint32, bytes));
        assertEq(leaf, LEAF);
        assertEq(envelope, expectedEnvelope);
    }

    /* ─────────────────────────────── MALFORMED INPUT ─────────────────────────────── */

    /// @dev Top-level malformation is the codec's `MalformedPayload` revert; it propagates to the
    ///      caller's try/catch (which maps it to `PaymasterValidationFailure.MalformedPayload`).
    function test_sponsorshipEnvelope_revertsWhen_topLevelMalformed() public {
        bytes memory tooShort = new bytes(0x20);
        vm.prank(address(paymaster));
        vm.expectPartialRevert(Codec.MalformedPayload.selector);
        paymaster.sponsorshipEnvelope(tooShort);

        bytes memory hugeOffsets = _fill(0x40, 0xff);
        vm.prank(address(paymaster));
        vm.expectPartialRevert(Codec.MalformedPayload.selector);
        paymaster.sponsorshipEnvelope(hugeOffsets);
    }

    /// @dev Nested malformation (a PublicKey / Signature tail offset past calldatasize) is the case
    ///      this function exists for: Solidity's calldata accessors revert (bare revert) at the leaf
    ///      read or inside the re-encode, and that revert must propagate to the caller's try/catch.
    function test_sponsorshipEnvelope_revertsWhen_nestedOffsetOutOfBounds() public {
        (bytes memory legit,) = _legit();
        uint256 pkOff = _word(legit, 0x00);
        uint256 sigOff = _word(legit, 0x20);

        bytes memory pkCorrupt = abi.encodePacked(legit);
        _setWord(pkCorrupt, pkOff, 1 << 64); // pk.statefulPublicKey offset -> re-encode
        vm.prank(address(paymaster));
        vm.expectRevert();
        paymaster.sponsorshipEnvelope(pkCorrupt);

        bytes memory authPathCorrupt = abi.encodePacked(legit);
        _setWord(authPathCorrupt, sigOff + 0x60, 1 << 64); // sig.authPath offset -> `_leafIndex`
        vm.prank(address(paymaster));
        vm.expectRevert();
        paymaster.sponsorshipEnvelope(authPathCorrupt);

        // Exact edge: the blob ends where calldata ends, so an offset whose length word starts one
        // byte past the blob is one byte past calldatasize.
        bytes memory edgeCorrupt = abi.encodePacked(legit);
        _setWord(edgeCorrupt, pkOff, legit.length - pkOff - 0x20 + 1);
        vm.prank(address(paymaster));
        vm.expectRevert();
        paymaster.sponsorshipEnvelope(edgeCorrupt);
    }

    /* ─────────────────────────────── HELPERS ─────────────────────────────── */

    function _fill(uint256 n, uint8 b) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; ++i) {
            out[i] = bytes1(b);
        }
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
}
