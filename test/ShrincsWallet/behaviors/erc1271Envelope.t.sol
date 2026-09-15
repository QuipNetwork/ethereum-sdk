// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `erc1271Envelope` — the self-call target `_checkErc1271Signature` uses
///      to re-encode the SHRINCS half of a 1271 blob into the verifier envelope. It exists to put a
///      call boundary around the nested-calldata reads (the codec bounds-checks only a blob's
///      top-level tail offsets), so its contract is: self-call only; byte-identical to
///      `abi.encode(publicKey, signature)`; independent of the ECDSA half; and it REVERTS (rather
///      than soft-fails) on every malformed input, because the caller's try/catch is the policy.
contract ShrincsWallet_erc1271Envelope is ShrincsWalletTest {
    bytes32 internal constant HASH = keccak256("erc1271-message");

    function _legit() internal returns (bytes memory blob, bytes memory expected) {
        SPHINCSPlusC.Signature memory sig = _signErc1271(HASH);
        blob = abi.encode(erc1271Pk, sig, _ownerEcdsa(HASH));
        expected = abi.encode(erc1271Pk, sig);
    }

    /* ─────────────────────────────── ACCESS ─────────────────────────────── */

    function test_erc1271Envelope_revertsWhen_notSelf() public {
        (bytes memory blob, ) = _legit();
        vm.expectRevert(IShrincsWallet.SelfCallOnly.selector);
        wallet.erc1271Envelope(blob);
    }

    function test_erc1271Envelope_revertsWhen_owner() public {
        (bytes memory blob, ) = _legit();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.SelfCallOnly.selector);
        wallet.erc1271Envelope(blob);
    }

    /* ─────────────────────────────── ENCODING ─────────────────────────────── */

    /// @dev The envelope is exactly `abi.encode(publicKey, signature)` — the format the pinned
    ///      verifier decodes and the one `_tryVerifyStateless` previously built inline.
    function test_erc1271Envelope_matchesAbiEncode() public {
        (bytes memory blob, bytes memory expected) = _legit();
        vm.prank(address(wallet));
        bytes memory envelope = wallet.erc1271Envelope(blob);
        assertEq(envelope, expected, "envelope == abi.encode(pk, sig)");
    }

    /// @dev The ECDSA half rides in the blob but is not part of the envelope: two blobs that differ
    ///      only in their ECDSA bytes produce the same envelope.
    function test_erc1271Envelope_ignoresEcdsaHalf() public {
        SPHINCSPlusC.Signature memory sig = _signErc1271(HASH);
        bytes memory a = abi.encode(erc1271Pk, sig, _ownerEcdsa(HASH));
        bytes memory b = abi.encode(erc1271Pk, sig, new bytes(65));
        bytes memory c = abi.encode(erc1271Pk, sig, new bytes(0));
        vm.prank(address(wallet));
        bytes memory envA = wallet.erc1271Envelope(a);
        vm.prank(address(wallet));
        bytes memory envB = wallet.erc1271Envelope(b);
        vm.prank(address(wallet));
        bytes memory envC = wallet.erc1271Envelope(c);
        assertEq(envA, envB, "ecdsa bytes do not affect the envelope");
        assertEq(envA, envC, "empty ecdsa slice does not affect the envelope");
    }

    /// @dev `isValidSignature` is staticcalled by relying contracts, so the self-call inside it is
    ///      a STATICCALL too; the function must be usable in a static context.
    function test_erc1271Envelope_worksUnderStaticcall() public {
        (bytes memory blob, bytes memory expected) = _legit();
        vm.prank(address(wallet));
        (bool ok, bytes memory ret) = address(wallet).staticcall(
            abi.encodeCall(wallet.erc1271Envelope, (blob))
        );
        assertTrue(ok, "staticcall succeeds");
        assertEq(abi.decode(ret, (bytes)), expected);
    }

    /* ─────────────────────────────── MALFORMED INPUT ─────────────────────────────── */

    /// @dev Top-level malformation (what `tryDecodeErc1271Signature` reports as `!ok`) reverts
    ///      `InvalidSignature` here. Unreachable from `_checkErc1271Signature`, which returns
    ///      `MalformedErc1271Payload` before the self-call; pinned so the function never
    ///      dereferences the decoder's zero-length failure slices.
    function test_erc1271Envelope_revertsWhen_topLevelMalformed() public {
        bytes memory tooShort = new bytes(0x40);
        vm.prank(address(wallet));
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.erc1271Envelope(tooShort);

        bytes memory hugeOffsets = _fill(0x60, 0xff);
        vm.prank(address(wallet));
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.erc1271Envelope(hugeOffsets);

        // Head OK, ecdsaSig length word overruns the blob.
        bytes memory ecdsaOverrun =
            abi.encodePacked(bytes32(0), bytes32(0), bytes32(uint256(0x60)), bytes32(type(uint256).max));
        vm.prank(address(wallet));
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.erc1271Envelope(ecdsaOverrun);
    }

    /// @dev Nested malformation (a PublicKey / Signature tail offset past calldatasize) is the case
    ///      this function exists for: Solidity's calldata accessors revert (bare revert) inside the
    ///      re-encode, and that revert must propagate to the caller's try/catch, not be swallowed.
    function test_erc1271Envelope_revertsWhen_nestedOffsetOutOfBounds() public {
        (bytes memory legit, ) = _legit();
        uint256 pkOff = _word(legit, 0x00);
        uint256 sigOff = _word(legit, 0x20);

        bytes memory pkCorrupt = abi.encodePacked(legit);
        _setWord(pkCorrupt, pkOff, 1 << 64); // pk.statefulPublicKey offset
        vm.prank(address(wallet));
        vm.expectRevert();
        wallet.erc1271Envelope(pkCorrupt);

        bytes memory sigCorrupt = abi.encodePacked(legit);
        _setWord(sigCorrupt, sigOff + 0x20, 1 << 64); // sig.hypertree offset
        vm.prank(address(wallet));
        vm.expectRevert();
        wallet.erc1271Envelope(sigCorrupt);

        // Exact edge: the blob ends where calldata ends, so an offset whose length word starts one
        // byte past the blob is one byte past calldatasize.
        bytes memory edgeCorrupt = abi.encodePacked(legit);
        _setWord(edgeCorrupt, pkOff, legit.length - pkOff - 0x20 + 1);
        vm.prank(address(wallet));
        vm.expectRevert();
        wallet.erc1271Envelope(edgeCorrupt);
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
