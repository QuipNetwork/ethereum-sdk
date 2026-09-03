// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `userOpEnvelope` — the self-call target `_validateSignature` uses to
///      decode the hybrid `userOp.signature` blob, derive the stateful leaf, and re-encode the
///      SHRINCS half into the verifier envelope. Twin of `erc1271Envelope`: it exists to put a call
///      boundary around the nested-calldata reads (the codec bounds-checks only a blob's top-level
///      tail offsets), so its contract is: self-call only; `leaf == authPath.length`; envelope
///      byte-identical to `abi.encode(publicKey, signature)`; the ECDSA bytes passed through
///      untouched; and it REVERTS (rather than soft-fails) on every malformed input, because the
///      caller's try/catch is the policy.
contract ShrincsWallet_userOpEnvelope is ShrincsWalletTest {
    bytes32 internal constant USER_OP_HASH = keccak256("erc4337-userop-envelope");
    uint32 internal constant LEAF = 3;

    function _legit()
        internal
        view
        returns (bytes memory blob, bytes memory expectedEnvelope, bytes memory expectedEcdsa, uint32 expectedLeaf)
    {
        SHRINCS.Signature memory sig = _signErc4337(USER_OP_HASH, LEAF);
        expectedEcdsa = _ownerUserOpEcdsa(USER_OP_HASH);
        blob = abi.encode(_mainPk(), sig, expectedEcdsa);
        expectedEnvelope = abi.encode(_mainPk(), sig);
        expectedLeaf = uint32(sig.authPath.length);
    }

    /* ─────────────────────────────── ACCESS ─────────────────────────────── */

    function test_userOpEnvelope_revertsWhen_notSelf() public {
        (bytes memory blob,,,) = _legit();
        vm.expectRevert(IShrincsWallet.SelfCallOnly.selector);
        wallet.userOpEnvelope(blob);
    }

    function test_userOpEnvelope_revertsWhen_owner() public {
        (bytes memory blob,,,) = _legit();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.SelfCallOnly.selector);
        wallet.userOpEnvelope(blob);
    }

    /* ─────────────────────────────── DECODING ─────────────────────────────── */

    /// @dev Leaf is the authPath length (the wallet's single leaf-derivation rule), the envelope
    ///      is exactly `abi.encode(publicKey, signature)`, and the ECDSA half passes through.
    function test_userOpEnvelope_decodesLeafEnvelopeAndEcdsa() public {
        (bytes memory blob, bytes memory expectedEnvelope, bytes memory expectedEcdsa, uint32 expectedLeaf) = _legit();
        vm.prank(address(wallet));
        (uint32 leaf, bytes memory envelope, bytes memory ecdsaSig) = wallet.userOpEnvelope(blob);
        assertEq(leaf, expectedLeaf, "leaf == authPath.length");
        assertEq(leaf, SIGN_BASE + LEAF, "leaf is the signed absolute index");
        assertEq(envelope, expectedEnvelope, "envelope == abi.encode(pk, sig)");
        assertEq(ecdsaSig, expectedEcdsa, "ecdsa bytes passed through");
    }

    /// @dev The ECDSA half is not part of the envelope: blobs differing only in their ECDSA bytes
    ///      produce the same envelope (and the differing ECDSA bytes come back verbatim).
    function test_userOpEnvelope_envelopeIgnoresEcdsaHalf() public {
        SHRINCS.Signature memory sig = _signErc4337(USER_OP_HASH, LEAF);
        bytes memory a = abi.encode(_mainPk(), sig, _ownerUserOpEcdsa(USER_OP_HASH));
        bytes memory b = abi.encode(_mainPk(), sig, new bytes(65));
        bytes memory c = abi.encode(_mainPk(), sig, new bytes(0));
        vm.prank(address(wallet));
        (, bytes memory envA, bytes memory ecdsaA) = wallet.userOpEnvelope(a);
        vm.prank(address(wallet));
        (, bytes memory envB, bytes memory ecdsaB) = wallet.userOpEnvelope(b);
        vm.prank(address(wallet));
        (, bytes memory envC, bytes memory ecdsaC) = wallet.userOpEnvelope(c);
        assertEq(envA, envB, "ecdsa bytes do not affect the envelope");
        assertEq(envA, envC, "empty ecdsa slice does not affect the envelope");
        assertEq(ecdsaA, _ownerUserOpEcdsa(USER_OP_HASH));
        assertEq(ecdsaB, new bytes(65));
        assertEq(ecdsaC.length, 0);
    }

    /// @dev `_validateSignature` calls it via `this.` from a non-view context, which compiles to a
    ///      STATICCALL; the function must be usable in a static context.
    function test_userOpEnvelope_worksUnderStaticcall() public {
        (bytes memory blob, bytes memory expectedEnvelope,, uint32 expectedLeaf) = _legit();
        vm.prank(address(wallet));
        (bool ok, bytes memory ret) = address(wallet).staticcall(abi.encodeCall(wallet.userOpEnvelope, (blob)));
        assertTrue(ok, "staticcall succeeds");
        (uint32 leaf, bytes memory envelope,) = abi.decode(ret, (uint32, bytes, bytes));
        assertEq(leaf, expectedLeaf);
        assertEq(envelope, expectedEnvelope);
    }

    /* ─────────────────────────────── MALFORMED INPUT ─────────────────────────────── */

    /// @dev Top-level malformation is the codec's `MalformedPayload` revert. It propagates to the
    ///      caller's try/catch (which maps it to `MalformedSignature`) rather than being swallowed.
    function test_userOpEnvelope_revertsWhen_topLevelMalformed() public {
        bytes memory tooShort = new bytes(0x40);
        vm.prank(address(wallet));
        vm.expectPartialRevert(Codec.MalformedPayload.selector);
        wallet.userOpEnvelope(tooShort);

        bytes memory hugeOffsets = _fill(0x60, 0xff);
        vm.prank(address(wallet));
        vm.expectPartialRevert(Codec.MalformedPayload.selector);
        wallet.userOpEnvelope(hugeOffsets);

        // Head OK, ecdsaSig length word overruns the blob.
        bytes memory ecdsaOverrun =
            abi.encodePacked(bytes32(0), bytes32(0), bytes32(uint256(0x60)), bytes32(type(uint256).max));
        vm.prank(address(wallet));
        vm.expectPartialRevert(Codec.MalformedPayload.selector);
        wallet.userOpEnvelope(ecdsaOverrun);
    }

    /// @dev Nested malformation (a PublicKey / Signature tail offset past calldatasize) is the case
    ///      this function exists for: Solidity's calldata accessors revert (bare revert) at the leaf
    ///      read or inside the re-encode, and that revert must propagate to the caller's try/catch.
    function test_userOpEnvelope_revertsWhen_nestedOffsetOutOfBounds() public {
        (bytes memory legit,,,) = _legit();
        uint256 pkOff = _word(legit, 0x00);
        uint256 sigOff = _word(legit, 0x20);

        bytes memory pkCorrupt = abi.encodePacked(legit);
        _setWord(pkCorrupt, pkOff, 1 << 64); // pk.statefulPublicKey offset -> re-encode
        vm.prank(address(wallet));
        vm.expectRevert();
        wallet.userOpEnvelope(pkCorrupt);

        bytes memory authPathCorrupt = abi.encodePacked(legit);
        _setWord(authPathCorrupt, sigOff + 0x60, 1 << 64); // sig.authPath offset -> `_leafIndex`
        vm.prank(address(wallet));
        vm.expectRevert();
        wallet.userOpEnvelope(authPathCorrupt);

        bytes memory chainsCorrupt = abi.encodePacked(legit);
        _setWord(chainsCorrupt, sigOff + 0x40, 1 << 64); // sig.chains offset -> re-encode
        vm.prank(address(wallet));
        vm.expectRevert();
        wallet.userOpEnvelope(chainsCorrupt);

        // Exact edge: the blob ends where calldata ends, so an offset whose length word starts one
        // byte past the blob is one byte past calldatasize.
        bytes memory edgeCorrupt = abi.encodePacked(legit);
        _setWord(edgeCorrupt, pkOff, legit.length - pkOff - 0x20 + 1);
        vm.prank(address(wallet));
        vm.expectRevert();
        wallet.userOpEnvelope(edgeCorrupt);
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
