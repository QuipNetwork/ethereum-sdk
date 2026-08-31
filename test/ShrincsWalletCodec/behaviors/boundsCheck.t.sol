// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

/// @title ShrincsWalletCodec calldata-bounds tests
/// @dev The decoders read ABI tail offsets and dynamic lengths straight out of calldata via
///      `calldataload`, which bypasses Solidity's calldata bounds checks. A payload that clears
///      the fixed head-length check can still carry a tail offset (or a declared dynamic length)
///      that points past the slice; before the bounds asserts were added such a payload read
///      adjacent calldata instead of reverting. Each OOB / oversized-length case below therefore
///      FAILS on the unbounded decoders (no `MalformedPayload`) and passes once the asserts land.
contract ShrincsWalletCodec_boundsCheck is ShrincsWalletCodecTest {
    /* ───────────────────────────────── decodeInit ──────────────────────────────── */

    function test_decodeInit_boundsHappyPath() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        SHRINCS.PublicKey memory epk = _sampleErc1271PublicKey();
        bytes memory payload = abi.encode(
            keccak256("commit"), keccak256("seed"), pk, HashSuite.HASH_SUITE_ID, epk, uint32(2)
        );
        (,, SHRINCS.PublicKey memory mb,, SHRINCS.PublicKey memory eb,) = codec.exposed_decodeInit(payload);
        _assertPkEq(mb, pk);
        _assertPkEq(eb, epk);
    }

    function test_decodeInit_revertsWhen_erc1271TailOffsetOutOfBounds() public {
        // word[2] (main bundle) points at a valid in-range tail head; word[4] (erc1271 bundle)
        // points at the slice end so its pointed-to head word spills past `len`.
        bytes memory payload = bytes.concat(
            bytes32(0), bytes32(0), bytes32(uint256(0xc0)), bytes32(0), bytes32(uint256(0xe0)), bytes32(0),
            bytes32(0) // one word of tail so the main offset (0xc0) is in range; 0xe0 is not
        );
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x100, 0xe0));
        codec.exposed_decodeInit(payload);
    }

    function test_decodeInit_revertsWhen_tailOffsetOutOfBounds() public {
        // Head is 0xc0; word[2] is the `mainBundle` tail offset. Point it at the slice end so
        // the pointed-to head word (off + 0x20) spills past `len`.
        bytes memory payload = bytes.concat(
            bytes32(0), bytes32(0), bytes32(uint256(0xc0)), bytes32(0), bytes32(0), bytes32(0)
        );
        // Reading the pointed-to head word needs 0xc0 + 0x20 = 0xe0 bytes; the slice is 0xc0.
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0xe0, 0xc0));
        codec.exposed_decodeInit(payload);
    }

    /* ─────────────────────────── decodeUserOpSignature ─────────────────────────── */

    function test_decodeUserOpSignature_boundsHappyPath() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        bytes memory blob = abi.encode(pk, _sampleStatefulSig(), hex"1b");
        (SHRINCS.PublicKey memory dpk,,) = codec.exposed_decodeUserOpSignature(blob);
        _assertPkEq(dpk, pk);
    }

    function test_decodeUserOpSignature_revertsWhen_tailOffsetOutOfBounds() public {
        // Head is 0x60 (three offset words); point the first past the slice end.
        bytes memory blob = bytes.concat(bytes32(uint256(0x60)), bytes32(0), bytes32(0));
        // Reading the pointed-to head word needs 0x60 + 0x20 = 0x80 bytes; the slice is 0x60.
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x80, 0x60));
        codec.exposed_decodeUserOpSignature(blob);
    }

    function test_decodeUserOpSignature_revertsWhen_ecdsaSigLengthOversized() public {
        // All three offsets in range, but the ecdsaSig length word declares more bytes than
        // the slice holds (off + 0x20 + length > len).
        bytes memory blob = bytes.concat(
            bytes32(uint256(0x60)), bytes32(uint256(0x60)), bytes32(uint256(0x60)), bytes32(type(uint256).max)
        );
        // Diagnostic `expected` = off + 0x20 + length wraps mod 2^256 for the max-value length;
        // the revert still carries MalformedPayload with the real slice length as `actual`.
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x7f, 0x80));
        codec.exposed_decodeUserOpSignature(blob);
    }

    /* ────────────────────────── decodeSponsorshipSignature ─────────────────────── */

    function test_decodeSponsorshipSignature_boundsHappyPath() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        bytes memory blob = abi.encode(pk, _sampleStatefulSig());
        (SHRINCS.PublicKey memory dpk,) = codec.exposed_decodeSponsorshipSignature(blob);
        _assertPkEq(dpk, pk);
    }

    function test_decodeSponsorshipSignature_revertsWhen_tailOffsetOutOfBounds() public {
        // Head is 0x40 (two offset words); point the first past the slice end.
        bytes memory blob = bytes.concat(bytes32(uint256(0x40)), bytes32(0));
        // Reading the pointed-to head word needs 0x40 + 0x20 = 0x60 bytes; the slice is 0x40.
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x60, 0x40));
        codec.exposed_decodeSponsorshipSignature(blob);
    }

    /* ──────────────────────────── decodeUpgradeAuth ────────────────────────────── */

    function test_decodeUpgradeAuth_boundsHappyPath() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        bytes memory data = abi.encode(pk, _sampleStatefulSig(), true, hex"deadbeef", uint256(7));
        (SHRINCS.PublicKey memory dpk,,, bytes memory dPayload, uint256 dNonce) =
            codec.exposed_decodeUpgradeAuth(data);
        _assertPkEq(dpk, pk);
        assertEq(dPayload, hex"deadbeef", "migratorPayload");
        assertEq(dNonce, 7, "nonce");
    }

    function test_decodeUpgradeAuth_revertsWhen_tailOffsetOutOfBounds() public {
        // Head is 0xa0 (five words); word[0] is the `publicKey` tail offset — send it past the end.
        bytes memory data = bytes.concat(
            bytes32(uint256(0xa0)), bytes32(0), bytes32(0), bytes32(0), bytes32(0)
        );
        // Reading the pointed-to head word needs 0xa0 + 0x20 = 0xc0 bytes; the slice is 0xa0.
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0xc0, 0xa0));
        codec.exposed_decodeUpgradeAuth(data);
    }

    function test_decodeUpgradeAuth_revertsWhen_migratorPayloadLengthOversized() public {
        // All offsets in range (len 0xc0), but the migratorPayload length word at word[3]'s
        // target declares more bytes than remain in the slice.
        bytes memory data = bytes.concat(
            bytes32(uint256(0xa0)), // publicKey offset -> in range
            bytes32(uint256(0xa0)), // signature offset -> in range
            bytes32(0),             // shouldMigrate
            bytes32(uint256(0xa0)), // migratorPayload offset -> length word at o+0xa0
            bytes32(0),             // nonce
            bytes32(type(uint256).max) // declared migratorPayload length -> oversized
        );
        // Diagnostic `expected` = off + 0x20 + length wraps mod 2^256 for the max-value length;
        // the revert still carries MalformedPayload with the real slice length as `actual`.
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0xbf, 0xc0));
        codec.exposed_decodeUpgradeAuth(data);
    }

    /* ───────────────────────── tryDecodeErc1271Signature ───────────────────────── */

    // The ERC-1271 decoder is non-reverting (`tryDecodeErc1271Signature`): out-of-bounds tail
    // offsets return `ok == false` instead of reverting, so a staticcalling relying contract is
    // never DoS'd. The same bounds are still enforced — a malformed blob never decodes.
    function test_tryDecodeErc1271Signature_boundsHappyPath() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        bytes memory blob = abi.encode(pk, _sampleStatelessSig(), hex"1b");
        (bool ok, SHRINCS.PublicKey memory dpk,,) = codec.exposed_tryDecodeErc1271Signature(blob);
        assertTrue(ok, "well-formed blob decodes");
        _assertPkEq(dpk, pk);
    }

    function test_tryDecodeErc1271Signature_notOkWhen_tailOffsetOutOfBounds() public view {
        // Head is 0x60 (three offset words); point the first past the slice end.
        bytes memory blob = bytes.concat(bytes32(uint256(0x60)), bytes32(0), bytes32(0));
        // Reading the pointed-to head word needs 0x60 + 0x20 = 0x80 bytes; the slice is 0x60.
        (bool ok,,,) = codec.exposed_tryDecodeErc1271Signature(blob);
        assertFalse(ok, "out-of-bounds tail offset rejected without reverting");
    }

    function test_tryDecodeErc1271Signature_notOkWhen_ecdsaSigLengthOversized() public view {
        // All three offsets in range, but the ecdsaSig length word is oversized.
        bytes memory blob = bytes.concat(
            bytes32(uint256(0x60)), bytes32(uint256(0x60)), bytes32(uint256(0x60)), bytes32(type(uint256).max)
        );
        (bool ok,,,) = codec.exposed_tryDecodeErc1271Signature(blob);
        assertFalse(ok, "oversized ecdsaSig length rejected without reverting");
    }
}
