// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_decodeUserOpSignature is ShrincsWalletCodecTest {
    function test_decodeUserOpSignature_roundTrip() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        SHRINCS.Signature memory sig = _sampleStatefulSig();
        bytes memory ecdsaSig = hex"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
            hex"c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
            hex"1b";
        bytes memory blob = abi.encode(pk, sig, ecdsaSig);

        (SHRINCS.PublicKey memory dpk, SHRINCS.Signature memory dsig, bytes memory des) =
            codec.exposed_decodeUserOpSignature(blob);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dsig, sig);
        assertEq(des, ecdsaSig, "ecdsaSig");
    }

    function test_decodeUserOpSignature_emptyEcdsaSig() public view {
        // An empty co-signature must decode cleanly (the wallet rejects it later via
        // tryRecoverCalldata returning address(0), not via decode).
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        SHRINCS.Signature memory sig = _sampleStatefulSig();
        bytes memory blob = abi.encode(pk, sig, bytes(""));

        (,, bytes memory des) = codec.exposed_decodeUserOpSignature(blob);
        assertEq(des.length, 0, "empty ecdsaSig round-trips");
    }

    function test_decodeUserOpSignature_revertsWhen_tooShort() public {
        bytes memory short = new bytes(0x40); // < 0x60 (three head words now)
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x60, 0x40));
        codec.exposed_decodeUserOpSignature(short);
    }

    function test_decodeSponsorshipSignature_roundTrip() public view {
        // The paymaster's sponsorship blob keeps the plain (PublicKey, Signature) pair —
        // no ECDSA co-signer on the global sponsorship key.
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        SHRINCS.Signature memory sig = _sampleStatefulSig();
        bytes memory blob = abi.encode(pk, sig);

        (SHRINCS.PublicKey memory dpk, SHRINCS.Signature memory dsig) =
            codec.exposed_decodeSponsorshipSignature(blob);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dsig, sig);
    }

    function test_decodeSponsorshipSignature_revertsWhen_tooShort() public {
        bytes memory short = new bytes(0x20); // < 0x40
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x40, 0x20));
        codec.exposed_decodeSponsorshipSignature(short);
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev The assembly offset-decoder must round-trip ANY ABI-encoded `(PublicKey,
    ///      StatefulSignature, bytes)` — arbitrary `bytes` field contents and arbitrary
    ///      dynamic-array lengths (the `authPath` length is what the wallet reads as the leaf
    ///      index) plus an arbitrary-length ECDSA co-signature.
    function testFuzz_decodeUserOpSignature_roundTrip(
        bytes memory statefulPublicKey,
        bytes memory commitment,
        bytes memory pkSeed,
        bytes memory hypertreeRoot,
        bytes32 randomizer,
        uint32 counter,
        bytes32[] memory chains,
        bytes32[] memory authPath,
        bytes memory ecdsaSig
    ) public view {
        // Keep arrays modest so the fuzzer stays fast; lengths are still varied.
        vm.assume(chains.length <= 64 && authPath.length <= 64);

        SHRINCS.PublicKey memory pk;
        pk.statefulPublicKey = statefulPublicKey;
        pk.publicKeyCommitment = commitment;
        pk.pkSeed = pkSeed;
        pk.hypertreeRoot = hypertreeRoot;

        SHRINCS.Signature memory sig;
        sig.randomizer = randomizer;
        sig.counter = counter;
        sig.chains = chains;
        sig.authPath = authPath;

        bytes memory blob = abi.encode(pk, sig, ecdsaSig);
        (SHRINCS.PublicKey memory dpk, SHRINCS.Signature memory dsig, bytes memory des) =
            codec.exposed_decodeUserOpSignature(blob);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dsig, sig);
        assertEq(des, ecdsaSig, "ecdsaSig");
    }
}
