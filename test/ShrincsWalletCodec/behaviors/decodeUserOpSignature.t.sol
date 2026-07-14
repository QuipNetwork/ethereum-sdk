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
        bytes memory blob = abi.encode(pk, sig);

        (SHRINCS.PublicKey memory dpk, SHRINCS.Signature memory dsig) =
            codec.exposed_decodeUserOpSignature(blob);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dsig, sig);
    }

    function test_decodeUserOpSignature_revertsWhen_tooShort() public {
        bytes memory short = new bytes(0x20); // < 0x40
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x40, 0x20));
        codec.exposed_decodeUserOpSignature(short);
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev The assembly offset-decoder must round-trip ANY ABI-encoded `(PublicKey,
    ///      StatefulSignature)` — arbitrary `bytes` field contents and arbitrary dynamic-array
    ///      lengths (the `authPath` length is what the wallet reads as the leaf index).
    function testFuzz_decodeUserOpSignature_roundTrip(
        bytes memory statefulPublicKey,
        bytes memory commitment,
        bytes memory pkSeed,
        bytes memory hypertreeRoot,
        bytes32 randomizer,
        uint32 counter,
        bytes32[] memory chains,
        bytes32[] memory authPath
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

        bytes memory blob = abi.encode(pk, sig);
        (SHRINCS.PublicKey memory dpk, SHRINCS.Signature memory dsig) =
            codec.exposed_decodeUserOpSignature(blob);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dsig, sig);
    }
}
