// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_decodeUserOpSignature is ShrincsWalletCodecTest {
    function test_decodeUserOpSignature_roundTrip() public view {
        ShrincsTypes.PublicKey memory pk = _samplePublicKey();
        ShrincsTypes.StatefulSignature memory sig = _sampleStatefulSig();
        bytes memory blob = abi.encode(pk, sig);

        (ShrincsTypes.PublicKey memory dpk, ShrincsTypes.StatefulSignature memory dsig) =
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
        uint8 paramId,
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

        ShrincsTypes.PublicKey memory pk;
        pk.parameterSetId = ShrincsTypes.ParameterSetId(bound(paramId, 0, 1));
        pk.statefulPublicKey = statefulPublicKey;
        pk.publicKeyCommitment = commitment;
        pk.pkSeed = pkSeed;
        pk.hypertreeRoot = hypertreeRoot;

        ShrincsTypes.StatefulSignature memory sig;
        sig.randomizer = randomizer;
        sig.counter = counter;
        sig.chains = chains;
        sig.authPath = authPath;

        bytes memory blob = abi.encode(pk, sig);
        (ShrincsTypes.PublicKey memory dpk, ShrincsTypes.StatefulSignature memory dsig) =
            codec.exposed_decodeUserOpSignature(blob);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dsig, sig);
    }
}
