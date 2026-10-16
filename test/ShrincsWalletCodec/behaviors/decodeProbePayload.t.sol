// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_decodeProbePayload is ShrincsWalletCodecTest {
    function test_decodeProbePayload_roundTrip() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        SHRINCS.Signature memory statefulSig = _sampleStatefulSig();
        SPHINCSPlusC.Signature memory statelessSig = _sampleStatelessSig();
        bytes memory payload = abi.encode(pk, statefulSig, statelessSig);

        (
            SHRINCS.PublicKey memory dpk,
            SHRINCS.Signature memory dStateful,
            SPHINCSPlusC.Signature memory dStateless
        ) = codec.exposed_decodeProbePayload(payload);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dStateful, statefulSig);
        assertEq(
            keccak256(abi.encode(dStateless)), keccak256(abi.encode(statelessSig)), "stateless sig round-trips"
        );
    }

    function test_decodeProbePayload_revertsWhen_tooShort() public {
        // A 2-word head is one word short of the 0x60 floor.
        bytes memory short = new bytes(0x40);
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x60, 0x40));
        codec.exposed_decodeProbePayload(short);
    }

    function test_decodeProbePayload_revertsWhen_tailOffsetOutOfBounds() public {
        // Head is 0x60 (three words); word[0] is the bundle tail offset — send it past the end.
        bytes memory payload = bytes.concat(bytes32(uint256(0x60)), bytes32(0), bytes32(0));
        // Reading the pointed-to head word needs 0x60 + 0x20 = 0x80 bytes; the slice is 0x60.
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x80, 0x60));
        codec.exposed_decodeProbePayload(payload);
    }
}
