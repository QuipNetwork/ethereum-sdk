// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_decodeErc1271Signature is ShrincsWalletCodecTest {
    function test_decodeErc1271Signature_roundTrip() public view {
        ShrincsTypes.PublicKey memory pk = _samplePublicKey();
        ShrincsTypes.StatelessSignature memory sig = _sampleStatelessSig();
        bytes memory ecdsaSig = abi.encodePacked(keccak256("r"), keccak256("s"), uint8(27)); // 65 bytes
        bytes memory blob = abi.encode(pk, sig, ecdsaSig);

        (ShrincsTypes.PublicKey memory dpk, ShrincsTypes.StatelessSignature memory dsig, bytes memory dEcdsa) =
            codec.exposed_decodeErc1271Signature(blob);

        _assertPkEq(dpk, pk);
        assertEq(dEcdsa, ecdsaSig, "ecdsaSig tail resolved");
        assertEq(dsig.fors.counter, sig.fors.counter, "stateless fors counter");
        assertEq(dsig.hypertree.length, 0, "stateless hypertree length");
    }

    function test_decodeErc1271Signature_revertsWhen_tooShort() public {
        bytes memory short = new bytes(0x40); // < 0x60
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x60, 0x40));
        codec.exposed_decodeErc1271Signature(short);
    }
}
