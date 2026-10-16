// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_tryDecodeErc1271Signature is ShrincsWalletCodecTest {
    function test_tryDecodeErc1271Signature_roundTrip() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        SPHINCSPlusC.Signature memory sig = _sampleStatelessSig();
        bytes memory ecdsaSig = abi.encodePacked(keccak256("r"), keccak256("s"), uint8(27)); // 65 bytes
        bytes memory blob = abi.encode(pk, sig, ecdsaSig);

        (bool ok, SHRINCS.PublicKey memory dpk, SPHINCSPlusC.Signature memory dsig, bytes memory dEcdsa) =
            codec.exposed_tryDecodeErc1271Signature(blob);

        assertTrue(ok, "well-formed blob decodes");
        _assertPkEq(dpk, pk);
        assertEq(dEcdsa, ecdsaSig, "ecdsaSig tail resolved");
        assertEq(dsig.fors.counter, sig.fors.counter, "stateless fors counter");
        assertEq(dsig.hypertree.length, 0, "stateless hypertree length");
    }

    // Non-reverting: a too-short blob returns `ok == false` rather than reverting, so the ERC-1271
    // staticcall path can map it to the failure magic instead of propagating a DoS revert.
    function test_tryDecodeErc1271Signature_notOkWhen_tooShort() public view {
        bytes memory short = new bytes(0x40); // < 0x60
        (bool ok,,,) = codec.exposed_tryDecodeErc1271Signature(short);
        assertFalse(ok, "too-short blob rejected without reverting");
    }
}
