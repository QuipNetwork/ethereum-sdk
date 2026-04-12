// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__completeOwnershipHandoverDigest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant S1 = bytes32(uint256(10));
    bytes32 constant H1 = bytes32(uint256(11));
    bytes32 constant S2 = bytes32(uint256(20));
    bytes32 constant H2 = bytes32(uint256(21));

    function test_exposed_completeOwnershipHandoverDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.completeOwnershipHandover");
        address pendingOwner = address(0xBEEF);
        bytes32 expected = EfficientHashLib.hash(
            tag, bytes32(C), bytes32(uint256(uint160(W))),
            S1, H1, S2, H2,
            bytes32(uint256(uint160(pendingOwner)))
        );
        assertEq(
            codec.exposed_completeOwnershipHandoverDigest(W, C, S1, H1, S2, H2, pendingOwner),
            expected
        );
    }

    function test_exposed_completeOwnershipHandoverDigest_differsByPendingOwner() public view {
        bytes32 a = codec.exposed_completeOwnershipHandoverDigest(W, C, S1, H1, S2, H2, address(0x1));
        bytes32 b = codec.exposed_completeOwnershipHandoverDigest(W, C, S1, H1, S2, H2, address(0x2));
        assertTrue(a != b);
    }

    /// @dev Domain separation — digests with identical inputs differ from transferOwnership.
    function test_exposed_completeOwnershipHandoverDigest_domainSeparatedFromTransferOwnership() public view {
        address who = address(0xBEEF);
        bytes32 complete = codec.exposed_completeOwnershipHandoverDigest(W, C, S1, H1, S2, H2, who);
        bytes32 transfer = codec.exposed_transferOwnershipDigest(W, C, S1, H1, S2, H2, who);
        assertTrue(complete != transfer);
    }
}
