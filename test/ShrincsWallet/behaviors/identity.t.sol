// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";

/// @dev Pins the `V1` identity codec to a cross-language golden. The same
///      `GOLDEN` is asserted by the SDK test (`src/v1/shrincs/tests/addresses.test.ts`);
///      if the two ever disagree, the truncation or the ABI encoding drifted.
contract ShrincsWallet_identity is Test {
    bytes32 internal constant STATEFUL_C =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 internal constant STATELESS_C =
        0x2222222222222222222222222222222222222222222222222222222222222222;
    address internal constant OWNER = address(0xAA);

    /// @dev The 32-byte commitment for the fixture above, computed independently
    ///      (viem) and pinned. Byte-exact with the SDK `v1Commitment`.
    bytes32 internal constant GOLDEN =
        0x515630318f6887fa095d9004d2c66b2770cce3714f8805f2484e9083e41b0764;

    function test_v1Commitment_matchesGolden() public pure {
        assertEq(Codec.v1Commitment(STATEFUL_C, STATELESS_C, OWNER), GOLDEN);
    }

    function test_v1Commitment_prefixIsV1() public pure {
        // High 4 bytes match V1_PREFIX (0x51563031).
        assertEq(bytes4(GOLDEN), Codec.V1_PREFIX);
        assertEq(bytes4(GOLDEN), bytes4(0x51563031));
    }

    function test_v1CommitmentTail_isLow28Bytes() public pure {
        bytes28 tail = Codec.v1CommitmentTail(STATEFUL_C, STATELESS_C, OWNER);
        // The tail follows the 4-byte prefix in the commitment.
        assertEq(bytes32(abi.encodePacked(Codec.V1_PREFIX, tail)), GOLDEN);
    }

    function test_isV1Commitment_trueForPrefixedSalt() public pure {
        assertTrue(Codec.isV1Commitment(GOLDEN));
    }

    function test_isV1Commitment_falseForNonPrefixedSalt() public pure {
        assertFalse(Codec.isV1Commitment(bytes32(uint256(1))));
    }
}
