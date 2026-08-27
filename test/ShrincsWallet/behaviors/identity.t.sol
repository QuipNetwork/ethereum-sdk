// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";

/// @dev Pins the `V1` identity codec to a cross-language golden. The same
///      `GOLDEN` is asserted by the SDK test (`src/v1/shrincs/tests/addresses.test.ts`);
///      if the two ever disagree, the domain or ABI encoding drifted.
contract ShrincsWallet_identity is Test {
    bytes32 internal constant STATEFUL_C =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 internal constant STATELESS_C =
        0x2222222222222222222222222222222222222222222222222222222222222222;
    address internal constant OWNER = address(0xAA);

    /// @dev The 32-byte commitment for the fixture above, computed independently
    ///      (viem) and pinned. Byte-exact with the SDK `v1Commitment`.
    bytes32 internal constant GOLDEN =
        0xd165e4bbba9307d943f384fcaeaeb3c123bd87cfb9124a19d0a14fd4a3ae57df;

    function test_v1Commitment_matchesGolden() public pure {
        assertEq(Codec.v1Commitment(STATEFUL_C, STATELESS_C, OWNER), GOLDEN);
    }

    function test_v1IdentityDomain_matchesGolden() public pure {
        assertEq(
            Codec.V1_IDENTITY_DOMAIN,
            keccak256("QUIP_SHRINCS_IDENTITY_V1")
        );
    }
}
