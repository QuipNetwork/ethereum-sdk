// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";

/// @dev Pins the `QSalt1` identity codec to a cross-language golden. The same
///      `GOLDEN` is asserted by the SDK test (`src/v1/shrincs/tests/addresses.test.ts`);
///      if the two ever disagree, the truncation or the ABI encoding drifted.
contract ShrincsWallet_identity is Test {
    bytes32 internal constant STATEFUL_C =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 internal constant STATELESS_C =
        0x2222222222222222222222222222222222222222222222222222222222222222;
    address internal constant OWNER = address(0xAA);

    /// @dev The 32-byte vault id for the fixture above, computed independently
    ///      (viem) and pinned. Byte-exact with the SDK `qsalt1VaultId`.
    bytes32 internal constant GOLDEN =
        0x5153616c743187fa095d9004d2c66b2770cce3714f8805f2484e9083e41b0764;

    function test_qsalt1VaultId_matchesGolden() public pure {
        assertEq(Codec.qsalt1VaultId(STATEFUL_C, STATELESS_C, OWNER), GOLDEN);
    }

    function test_qsalt1VaultId_prefixIsQSalt1() public pure {
        // High 6 bytes are ASCII "QSalt1".
        assertEq(bytes6(GOLDEN), Codec.QSALT1_PREFIX);
        assertEq(bytes6(GOLDEN), bytes6(0x5153616c7431));
    }

    function test_qsalt1Tail_isLow26Bytes() public pure {
        bytes26 tail = Codec.qsalt1Tail(STATEFUL_C, STATELESS_C, OWNER);
        // The tail follows the 6-byte prefix in the vault id.
        assertEq(bytes32(abi.encodePacked(Codec.QSALT1_PREFIX, tail)), GOLDEN);
    }

    function test_isQSalt1Salt_trueForPrefixedSalt() public pure {
        assertTrue(Codec.isQSalt1Salt(GOLDEN));
    }

    function test_isQSalt1Salt_falseForNonPrefixedSalt() public pure {
        assertFalse(Codec.isQSalt1Salt(bytes32(uint256(1))));
    }
}
