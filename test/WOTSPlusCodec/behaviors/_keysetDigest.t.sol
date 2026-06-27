// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__keysetDigest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant S1 = bytes32(uint256(10));
    bytes32 constant H1 = bytes32(uint256(11));
    bytes32 constant S2 = bytes32(uint256(20));
    bytes32 constant H2 = bytes32(uint256(21));
    bytes32 constant KEYS_HASH = bytes32(uint256(77));

    function _expected(bytes32 tag) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                tag,
                bytes32(C),
                bytes32(uint256(uint160(W))),
                S1,
                H1,
                S2,
                H2,
                KEYS_HASH
            );
    }

    function test_exposed_keysetDigest_transactionMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_keysetDigest(
                Codec.KeyType.Transaction,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                KEYS_HASH
            ),
            _expected(keccak256("quip.digest.addTransactionKeys"))
        );
    }

    function test_exposed_keysetDigest_recoveryMatchesManualHash() public view {
        assertEq(
            codec.exposed_keysetDigest(
                Codec.KeyType.Recovery,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                KEYS_HASH
            ),
            _expected(keccak256("quip.digest.keyManagement"))
        );
    }

    function test_exposed_keysetDigest_verificationMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_keysetDigest(
                Codec.KeyType.Verification,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                KEYS_HASH
            ),
            _expected(keccak256("quip.digest.verificationKeys"))
        );
    }

    /// @dev Same inputs under different kinds must produce distinct digests.
    ///      This is the cross-type replay-prevention property.
    function test_exposed_keysetDigest_kindsAreDistinct() public view {
        bytes32 tx_ = codec.exposed_keysetDigest(
            Codec.KeyType.Transaction,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );
        bytes32 rec = codec.exposed_keysetDigest(
            Codec.KeyType.Recovery,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );
        bytes32 ver = codec.exposed_keysetDigest(
            Codec.KeyType.Verification,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );
        assertTrue(tx_ != rec);
        assertTrue(tx_ != ver);
        assertTrue(rec != ver);
    }
}
