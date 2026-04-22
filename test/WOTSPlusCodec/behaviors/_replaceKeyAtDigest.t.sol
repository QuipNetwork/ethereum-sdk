// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__replaceKeyAtDigest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant S1 = bytes32(uint256(10));
    bytes32 constant H1 = bytes32(uint256(11));
    bytes32 constant S2 = bytes32(uint256(20));
    bytes32 constant H2 = bytes32(uint256(21));
    uint256 constant IDX = 3;
    bytes32 constant NEW_SEED = bytes32(uint256(77));
    bytes32 constant NEW_HASH = bytes32(uint256(88));

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
                bytes32(IDX),
                NEW_SEED,
                NEW_HASH
            );
    }

    function test_exposed_replaceKeyAtDigest_transactionMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_replaceKeyAtDigest(
                Codec.KeyType.Transaction,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                IDX,
                NEW_SEED,
                NEW_HASH
            ),
            _expected(keccak256("quip.digest.replaceTransactionKeyAt"))
        );
    }

    function test_exposed_replaceKeyAtDigest_recoveryMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_replaceKeyAtDigest(
                Codec.KeyType.Recovery,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                IDX,
                NEW_SEED,
                NEW_HASH
            ),
            _expected(keccak256("quip.digest.replaceRecoveryKeyAt"))
        );
    }

    function test_exposed_replaceKeyAtDigest_verificationMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_replaceKeyAtDigest(
                Codec.KeyType.Verification,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                IDX,
                NEW_SEED,
                NEW_HASH
            ),
            _expected(keccak256("quip.digest.replaceVerificationKeyAt"))
        );
    }

    /// @dev Same inputs under different kinds must produce distinct digests —
    ///      this is the cross-type replay-prevention property (indexed variant).
    function test_exposed_replaceKeyAtDigest_kindsAreDistinct() public view {
        bytes32 tx_ = codec.exposed_replaceKeyAtDigest(
            Codec.KeyType.Transaction,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            IDX,
            NEW_SEED,
            NEW_HASH
        );
        bytes32 rec = codec.exposed_replaceKeyAtDigest(
            Codec.KeyType.Recovery,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            IDX,
            NEW_SEED,
            NEW_HASH
        );
        bytes32 ver = codec.exposed_replaceKeyAtDigest(
            Codec.KeyType.Verification,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            IDX,
            NEW_SEED,
            NEW_HASH
        );
        assertTrue(tx_ != rec);
        assertTrue(tx_ != ver);
        assertTrue(rec != ver);
    }

    function test_exposed_replaceKeyAtDigest_differsByIndex() public view {
        bytes32 a = codec.exposed_replaceKeyAtDigest(
            Codec.KeyType.Transaction,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            1,
            NEW_SEED,
            NEW_HASH
        );
        bytes32 b = codec.exposed_replaceKeyAtDigest(
            Codec.KeyType.Transaction,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            2,
            NEW_SEED,
            NEW_HASH
        );
        assertTrue(a != b);
    }

    function test_exposed_replaceKeyAtDigest_differsByNewKey() public view {
        bytes32 a = codec.exposed_replaceKeyAtDigest(
            Codec.KeyType.Transaction,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            IDX,
            bytes32(uint256(0x111)),
            NEW_HASH
        );
        bytes32 b = codec.exposed_replaceKeyAtDigest(
            Codec.KeyType.Transaction,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            IDX,
            bytes32(uint256(0x222)),
            NEW_HASH
        );
        assertTrue(a != b);
    }
}
