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

    /*──────────────── per-kind/mode tag matches manual hash ─────────────*/

    function test_exposed_keysetDigest_addTransactionMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_keysetDigest(
                Codec.KeyType.Transaction,
                false,
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

    function test_exposed_keysetDigest_addRecoveryMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_keysetDigest(
                Codec.KeyType.Recovery,
                false,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                KEYS_HASH
            ),
            _expected(keccak256("quip.digest.addRecoveryKeys"))
        );
    }

    function test_exposed_keysetDigest_refreshRecoveryMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_keysetDigest(
                Codec.KeyType.Recovery,
                true,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                KEYS_HASH
            ),
            _expected(keccak256("quip.digest.refreshRecoveryKeys"))
        );
    }

    function test_exposed_keysetDigest_addVerificationMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_keysetDigest(
                Codec.KeyType.Verification,
                false,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                KEYS_HASH
            ),
            _expected(keccak256("quip.digest.addVerificationKeys"))
        );
    }

    function test_exposed_keysetDigest_refreshVerificationMatchesManualHash()
        public
        view
    {
        assertEq(
            codec.exposed_keysetDigest(
                Codec.KeyType.Verification,
                true,
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                KEYS_HASH
            ),
            _expected(keccak256("quip.digest.refreshVerificationKeys"))
        );
    }

    /// @dev refresh-Transaction is contract-forbidden but the digest helper
    ///      doesn't enforce that — it returns the same digest as add-Transaction
    ///      since only ADD_TRANSACTION_KEYS_TAG exists. Locks down the
    ///      "replace bit is ignored for Transaction" behaviour so a future
    ///      refactor that introduces a REFRESH_TRANSACTION tag without
    ///      updating the wallet's RefreshTransactionForbidden guard would
    ///      surface here as a digest drift.
    function test_exposed_keysetDigest_refreshTransactionIgnoresReplaceBit()
        public
        view
    {
        bytes32 add = codec.exposed_keysetDigest(
            Codec.KeyType.Transaction,
            false,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );
        bytes32 refresh = codec.exposed_keysetDigest(
            Codec.KeyType.Transaction,
            true,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );
        assertEq(add, refresh);
    }

    /*──────────────── cross-kind / cross-mode distinctness ──────────────*/

    /// @dev Same inputs under different (kind, replace) tuples must produce
    ///      distinct digests. This is the load-bearing replay-prevention
    ///      property — both cross-KIND (Recovery vs Verification) and
    ///      cross-MODE (add vs refresh of the same kind) must be enforced.
    function test_exposed_keysetDigest_allTagsAreDistinct() public view {
        bytes32 addTx = codec.exposed_keysetDigest(
            Codec.KeyType.Transaction,
            false,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );
        bytes32 addRec = codec.exposed_keysetDigest(
            Codec.KeyType.Recovery,
            false,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );
        bytes32 refRec = codec.exposed_keysetDigest(
            Codec.KeyType.Recovery,
            true,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );
        bytes32 addVer = codec.exposed_keysetDigest(
            Codec.KeyType.Verification,
            false,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );
        bytes32 refVer = codec.exposed_keysetDigest(
            Codec.KeyType.Verification,
            true,
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            KEYS_HASH
        );

        // Cross-kind distinctness.
        assertTrue(addTx != addRec);
        assertTrue(addTx != refRec);
        assertTrue(addTx != addVer);
        assertTrue(addTx != refVer);
        assertTrue(addRec != addVer);
        assertTrue(refRec != refVer);

        // Cross-mode distinctness (the audit fix — these used to be equal).
        assertTrue(addRec != refRec);
        assertTrue(addVer != refVer);
    }
}
