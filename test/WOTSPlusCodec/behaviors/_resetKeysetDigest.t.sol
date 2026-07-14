// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";

contract WOTSPlusCodec__resetKeysetDigest is WOTSPlusCodecTest {
    address constant WALLET = address(0xC0FFEE);
    uint256 constant CHAIN_ID = 31337;
    bytes32 constant S1 = bytes32(uint256(0xA1));
    bytes32 constant H1 = bytes32(uint256(0xA2));
    bytes32 constant S2 = bytes32(uint256(0xB1));
    bytes32 constant H2 = bytes32(uint256(0xB2));
    bytes32 constant NEW_HASH = bytes32(uint256(0xC2));

    function _expected(bytes32 tag) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(tag, bytes32(CHAIN_ID), bytes32(uint256(uint160(WALLET))), S1, H1, S2, H2, NEW_HASH);
    }

    /*──────── per-combo tag selection matches manual hash ────────*/

    function test_exposed_resetKeysetDigest_txSign_txTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_resetKeysetDigest(
                Codec.KeyType.Transaction, Codec.KeyType.Transaction, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH
            ),
            _expected(keccak256("quip.digest.resetKeyset.txSign.tx"))
        );
    }

    function test_exposed_resetKeysetDigest_txSign_recoveryTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_resetKeysetDigest(
                Codec.KeyType.Recovery, Codec.KeyType.Transaction, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH
            ),
            _expected(keccak256("quip.digest.resetKeyset.txSign.recovery"))
        );
    }

    function test_exposed_resetKeysetDigest_txSign_verifyTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_resetKeysetDigest(
                Codec.KeyType.Verification, Codec.KeyType.Transaction, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH
            ),
            _expected(keccak256("quip.digest.resetKeyset.txSign.verification"))
        );
    }

    function test_exposed_resetKeysetDigest_recSign_txTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_resetKeysetDigest(
                Codec.KeyType.Transaction, Codec.KeyType.Recovery, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH
            ),
            _expected(keccak256("quip.digest.resetKeyset.recoverySign.tx"))
        );
    }

    function test_exposed_resetKeysetDigest_recSign_recoveryTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_resetKeysetDigest(
                Codec.KeyType.Recovery, Codec.KeyType.Recovery, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH
            ),
            _expected(keccak256("quip.digest.resetKeyset.recoverySign.recovery"))
        );
    }

    function test_exposed_resetKeysetDigest_recSign_verifyTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_resetKeysetDigest(
                Codec.KeyType.Verification, Codec.KeyType.Recovery, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH
            ),
            _expected(keccak256("quip.digest.resetKeyset.recoverySign.verification"))
        );
    }

    /*──────────────── input-sensitivity / distinctness ────────────────*/

    function test_exposed_resetKeysetDigest_deterministic() public view {
        bytes32 d1 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery);
        bytes32 d2 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery);
        assertEq(d1, d2);
    }

    /// @dev Property: each of the 6 valid (signingKind, kind) combos produces
    ///      a distinct digest from every other combo. Valid signingKinds are
    ///      Transaction and Recovery (Verification is rejected at the wallet
    ///      layer); kind spans all three.
    function test_exposed_resetKeysetDigest_allSixCombosDistinct() public view {
        bytes32[6] memory ds;
        ds[0] = _digest(Codec.KeyType.Transaction, Codec.KeyType.Transaction);
        ds[1] = _digest(Codec.KeyType.Recovery, Codec.KeyType.Transaction);
        ds[2] = _digest(Codec.KeyType.Verification, Codec.KeyType.Transaction);
        ds[3] = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery);
        ds[4] = _digest(Codec.KeyType.Recovery, Codec.KeyType.Recovery);
        ds[5] = _digest(Codec.KeyType.Verification, Codec.KeyType.Recovery);
        for (uint256 i = 0; i < 6; i++) {
            for (uint256 j = i + 1; j < 6; j++) {
                assertTrue(ds[i] != ds[j]);
            }
        }
    }

    /// @dev Property: resetKeyset digests must not collide with replaceKeys
    ///      digests for the same `(signingKind, kind, wallet, chain, keys)` —
    ///      distinct tag families prevent a resetKeyset signature from being
    ///      replayed as a replaceKeys signature or vice versa.
    function test_exposed_resetKeysetDigest_distinctFromReplaceKeys() public view {
        bytes32 reset = codec.exposed_resetKeysetDigest(
            Codec.KeyType.Transaction, Codec.KeyType.Transaction, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH
        );
        bytes32 replace = codec.exposed_replaceKeysDigest(
            Codec.KeyType.Transaction,
            Codec.KeyType.Transaction,
            10,
            WALLET,
            CHAIN_ID,
            S1,
            H1,
            S2,
            H2,
            bytes32(0),
            NEW_HASH
        );
        assertTrue(reset != replace);
    }

    function test_exposed_resetKeysetDigest_changesOnKindChange() public view {
        bytes32 d1 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery);
        bytes32 d2 = _digest(Codec.KeyType.Recovery, Codec.KeyType.Recovery);
        assertTrue(d1 != d2);
    }

    function test_exposed_resetKeysetDigest_changesOnSigningKindChange() public view {
        bytes32 d1 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery);
        bytes32 d2 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Transaction);
        assertTrue(d1 != d2);
    }

    function test_exposed_resetKeysetDigest_changesOnWalletChange() public view {
        bytes32 d1 = codec.exposed_resetKeysetDigest(
            Codec.KeyType.Transaction, Codec.KeyType.Recovery, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH
        );
        bytes32 d2 = codec.exposed_resetKeysetDigest(
            Codec.KeyType.Transaction, Codec.KeyType.Recovery, address(0xBEEF), CHAIN_ID, S1, H1, S2, H2, NEW_HASH
        );
        assertTrue(d1 != d2);
    }

    function test_exposed_resetKeysetDigest_changesOnChainIdChange() public view {
        bytes32 d1 = codec.exposed_resetKeysetDigest(
            Codec.KeyType.Transaction, Codec.KeyType.Recovery, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH
        );
        bytes32 d2 = codec.exposed_resetKeysetDigest(
            Codec.KeyType.Transaction, Codec.KeyType.Recovery, WALLET, CHAIN_ID + 1, S1, H1, S2, H2, NEW_HASH
        );
        assertTrue(d1 != d2);
    }

    function test_exposed_resetKeysetDigest_changesOnNewKeysHashChange() public view {
        bytes32 d1 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery);
        bytes32 d2 = codec.exposed_resetKeysetDigest(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            WALLET,
            CHAIN_ID,
            S1,
            H1,
            S2,
            H2,
            bytes32(uint256(0xDEADBEEF))
        );
        assertTrue(d1 != d2);
    }

    function _digest(Codec.KeyType kind, Codec.KeyType signingKind) internal view returns (bytes32) {
        return codec.exposed_resetKeysetDigest(kind, signingKind, WALLET, CHAIN_ID, S1, H1, S2, H2, NEW_HASH);
    }
}
