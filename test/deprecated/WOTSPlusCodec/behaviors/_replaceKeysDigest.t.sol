// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";

contract WOTSPlusCodec__replaceKeysDigest is WOTSPlusCodecTest {
    address constant WALLET = address(0xC0FFEE);
    uint256 constant CHAIN_ID = 31337;
    uint256 constant N = 3;
    bytes32 constant S1 = bytes32(uint256(0xA1));
    bytes32 constant H1 = bytes32(uint256(0xA2));
    bytes32 constant S2 = bytes32(uint256(0xB1));
    bytes32 constant H2 = bytes32(uint256(0xB2));
    bytes32 constant OLD_HASH = bytes32(uint256(0xC1));
    bytes32 constant NEW_HASH = bytes32(uint256(0xC2));

    function _expected(bytes32 tag) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            tag, bytes32(CHAIN_ID), bytes32(uint256(uint160(WALLET))), bytes32(N), S1, H1, S2, H2, OLD_HASH, NEW_HASH
        );
    }

    /*──────── per-combo tag selection matches manual hash ────────*/

    function test_exposed_replaceKeysDigest_txSign_txTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_replaceKeysDigest(
                Codec.KeyType.Transaction,
                Codec.KeyType.Transaction,
                N,
                WALLET,
                CHAIN_ID,
                S1,
                H1,
                S2,
                H2,
                OLD_HASH,
                NEW_HASH
            ),
            _expected(keccak256("quip.digest.replaceKeys.txSign.tx"))
        );
    }

    function test_exposed_replaceKeysDigest_txSign_recoveryTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_replaceKeysDigest(
                Codec.KeyType.Recovery,
                Codec.KeyType.Transaction,
                N,
                WALLET,
                CHAIN_ID,
                S1,
                H1,
                S2,
                H2,
                OLD_HASH,
                NEW_HASH
            ),
            _expected(keccak256("quip.digest.replaceKeys.txSign.recovery"))
        );
    }

    function test_exposed_replaceKeysDigest_txSign_verifyTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_replaceKeysDigest(
                Codec.KeyType.Verification,
                Codec.KeyType.Transaction,
                N,
                WALLET,
                CHAIN_ID,
                S1,
                H1,
                S2,
                H2,
                OLD_HASH,
                NEW_HASH
            ),
            _expected(keccak256("quip.digest.replaceKeys.txSign.verification"))
        );
    }

    function test_exposed_replaceKeysDigest_recSign_txTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_replaceKeysDigest(
                Codec.KeyType.Transaction,
                Codec.KeyType.Recovery,
                N,
                WALLET,
                CHAIN_ID,
                S1,
                H1,
                S2,
                H2,
                OLD_HASH,
                NEW_HASH
            ),
            _expected(keccak256("quip.digest.replaceKeys.recoverySign.tx"))
        );
    }

    function test_exposed_replaceKeysDigest_recSign_recoveryTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_replaceKeysDigest(
                Codec.KeyType.Recovery, Codec.KeyType.Recovery, N, WALLET, CHAIN_ID, S1, H1, S2, H2, OLD_HASH, NEW_HASH
            ),
            _expected(keccak256("quip.digest.replaceKeys.recoverySign.recovery"))
        );
    }

    function test_exposed_replaceKeysDigest_recSign_verifyTarget_matchesManualHash() public view {
        assertEq(
            codec.exposed_replaceKeysDigest(
                Codec.KeyType.Verification,
                Codec.KeyType.Recovery,
                N,
                WALLET,
                CHAIN_ID,
                S1,
                H1,
                S2,
                H2,
                OLD_HASH,
                NEW_HASH
            ),
            _expected(keccak256("quip.digest.replaceKeys.recoverySign.verification"))
        );
    }

    /*──────────────── input-sensitivity / distinctness ────────────────*/

    function test_exposed_replaceKeysDigest_deterministic() public view {
        bytes32 d1 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery, 3);
        bytes32 d2 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery, 3);
        assertEq(d1, d2);
    }

    /// @dev Property: each of the 6 valid (signingKind, kind) combos produces
    ///      a distinct digest from every other combo. Valid signingKinds are
    ///      Transaction and Recovery (Verification is rejected at the wallet
    ///      layer); kind spans all three. Catches tag-table errors where two
    ///      combos collide on the same tag.
    function test_exposed_replaceKeysDigest_allSixCombosDistinct() public view {
        bytes32[6] memory ds;
        // signingKind = Transaction
        ds[0] = _digest(Codec.KeyType.Transaction, Codec.KeyType.Transaction, 1);
        ds[1] = _digest(Codec.KeyType.Recovery, Codec.KeyType.Transaction, 1);
        ds[2] = _digest(Codec.KeyType.Verification, Codec.KeyType.Transaction, 1);
        // signingKind = Recovery
        ds[3] = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery, 1);
        ds[4] = _digest(Codec.KeyType.Recovery, Codec.KeyType.Recovery, 1);
        ds[5] = _digest(Codec.KeyType.Verification, Codec.KeyType.Recovery, 1);
        for (uint256 i = 0; i < 6; i++) {
            for (uint256 j = i + 1; j < 6; j++) {
                assertTrue(ds[i] != ds[j]);
            }
        }
    }

    function test_exposed_replaceKeysDigest_changesOnKindChange() public view {
        bytes32 d1 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery, 3);
        bytes32 d2 = _digest(Codec.KeyType.Recovery, Codec.KeyType.Recovery, 3);
        assertTrue(d1 != d2);
    }

    function test_exposed_replaceKeysDigest_changesOnSigningKindChange() public view {
        bytes32 d1 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery, 3);
        bytes32 d2 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Transaction, 3);
        assertTrue(d1 != d2);
    }

    function test_exposed_replaceKeysDigest_changesOnNChange() public view {
        bytes32 d1 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery, 3);
        bytes32 d2 = _digest(Codec.KeyType.Transaction, Codec.KeyType.Recovery, 4);
        assertTrue(d1 != d2);
    }

    function test_exposed_replaceKeysDigest_changesOnWalletChange() public view {
        bytes32 d1 = _digestAt(WALLET, CHAIN_ID);
        bytes32 d2 = _digestAt(address(0xBEEF), CHAIN_ID);
        assertTrue(d1 != d2);
    }

    function test_exposed_replaceKeysDigest_changesOnChainIdChange() public view {
        bytes32 d1 = _digestAt(WALLET, CHAIN_ID);
        bytes32 d2 = _digestAt(WALLET, CHAIN_ID + 1);
        assertTrue(d1 != d2);
    }

    function test_exposed_replaceKeysDigest_changesOnKeysHashChange() public view {
        bytes32 d1 = codec.exposed_replaceKeysDigest(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            3,
            WALLET,
            CHAIN_ID,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6))
        );
        bytes32 dOld = codec.exposed_replaceKeysDigest(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            3,
            WALLET,
            CHAIN_ID,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(999)),
            bytes32(uint256(6))
        );
        bytes32 dNew = codec.exposed_replaceKeysDigest(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            3,
            WALLET,
            CHAIN_ID,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(999))
        );
        assertTrue(d1 != dOld);
        assertTrue(d1 != dNew);
        assertTrue(dOld != dNew);
    }

    function _digest(Codec.KeyType kind, Codec.KeyType signingKind, uint256 n) internal view returns (bytes32) {
        return codec.exposed_replaceKeysDigest(
            kind,
            signingKind,
            n,
            WALLET,
            CHAIN_ID,
            bytes32(uint256(0xA1)),
            bytes32(uint256(0xA2)),
            bytes32(uint256(0xB1)),
            bytes32(uint256(0xB2)),
            bytes32(uint256(0xC1)),
            bytes32(uint256(0xC2))
        );
    }

    function _digestAt(address wallet, uint256 chainId) internal view returns (bytes32) {
        return codec.exposed_replaceKeysDigest(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            3,
            wallet,
            chainId,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6))
        );
    }
}
