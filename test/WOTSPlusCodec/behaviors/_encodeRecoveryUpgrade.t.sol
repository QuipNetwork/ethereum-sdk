// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeRecoveryUpgrade is WOTSPlusCodecTest {
    function test_exposed_encodeRecoveryUpgrade_producesCorrectLength()
        public
        view
    {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzAddress memory verifier = WOTSPlus.WinternitzAddress(
            bytes32(uint256(5)),
            bytes32(uint256(6))
        );
        WOTSPlus.WinternitzElements memory pqSig;
        WOTSPlus.WinternitzElements memory verifySig;
        bytes memory encoded = codec.exposed_encodeRecoveryUpgrade(
            cur,
            nxt,
            pqSig,
            verifier,
            verifySig
        );
        assertEq(encoded.length, 4480);
    }

    function test_exposed_encodeRecoveryUpgrade_roundtripsAuth() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(10)),
            bytes32(uint256(11))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(12)),
            bytes32(uint256(13))
        );
        WOTSPlus.WinternitzElements memory pqSig;
        for (uint256 i = 0; i < 67; i++) pqSig.elements[i] = bytes32(i + 200);
        WOTSPlus.WinternitzAddress memory verifier = WOTSPlus.WinternitzAddress(
            bytes32(uint256(20)),
            bytes32(uint256(21))
        );
        WOTSPlus.WinternitzElements memory verifySig;

        bytes memory encoded = codec.exposed_encodeRecoveryUpgrade(
            cur,
            nxt,
            pqSig,
            verifier,
            verifySig
        );
        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig
        ) = codec.exposed_decodeRecoveryUpgradeAuth(encoded);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dCur.publicKeyHash, cur.publicKeyHash);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], pqSig.elements[i]);
        }
    }

    function test_exposed_encodeRecoveryUpgrade_roundtripsVerification()
        public
        view
    {
        WOTSPlus.WinternitzAddress memory zero;
        WOTSPlus.WinternitzElements memory pqSig;
        WOTSPlus.WinternitzAddress memory verifier = WOTSPlus.WinternitzAddress(
            bytes32(uint256(77)),
            bytes32(uint256(78))
        );
        WOTSPlus.WinternitzElements memory verifySig;
        for (uint256 i = 0; i < 67; i++)
            verifySig.elements[i] = bytes32(i + 900);

        bytes memory encoded = codec.exposed_encodeRecoveryUpgrade(
            zero,
            zero,
            pqSig,
            verifier,
            verifySig
        );
        (
            WOTSPlus.WinternitzAddress memory dVerifier,
            WOTSPlus.WinternitzElements memory dVerifySig
        ) = codec.exposed_decodeRecoveryUpgradeVerification(encoded);

        assertEq(dVerifier.publicSeed, verifier.publicSeed);
        assertEq(dVerifier.publicKeyHash, verifier.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dVerifySig.elements[i], verifySig.elements[i]);
        }
    }

    /// @dev Property: encode → decode preserves every field for any seed,
    ///      across both halves of the 4480-byte recoveryUpgrade payload.
    ///      The auth and verification decoders share the same payload but
    ///      consume different offsets, so we verify both decoders see the
    ///      same encoder output.
    function testFuzz_exposed_encodeRecoveryUpgrade_roundtrips(
        bytes32 seed
    ) public view {
        WOTSPlus.WinternitzAddress memory cur = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory nxt = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzElements memory pqSig = _fuzzWinternitzElements(seed);
        WOTSPlus.WinternitzAddress memory verifier = _fuzzWinternitzAddress(seed, 2);
        WOTSPlus.WinternitzElements memory verifySig = _fuzzWinternitzElementsAlt(seed);

        bytes memory encoded = codec.exposed_encodeRecoveryUpgrade(
            cur,
            nxt,
            pqSig,
            verifier,
            verifySig
        );
        assertEq(encoded.length, 4480);

        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dPqSig
        ) = codec.exposed_decodeRecoveryUpgradeAuth(encoded);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dCur.publicKeyHash, cur.publicKeyHash);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dPqSig.elements[i], pqSig.elements[i]);
        }

        (
            WOTSPlus.WinternitzAddress memory dVerifier,
            WOTSPlus.WinternitzElements memory dVerifySig
        ) = codec.exposed_decodeRecoveryUpgradeVerification(encoded);

        assertEq(dVerifier.publicSeed, verifier.publicSeed);
        assertEq(dVerifier.publicKeyHash, verifier.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dVerifySig.elements[i], verifySig.elements[i]);
        }
    }
}
