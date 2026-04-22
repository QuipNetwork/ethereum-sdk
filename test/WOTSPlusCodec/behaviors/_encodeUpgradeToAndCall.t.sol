// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeUpgradeToAndCall is WOTSPlusCodecTest {
    function _samplePair()
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt
        )
    {
        cur = WOTSPlus.WinternitzAddress(bytes32(uint256(1)), bytes32(uint256(2)));
        nxt = WOTSPlus.WinternitzAddress(bytes32(uint256(3)), bytes32(uint256(4)));
    }

    function test_exposed_encodeUpgradeToAndCall_producesCorrectLengthMigrateTrue()
        public
        view
    {
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt
        ) = _samplePair();
        WOTSPlus.WinternitzAddress memory verifier;
        WOTSPlus.WinternitzElements memory pqSig;
        WOTSPlus.WinternitzElements memory verifySig;
        bytes memory migrator = new bytes(1088);

        bytes memory encoded = codec.exposed_encodeUpgradeToAndCall(
            cur,
            nxt,
            pqSig,
            verifier,
            verifySig,
            true,
            migrator
        );
        // 64 + 64 + 2144 + 64 + 2144 + 1 + 1088 = 5569
        assertEq(encoded.length, 5569);
    }

    function test_exposed_encodeUpgradeToAndCall_producesCorrectLengthMigrateFalse()
        public
        view
    {
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt
        ) = _samplePair();
        WOTSPlus.WinternitzAddress memory verifier;
        WOTSPlus.WinternitzElements memory pqSig;
        WOTSPlus.WinternitzElements memory verifySig;
        bytes memory migrator = new bytes(1088);

        bytes memory encoded = codec.exposed_encodeUpgradeToAndCall(
            cur,
            nxt,
            pqSig,
            verifier,
            verifySig,
            false,
            migrator
        );
        assertEq(encoded.length, 5569);
        // shouldMigrate byte at offset 4480 must be 0x00.
        assertEq(uint8(encoded[4480]), 0);
    }

    function test_exposed_encodeUpgradeToAndCall_migrateTrueByte() public view {
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt
        ) = _samplePair();
        WOTSPlus.WinternitzAddress memory verifier;
        WOTSPlus.WinternitzElements memory pqSig;
        WOTSPlus.WinternitzElements memory verifySig;
        bytes memory migrator = new bytes(1088);

        bytes memory encoded = codec.exposed_encodeUpgradeToAndCall(
            cur,
            nxt,
            pqSig,
            verifier,
            verifySig,
            true,
            migrator
        );
        assertEq(uint8(encoded[4480]), 1);
    }

    function test_exposed_encodeUpgradeToAndCall_roundtripsAuth() public view {
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt
        ) = _samplePair();
        WOTSPlus.WinternitzAddress memory verifier = WOTSPlus.WinternitzAddress(
            bytes32(uint256(50)),
            bytes32(uint256(51))
        );
        WOTSPlus.WinternitzElements memory pqSig;
        for (uint256 i = 0; i < 67; i++) pqSig.elements[i] = bytes32(i + 1000);
        WOTSPlus.WinternitzElements memory verifySig;
        for (uint256 i = 0; i < 67; i++)
            verifySig.elements[i] = bytes32(i + 3000);
        bytes memory migrator = new bytes(1088);

        bytes memory encoded = codec.exposed_encodeUpgradeToAndCall(
            cur,
            nxt,
            pqSig,
            verifier,
            verifySig,
            true,
            migrator
        );
        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig
        ) = codec.exposed_decodeUpgradeAuth(encoded);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], pqSig.elements[i]);
        }
    }

    function test_exposed_encodeUpgradeToAndCall_roundtripsMigration()
        public
        view
    {
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt
        ) = _samplePair();
        WOTSPlus.WinternitzAddress memory verifier;
        WOTSPlus.WinternitzElements memory pqSig;
        WOTSPlus.WinternitzElements memory verifySig;
        bytes memory migrator = _buildInitPayload(99);

        bytes memory encoded = codec.exposed_encodeUpgradeToAndCall(
            cur,
            nxt,
            pqSig,
            verifier,
            verifySig,
            true,
            migrator
        );
        (bool shouldMigrate, bytes memory dMigrator) = codec
            .exposed_decodeUpgradeMigration(encoded);

        assertTrue(shouldMigrate);
        assertEq(dMigrator.length, 1088);
        assertEq(dMigrator, migrator);
    }
}
