// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";

contract WOTSPlusCodec__decodeUpgradeMigration is WOTSPlusCodecTest {
    function test_exposed_decodeUpgradeMigration_decodesTrue() public view {
        bytes memory payload = _buildUpgradePayload(1);
        // shouldMigrate byte was set to 0x01 in _buildUpgradePayload
        (bool shouldMigrate,) = codec.exposed_decodeUpgradeMigration(payload);
        assertTrue(shouldMigrate);
    }

    function test_exposed_decodeUpgradeMigration_decodesFalse() public view {
        bytes memory payload = _buildUpgradePayload(1);
        // Overwrite the shouldMigrate byte at position 4416 to 0x00
        payload[4416] = 0x00;
        (bool shouldMigrate,) = codec.exposed_decodeUpgradeMigration(payload);
        assertFalse(shouldMigrate);
    }

    function test_exposed_decodeUpgradeMigration_extractsPayload() public view {
        bytes memory payload = _buildUpgradePayload(1);
        (, bytes memory migratorPayload) = codec.exposed_decodeUpgradeMigration(payload);
        assertEq(migratorPayload.length, 704);
        // Verify first 32 bytes of migratorPayload match the init payload built with seed+5000
        bytes32 expected = bytes32(uint256(1 + 5000));
        bytes32 actual;
        assembly { actual := mload(add(migratorPayload, 32)) }
        assertEq(actual, expected);
    }

    function test_exposed_decodeUpgradeMigration_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeUpgradeMigration("");
    }

    function test_exposed_decodeUpgradeMigration_revertsWhen_shortPayload() public {
        vm.expectRevert();
        codec.exposed_decodeUpgradeMigration(_filledBytes(4416));
    }

    function test_exposed_decodeUpgradeMigration_revertsWhen_truncatedMigratorPayload() public {
        vm.expectRevert();
        codec.exposed_decodeUpgradeMigration(_filledBytes(5000));
    }

    function test_exposed_decodeUpgradeMigration_exactLength_succeeds() public view {
        bytes memory payload = _filledBytes(5121);
        (bool shouldMigrate, bytes memory mp) = codec.exposed_decodeUpgradeMigration(payload);
        assertTrue(shouldMigrate);
        assertEq(mp.length, 704);
    }

    function test_exposed_decodeUpgradeMigration_extraBytes_succeeds() public view {
        bytes memory payload = _filledBytes(6000);
        (, bytes memory mp) = codec.exposed_decodeUpgradeMigration(payload);
        assertEq(mp.length, 704);
    }
}
