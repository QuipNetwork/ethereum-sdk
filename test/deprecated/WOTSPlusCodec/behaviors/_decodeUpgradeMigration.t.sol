// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

contract WOTSPlusCodec__decodeUpgradeMigration is WOTSPlusCodecTest {
    function test_exposed_decodeUpgradeMigration_decodesTrue() public view {
        bytes memory payload = _buildUpgradePayload(1);
        // shouldMigrate byte was set to 0x01 in _buildUpgradePayload
        (bool shouldMigrate,) = codec.exposed_decodeUpgradeMigration(payload);
        assertTrue(shouldMigrate);
    }

    function test_exposed_decodeUpgradeMigration_decodesFalse() public view {
        bytes memory payload = _buildUpgradePayload(1);
        // Overwrite the shouldMigrate byte at position 4480 to 0x00
        payload[4480] = 0x00;
        (bool shouldMigrate,) = codec.exposed_decodeUpgradeMigration(payload);
        assertFalse(shouldMigrate);
    }

    function test_exposed_decodeUpgradeMigration_extractsPayload() public view {
        bytes memory payload = _buildUpgradePayload(1);
        (, bytes memory migratorPayload) = codec.exposed_decodeUpgradeMigration(payload);
        assertEq(migratorPayload.length, 2048);
        // First 32 bytes of migratorPayload are the disaster recovery key's publicSeed,
        // seeded as (initSeed + 500) where initSeed = 1 + 5000.
        bytes32 expected = bytes32(uint256(1 + 5000 + 500));
        bytes32 actual;
        assembly {
            actual := mload(add(migratorPayload, 32))
        }
        assertEq(actual, expected);
    }

    function test_exposed_decodeUpgradeMigration_revertsWhen_emptyPayload() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 6529, 0));
        codec.exposed_decodeUpgradeMigration("");
    }

    function test_exposed_decodeUpgradeMigration_revertsWhen_shortPayload() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 6529, 4480));
        codec.exposed_decodeUpgradeMigration(_filledBytes(4480));
    }

    function test_exposed_decodeUpgradeMigration_revertsWhen_truncatedMigratorPayload() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 6529, 5000));
        codec.exposed_decodeUpgradeMigration(_filledBytes(5000));
    }

    function test_exposed_decodeUpgradeMigration_exactLength_succeeds() public view {
        bytes memory payload = _filledBytes(6529);
        // `_filledBytes` writes 0xAB everywhere, including byte 4480 — but
        // the strict shouldMigrate check rejects anything outside {0x00,
        // 0x01}. Overwrite byte 4480 to a valid sentinel so this test
        // exercises the length-only branch without crossing the
        // byte-range check.
        payload[4480] = 0x01;
        (bool shouldMigrate, bytes memory mp) = codec.exposed_decodeUpgradeMigration(payload);
        assertTrue(shouldMigrate);
        assertEq(mp.length, 2048);
    }

    function test_exposed_decodeUpgradeMigration_revertsWhen_extraBytes() public {
        bytes memory payload = _filledBytes(6000);
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 6529, 6000));
        codec.exposed_decodeUpgradeMigration(payload);
    }

    /// @dev Property: any payload length other than 6529 reverts.
    function testFuzz_exposed_decodeUpgradeMigration_revertsWhen_wrongLength(uint256 len) public {
        len = bound(len, 0, 9000);
        vm.assume(len != 6529);
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 6529, len));
        codec.exposed_decodeUpgradeMigration(_filledBytes(len));
    }

    /// @dev The shouldMigrate byte is contractually 0x00 or 0x01. 0x02
    ///      onward must revert with `MalformedPayload(1, badByte)` — without
    ///      this strict check, a malformed off-chain encoder could smuggle
    ///      shouldMigrate=true via any non-zero byte (the prior
    ///      `uint8(...) != 0` semantics).
    function test_exposed_decodeUpgradeMigration_revertsWhen_shouldMigrateByte_0x02() public {
        bytes memory payload = _filledBytes(6529);
        payload[4480] = 0x02;
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 1, 2));
        codec.exposed_decodeUpgradeMigration(payload);
    }

    function test_exposed_decodeUpgradeMigration_revertsWhen_shouldMigrateByte_0xff() public {
        bytes memory payload = _filledBytes(6529);
        payload[4480] = 0xff;
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 1, 255));
        codec.exposed_decodeUpgradeMigration(payload);
    }

    /// @dev Positive sentinel test: 0x00 decodes to shouldMigrate=false,
    ///      complementing `_decodesFalse` above (which uses the encoder
    ///      path) by going through the raw-byte branch.
    function test_exposed_decodeUpgradeMigration_shouldMigrateByte_0x00_decodesFalse() public view {
        bytes memory payload = _filledBytes(6529);
        payload[4480] = 0x00;
        (bool shouldMigrate,) = codec.exposed_decodeUpgradeMigration(payload);
        assertFalse(shouldMigrate);
    }

    /// @dev Property: only 0x00 and 0x01 are accepted at byte 4480; every
    ///      other value reverts with `MalformedPayload(1, badByte)`.
    function testFuzz_exposed_decodeUpgradeMigration_revertsWhen_shouldMigrateByteOutOfRange(uint8 badByte) public {
        vm.assume(badByte > 1);
        bytes memory payload = _filledBytes(6529);
        payload[4480] = bytes1(badByte);
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 1, uint256(badByte)));
        codec.exposed_decodeUpgradeMigration(payload);
    }
}
