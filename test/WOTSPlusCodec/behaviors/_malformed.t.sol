// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__malformed is WOTSPlusCodecTest {
    // ---- Pure assembly decoders: revert on short input ----
    // The library decoders set calldata pointers via assembly without bounds-checking.
    // However, the harness must copy calldata→memory to return, and Solidity's
    // calldatacopy bounds-checks the source range, reverting on short payloads.

    function test_exposed_decodeInit_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeInit("");
    }

    function test_exposed_decodeInit_revertsWhen_truncatedPayload() public {
        // 64 bytes = pqOwner only, not enough for full 704-byte decode
        bytes memory payload = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert();
        codec.exposed_decodeInit(payload);
    }

    function test_exposed_decodeInit_extraBytes_ignored() public view {
        bytes memory payload = _buildInitPayload(42);
        // Append 96 extra bytes
        payload = abi.encodePacked(payload, bytes32(uint256(0xFF)), bytes32(uint256(0xFF)), bytes32(uint256(0xFF)));
        (WOTSPlus.WinternitzAddress memory pq,) = codec.exposed_decodeInit(payload);
        assertEq(pq.publicSeed, bytes32(uint256(42)));
    }

    function test_exposed_decodeUpgradeAuth_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeUpgradeAuth("");
    }

    function test_exposed_decodeUpgradeVerification_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeUpgradeVerification("");
    }

    function test_exposed_decodeChangePqOwner_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeChangePqOwner("");
    }

    function test_exposed_decodeRecoverWallet_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeRecoverWallet("");
    }

    // ---- decodeExecute: mixed (assembly + Solidity slice) ----

    function test_exposed_decodeExecute_revertsWhen_shortPayload() public {
        // 2200 bytes < 2272 minimum
        bytes memory payload = _filledBytes(2200);
        vm.expectRevert();
        codec.exposed_decodeExecute(payload);
    }

    function test_exposed_decodeExecute_exactMinLength_succeeds() public view {
        bytes memory payload = _filledBytes(2272);
        (,,,, bytes memory d) = codec.exposed_decodeExecute(payload);
        assertEq(d.length, 0);
    }

    // ---- decodeKeyManagement: assembly length underflow ----

    function test_exposed_decodeKeyManagement_revertsWhen_shortPayload() public {
        // < 2208 bytes: sub(payload.length, 2208) underflows → huge length → OOG
        bytes memory payload = _filledBytes(100);
        vm.expectRevert();
        codec.exposed_decodeKeyManagement(payload);
    }

    function test_exposed_decodeKeyManagement_exactMinLength_succeeds() public view {
        bytes memory payload = _filledBytes(2208);
        (,, WOTSPlus.WinternitzAddress[] memory keys) = codec.exposed_decodeKeyManagement(payload);
        assertEq(keys.length, 0);
    }

    function test_exposed_decodeKeyManagement_unalignedLength() public view {
        // 2240 bytes = 2208 + 32; 32/64 = 0 (integer division truncates)
        bytes memory payload = _filledBytes(2240);
        (,, WOTSPlus.WinternitzAddress[] memory keys) = codec.exposed_decodeKeyManagement(payload);
        assertEq(keys.length, 0);
    }

    // ---- decodeUpgradeMigration: Solidity indexing ----

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
        // 0xAB != 0, so shouldMigrate = true
        assertTrue(shouldMigrate);
        assertEq(mp.length, 704);
    }

    function test_exposed_decodeUpgradeMigration_extraBytes_succeeds() public view {
        bytes memory payload = _filledBytes(6000);
        (, bytes memory mp) = codec.exposed_decodeUpgradeMigration(payload);
        assertEq(mp.length, 704);
    }
}
