// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeExecute is WOTSPlusCodecTest {
    function test_exposed_decodeExecute_decodesFixedFields() public view {
        address target = address(0xBEEF);
        uint256 value = 1.5 ether;
        bytes memory opdata = hex"deadbeef";
        bytes memory payload = _buildExecutePayload(10, target, value, opdata);

        (
            WOTSPlus.WinternitzAddress memory pq,
            ,
            address t,
            uint256 v,
            bytes memory d
        ) = codec.exposed_decodeExecute(payload);

        assertEq(pq.publicSeed, bytes32(uint256(10)));
        assertEq(t, target);
        assertEq(v, value);
        assertEq(d, opdata);
    }

    function test_exposed_decodeExecute_decodesEmptyData() public view {
        bytes memory payload = _buildExecutePayload(10, address(0x1), 0, "");
        (,,,, bytes memory d) = codec.exposed_decodeExecute(payload);
        assertEq(d.length, 0);
    }

    function test_exposed_decodeExecute_decodesDynamicData() public view {
        bytes memory opdata = hex"aabbccdd11223344";
        bytes memory payload = _buildExecutePayload(10, address(0x1), 0, opdata);
        (,,,, bytes memory d) = codec.exposed_decodeExecute(payload);
        assertEq(d, opdata);
    }

    function test_exposed_decodeExecute_revertsWhen_shortPayload() public {
        bytes memory payload = _filledBytes(2200);
        vm.expectRevert();
        codec.exposed_decodeExecute(payload);
    }

    function test_exposed_decodeExecute_exactMinLength_succeeds() public view {
        bytes memory payload = _filledBytes(2272);
        (,,,, bytes memory d) = codec.exposed_decodeExecute(payload);
        assertEq(d.length, 0);
    }
}
