// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeWithdrawDeposit is WOTSPlusCodecTest {
    function test_exposed_decodeWithdrawDeposit_decodesCorrectly() public view {
        bytes memory base = _buildChangePqOwnerPayload(10);
        address to = address(0xBEEF);
        uint256 amount = 1.5 ether;
        bytes memory payload = abi.encodePacked(base, bytes32(uint256(uint160(to))), amount);

        (
            WOTSPlus.WinternitzAddress memory pq,,
            address decodedTo,
            uint256 decodedAmount
        ) = codec.exposed_decodeWithdrawDeposit(payload);

        assertEq(pq.publicSeed, bytes32(uint256(10)));
        assertEq(pq.publicKeyHash, bytes32(uint256(11)));
        assertEq(decodedTo, to);
        assertEq(decodedAmount, amount);
    }

    function test_exposed_decodeWithdrawDeposit_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeWithdrawDeposit("");
    }
}
