// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeRecoverWallet is WOTSPlusCodecTest {
    function test_exposed_decodeRecoverWallet_decodesCorrectly() public view {
        bytes memory payload = _buildRecoverWalletPayload(20);
        (
            WOTSPlus.WinternitzAddress memory rk,
            WOTSPlus.WinternitzAddress memory newRk,
            WOTSPlus.WinternitzAddress memory pq,
            WOTSPlus.WinternitzElements memory sig
        ) = codec.exposed_decodeRecoverWallet(payload);

        assertEq(rk.publicSeed, bytes32(uint256(20)));
        assertEq(rk.publicKeyHash, bytes32(uint256(21)));
        assertEq(newRk.publicSeed, bytes32(uint256(25)));
        assertEq(newRk.publicKeyHash, bytes32(uint256(26)));
        assertEq(pq.publicSeed, bytes32(uint256(30)));
        assertEq(pq.publicKeyHash, bytes32(uint256(31)));
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(20 + 100 + i)));
        }
    }

    function test_exposed_decodeRecoverWallet_revertsWhen_emptyPayload()
        public
    {
        vm.expectRevert();
        codec.exposed_decodeRecoverWallet("");
    }
}
