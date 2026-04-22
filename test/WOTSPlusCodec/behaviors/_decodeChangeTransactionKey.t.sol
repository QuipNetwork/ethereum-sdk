// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeChangeTransactionKey is WOTSPlusCodecTest {
    function test_exposed_decodeChangeTransactionKey_decodesCurrentKey()
        public
        view
    {
        bytes memory payload = _buildChangeTransactionKeyPayload(7);
        (WOTSPlus.WinternitzAddress memory cur, , ) = codec
            .exposed_decodeChangeTransactionKey(payload);
        assertEq(cur.publicSeed, bytes32(uint256(7)));
        assertEq(cur.publicKeyHash, bytes32(uint256(8)));
    }

    function test_exposed_decodeChangeTransactionKey_decodesNextKey()
        public
        view
    {
        bytes memory payload = _buildChangeTransactionKeyPayload(7);
        (, WOTSPlus.WinternitzAddress memory nxt, ) = codec
            .exposed_decodeChangeTransactionKey(payload);
        assertEq(nxt.publicSeed, bytes32(uint256(9)));
        assertEq(nxt.publicKeyHash, bytes32(uint256(10)));
    }

    function test_exposed_decodeChangeTransactionKey_decodesPqSig() public view {
        bytes memory payload = _buildChangeTransactionKeyPayload(7);
        (, , WOTSPlus.WinternitzElements memory sig) = codec
            .exposed_decodeChangeTransactionKey(payload);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(7 + 100 + i)));
        }
    }

    function test_exposed_decodeChangeTransactionKey_revertsWhen_emptyPayload()
        public
    {
        vm.expectRevert();
        codec.exposed_decodeChangeTransactionKey("");
    }
}
