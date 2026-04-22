// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeRecoverWallet is WOTSPlusCodecTest {
    function test_exposed_encodeRecoverWallet_producesCorrectLength()
        public
        view
    {
        WOTSPlus.WinternitzAddress memory rk = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory pq = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        bytes memory encoded = codec.exposed_encodeRecoverWallet(rk, pq, sig);
        assertEq(encoded.length, 2272);
    }

    function test_exposed_encodeRecoverWallet_roundtrips() public view {
        WOTSPlus.WinternitzAddress memory rk = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory pq = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        for (uint256 i = 0; i < 67; i++) sig.elements[i] = bytes32(i + 50);

        bytes memory encoded = codec.exposed_encodeRecoverWallet(rk, pq, sig);
        (
            WOTSPlus.WinternitzAddress memory dRk,
            WOTSPlus.WinternitzAddress memory dPq,
            WOTSPlus.WinternitzElements memory dSig
        ) = codec.exposed_decodeRecoverWallet(encoded);

        assertEq(dRk.publicSeed, rk.publicSeed);
        assertEq(dRk.publicKeyHash, rk.publicKeyHash);
        assertEq(dPq.publicSeed, pq.publicSeed);
        assertEq(dPq.publicKeyHash, pq.publicKeyHash);
        for (uint256 i = 0; i < 67; i++)
            assertEq(dSig.elements[i], sig.elements[i]);
    }
}
