// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeWithdrawDeposit is WOTSPlusCodecTest {
    function test_exposed_encodeWithdrawDeposit_producesCorrectLength()
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
        WOTSPlus.WinternitzElements memory sig;
        bytes memory encoded = codec.exposed_encodeWithdrawDeposit(
            cur,
            nxt,
            sig,
            address(0xBEEF),
            1 ether
        );
        assertEq(encoded.length, 2336);
    }

    function test_exposed_encodeWithdrawDeposit_roundtrips() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        for (uint256 i = 0; i < 67; i++) sig.elements[i] = bytes32(i + 100);
        address to = address(0xCAFE);
        uint256 amount = 2.5 ether;

        bytes memory encoded = codec.exposed_encodeWithdrawDeposit(
            cur,
            nxt,
            sig,
            to,
            amount
        );
        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            address dTo,
            uint256 dAmount
        ) = codec.exposed_decodeWithdrawDeposit(encoded);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dTo, to);
        assertEq(dAmount, amount);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
    }

    /// @dev Property: encode → decode preserves every field for any inputs.
    ///      Pins the 2336-byte withdrawDeposit layout against encoder/decoder
    ///      drift around the 32-byte left-padded `to` and `amount` tail.
    function testFuzz_exposed_encodeWithdrawDeposit_roundtrips(
        bytes32 seed,
        address to,
        uint256 amount
    ) public view {
        WOTSPlus.WinternitzAddress memory cur = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory nxt = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzElements memory sig = _fuzzWinternitzElements(seed);

        bytes memory encoded = codec.exposed_encodeWithdrawDeposit(
            cur,
            nxt,
            sig,
            to,
            amount
        );
        assertEq(encoded.length, 2336);

        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            address dTo,
            uint256 dAmount
        ) = codec.exposed_decodeWithdrawDeposit(encoded);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dCur.publicKeyHash, cur.publicKeyHash);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
        assertEq(dTo, to);
        assertEq(dAmount, amount);
    }
}
