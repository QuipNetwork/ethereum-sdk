// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @title WOTSPlusCodec — upstream-type-size regression
/// @dev Pins the upstream `WOTSPlus.WinternitzAddress` (64 B) and
///      `WOTSPlus.WinternitzElements` (2144 B) sizes that every absolute
///      calldata offset hardcoded in the codec depends on. The auth-prefix
///      boundary `2272 = 2 × sizeof(WinternitzAddress) + sizeof(WinternitzElements)`
///      is used by EVERY authenticated decoder via
///      `calldataload(add(payload.offset, 2272))`; downstream offsets
///      (`2304`, `2336`, `2368`, `3008`, `3648`, `4288`) are all derived
///      from `2272 + N × sizeof(WinternitzAddress)`.
///
///      Latent regression: if a future upstream-library bump changes
///      `NumSignatureChunks` (currently 67), `WinternitzElements` grows but
///      every codec-side hardcode silently stays the same. The decoders
///      would either revert with `MalformedPayload` against a properly-sized
///      new payload, or — worse, against an adversary-crafted payload of
///      the OLD size — silently decode fields from the wrong offsets.
///
///      Strategy: derive expected sizes from `abi.encode` of empty stack
///      instances of the upstream types, NOT from project-internal helpers
///      (which themselves hardcode `67` and `2272`). For each decoder that
///      pulls an address out of a raw calldata word, build a payload by
///      directly concatenating `abi.encode(upstreamStruct)` segments and
///      assert the codec's hardcoded offsets land on the right bytes.
///
///      Parallel coverage from the library consumer side
///      (`EnumerableWinternitzAddressSet.values()`'s in-memory struct-size
///      pin) lives in `EnumerableWinternitzAddressSet_values_sentinel.t.sol`.
contract WOTSPlusCodec_upstreamTypeSizeRegression is WOTSPlusCodecTest {
    uint256 private constant _EXPECTED_WINTERNITZ_ADDRESS_SIZE = 64;
    uint256 private constant _EXPECTED_WINTERNITZ_ELEMENTS_SIZE = 2144;
    uint256 private constant _EXPECTED_NUM_SIGNATURE_CHUNKS = 67;
    uint256 private constant _EXPECTED_AUTH_PREFIX_SIZE = 2272;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  upstream-size sentinels                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.+°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev If `WinternitzAddress` ever grows or shrinks a field, `abi.encode`
    ///      of an empty stack instance returns a different number of bytes.
    ///      Every codec offset that adds `64` (or a multiple of it) breaks
    ///      silently — the compile still succeeds because the codec uses raw
    ///      integer literals, not `sizeof()`-style expressions.
    function test_winternitzAddress_abiEncodeIs64Bytes() public pure {
        WOTSPlus.WinternitzAddress memory a;
        assertEq(abi.encode(a).length, _EXPECTED_WINTERNITZ_ADDRESS_SIZE);
    }

    /// @dev If `NumSignatureChunks` changes, `WinternitzElements` grows by a
    ///      multiple of 32. The codec's `2272` constant — used as the offset
    ///      of EVERY non-prefix field across every decoder — silently
    ///      desynchronises from the actual end of the pqSig section.
    function test_winternitzElements_abiEncodeIs2144Bytes() public pure {
        WOTSPlus.WinternitzElements memory e;
        assertEq(abi.encode(e).length, _EXPECTED_WINTERNITZ_ELEMENTS_SIZE);
    }

    /// @dev Direct pin on the upstream constant that drives
    ///      `sizeof(WinternitzElements) = 32 × NumSignatureChunks`. Catches
    ///      the case where the upstream library bumps the constant without
    ///      bumping the dependency version — easy to miss in diff review.
    function test_numSignatureChunks_isExactlySixtySeven() public pure {
        assertEq(uint256(WOTSPlus.NumSignatureChunks), _EXPECTED_NUM_SIGNATURE_CHUNKS);
    }

    /// @dev The auth-prefix size is the load-bearing derived quantity. Pins
    ///      `2272 == 2 × WinternitzAddress + WinternitzElements` end-to-end.
    function test_authPrefixSize_equalsTwoAddressesPlusElements() public pure {
        WOTSPlus.WinternitzAddress memory addr;
        WOTSPlus.WinternitzElements memory elems;
        assertEq(2 * abi.encode(addr).length + abi.encode(elems).length, _EXPECTED_AUTH_PREFIX_SIZE);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*               per-decoder offset sentinels                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.+°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Build the canonical authenticated prefix by concatenating
    ///      `abi.encode` of the upstream structs DIRECTLY — no project
    ///      helpers, no hardcoded `67` loop. If the upstream types change
    ///      size, this prefix changes size too, and the codec's hardcoded
    ///      offsets stop landing on the right fields.
    function _buildAuthPrefixFromUpstream(
        WOTSPlus.WinternitzAddress memory cur,
        WOTSPlus.WinternitzAddress memory nxt,
        WOTSPlus.WinternitzElements memory sig
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(abi.encode(cur), abi.encode(nxt), abi.encode(sig));
    }

    /// @dev Pins `decodeExecute`'s field offsets against the upstream-derived
    ///      prefix size. The target slot must land at exactly
    ///      `2 × sizeof(WinternitzAddress) + sizeof(WinternitzElements)`.
    function test_decodeExecute_offsetsDeriveFromUpstreamSizes() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(0xcafe01)), publicKeyHash: bytes32(uint256(0xcafe02))
        });
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(0xcafe03)), publicKeyHash: bytes32(uint256(0xcafe04))
        });
        WOTSPlus.WinternitzElements memory sig;
        address target = address(uint160(0xdeadbeef));
        uint256 value = 7 ether;
        bytes memory opdata = hex"a1b2c3";

        bytes memory payload = abi.encodePacked(
            _buildAuthPrefixFromUpstream(cur, nxt, sig), bytes32(uint256(uint160(target))), value, opdata
        );
        // Sanity: the prefix-derived payload must be exactly the size the
        // codec's literal `2336` constant assumes (auth prefix + 32 target +
        // 32 value + 3 bytes opdata).
        assertEq(payload.length, _EXPECTED_AUTH_PREFIX_SIZE + 64 + opdata.length);

        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,,
            address t,
            uint256 v,
            bytes memory d
        ) = codec.exposed_decodeExecute(payload);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dCur.publicKeyHash, cur.publicKeyHash);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, nxt.publicKeyHash);
        assertEq(t, target);
        assertEq(v, value);
        assertEq(d, opdata);
    }

    /// @dev Same shape as `decodeExecute` but for the `to` / `amount` field
    ///      pair in `decodeWithdrawDeposit`. Layout is identical except the
    ///      payload is fixed-length (no trailing dynamic data).
    function test_decodeWithdrawDeposit_offsetsDeriveFromUpstreamSizes() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(0xbeef01)), publicKeyHash: bytes32(uint256(0xbeef02))
        });
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(0xbeef03)), publicKeyHash: bytes32(uint256(0xbeef04))
        });
        WOTSPlus.WinternitzElements memory sig;
        address to = address(uint160(0xfeedface));
        uint256 amount = 123 ether;

        bytes memory payload =
            abi.encodePacked(_buildAuthPrefixFromUpstream(cur, nxt, sig), bytes32(uint256(uint160(to))), amount);
        assertEq(payload.length, _EXPECTED_AUTH_PREFIX_SIZE + 64);

        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,,
            address dTo,
            uint256 dAmount
        ) = codec.exposed_decodeWithdrawDeposit(payload);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dTo, to);
        assertEq(dAmount, amount);
    }

    /// @dev `decodeOwnershipTransfer` packs the most fields after the auth
    ///      prefix — newOwner at +2272, newDisasterKey at +2304, then three
    ///      `[10]` keysets at +2368, +3008, +3648, ending at +4288. Every
    ///      one of those offsets is `2272 + k × 64` for various k. Pinning
    ///      one decoded value at each of the four boundary positions covers
    ///      all of them in a single test.
    function test_decodeOwnershipTransfer_offsetsDeriveFromUpstreamSizes() public view {
        bytes memory payload = _buildOwnershipPayload();
        assertEq(payload.length, 4288);
        _assertOwnershipDecodesAtPinnedOffsets(payload);
    }

    /// @dev Splits payload construction out of the test body to keep stack
    ///      depth manageable. Sentinels are deterministic so the assertion
    ///      half can reconstruct expected values independently.
    function _buildOwnershipPayload() internal pure returns (bytes memory) {
        WOTSPlus.WinternitzAddress memory cur =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(0xa1a2)), publicKeyHash: bytes32(uint256(0xa3a4))});
        WOTSPlus.WinternitzAddress memory nxt =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(0xa5a6)), publicKeyHash: bytes32(uint256(0xa7a8))});
        WOTSPlus.WinternitzElements memory sig;
        WOTSPlus.WinternitzAddress memory newDisaster =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(0xd1)), publicKeyHash: bytes32(uint256(0xd2))});
        // Each keyset = 10 WinternitzAddresses. Distinct first-element
        // sentinels (0x100 / 0x200 / 0x300) so the decoder reading from
        // offsets 2368, 3008, 3648 must hit a unique value to pass.
        return abi.encodePacked(
            _buildAuthPrefixFromUpstream(cur, nxt, sig),
            bytes32(uint256(uint160(0x0b0b0b))),
            abi.encode(newDisaster),
            _buildKeysetBlock(0x100),
            _buildKeysetBlock(0x200),
            _buildKeysetBlock(0x300)
        );
    }

    /// @dev Decodes a `_buildOwnershipPayload`-shaped payload and asserts
    ///      every field landed at its expected offset. Split from the test
    ///      body to keep the decoder's 8-tuple return out of the test stack.
    function _assertOwnershipDecodesAtPinnedOffsets(bytes memory payload) internal view {
        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,,
            address dNewOwner,
            WOTSPlus.WinternitzAddress memory dNewDisaster,
            WOTSPlus.WinternitzAddress[10] memory dTxKeys,
            WOTSPlus.WinternitzAddress[10] memory dRecKeys,
            WOTSPlus.WinternitzAddress[10] memory dVerKeys
        ) = codec.exposed_decodeOwnershipTransfer(payload);

        assertEq(dCur.publicSeed, bytes32(uint256(0xa1a2)));
        assertEq(dNxt.publicSeed, bytes32(uint256(0xa5a6)));
        assertEq(dNewOwner, address(uint160(0x0b0b0b)));
        assertEq(dNewDisaster.publicSeed, bytes32(uint256(0xd1)));
        // First-element sentinel of each keyset pins the block-start offset.
        assertEq(dTxKeys[0].publicSeed, bytes32(uint256(0x100)));
        assertEq(dRecKeys[0].publicSeed, bytes32(uint256(0x200)));
        assertEq(dVerKeys[0].publicSeed, bytes32(uint256(0x300)));
        // Last-element sentinel of each keyset pins the block-end offset.
        assertEq(dTxKeys[9].publicSeed, bytes32(uint256(0x100 + 9 * 2)));
        assertEq(dRecKeys[9].publicSeed, bytes32(uint256(0x200 + 9 * 2)));
        assertEq(dVerKeys[9].publicSeed, bytes32(uint256(0x300 + 9 * 2)));
    }

    /// @dev Build a `WinternitzAddress[10]` block by concatenating
    ///      `abi.encode(WinternitzAddress)` 10 times. Length must be
    ///      `10 × sizeof(WinternitzAddress) = 640` for any upstream-stable
    ///      `WinternitzAddress` size. If the struct ever changes shape, this
    ///      helper produces a differently-sized block and the
    ///      `payload.length == 4288` assertion above fails.
    function _buildKeysetBlock(uint256 startSeed) internal pure returns (bytes memory block_) {
        for (uint256 i = 0; i < 10; ++i) {
            WOTSPlus.WinternitzAddress memory a = WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(startSeed + i * 2), publicKeyHash: bytes32(startSeed + i * 2 + 1)
            });
            block_ = abi.encodePacked(block_, abi.encode(a));
        }
    }
}
