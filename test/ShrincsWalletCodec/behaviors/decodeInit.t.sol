// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_decodeInit is ShrincsWalletCodecTest {
    function test_decodeInit_roundTrip() public view {
        ShrincsTypes.PublicKey memory pk = _samplePublicKey();
        bytes32 commitment = keccak256("commit");
        bytes32 pkSeed = keccak256("seed");
        bytes32 erc1271Commitment = keccak256("erc1271");
        bytes memory payload = abi.encode(commitment, pkSeed, pk, uint8(0), erc1271Commitment, uint8(1));

        (bytes32 c, bytes32 ps, ShrincsTypes.PublicKey memory mb, uint8 pid, bytes32 ec, uint8 epid) =
            codec.exposed_decodeInit(payload);

        assertEq(c, commitment, "commitment");
        assertEq(ps, pkSeed, "pkSeed");
        assertEq(pid, 0, "parameterSetId");
        assertEq(ec, erc1271Commitment, "erc1271Commitment");
        assertEq(epid, 1, "erc1271ParameterSetId");
        _assertPkEq(mb, pk);
    }

    function test_decodeInit_revertsWhen_tooShort() public {
        bytes memory shortPayload = new bytes(0xa0); // < 0xc0
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0xc0, 0xa0));
        codec.exposed_decodeInit(shortPayload);
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev Round-trips an arbitrary init payload. `commitment`/`pkSeed` ride in the first two head
    ///      words (the factory's opaque `payload[0:64]` indexing handle), and the top-level
    ///      `parameterSetId` is decoded independently of the bundle's own field.
    function testFuzz_decodeInit_roundTrip(
        bytes32 commitment,
        bytes32 pkSeed,
        uint8 topParamId,
        bytes32 erc1271Commitment,
        uint8 erc1271ParamId,
        uint8 bundleParamId,
        bytes memory statefulPublicKey,
        bytes memory pkCommitment,
        bytes memory innerPkSeed,
        bytes memory hypertreeRoot
    ) public view {
        ShrincsTypes.PublicKey memory pk;
        pk.parameterSetId = ShrincsTypes.ParameterSetId(bound(bundleParamId, 0, 1));
        pk.statefulPublicKey = statefulPublicKey;
        pk.publicKeyCommitment = pkCommitment;
        pk.pkSeed = innerPkSeed;
        pk.hypertreeRoot = hypertreeRoot;

        bytes memory payload = abi.encode(commitment, pkSeed, pk, topParamId, erc1271Commitment, erc1271ParamId);

        (bytes32 c, bytes32 ps, ShrincsTypes.PublicKey memory mb, uint8 pid, bytes32 ec, uint8 epid) =
            codec.exposed_decodeInit(payload);

        assertEq(c, commitment, "commitment");
        assertEq(ps, pkSeed, "pkSeed");
        assertEq(pid, topParamId, "parameterSetId");
        assertEq(ec, erc1271Commitment, "erc1271Commitment");
        assertEq(epid, erc1271ParamId, "erc1271ParameterSetId");
        _assertPkEq(mb, pk);
    }
}
