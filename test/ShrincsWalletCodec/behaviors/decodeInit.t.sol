// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_decodeInit is ShrincsWalletCodecTest {
    function test_decodeInit_roundTrip() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        bytes32 commitment = keccak256("commit");
        bytes32 pkSeed = keccak256("seed");
        bytes32 erc1271Commitment = keccak256("erc1271");
        bytes memory payload = abi.encode(
            commitment, pkSeed, pk, HashSuite.HASH_SUITE_ID, erc1271Commitment, uint32(2)
        );

        (bytes32 c, bytes32 ps, SHRINCS.PublicKey memory mb, uint32 hs, bytes32 ec, uint32 ehs) =
            codec.exposed_decodeInit(payload);

        assertEq(c, commitment, "commitment");
        assertEq(ps, pkSeed, "pkSeed");
        assertEq(hs, HashSuite.HASH_SUITE_ID, "hashSuite");
        assertEq(ec, erc1271Commitment, "erc1271Commitment");
        assertEq(ehs, 2, "erc1271HashSuite");
        _assertPkEq(mb, pk);
    }

    function test_decodeInit_revertsWhen_tooShort() public {
        bytes memory shortPayload = new bytes(0xa0); // < 0xc0
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0xc0, 0xa0));
        codec.exposed_decodeInit(shortPayload);
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev Round-trips an arbitrary init payload. `commitment`/`pkSeed` ride in the first two head
    ///      words (the factory's opaque `payload[0:64]` indexing handle), and the hash-suite words
    ///      are decoded as full uint32s.
    function testFuzz_decodeInit_roundTrip(
        bytes32 commitment,
        bytes32 pkSeed,
        uint32 hashSuite,
        bytes32 erc1271Commitment,
        uint32 erc1271HashSuite,
        bytes memory statefulPublicKey,
        bytes memory pkCommitment,
        bytes memory innerPkSeed,
        bytes memory hypertreeRoot
    ) public view {
        SHRINCS.PublicKey memory pk;
        pk.statefulPublicKey = statefulPublicKey;
        pk.publicKeyCommitment = pkCommitment;
        pk.pkSeed = innerPkSeed;
        pk.hypertreeRoot = hypertreeRoot;

        bytes memory payload = abi.encode(commitment, pkSeed, pk, hashSuite, erc1271Commitment, erc1271HashSuite);

        (bytes32 c, bytes32 ps, SHRINCS.PublicKey memory mb, uint32 hs, bytes32 ec, uint32 ehs) =
            codec.exposed_decodeInit(payload);

        assertEq(c, commitment, "commitment");
        assertEq(ps, pkSeed, "pkSeed");
        assertEq(hs, hashSuite, "hashSuite");
        assertEq(ec, erc1271Commitment, "erc1271Commitment");
        assertEq(ehs, erc1271HashSuite, "erc1271HashSuite");
        _assertPkEq(mb, pk);
    }
}
