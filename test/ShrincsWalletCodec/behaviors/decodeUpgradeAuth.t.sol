// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_decodeUpgradeAuth is ShrincsWalletCodecTest {
    function test_decodeUpgradeAuth_roundTrip_migrateTrue() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        SHRINCS.Signature memory sig = _sampleStatefulSig();
        bytes memory migratorPayload = hex"deadbeefcafe";
        bytes memory probePayload = hex"0badf00d";
        bytes memory data = abi.encode(pk, sig, true, migratorPayload, uint256(7), probePayload);

        (
            SHRINCS.PublicKey memory dpk,
            SHRINCS.Signature memory dsig,
            bool shouldMigrate,
            bytes memory dPayload,
            uint256 dNonce,
            bytes memory dProbe
        ) = codec.exposed_decodeUpgradeAuth(data);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dsig, sig);
        assertTrue(shouldMigrate, "shouldMigrate");
        assertEq(dPayload, migratorPayload, "migratorPayload");
        assertEq(dNonce, 7, "blob nonce");
        assertEq(dProbe, probePayload, "probePayload");
    }

    function test_decodeUpgradeAuth_roundTrip_migrateFalseEmptyPayload() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        SHRINCS.Signature memory sig = _sampleStatefulSig();
        bytes memory data = abi.encode(pk, sig, false, bytes(""), uint256(0), bytes(""));

        (,, bool shouldMigrate, bytes memory dPayload, uint256 dNonce, bytes memory dProbe) =
            codec.exposed_decodeUpgradeAuth(data);
        assertFalse(shouldMigrate, "shouldMigrate false");
        assertEq(dPayload.length, 0, "empty migratorPayload");
        assertEq(dNonce, 0, "zero blob nonce");
        assertEq(dProbe.length, 0, "empty probePayload");
    }

    function test_decodeUpgradeAuth_revertsWhen_tooShort() public {
        // A 5-field (pre-probe) head is 0xa0 bytes — now one word short of the 0xc0 floor.
        bytes memory short = new bytes(0xa0);
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0xc0, 0xa0));
        codec.exposed_decodeUpgradeAuth(short);
    }
}
