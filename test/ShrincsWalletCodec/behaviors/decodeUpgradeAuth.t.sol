// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_decodeUpgradeAuth is ShrincsWalletCodecTest {
    function test_decodeUpgradeAuth_roundTrip_migrateTrue() public view {
        ShrincsTypes.PublicKey memory pk = _samplePublicKey();
        ShrincsTypes.StatefulSignature memory sig = _sampleStatefulSig();
        bytes memory migratorPayload = hex"deadbeefcafe";
        bytes memory data = abi.encode(pk, sig, true, migratorPayload);

        (
            ShrincsTypes.PublicKey memory dpk,
            ShrincsTypes.StatefulSignature memory dsig,
            bool shouldMigrate,
            bytes memory dPayload
        ) = codec.exposed_decodeUpgradeAuth(data);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dsig, sig);
        assertTrue(shouldMigrate, "shouldMigrate");
        assertEq(dPayload, migratorPayload, "migratorPayload");
    }

    function test_decodeUpgradeAuth_roundTrip_migrateFalseEmptyPayload() public view {
        ShrincsTypes.PublicKey memory pk = _samplePublicKey();
        ShrincsTypes.StatefulSignature memory sig = _sampleStatefulSig();
        bytes memory data = abi.encode(pk, sig, false, bytes(""));

        (,, bool shouldMigrate, bytes memory dPayload) = codec.exposed_decodeUpgradeAuth(data);
        assertFalse(shouldMigrate, "shouldMigrate false");
        assertEq(dPayload.length, 0, "empty migratorPayload");
    }

    function test_decodeUpgradeAuth_revertsWhen_tooShort() public {
        bytes memory short = new bytes(0x60); // < 0x80
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x80, 0x60));
        codec.exposed_decodeUpgradeAuth(short);
    }
}
