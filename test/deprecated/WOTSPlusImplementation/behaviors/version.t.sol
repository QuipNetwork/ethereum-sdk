// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

contract WOTSPlusImplementation_version is WOTSPlusImplementationTest {
    function test_version_returnsZeroForFirstImpl() public view {
        assertEq(wallet.version(), 0);
    }

    function test_version_returnsUpdatedIndexAfterUpgrade() public {
        // Deploy and vet a second implementation
        WOTSPlusImplementation secondImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(secondImpl));

        // Upgrade the wallet
        bytes memory data = _buildUpgradePayload(address(secondImpl));
        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(secondImpl), data);

        assertEq(wallet.version(), 1);
    }

    function _buildUpgradePayload(address newImpl) internal view returns (bytes memory) {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("version-next-pq");

        // No migration: migrator slot is zero-filled (2048 bytes).
        bytes memory migratorPayload = new bytes(2048);

        bytes32 digest = Codec.upgradeDigest(
            address(wallet),
            block.chainid,
            newImpl,
            alicePubkey.publicSeed,
            alicePubkey.publicKeyHash,
            nextPq.publicSeed,
            nextPq.publicKeyHash,
            false,
            keccak256(migratorPayload)
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, digest);

        (WOTSPlus.WinternitzAddress memory vPub, bytes32 vPriv) = _generateKeyPair("version-verifier");
        bytes32 vHash =
            Codec.verificationDigest(address(wallet), block.chainid, newImpl, vPub.publicSeed, vPub.publicKeyHash);
        WOTSPlus.WinternitzElements memory vSig = _sign(vPriv, vHash);

        return
            Codec.encodeUpgradeToAndCall(
                alicePubkey,
                nextPq,
                sig,
                vPub,
                vSig,
                false,
                migratorPayload
            );
    }
}
