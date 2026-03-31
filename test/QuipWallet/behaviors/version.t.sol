// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

contract QuipWallet_version is QuipWalletTest {
    function test_version_returnsZeroForFirstImpl() public view {
        assertEq(wallet.version(), 0);
    }

    function test_version_returnsUpdatedIndexAfterUpgrade() public {
        // Deploy and vet a second implementation
        QuipWallet secondImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(secondImpl));

        // Upgrade the wallet
        bytes memory data = _buildUpgradePayload(address(secondImpl));
        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(secondImpl), data);

        assertEq(wallet.version(), 1);
    }

    function _buildUpgradePayload(address newImpl) internal view returns (bytes memory) {
        // Reuse the helper from upgradeToAndCall tests — build a minimal valid upgrade payload
        (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) = _generateKeyPair("version-next-pq");

        // Sign upgrade digest with current pqOwner key
        bytes32 digest = Codec.upgradeDigest(
            address(wallet), block.chainid, newImpl,
            alicePubkey.publicSeed, alicePubkey.publicKeyHash,
            nextPq.publicSeed, nextPq.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, digest);

        // Pack nextPqOwner (64 bytes)
        bytes memory pqSigner = abi.encodePacked(nextPq.publicSeed, nextPq.publicKeyHash);

        // Pack pqSig (2144 bytes)
        bytes memory pqSig;
        for (uint256 i = 0; i < 67; i++) {
            pqSig = abi.encodePacked(pqSig, sig.elements[i]);
        }

        // Build verifier data (2208 bytes)
        (WOTSPlus.WinternitzAddress memory vPub, bytes32 vPriv) = _generateKeyPair("version-verifier");
        bytes32 vHash = Codec.verificationDigest(
            address(wallet), block.chainid, newImpl,
            vPub.publicSeed, vPub.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory vSig = _sign(vPriv, vHash);
        bytes memory verifierData = abi.encodePacked(vPub.publicSeed, vPub.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            verifierData = abi.encodePacked(verifierData, vSig.elements[i]);
        }

        // No migration, dummy migrator payload (705 bytes)
        bytes memory migrateFlag = abi.encodePacked(uint8(0));
        bytes memory migratorPayload;
        for (uint256 i = 0; i < 11; i++) {
            migratorPayload = abi.encodePacked(
                migratorPayload,
                bytes32(uint256(i + 1)),
                bytes32(uint256(i + 100))
            );
        }

        return abi.encodePacked(
            pqSigner, pqSig, verifierData, migrateFlag, migratorPayload
        );
    }
}
