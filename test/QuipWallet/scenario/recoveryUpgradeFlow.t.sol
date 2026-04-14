// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

/// @title Recovery Upgrade Flow Scenario Test
/// @dev Emergency upgrade via recovery key when PQ key is compromised.
///      Flow: recoveryUpgrade (no PQ rotation) → recoverWallet (fix PQ key) → resume.
contract QuipWallet_recoveryUpgradeFlow is QuipWalletTest {
    QuipWallet public newImpl;

    function setUp() public override {
        super.setUp();
        newImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(newImpl));
    }

    function _buildRecoveryUpgradePayload(
        WOTSPlus.WinternitzAddress memory rKey,
        WOTSPlus.WinternitzElements memory sig,
        address impl,
        bytes32 verifierSeed
    ) internal view returns (bytes memory) {
        (WOTSPlus.WinternitzAddress memory vPub, bytes32 vPriv) = _generateKeyPair(verifierSeed);
        bytes32 vHash = Codec.verificationDigest(
            address(wallet), block.chainid, impl,
            vPub.publicSeed, vPub.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory vSig = _sign(vPriv, vHash);

        return Codec.encodeRecoveryUpgrade(rKey, sig, vPub, vSig);
    }

    /// @dev Emergency upgrade via recovery key → recoverWallet → resume operations.
    function test_simulation_recoveryUpgradeFlow() public {
        // Step 1: Simulate PQ key compromised — we still have recovery keys.
        //         Use recovery key 0 to perform emergency upgrade.
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(
            address(wallet), address(newImpl), alicePubkey, rKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey, sig, address(newImpl), "recovery-upgrade-verifier"
        );

        (bytes32 pqSeedBefore, bytes32 pqHashBefore) = wallet.pqOwner();
        uint256 balBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.recoveryUpgrade(address(newImpl), payload);

        // Step 2: Verify post-upgrade state
        // 2a: Implementation changed
        assertEq(
            wallet.version(),
            factory.getVettedCodeIndex(address(newImpl).codehash)
        );

        // 2b: PQ owner NOT rotated (critical: recoveryUpgrade doesn't rotate)
        (bytes32 pqSeedAfter, bytes32 pqHashAfter) = wallet.pqOwner();
        assertEq(pqSeedAfter, pqSeedBefore);
        assertEq(pqHashAfter, pqHashBefore);

        // 2c: Recovery key 0 consumed
        assertEq(wallet.getRecoveryKeyCount(), 9);
        assertFalse(wallet.isRecoveryKey(rKey));

        // 2d: Balance and owner preserved
        assertEq(address(wallet).balance, balBefore);
        assertEq(wallet.owner(), ALICE);

        // Step 3: Fix the compromised PQ key via recoverWallet (using recovery key 1)
        (WOTSPlus.WinternitzAddress memory newPqOwner, bytes32 newPqPrivKey) =
            _generateKeyPair("new-pq-after-recovery-upgrade");

        WOTSPlus.WinternitzAddress memory rKey1 = recoveryPubkeys[1];
        bytes32 rPrivKey1 = _recoverySigningKey(alicePrivateKey, 1);

        bytes32 recoverHash = _buildRecoverWalletMessageHash(
            address(wallet), rKey1, newPqOwner
        );
        WOTSPlus.WinternitzElements memory recoverSig = _sign(rPrivKey1, recoverHash);

        vm.prank(ALICE);
        wallet.recoverWallet(Codec.encodeRecoverWallet(rKey1, newPqOwner, recoverSig));

        // PQ key now fixed
        (bytes32 s, bytes32 h) = wallet.pqOwner();
        assertEq(s, newPqOwner.publicSeed);
        assertEq(h, newPqOwner.publicKeyHash);
        assertEq(wallet.getRecoveryKeyCount(), 8);

        // Step 4: Resume normal operations with the new key
        (WOTSPlus.WinternitzAddress memory postPq,) = _generateKeyPair("post-recovery-upgrade-key");
        uint256 fee = wallet.getExecuteFee();
        bytes32 execHash = _buildExecuteMessageHash(
            address(wallet), newPqOwner, postPq, BOB, 0.05 ether, "", fee
        );
        WOTSPlus.WinternitzElements memory execSig = _sign(newPqPrivKey, execHash);

        uint256 bobBal = BOB.balance;
        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(postPq, execSig, BOB, 0.05 ether, ""));
        assertEq(BOB.balance, bobBal + 0.05 ether);
    }
}
