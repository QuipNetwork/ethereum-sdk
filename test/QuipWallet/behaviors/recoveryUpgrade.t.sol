// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipWallet_recoveryUpgrade is QuipWalletTest {
    QuipWallet public newImpl;

    function setUp() public override {
        super.setUp();
        newImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(newImpl));
    }

    // ── Helpers ──────────────────────────────────────────────────────

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

    function _doRecoveryUpgrade(
        address impl,
        uint256 keyIndex
    ) internal returns (WOTSPlus.WinternitzAddress memory rKey) {
        rKey = recoveryPubkeys[keyIndex];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, keyIndex);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), impl, alicePubkey, rKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey, sig, impl, keccak256(abi.encodePacked("recovery-verifier", keyIndex))
        );

        vm.prank(ALICE);
        wallet.recoveryUpgrade(impl, payload);
    }

    // ── Happy paths ─────────────────────────────────────────────────

    function test_recoveryUpgrade_upgradesImplementation() public {
        _doRecoveryUpgrade(address(newImpl), 0);

        // Implementation slot should now point to newImpl
        // Verify via version() which reads codehash from the impl slot
        uint256 ver = wallet.version();
        assertEq(ver, factory.getVettedCodeIndex(address(newImpl).codehash));
    }

    function test_recoveryUpgrade_consumesRecoveryKey() public {
        uint256 countBefore = wallet.getRecoveryKeyCount();

        WOTSPlus.WinternitzAddress memory rKey = _doRecoveryUpgrade(address(newImpl), 0);

        assertEq(wallet.getRecoveryKeyCount(), countBefore - 1);
        assertFalse(wallet.isRecoveryKey(rKey));
    }

    function test_recoveryUpgrade_preservesPqOwner() public {
        (bytes32 seedBefore, bytes32 hashBefore) = wallet.pqOwner();

        _doRecoveryUpgrade(address(newImpl), 0);

        (bytes32 seedAfter, bytes32 hashAfter) = wallet.pqOwner();
        assertEq(seedAfter, seedBefore);
        assertEq(hashAfter, hashBefore);
    }

    function test_recoveryUpgrade_preservesBalance() public {
        uint256 balBefore = address(wallet).balance;

        _doRecoveryUpgrade(address(newImpl), 0);

        assertEq(address(wallet).balance, balBefore);
    }

    function test_recoveryUpgrade_emitsRecoveryUpgrade() public {
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(newImpl), alicePubkey, rKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey, sig, address(newImpl), keccak256("emit-verifier")
        );

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.recoveryUpgrade(address(newImpl), payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.RecoveryUpgrade.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "RecoveryUpgrade event not emitted");
    }

    function test_recoveryUpgrade_preservesOtherRecoveryKeys() public {
        _doRecoveryUpgrade(address(newImpl), 0);

        for (uint256 i = 1; i < recoveryPubkeys.length; i++) {
            assertTrue(wallet.isRecoveryKey(recoveryPubkeys[i]));
        }
    }

    function test_recoveryUpgrade_multipleUpgradesWithDifferentKeys() public {
        // First upgrade with key 0
        _doRecoveryUpgrade(address(newImpl), 0);

        // Deploy + vet a third implementation
        QuipWallet thirdImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(thirdImpl));

        // Second upgrade with key 1
        _doRecoveryUpgrade(address(thirdImpl), 1);

        assertEq(wallet.getRecoveryKeyCount(), 8);
    }

    function test_recoveryUpgrade_walletOperationalAfterUpgrade() public {
        _doRecoveryUpgrade(address(newImpl), 0);

        // The original pqOwner key should still work for operations
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-after-recovery");

        bytes32 digest = _buildChangePqOwnerMessageHash(address(wallet), alicePubkey, nextPq);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, digest);

        vm.prank(ALICE);
        wallet.changePqOwner(Codec.encodeChangePqOwner(nextPq, sig));

        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, nextPq.publicSeed);
        assertEq(publicKeyHash, nextPq.publicKeyHash);
    }

    // ── Reverts ─────────────────────────────────────────────────────

    function test_recoveryUpgrade_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(newImpl), alicePubkey, rKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey, sig, address(newImpl), keccak256("notOwner-verifier")
        );

        vm.prank(makeAddr("bob"));
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.recoveryUpgrade(address(newImpl), payload);
    }

    function test_recoveryUpgrade_revertsWhen_keyNotInSet() public {
        (WOTSPlus.WinternitzAddress memory fakeKey, bytes32 fakePriv) = _generateKeyPair("fake-recovery");

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(newImpl), alicePubkey, fakeKey);
        WOTSPlus.WinternitzElements memory sig = _sign(fakePriv, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            fakeKey, sig, address(newImpl), keccak256("keyNotInSet-verifier")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.RecoveryKeyNotFound.selector);
        wallet.recoveryUpgrade(address(newImpl), payload);
    }

    function test_recoveryUpgrade_revertsWhen_invalidSignature() public {
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        // Sign a wrong message
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, keccak256("wrong message"));

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey, sig, address(newImpl), keccak256("invalidSig-verifier")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.recoveryUpgrade(address(newImpl), payload);
    }

    function test_recoveryUpgrade_revertsWhen_implementationNotVetted() public {
        QuipWallet unvetted = new QuipWallet(payable(address(factory)));

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(unvetted), alicePubkey, rKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey, sig, address(unvetted), keccak256("notVetted-verifier")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ImplementationNotVetted.selector);
        wallet.recoveryUpgrade(address(unvetted), payload);
    }

    function test_recoveryUpgrade_revertsWhen_implementationDeprecated() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(newImpl));

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(newImpl), alicePubkey, rKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey, sig, address(newImpl), keccak256("deprecated-verifier")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ImplementationDeprecated.selector);
        wallet.recoveryUpgrade(address(newImpl), payload);
    }

    function test_recoveryUpgrade_revertsWhen_keyAlreadyConsumed() public {
        // First upgrade succeeds
        _doRecoveryUpgrade(address(newImpl), 0);

        // Deploy another impl for second attempt
        QuipWallet thirdImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(thirdImpl));

        // Try to reuse key 0
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(thirdImpl), alicePubkey, rKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey, sig, address(thirdImpl), keccak256("consumed-verifier")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.RecoveryKeyNotFound.selector);
        wallet.recoveryUpgrade(address(thirdImpl), payload);
    }
}
