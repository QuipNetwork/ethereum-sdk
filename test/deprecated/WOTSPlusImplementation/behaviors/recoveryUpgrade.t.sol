// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/WOTSPlusTestSigner.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {WOTSPlusStorage as Storage} from "../../../../contracts/deprecated/wots/WOTSPlusStorage.sol";

/// @dev Minimal "rogue vetted impl" used to prove the verify-delegatecall guard
///      catches SSTOREs to any guarded slot. The fallback overwrites the
///      `disasterRecoveryKey` publicSeed slot — one of the seven slots
///      snapshotted by the guard. If the guard did not fire, this SSTORE would
///      silently succeed against the wallet's storage and brick the disaster
///      recovery path. Slot is taken from `WOTSPlusStorage` (Yul can't
///      reference cross-library constants directly, but loading into a local
///      Solidity variable first works around that restriction).
contract RogueImpl_WritesGuardedSlot {
    fallback() external payable {
        bytes32 slot = Storage._DISASTER_KEY_SEED_SLOT;
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, 0xdeadbeef)
        }
    }
}

contract WOTSPlusImplementation_recoveryUpgrade is WOTSPlusImplementationTest {
    WOTSPlusImplementation public newImpl;

    function setUp() public override {
        super.setUp();
        newImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(newImpl));
    }

    // ── Helpers ──────────────────────────────────────────────────────

    function _replacementKey(uint256 keyIndex) internal pure returns (WOTSPlus.WinternitzAddress memory pub) {
        bytes32 seed = keccak256(abi.encodePacked("recovery-replacement", keyIndex));
        (pub,) = WOTSPlusTestSigner.generateKeyPair(seed);
    }

    function _buildRecoveryUpgradePayload(
        WOTSPlus.WinternitzAddress memory rKey,
        WOTSPlus.WinternitzAddress memory newRKey,
        WOTSPlus.WinternitzElements memory sig,
        address impl,
        bytes32 verifierSeed
    ) internal view returns (bytes memory) {
        (WOTSPlus.WinternitzAddress memory vPub, bytes32 vPriv) = _generateKeyPair(verifierSeed);
        bytes32 vHash =
            Codec.verificationDigest(address(wallet), block.chainid, impl, vPub.publicSeed, vPub.publicKeyHash);
        WOTSPlus.WinternitzElements memory vSig = _sign(vPriv, vHash);

        return Codec.encodeRecoveryUpgrade(rKey, newRKey, sig, vPub, vSig);
    }

    function _doRecoveryUpgrade(address impl, uint256 keyIndex)
        internal
        returns (WOTSPlus.WinternitzAddress memory rKey, WOTSPlus.WinternitzAddress memory newRKey)
    {
        rKey = recoveryPubkeys[keyIndex];
        newRKey = _replacementKey(keyIndex);
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, keyIndex);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), impl, rKey, newRKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey, newRKey, sig, impl, keccak256(abi.encodePacked("recovery-verifier", keyIndex))
        );

        vm.prank(ALICE);
        wallet.recoveryUpgrade(impl, payload);
    }

    // ── Happy paths ─────────────────────────────────────────────────

    function test_recoveryUpgrade_upgradesImplementation() public {
        _doRecoveryUpgrade(address(newImpl), 0);

        // Implementation slot should now point to newImpl
        uint256 ver = wallet.version();
        assertEq(ver, factory.getVettedCodeIndex(address(newImpl).codehash));
    }

    function test_recoveryUpgrade_rotatesRecoveryKey() public {
        uint256 countBefore = wallet.keyCount(Codec.KeyType.Recovery);

        (WOTSPlus.WinternitzAddress memory rKey, WOTSPlus.WinternitzAddress memory newRKey) =
            _doRecoveryUpgrade(address(newImpl), 0);

        // Count is preserved: remove-then-add keeps the pool stable.
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), countBefore);
        // Consumed key is gone; replacement is installed.
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, rKey));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, newRKey));
    }

    function test_recoveryUpgrade_preservesTransactionKeys() public {
        uint256 countBefore = wallet.keyCount(Codec.KeyType.Transaction);
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));

        _doRecoveryUpgrade(address(newImpl), 0);

        assertEq(wallet.keyCount(Codec.KeyType.Transaction), countBefore);
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
    }

    function test_recoveryUpgrade_preservesBalance() public {
        uint256 balBefore = address(wallet).balance;

        _doRecoveryUpgrade(address(newImpl), 0);

        assertEq(address(wallet).balance, balBefore);
    }

    function test_recoveryUpgrade_emitsRecoveryUpgrade() public {
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress memory newRKey = _replacementKey(0);
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(newImpl), rKey, newRKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload =
            _buildRecoveryUpgradePayload(rKey, newRKey, sig, address(newImpl), keccak256("emit-verifier"));

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.recoveryUpgrade(address(newImpl), payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IWOTSPlusImplementation.RecoveryUpgrade.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "RecoveryUpgrade event not emitted");
    }

    function test_recoveryUpgrade_preservesOtherRecoveryKeys() public {
        _doRecoveryUpgrade(address(newImpl), 0);

        for (uint256 i = 1; i < recoveryPubkeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }
    }

    function test_recoveryUpgrade_multipleUpgradesWithDifferentKeys() public {
        // First upgrade with key 0
        _doRecoveryUpgrade(address(newImpl), 0);

        // Deploy + vet a third implementation
        WOTSPlusImplementation thirdImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(thirdImpl));

        // Second upgrade with key 1
        _doRecoveryUpgrade(address(thirdImpl), 1);

        // Count stays at 10 — each upgrade replaced its key instead of draining.
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_recoveryUpgrade_walletOperationalAfterUpgrade() public {
        _doRecoveryUpgrade(address(newImpl), 0);

        // The original pqOwner key should still work for operations.
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-after-recovery");

        uint256 fee = wallet.getExecuteFee();
        bytes32 digest = _buildExecuteMessageHash(address(wallet), alicePubkey, nextPq, BOB, 0, "", fee);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, digest);

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPq, sig, BOB, 0, ""));

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
    }

    // ── Reverts ─────────────────────────────────────────────────────

    function test_recoveryUpgrade_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress memory newRKey = _replacementKey(0);
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(newImpl), rKey, newRKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload =
            _buildRecoveryUpgradePayload(rKey, newRKey, sig, address(newImpl), keccak256("notOwner-verifier"));

        vm.prank(makeAddr("bob"));
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.recoveryUpgrade(address(newImpl), payload);
    }

    function test_recoveryUpgrade_revertsWhen_keyNotInSet() public {
        (WOTSPlus.WinternitzAddress memory fakeKey, bytes32 fakePriv) = _generateKeyPair("fake-recovery");
        WOTSPlus.WinternitzAddress memory newRKey = _replacementKey(999);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(newImpl), fakeKey, newRKey);
        WOTSPlus.WinternitzElements memory sig = _sign(fakePriv, msgHash);

        bytes memory payload =
            _buildRecoveryUpgradePayload(fakeKey, newRKey, sig, address(newImpl), keccak256("keyNotInSet-verifier"));

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        wallet.recoveryUpgrade(address(newImpl), payload);
    }

    /// @dev If the replacement key is already a member of the recovery set
    ///      (e.g. the caller reuses one of the existing recovery keys), the
    ///      pre-verify uncontained check rejects it before the WOTS+ signature
    ///      is even verified.
    function test_recoveryUpgrade_revertsWhen_newKeyAlreadyInSet() public {
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        // Use recovery key 1 as the "new" key → already a member.
        WOTSPlus.WinternitzAddress memory newRKey = recoveryPubkeys[1];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(newImpl), rKey, newRKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload =
            _buildRecoveryUpgradePayload(rKey, newRKey, sig, address(newImpl), keccak256("dupNew-verifier"));

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.recoveryUpgrade(address(newImpl), payload);
    }

    function test_recoveryUpgrade_revertsWhen_invalidSignature() public {
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress memory newRKey = _replacementKey(0);
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        // Sign a wrong message
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, keccak256("wrong message"));

        bytes memory payload =
            _buildRecoveryUpgradePayload(rKey, newRKey, sig, address(newImpl), keccak256("invalidSig-verifier"));

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.recoveryUpgrade(address(newImpl), payload);
    }

    function test_recoveryUpgrade_revertsWhen_implementationNotVetted() public {
        WOTSPlusImplementation unvetted = new WOTSPlusImplementation(payable(address(factory)));

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress memory newRKey = _replacementKey(0);
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(unvetted), rKey, newRKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload =
            _buildRecoveryUpgradePayload(rKey, newRKey, sig, address(unvetted), keccak256("notVetted-verifier"));

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.ImplementationNotVetted.selector);
        wallet.recoveryUpgrade(address(unvetted), payload);
    }

    function test_recoveryUpgrade_revertsWhen_implementationDeprecated() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(newImpl));

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress memory newRKey = _replacementKey(0);
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(newImpl), rKey, newRKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload =
            _buildRecoveryUpgradePayload(rKey, newRKey, sig, address(newImpl), keccak256("deprecated-verifier"));

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.ImplementationDeprecated.selector);
        wallet.recoveryUpgrade(address(newImpl), payload);
    }

    function test_recoveryUpgrade_revertsWhen_keyAlreadyConsumed() public {
        // First upgrade succeeds and rotates key 0 → replacementKey(0).
        _doRecoveryUpgrade(address(newImpl), 0);

        // Deploy another impl for second attempt
        WOTSPlusImplementation thirdImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(thirdImpl));

        // Try to reuse the ORIGINAL key 0 — it's been replaced by _replacementKey(0),
        // so the old key is no longer a member and the pre-verify check fires.
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress memory newRKey = _replacementKey(100);
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(thirdImpl), rKey, newRKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload =
            _buildRecoveryUpgradePayload(rKey, newRKey, sig, address(thirdImpl), keccak256("consumed-verifier"));

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        wallet.recoveryUpgrade(address(thirdImpl), payload);
    }

    /// @dev Belt-and-suspenders test for the verify-delegatecall storage guard.
    ///      A rogue but factory-vetted impl whose `verifyRecoveryUpgrade` SSTOREs
    ///      to the disasterRecoveryKey seed slot must be caught by the post-
    ///      delegatecall snapshot check in `recoveryUpgrade`.
    function test_recoveryUpgrade_revertsWhen_verifyDelegateCallMutatesGuardedSlot() public {
        RogueImpl_WritesGuardedSlot rogue = new RogueImpl_WritesGuardedSlot();
        vm.prank(ADMIN);
        factory.vetImplementation(address(rogue));

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress memory newRKey = _replacementKey(0);
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(address(wallet), address(rogue), rKey, newRKey);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        // The rogue's fallback ignores the verifier portion of the payload, but the
        // codec still requires a well-formed payload shape so we build it normally.
        bytes memory payload =
            _buildRecoveryUpgradePayload(rKey, newRKey, sig, address(rogue), keccak256("rogue-verifier"));

        // The guard reverts with empty data (plain revert), consistent with
        // Solady's parent guard style.
        vm.prank(ALICE);
        vm.expectRevert();
        wallet.recoveryUpgrade(address(rogue), payload);
    }
}
