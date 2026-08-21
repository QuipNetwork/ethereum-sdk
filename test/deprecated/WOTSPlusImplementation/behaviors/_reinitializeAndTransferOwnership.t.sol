// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

/// @dev Behaviour tests for `_reinitializeAndTransferOwnership(payload)`.
///      Exercises the full re-init flow: decode payload, validate the supplied
///      ownership-key pair, verify WOTS+ sig over the transfer-or-handover digest,
///      rotate disaster + ownership keys, wipe/repopulate all three keysets
///      (transaction, recovery, verification) to the always-10 invariant,
///      switch classical owner.
contract WOTSPlusImplementation__reinitializeAndTransferOwnership is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    WOTSPlus.WinternitzAddress internal pqOwner;
    bytes32 internal pqOwnerPriv;
    WOTSPlus.WinternitzAddress internal ownershipPub;
    bytes32 internal ownershipPriv;
    WOTSPlus.WinternitzAddress internal disasterPub;

    address internal NEW_OWNER;

    struct Ctx {
        address newOwner;
        WOTSPlus.WinternitzAddress newOwnership;
        WOTSPlus.WinternitzAddress newDisaster;
        WOTSPlus.WinternitzAddress[10] newTxn;
        WOTSPlus.WinternitzAddress[10] newRec;
        WOTSPlus.WinternitzAddress[10] newVer;
    }

    function setUp() public override {
        super.setUp();
        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (pqOwner, pqOwnerPriv) = _generateKeyPair("h-rein");
        (ownershipPub, ownershipPriv) = _legacyOwnershipKey(pqOwner);
        (disasterPub,) = _legacyDisasterKey(pqOwner);

        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pqOwnerPriv, 10);
        bytes memory payload = _encodeInitPayload(pqOwner, rKeys);

        vm.prank(ALICE);
        address proxyAddr =
            factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("h-rein-vault"), COMMITMENT, payable(ALICE), payload);
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));

        NEW_OWNER = makeAddr("newOwner");
    }

    /*────────────────────────── derivation helpers ──────────────────────────*/

    function _legacyOwnershipKey(WOTSPlus.WinternitzAddress memory pq)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pub, bytes32 priv)
    {
        bytes32 seed = keccak256(abi.encodePacked(pq.publicSeed, pq.publicKeyHash, "ownership-legacy"));
        (pub, priv) = WOTSPlus.generateKeyPair(seed);
    }

    function _legacyDisasterKey(WOTSPlus.WinternitzAddress memory pq)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pub, bytes32 priv)
    {
        bytes32 seed = keccak256(abi.encodePacked(pq.publicSeed, pq.publicKeyHash, "disaster-legacy"));
        (pub, priv) = WOTSPlus.generateKeyPair(seed);
    }

    function _freshCtx() internal view returns (Ctx memory c) {
        c.newOwner = NEW_OWNER;
        (c.newOwnership,) = _generateKeyPair("h-rein-newown");
        (c.newDisaster,) = _generateKeyPair("h-rein-newdisaster");
        for (uint256 i; i < 10; i++) {
            (c.newTxn[i],) = _generateKeyPair(keccak256(abi.encodePacked("h-rein-newtxn", i)));
        }
        for (uint256 i; i < 10; i++) {
            (c.newRec[i],) = _generateKeyPair(keccak256(abi.encodePacked("h-rein-newrec", i)));
        }
        for (uint256 i; i < 10; i++) {
            (c.newVer[i],) = _generateKeyPair(keccak256(abi.encodePacked("h-rein-newver", i)));
        }
    }

    function _keysHash(Ctx memory c) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(c.newDisaster, c.newTxn, c.newRec, c.newVer));
    }

    function _digest(
        Ctx memory c,
        WOTSPlus.WinternitzAddress memory current,
        WOTSPlus.WinternitzAddress memory newOwnership
    ) internal view returns (bytes32) {
        bytes32 kh = _keysHash(c);
        return Codec.transferOwnershipDigest(
            address(harnessProxy),
            block.chainid,
            current.publicSeed,
            current.publicKeyHash,
            newOwnership.publicSeed,
            newOwnership.publicKeyHash,
            c.newOwner,
            kh
        );
    }

    function _encodeWithSig(
        Ctx memory c,
        WOTSPlus.WinternitzAddress memory current,
        WOTSPlus.WinternitzElements memory sig
    ) internal pure returns (bytes memory) {
        return Codec.encodeOwnershipTransfer(
            current, c.newOwnership, sig, c.newOwner, c.newDisaster, c.newTxn, c.newRec, c.newVer
        );
    }

    function _encodeTransfer(Ctx memory c) internal view returns (bytes memory) {
        bytes32 d = _digest(c, ownershipPub, c.newOwnership);
        WOTSPlus.WinternitzElements memory sig = _sign(ownershipPriv, d);
        return _encodeWithSig(c, ownershipPub, sig);
    }

    /*──────────────────────────── happy paths ────────────────────────────*/

    function test_exposed_reinitializeAndTransferOwnership_transferFlow() public {
        Ctx memory c = _freshCtx();
        bytes memory payload = _encodeTransfer(c);

        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);

        assertEq(harnessProxy.owner(), NEW_OWNER);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 10);
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, c.newTxn[0]));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, c.newRec[0]));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, c.newVer[0]));
    }

    function test_exposed_reinitializeAndTransferOwnership_emitsEvent() public {
        Ctx memory c = _freshCtx();
        bytes memory payload = _encodeTransfer(c);

        vm.recordLogs();
        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 expected = IWOTSPlusImplementation.OwnershipReinitialized.selector;
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == expected) {
                found = true;
                break;
            }
        }
        assertTrue(found, "OwnershipReinitialized not emitted");
    }

    /*──────────────────────────── reverts ────────────────────────────*/

    function test_exposed_reinitializeAndTransferOwnership_revertsWhen_zeroAddressOwner() public {
        Ctx memory c = _freshCtx();
        c.newOwner = address(0);
        bytes memory payload = _encodeTransfer(c);

        vm.expectRevert(IWOTSPlusImplementation.ZeroAddressOwner.selector);
        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);
    }

    function test_exposed_reinitializeAndTransferOwnership_revertsWhen_currentOwnershipKeyMismatch() public {
        Ctx memory c = _freshCtx();
        (WOTSPlus.WinternitzAddress memory stray, bytes32 strayPriv) = _generateKeyPair("h-rein-stray");

        // Sign a valid digest for `stray` (so we exercise only the mismatch gate).
        bytes32 d = _digest(c, stray, c.newOwnership);
        WOTSPlus.WinternitzElements memory sig = _sign(strayPriv, d);
        bytes memory payload = _encodeWithSig(c, stray, sig);

        vm.expectRevert(IWOTSPlusImplementation.UnknownOwnershipKey.selector);
        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);
    }

    function test_exposed_reinitializeAndTransferOwnership_revertsWhen_newOwnershipKeyZero() public {
        Ctx memory c = _freshCtx();
        c.newOwnership = WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        bytes memory payload = _encodeTransfer(c);

        vm.expectRevert(IWOTSPlusImplementation.UnknownOwnershipKey.selector);
        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);
    }

    function test_exposed_reinitializeAndTransferOwnership_revertsWhen_newOwnershipEqualsCurrent() public {
        Ctx memory c = _freshCtx();
        c.newOwnership = ownershipPub;
        bytes memory payload = _encodeTransfer(c);

        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);
    }

    function test_exposed_reinitializeAndTransferOwnership_revertsWhen_newDisasterKeyZero() public {
        Ctx memory c = _freshCtx();
        c.newDisaster = WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        bytes memory payload = _encodeTransfer(c);

        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);
    }

    function test_exposed_reinitializeAndTransferOwnership_revertsWhen_signatureInvalid() public {
        Ctx memory c = _freshCtx();
        // Sign the wrong digest so verification fails.
        WOTSPlus.WinternitzElements memory sig = _sign(ownershipPriv, keccak256("not-the-digest"));
        bytes memory payload = _encodeWithSig(c, ownershipPub, sig);

        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);
    }

    function test_exposed_reinitializeAndTransferOwnership_revertsWhen_txnKeyDuplicate() public {
        Ctx memory c = _freshCtx();
        c.newTxn[3] = c.newTxn[0]; // collide two transaction-key entries
        bytes memory payload = _encodeTransfer(c);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);
    }

    function test_exposed_reinitializeAndTransferOwnership_revertsWhen_recoveryKeyDuplicate() public {
        Ctx memory c = _freshCtx();
        c.newRec[5] = c.newRec[0]; // collide two recovery-key entries
        bytes memory payload = _encodeTransfer(c);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        vm.prank(ALICE);
        harnessProxy.exposed_reinitializeAndTransferOwnership(payload);
    }
}
