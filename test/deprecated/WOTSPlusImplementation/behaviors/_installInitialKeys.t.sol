// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusStorage as Storage} from "../../../../contracts/deprecated/wots/WOTSPlusStorage.sol";

/// @dev Behaviour tests for
///      `_installInitialKeys(disaster, ownership, txn[10], rec[10], ver[10])`.
///      Writes the two scalar keys, adds all 30 keyset members, then calls
///      `_verifyInitialState()` to assert the post-state invariants.
contract WOTSPlusImplementation__installInitialKeys is WOTSPlusImplementationTest {
    /// @dev Imported from `WOTSPlusStorage` so the offsets below stay aligned
    ///      with the canonical layout under any future namespace rename.
    bytes32 constant STORAGE_BASE = Storage._WOTSPLUS_STORAGE_SLOT;

    /// @dev Factory pre-filled (slot 0) into a fresh harness so the trailing
    ///      `_verifyInitialState()` has a non-zero factory address to observe.
    ///      Callers that only want to trigger the mid-execution KeyInUse
    ///      revert don't need it set.
    function _freshHarness(bool primeFactory) internal returns (WOTSPlusImplementationHarness h) {
        h = new WOTSPlusImplementationHarness(payable(address(factory)));
        if (primeFactory) {
            vm.store(address(h), STORAGE_BASE, bytes32(uint256(uint160(address(factory)))));
        }
    }

    function _mkKey(uint256 seed) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return WOTSPlus.WinternitzAddress({publicSeed: bytes32(seed), publicKeyHash: bytes32(seed + 1000)});
    }

    function _validTxn() internal pure returns (WOTSPlus.WinternitzAddress[10] memory arr) {
        for (uint256 i = 0; i < 10; i++) {
            arr[i] = _mkKey(0x1000 + i * 2);
        }
    }

    function _validRec() internal pure returns (WOTSPlus.WinternitzAddress[10] memory arr) {
        for (uint256 i = 0; i < 10; i++) {
            arr[i] = _mkKey(0x2000 + i * 2);
        }
    }

    function _validVer() internal pure returns (WOTSPlus.WinternitzAddress[10] memory arr) {
        for (uint256 i = 0; i < 10; i++) {
            arr[i] = _mkKey(0x2800 + i * 2);
        }
    }

    function _validDisaster() internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return _mkKey(0x3000);
    }

    function _validOwnership() internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return _mkKey(0x4000);
    }

    function test_exposed_installInitialKeys_happyPath() public {
        WOTSPlusImplementationHarness h = _freshHarness(true);
        h.exposed_installInitialKeys(_validDisaster(), _validOwnership(), _validTxn(), _validRec(), _validVer());

        assertEq(h.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(h.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(h.keyCount(Codec.KeyType.Verification), 10);
    }

    function test_exposed_installInitialKeys_revertsWhen_duplicateTxnKey() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress[10] memory txn = _validTxn();
        txn[4] = txn[0]; // collide entries 0 and 4

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        h.exposed_installInitialKeys(_validDisaster(), _validOwnership(), txn, _validRec(), _validVer());
    }

    function test_exposed_installInitialKeys_revertsWhen_duplicateRecoveryKey() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress[10] memory rec = _validRec();
        rec[7] = rec[0];

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        h.exposed_installInitialKeys(_validDisaster(), _validOwnership(), _validTxn(), rec, _validVer());
    }

    function test_exposed_installInitialKeys_revertsWhen_duplicateVerificationKey() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress[10] memory ver = _validVer();
        ver[6] = ver[2];

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        h.exposed_installInitialKeys(_validDisaster(), _validOwnership(), _validTxn(), _validRec(), ver);
    }

    // Happy inputs but no factory primed → `_verifyInitialState()` at the end
    // fires `ZeroAddressFactory`. Confirms the trailing invariant check runs.
    function test_exposed_installInitialKeys_revertsWhen_factoryUnset() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        vm.expectRevert(IWOTSPlusImplementation.ZeroAddressFactory.selector);
        h.exposed_installInitialKeys(_validDisaster(), _validOwnership(), _validTxn(), _validRec(), _validVer());
    }

    // `_installInitialKeys` adds disaster/ownership via plain SSTORE — zero
    // fields are not rejected at install time, but the trailing
    // `_verifyInitialState()` catches them.
    function test_exposed_installInitialKeys_revertsWhen_disasterKeyZero() public {
        WOTSPlusImplementationHarness h = _freshHarness(true);
        WOTSPlus.WinternitzAddress memory zeroDisaster =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        h.exposed_installInitialKeys(zeroDisaster, _validOwnership(), _validTxn(), _validRec(), _validVer());
    }

    function test_exposed_installInitialKeys_revertsWhen_ownershipKeyZero() public {
        WOTSPlusImplementationHarness h = _freshHarness(true);
        WOTSPlus.WinternitzAddress memory zeroOwnership =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        vm.expectRevert(IWOTSPlusImplementation.UnknownOwnershipKey.selector);
        h.exposed_installInitialKeys(_validDisaster(), zeroOwnership, _validTxn(), _validRec(), _validVer());
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CROSS-SET UNIQUENESS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // A key intended for the recovery set ALSO appearing in the transaction
    // set: the txn loop installs it first; the recovery loop's `_safeAddKey`
    // → `_enforceUnspentKey` sees it in `transactionKeys` and reverts
    // `KeyInUse`. WOTS+ one-time-use forbids the same public key sitting in
    // two role slots.
    function test_exposed_installInitialKeys_revertsWhen_recoveryKeyAlsoInTxnSet() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress[10] memory txn = _validTxn();
        WOTSPlus.WinternitzAddress[10] memory rec = _validRec();
        rec[3] = txn[1]; // same key in both sets

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        h.exposed_installInitialKeys(_validDisaster(), _validOwnership(), txn, rec, _validVer());
    }

    // A verification key also appearing in the txn set: txn loop installs
    // first, recovery loop runs cleanly, verification loop reverts.
    function test_exposed_installInitialKeys_revertsWhen_verificationKeyAlsoInTxnSet() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress[10] memory txn = _validTxn();
        WOTSPlus.WinternitzAddress[10] memory ver = _validVer();
        ver[4] = txn[2];

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        h.exposed_installInitialKeys(_validDisaster(), _validOwnership(), txn, _validRec(), ver);
    }

    // A verification key also appearing in the recovery set: both loops run
    // before verification; verification loop reverts.
    function test_exposed_installInitialKeys_revertsWhen_verificationKeyAlsoInRecoverySet() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress[10] memory rec = _validRec();
        WOTSPlus.WinternitzAddress[10] memory ver = _validVer();
        ver[7] = rec[1];

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        h.exposed_installInitialKeys(_validDisaster(), _validOwnership(), _validTxn(), rec, ver);
    }

    // A txn key collides with the disaster recovery key. Order in
    // `_installInitialKeys`: disaster is stored first, so the txn loop's
    // `_enforceUnspentKey` sees the disaster slot match and reverts.
    function test_exposed_installInitialKeys_revertsWhen_txnKeyEqualsDisasterKey() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress memory disaster = _validDisaster();
        WOTSPlus.WinternitzAddress[10] memory txn = _validTxn();
        txn[2] = disaster;

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        h.exposed_installInitialKeys(disaster, _validOwnership(), txn, _validRec(), _validVer());
    }

    // A recovery key collides with the ownership key. Both singles are
    // installed before either keyset loop, so the recovery loop sees the
    // ownership slot match and reverts.
    function test_exposed_installInitialKeys_revertsWhen_recoveryKeyEqualsOwnershipKey() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress memory ownership = _validOwnership();
        WOTSPlus.WinternitzAddress[10] memory rec = _validRec();
        rec[5] = ownership;

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        h.exposed_installInitialKeys(_validDisaster(), ownership, _validTxn(), rec, _validVer());
    }

    // ownership == disaster: ownership is enforced AFTER disaster is stored,
    // so `_enforceUnspentKey(ownershipKey)` sees the disaster slot match and
    // reverts before any keyset add runs.
    function test_exposed_installInitialKeys_revertsWhen_ownershipEqualsDisaster() public {
        WOTSPlusImplementationHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress memory shared = _mkKey(0x9000);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        h.exposed_installInitialKeys(shared, shared, _validTxn(), _validRec(), _validVer());
    }
}
