// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../../contracts/deprecated/wots/EnumerableWinternitzAddressSet.sol";
import {WOTSPlusStorage as Storage} from "../../../../contracts/deprecated/wots/WOTSPlusStorage.sol";

contract WOTSPlusImplementation_initialize is WOTSPlusImplementationTest {
    /// @dev ERC-7201 base slot for `WOTSPlusStorage.Layout`. Layout:
    ///      quipFactory at +0, disasterRecoveryKey.publicSeed at +1,
    ///      .publicKeyHash at +2, ownershipKey.publicSeed at +3,
    ///      .publicKeyHash at +4. Imported so any drift between this test
    ///      and the storage library shows up here too.
    bytes32 internal constant STORAGE_BASE = Storage._WOTSPLUS_STORAGE_SLOT;

    /// @dev Builds 10 transaction, 10 recovery, and 10 verification keys
    ///      deterministically from `tag`. Returns fresh-shape arrays the
    ///      caller can mutate before encoding.
    function _freshKeyArrays(string memory tag)
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        )
    {
        for (uint256 i = 0; i < 10; i++) {
            (txn[i],) = WOTSPlus.generateKeyPair(keccak256(abi.encodePacked(tag, "-txn-", i)));
        }
        for (uint256 i = 0; i < 10; i++) {
            (rec[i],) = WOTSPlus.generateKeyPair(keccak256(abi.encodePacked(tag, "-rec-", i)));
        }
        for (uint256 i = 0; i < 10; i++) {
            (ver[i],) = WOTSPlus.generateKeyPair(keccak256(abi.encodePacked(tag, "-ver-", i)));
        }
    }

    function _key(string memory tag) internal pure returns (WOTSPlus.WinternitzAddress memory pub) {
        (pub,) = WOTSPlus.generateKeyPair(keccak256(abi.encodePacked(tag)));
    }

    function test_initialize_setsOwner() public view {
        assertEq(wallet.owner(), ALICE);
    }

    function test_initialize_setsTransactionKeys() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[i]));
        }
    }

    function test_initialize_setsRecoveryKeys() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }
    }

    function test_initialize_setsVerificationKeys() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
    }

    function test_initialize_setsDisasterRecoveryKey() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("set-disaster");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("set-disaster");
        WOTSPlus.WinternitzAddress memory disaster = _key("set-disaster-d");
        WOTSPlus.WinternitzAddress memory ownership = _key("set-disaster-o");
        bytes memory payload = Codec.encodeInit(disaster, ownership, txn, rec, ver);

        vm.prank(address(factory));
        freshWallet.initialize(payable(ALICE), payload);

        assertEq(vm.load(address(freshWallet), bytes32(uint256(STORAGE_BASE) + 1)), disaster.publicSeed);
        assertEq(vm.load(address(freshWallet), bytes32(uint256(STORAGE_BASE) + 2)), disaster.publicKeyHash);
    }

    function test_initialize_setsOwnershipKey() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("set-ownership");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("set-ownership");
        WOTSPlus.WinternitzAddress memory disaster = _key("set-ownership-d");
        WOTSPlus.WinternitzAddress memory ownership = _key("set-ownership-o");
        bytes memory payload = Codec.encodeInit(disaster, ownership, txn, rec, ver);

        vm.prank(address(factory));
        freshWallet.initialize(payable(ALICE), payload);

        assertEq(vm.load(address(freshWallet), bytes32(uint256(STORAGE_BASE) + 3)), ownership.publicSeed);
        assertEq(vm.load(address(freshWallet), bytes32(uint256(STORAGE_BASE) + 4)), ownership.publicKeyHash);
    }

    function test_initialize_setsQuipFactory() public view {
        assertEq(address(wallet.quipFactory()), address(factory));
    }

    function test_initialize_emitsWalletInitialized() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("fresh-event");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("emit");
        WOTSPlus.WinternitzAddress memory disaster = _key("emit-d");
        WOTSPlus.WinternitzAddress memory ownership = _key("emit-o");
        bytes memory payload = Codec.encodeInit(disaster, ownership, txn, rec, ver);

        vm.expectEmit(true, true, false, true, address(freshWallet));
        emit IWOTSPlusImplementation.WalletInitialized(
            address(factory), ALICE, keccak256(abi.encode(txn)), keccak256(abi.encode(rec)), keccak256(abi.encode(ver))
        );

        vm.prank(address(factory));
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_ownerIsZero() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("fresh-zero-owner");
        (WOTSPlus.WinternitzAddress memory newPubkey, bytes32 newPrivKey) = _generateKeyPair("new-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(newPrivKey, 10);
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.ZeroAddressOwner.selector);
        freshWallet.initialize(payable(address(0)), payload);
    }

    function test_initialize_revertsWhen_recoveryKeyHashIsZero() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("fresh-zero-recovery-hash");
        (WOTSPlus.WinternitzAddress memory newPubkey, bytes32 newPrivKey) = _generateKeyPair("new-seed");

        WOTSPlus.WinternitzAddress[] memory badRecovery = _generateRecoveryKeys(newPrivKey, 10);
        badRecovery[5] = WOTSPlus.WinternitzAddress({publicSeed: bytes32("non-empty"), publicKeyHash: bytes32(0)});
        bytes memory payload = _encodeInitPayload(newPubkey, badRecovery);

        vm.prank(address(factory));
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_alreadyInitialized() public {
        (WOTSPlus.WinternitzAddress memory newPubkey, bytes32 newPrivKey) = _generateKeyPair("new-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(newPrivKey, 10);
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        wallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_callerNotFactory() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("fresh-not-factory");
        (WOTSPlus.WinternitzAddress memory newPubkey, bytes32 newPrivKey) = _generateKeyPair("new-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(newPrivKey, 10);
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidFactory.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_transactionKeySeedIsZero() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("fresh-empty-seed");
        WOTSPlus.WinternitzAddress memory emptyPubkey =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32("non-empty")});
        (, bytes32 privKey) = _generateKeyPair("dummy");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privKey, 10);
        bytes memory payload = _encodeInitPayload(emptyPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_transactionKeyHashIsZero() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("fresh-empty-hash");
        WOTSPlus.WinternitzAddress memory emptyPubkey =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32("non-empty"), publicKeyHash: bytes32(0)});
        (, bytes32 privKey) = _generateKeyPair("dummy");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privKey, 10);
        bytes memory payload = _encodeInitPayload(emptyPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_recoveryKeySeedIsZero() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("fresh-zero-recovery");
        (WOTSPlus.WinternitzAddress memory newPubkey, bytes32 newPrivKey) = _generateKeyPair("new-seed");

        WOTSPlus.WinternitzAddress[] memory badRecovery = _generateRecoveryKeys(newPrivKey, 10);
        badRecovery[0] = WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32("non-empty")});
        bytes memory payload = _encodeInitPayload(newPubkey, badRecovery);

        vm.prank(address(factory));
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_keyAlreadyInUse() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("fresh-dup-recovery");
        (WOTSPlus.WinternitzAddress memory newPubkey, bytes32 newPrivKey) = _generateKeyPair("dup-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(newPrivKey, 10);
        rKeys[5] = rKeys[0]; // duplicate!
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_disasterRecoveryKeyIsZero() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("zero-disaster");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("zero-disaster");
        WOTSPlus.WinternitzAddress memory zeroDisaster =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        bytes memory payload = Codec.encodeInit(zeroDisaster, _key("zero-disaster-o"), txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_ownershipKeyIsZero() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("zero-ownership");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("zero-ownership");
        WOTSPlus.WinternitzAddress memory zeroOwnership =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        bytes memory payload = Codec.encodeInit(_key("zero-ownership-d"), zeroOwnership, txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.UnknownOwnershipKey.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_txnKeyEqualsAnotherTxnKey() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("dup-txn");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("dup-txn");
        txn[3] = txn[1];
        bytes memory payload = Codec.encodeInit(_key("dup-txn-d"), _key("dup-txn-o"), txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CROSS-SET KEY REUSE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // A recovery key collides with a transaction key. The txn loop installs
    // first; the recovery loop's `_safeAddKey` → `_enforceUnspentKey` sees the
    // key already in `transactionKeys` and reverts `KeyInUse`.
    function test_initialize_revertsWhen_recoveryKeyAlsoInTxnSet() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("xkey-rec-in-txn");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("xkey-rec-in-txn");
        rec[3] = txn[1];
        bytes memory payload =
            Codec.encodeInit(_key("xkey-rec-in-txn-disaster"), _key("xkey-rec-in-txn-ownership"), txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    // A verification key collides with a transaction key. Both txn and
    // recovery loops install before verification; the verification loop's
    // `_safeAddKey` reverts `KeyInUse`.
    function test_initialize_revertsWhen_verificationKeyAlsoInTxnSet() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("xkey-ver-in-txn");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("xkey-ver-in-txn");
        ver[4] = txn[2];
        bytes memory payload =
            Codec.encodeInit(_key("xkey-ver-in-txn-disaster"), _key("xkey-ver-in-txn-ownership"), txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    // A verification key collides with a recovery key.
    function test_initialize_revertsWhen_verificationKeyAlsoInRecoverySet() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("xkey-ver-in-rec");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("xkey-ver-in-rec");
        ver[6] = rec[3];
        bytes memory payload =
            Codec.encodeInit(_key("xkey-ver-in-rec-disaster"), _key("xkey-ver-in-rec-ownership"), txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    // A txn key matches the disaster recovery key. Disaster is stored before
    // either keyset loop runs, so the txn loop's `_enforceUnspentKey` sees
    // the disaster slot match and reverts.
    function test_initialize_revertsWhen_txnKeyEqualsDisasterKey() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("xkey-txn-eq-disaster");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("xkey-txn-eq-disaster");
        WOTSPlus.WinternitzAddress memory disaster = _key("xkey-txn-eq-disaster-d");
        txn[2] = disaster;
        bytes memory payload = Codec.encodeInit(disaster, _key("xkey-txn-eq-disaster-o"), txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    // A txn key matches the ownership key. Ownership is stored before the
    // keyset loops; the txn loop's pre-check fires `KeyInUse`.
    function test_initialize_revertsWhen_txnKeyEqualsOwnershipKey() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("xkey-txn-eq-ownership");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("xkey-txn-eq-ownership");
        WOTSPlus.WinternitzAddress memory ownership = _key("xkey-txn-eq-ownership-o");
        txn[4] = ownership;
        bytes memory payload = Codec.encodeInit(_key("xkey-txn-eq-ownership-d"), ownership, txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    // A recovery key matches the disaster recovery key. Caught by the
    // recovery loop after the txn loop has already run cleanly.
    function test_initialize_revertsWhen_recoveryKeyEqualsDisasterKey() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("xkey-rec-eq-disaster");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("xkey-rec-eq-disaster");
        WOTSPlus.WinternitzAddress memory disaster = _key("xkey-rec-eq-disaster-d");
        rec[6] = disaster;
        bytes memory payload = Codec.encodeInit(disaster, _key("xkey-rec-eq-disaster-o"), txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    // A recovery key matches the ownership key. Caught by the recovery loop.
    function test_initialize_revertsWhen_recoveryKeyEqualsOwnershipKey() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("xkey-rec-eq-ownership");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("xkey-rec-eq-ownership");
        WOTSPlus.WinternitzAddress memory ownership = _key("xkey-rec-eq-ownership-o");
        rec[2] = ownership;
        bytes memory payload = Codec.encodeInit(_key("xkey-rec-eq-ownership-d"), ownership, txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    // ownershipKey == disasterRecoveryKey. Disaster is enforced + stored
    // first; the next call to `_enforceUnspentKey(ownershipKey)` sees the
    // disaster slot match and reverts before any keyset loop runs.
    function test_initialize_revertsWhen_ownershipKeyEqualsDisasterKey() public {
        WOTSPlusImplementation freshWallet = _deployFreshProxy("xkey-own-eq-disaster");
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays("xkey-own-eq-disaster");
        WOTSPlus.WinternitzAddress memory shared = _key("xkey-own-eq-disaster-shared");
        bytes memory payload = Codec.encodeInit(shared, shared, txn, rec, ver);

        vm.prank(address(factory));
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }
}
