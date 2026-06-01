// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

/// @dev Behaviour tests for `migrate(bytes)`. Gated by `_upgradeGuard()` — the
///      transient-storage flag set by `upgradeToAndCall` around its migrator
///      delegatecall. Direct calls revert `NotUpgrading`; calls under the flag
///      clear + reinstall txn/recovery/verification keys and emit `WalletMigrated`.
///
///      The harness helper `exposed_migrateInUpgradeContext` sets the tstore
///      flag, invokes `this.migrate(payload)`, and clears the flag — so these
///      tests exercise migrate in isolation without a full upgrade round-trip.
contract QuipWallet_migrate is QuipWalletTest {
    QuipWalletHarness public harnessProxy;

    function setUp() public override {
        super.setUp();
        QuipWalletHarness harnessImpl = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (
            WOTSPlus.WinternitzAddress memory pub,
            bytes32 priv
        ) = _generateKeyPair("h-mig");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            priv,
            10
        );
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{
            value: INITIAL_DEPOSIT
        }(keccak256("h-mig-vault"), payable(ALICE), payload);
        harnessProxy = QuipWalletHarness(payable(proxyAddr));
    }

    function _mkKey(
        uint256 seed
    ) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return
            WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(seed),
                publicKeyHash: bytes32(seed + 1000)
            });
    }

    function _validMigratorPayload() internal pure returns (bytes memory) {
        WOTSPlus.WinternitzAddress[10] memory txn;
        WOTSPlus.WinternitzAddress[10] memory rec;
        WOTSPlus.WinternitzAddress[10] memory ver;
        for (uint256 i; i < 10; i++) txn[i] = _mkKey(0x1000 + i * 2);
        for (uint256 i; i < 10; i++) rec[i] = _mkKey(0x2000 + i * 2);
        for (uint256 i; i < 10; i++) ver[i] = _mkKey(0x2800 + i * 2);
        return
            Codec.encodeInit(_mkKey(0x3000), _mkKey(0x4000), txn, rec, ver);
    }

    /*──────────────────────────── happy path ────────────────────────────*/

    function test_migrate_clearsAndInstallsKeysInUpgradeContext() public {
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 10);

        bytes memory payload = _validMigratorPayload();
        harnessProxy.exposed_migrateInUpgradeContext(payload);

        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 10);
        // New txn/recovery/verification keys should now be present; old ones gone.
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, _mkKey(0x1000)));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, _mkKey(0x2000)));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, _mkKey(0x2800)));
    }

    function test_migrate_emitsWalletMigrated() public {
        bytes memory payload = _validMigratorPayload();

        vm.recordLogs();
        harnessProxy.exposed_migrateInUpgradeContext(payload);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 expected = IQuipWallet.WalletMigrated.selector;
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == expected) {
                found = true;
                break;
            }
        }
        assertTrue(found, "WalletMigrated not emitted");
    }

    /*──────────────────────────── reverts ────────────────────────────*/

    function test_migrate_revertsWhen_calledDirectlyOutsideUpgradeContext()
        public
    {
        bytes memory payload = _validMigratorPayload();
        vm.expectRevert(IQuipWallet.NotUpgrading.selector);
        harnessProxy.migrate(payload);
    }

    function test_migrate_revertsWhen_transactionKeyAlreadyInUse() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x5000);
        txn[3] = txn[0]; // collision
        bytes memory payload = Codec.encodeInit(
            _mkKey(0x7000),
            _mkKey(0x8000),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_duplicateRecoveryKey() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x9000);
        rec[7] = rec[0]; // collision
        bytes memory payload = Codec.encodeInit(
            _mkKey(0xb000),
            _mkKey(0xc000),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_duplicateVerificationKey() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x9100);
        ver[5] = ver[1]; // collision within verification batch
        bytes memory payload = Codec.encodeInit(
            _mkKey(0xb100),
            _mkKey(0xc100),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_zeroTxnKey() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0xd000);
        txn[2] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });
        bytes memory payload = Codec.encodeInit(
            _mkKey(0xf000),
            _mkKey(0x1100),
            txn,
            rec,
            ver
        );

        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_disasterKeyZero() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x1200);
        bytes memory payload = Codec.encodeInit(
            WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(0),
                publicKeyHash: bytes32(0)
            }),
            // _freshKeyArrays(0x1200) reserves 0x1200..0x1412; pick ownership
            // outside that range to avoid a verification-loop KeyInUse.
            _mkKey(0x1500),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_ownershipKeyZero() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x1500);
        bytes memory payload = Codec.encodeInit(
            // _freshKeyArrays(0x1500) reserves 0x1500..0x1712; pick disaster
            // outside that range.
            _mkKey(0x1800),
            WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(0),
                publicKeyHash: bytes32(0)
            }),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CROSS-SET KEY REUSE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Build 10 txn + 10 rec + 10 ver keys deterministically from `base`
    ///      so the caller can mutate one entry to stage a cross-set collision.
    function _freshKeyArrays(
        uint256 base
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        )
    {
        for (uint256 i = 0; i < 10; i++) txn[i] = _mkKey(base + i * 2);
        for (uint256 i = 0; i < 10; i++) rec[i] = _mkKey(base + 0x100 + i * 2);
        for (uint256 i = 0; i < 10; i++) ver[i] = _mkKey(base + 0x200 + i * 2);
    }

    // A recovery key collides with a transaction key. The txn loop installs
    // first; the recovery loop's `_safeAddKey` → `_enforceUnspentKey` sees
    // the key in `transactionKeys` and reverts `KeyInUse`.
    function test_migrate_revertsWhen_recoveryKeyAlsoInTxnSet() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x2000);
        rec[3] = txn[1];
        bytes memory payload = Codec.encodeInit(
            _mkKey(0x2900),
            _mkKey(0x2a00),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    // A verification key collides with a transaction key. Txn loop installs
    // first, recovery loop runs cleanly, verification loop's `_safeAddKey`
    // reverts `KeyInUse`.
    function test_migrate_revertsWhen_verificationKeyAlsoInTxnSet() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x2100);
        ver[4] = txn[2];
        bytes memory payload = Codec.encodeInit(
            _mkKey(0x2920),
            _mkKey(0x2a20),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    // A verification key collides with a recovery key. Both batches install
    // before verification; verification loop reverts `KeyInUse`.
    function test_migrate_revertsWhen_verificationKeyAlsoInRecoverySet() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x2200);
        ver[6] = rec[3];
        bytes memory payload = Codec.encodeInit(
            _mkKey(0x2940),
            _mkKey(0x2a40),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    // A txn key matches the disaster recovery key. Disaster is stored before
    // either keyset loop runs, so the txn loop's pre-check fires `KeyInUse`.
    function test_migrate_revertsWhen_txnKeyEqualsDisasterKey() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x3000);
        WOTSPlus.WinternitzAddress memory disaster = _mkKey(0x3900);
        txn[2] = disaster;
        bytes memory payload = Codec.encodeInit(
            disaster,
            _mkKey(0x3a00),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    // A txn key matches the ownership key. Ownership is stored before the
    // keyset loops; the txn loop's pre-check fires `KeyInUse`.
    function test_migrate_revertsWhen_txnKeyEqualsOwnershipKey() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x4000);
        WOTSPlus.WinternitzAddress memory ownership = _mkKey(0x4a00);
        txn[4] = ownership;
        bytes memory payload = Codec.encodeInit(
            _mkKey(0x4900),
            ownership,
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    // A recovery key matches the disaster recovery key. Caught by the
    // recovery loop after the txn loop runs cleanly.
    function test_migrate_revertsWhen_recoveryKeyEqualsDisasterKey() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x5000);
        WOTSPlus.WinternitzAddress memory disaster = _mkKey(0x5900);
        rec[6] = disaster;
        bytes memory payload = Codec.encodeInit(
            disaster,
            _mkKey(0x5a00),
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    // A recovery key matches the ownership key. Caught by the recovery loop.
    function test_migrate_revertsWhen_recoveryKeyEqualsOwnershipKey() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x6000);
        WOTSPlus.WinternitzAddress memory ownership = _mkKey(0x6a00);
        rec[2] = ownership;
        bytes memory payload = Codec.encodeInit(
            _mkKey(0x6900),
            ownership,
            txn,
            rec,
            ver
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    // ownershipKey == disasterRecoveryKey. Disaster is enforced + stored
    // first; the next call to `_enforceUnspentKey(ownershipKey)` sees the
    // disaster slot match and reverts before any keyset loop runs.
    function test_migrate_revertsWhen_ownershipKeyEqualsDisasterKey() public {
        (
            WOTSPlus.WinternitzAddress[10] memory txn,
            WOTSPlus.WinternitzAddress[10] memory rec,
            WOTSPlus.WinternitzAddress[10] memory ver
        ) = _freshKeyArrays(0x7000);
        WOTSPlus.WinternitzAddress memory shared = _mkKey(0x7900);
        bytes memory payload = Codec.encodeInit(shared, shared, txn, rec, ver);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }
}
