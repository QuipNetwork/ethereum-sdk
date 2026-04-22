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
///      clear + reinstall txn/recovery keys and emit `WalletMigrated`.
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
        WOTSPlus.WinternitzAddress[5] memory txn;
        WOTSPlus.WinternitzAddress[10] memory rec;
        for (uint256 i; i < 5; i++) txn[i] = _mkKey(0x1000 + i * 2);
        for (uint256 i; i < 10; i++) rec[i] = _mkKey(0x2000 + i * 2);
        return
            Codec.encodeInit(_mkKey(0x3000), _mkKey(0x4000), txn, rec);
    }

    /*──────────────────────────── happy path ────────────────────────────*/

    function test_migrate_clearsAndInstallsKeysInUpgradeContext() public {
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);

        bytes memory payload = _validMigratorPayload();
        harnessProxy.exposed_migrateInUpgradeContext(payload);

        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        // New txn/recovery keys should now be present; old ones gone.
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, _mkKey(0x1000)));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, _mkKey(0x2000)));
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

    function test_migrate_revertsWhen_duplicateTransactionKey() public {
        WOTSPlus.WinternitzAddress[5] memory txn;
        WOTSPlus.WinternitzAddress[10] memory rec;
        for (uint256 i; i < 5; i++) txn[i] = _mkKey(0x5000 + i * 2);
        txn[3] = txn[0]; // collision
        for (uint256 i; i < 10; i++) rec[i] = _mkKey(0x6000 + i * 2);
        bytes memory payload = Codec.encodeInit(
            _mkKey(0x7000),
            _mkKey(0x8000),
            txn,
            rec
        );

        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_duplicateRecoveryKey() public {
        WOTSPlus.WinternitzAddress[5] memory txn;
        WOTSPlus.WinternitzAddress[10] memory rec;
        for (uint256 i; i < 5; i++) txn[i] = _mkKey(0x9000 + i * 2);
        for (uint256 i; i < 10; i++) rec[i] = _mkKey(0xa000 + i * 2);
        rec[7] = rec[0]; // collision
        bytes memory payload = Codec.encodeInit(
            _mkKey(0xb000),
            _mkKey(0xc000),
            txn,
            rec
        );

        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_zeroTxnKey() public {
        WOTSPlus.WinternitzAddress[5] memory txn;
        WOTSPlus.WinternitzAddress[10] memory rec;
        for (uint256 i; i < 5; i++) txn[i] = _mkKey(0xd000 + i * 2);
        txn[2] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });
        for (uint256 i; i < 10; i++) rec[i] = _mkKey(0xe000 + i * 2);
        bytes memory payload = Codec.encodeInit(
            _mkKey(0xf000),
            _mkKey(0x1100),
            txn,
            rec
        );

        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_disasterKeyZero() public {
        WOTSPlus.WinternitzAddress[5] memory txn;
        WOTSPlus.WinternitzAddress[10] memory rec;
        for (uint256 i; i < 5; i++) txn[i] = _mkKey(0x1200 + i * 2);
        for (uint256 i; i < 10; i++) rec[i] = _mkKey(0x1300 + i * 2);
        bytes memory payload = Codec.encodeInit(
            WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(0),
                publicKeyHash: bytes32(0)
            }),
            _mkKey(0x1400),
            txn,
            rec
        );

        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_ownershipKeyZero() public {
        WOTSPlus.WinternitzAddress[5] memory txn;
        WOTSPlus.WinternitzAddress[10] memory rec;
        for (uint256 i; i < 5; i++) txn[i] = _mkKey(0x1500 + i * 2);
        for (uint256 i; i < 10; i++) rec[i] = _mkKey(0x1600 + i * 2);
        bytes memory payload = Codec.encodeInit(
            _mkKey(0x1700),
            WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(0),
                publicKeyHash: bytes32(0)
            }),
            txn,
            rec
        );

        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        harnessProxy.exposed_migrateInUpgradeContext(payload);
    }
}
