// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness, HarnessKeyset} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

/// @dev Behaviour tests for the `_rotateKeys(set, current, next)` primitive.
///      `_rotateKeys` is deliberately thin: it calls `set.remove(current)` then
///      `set.add(next)` and emits `KeyRotated`. Neither underlying library call
///      reverts on "current absent" or "next already present" — those checks
///      belong to `_enforceContained` / `_enforceUncontained` upstream. The only
///      library-level revert path is `ZeroValueWinternitzAddress` on `add`.
contract QuipWallet__rotateKeys is QuipWalletTest {
    QuipWalletHarness public harnessProxy;
    QuipWalletHarness public bare;

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
        ) = _generateKeyPair("h-rotate");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            priv,
            10
        );
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{
            value: INITIAL_DEPOSIT
        }(keccak256("h-rotate-vault"), payable(ALICE), payload);
        harnessProxy = QuipWalletHarness(payable(proxyAddr));

        bare = new QuipWalletHarness(payable(address(factory)));
    }

    function _makeKey(
        uint256 seed
    ) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return
            WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(seed),
                publicKeyHash: bytes32(seed + 1000)
            });
    }

    function _makeKeys(
        uint256 startSeed,
        uint256 count
    ) internal pure returns (WOTSPlus.WinternitzAddress[] memory keys) {
        keys = new WOTSPlus.WinternitzAddress[](count);
        for (uint256 i = 0; i < count; i++) {
            keys[i] = _makeKey(startSeed + i * 2);
        }
    }

    function test_exposed_rotateKeys_recovery_swaps() public {
        WOTSPlus.WinternitzAddress memory current = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 0);
        WOTSPlus.WinternitzAddress memory next = _makeKey(0x7777);

        harnessProxy.exposed_rotateKeys(HarnessKeyset.Recovery, current, next);

        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, current));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, next));
    }

    function test_exposed_rotateKeys_transaction_swaps() public {
        WOTSPlus.WinternitzAddress memory current = harnessProxy
            .keyAt(Codec.KeyType.Transaction, 0);
        WOTSPlus.WinternitzAddress memory next = _makeKey(0x8888);

        harnessProxy.exposed_rotateKeys(
            HarnessKeyset.Transaction,
            current,
            next
        );

        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, current));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, next));
    }

    function test_exposed_rotateKeys_verification_swaps() public {
        WOTSPlus.WinternitzAddress[] memory seed = _makeKeys(0x1000, 1);
        bare.exposed_addKeys(HarnessKeyset.Verification, seed);

        WOTSPlus.WinternitzAddress memory next = _makeKey(0x9999);
        bare.exposed_rotateKeys(HarnessKeyset.Verification, seed[0], next);

        assertFalse(bare.isKey(Codec.KeyType.Verification, seed[0]));
        assertTrue(bare.isKey(Codec.KeyType.Verification, next));
    }

    function test_exposed_rotateKeys_sizeUnchanged() public {
        uint256 sizeBefore = harnessProxy.keyCount(Codec.KeyType.Recovery);
        WOTSPlus.WinternitzAddress memory current = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 0);
        WOTSPlus.WinternitzAddress memory next = _makeKey(0x3333);

        harnessProxy.exposed_rotateKeys(HarnessKeyset.Recovery, current, next);

        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), sizeBefore);
    }

    function test_exposed_rotateKeys_emitsEvent() public {
        WOTSPlus.WinternitzAddress memory current = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 0);
        WOTSPlus.WinternitzAddress memory next = _makeKey(0x4444);

        vm.recordLogs();
        harnessProxy.exposed_rotateKeys(HarnessKeyset.Recovery, current, next);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 expected = IQuipWallet.KeyRotated.selector;
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == expected) {
                found = true;
                break;
            }
        }
        assertTrue(found, "KeyRotated not emitted");
    }

    // remove-then-add preserves size, so rotating while the set is at capacity
    // (10/10) must not trip ExceedsCapacity even though `_rotateKeys` uses the
    // uncapped `add`.
    function test_exposed_rotateKeys_succeedsAtFullCapacity() public {
        // Recovery set starts fully populated (10).
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        WOTSPlus.WinternitzAddress memory current = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 5);
        WOTSPlus.WinternitzAddress memory next = _makeKey(0x5555);

        harnessProxy.exposed_rotateKeys(HarnessKeyset.Recovery, current, next);

        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, next));
    }

    function test_exposed_rotateKeys_revertsWhen_nextZeroSeed() public {
        WOTSPlus.WinternitzAddress memory current = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 0);
        WOTSPlus.WinternitzAddress memory next = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(uint256(1))
        });

        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        harnessProxy.exposed_rotateKeys(HarnessKeyset.Recovery, current, next);
    }

    function test_exposed_rotateKeys_revertsWhen_nextZeroHash() public {
        WOTSPlus.WinternitzAddress memory current = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 0);
        WOTSPlus.WinternitzAddress memory next = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(0)
        });

        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        harnessProxy.exposed_rotateKeys(HarnessKeyset.Recovery, current, next);
    }

    // Quirk documented by the bodies of `_rotateKeys` itself: remove is
    // idempotent on "not present" (returns false silently) and add is
    // idempotent on "already present" — so the primitive does not enforce
    // "current must be present". The set grows by one in that pathological
    // case. Callers must go through `_verifyAndRotate` / the enforcement
    // helpers to get the enforced behaviour.
    function test_exposed_rotateKeys_currentAbsent_netAddsNext() public {
        WOTSPlus.WinternitzAddress memory stray = _makeKey(0x6666);
        WOTSPlus.WinternitzAddress memory next = _makeKey(0x6667);

        uint256 sizeBefore = bare.keyCount(Codec.KeyType.Verification);
        bare.exposed_rotateKeys(HarnessKeyset.Verification, stray, next);

        assertEq(bare.keyCount(Codec.KeyType.Verification), sizeBefore + 1);
        assertTrue(bare.isKey(Codec.KeyType.Verification, next));
    }

    // Quirk: when `next` is already present, the library `add` returns false
    // silently; `remove(current)` still removes, net-effect is size-1.
    function test_exposed_rotateKeys_nextAlreadyPresent_netRemovesCurrent()
        public
    {
        WOTSPlus.WinternitzAddress memory current = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 0);
        // Pick another existing key as `next` so the "already present" path triggers.
        WOTSPlus.WinternitzAddress memory next = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 1);

        uint256 sizeBefore = harnessProxy.keyCount(Codec.KeyType.Recovery);
        harnessProxy.exposed_rotateKeys(HarnessKeyset.Recovery, current, next);

        assertEq(
            harnessProxy.keyCount(Codec.KeyType.Recovery),
            sizeBefore - 1
        );
        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, current));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, next));
    }
}
