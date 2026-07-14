// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness, HarnessKeyset} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/wots/EnumerableWinternitzAddressSet.sol";

/// @dev Behaviour tests for `_safeAddKey(set, key)`. The function calls
///      `_enforceUnspentKey(key)` (revert `KeyInUse` on global collision)
///      and then `set.add(key, MAX_KEYS)` (revert `KeyAdditionFailed` on
///      bool=false — now exclusively cap excess since the global pre-check
///      caught any duplicate). Library-level reverts (`ZeroValueWinternitzAddress`,
///      `ExceedsCapacity`) preempt the bool check and bubble through unchanged.
contract WOTSPlusImplementation__safeAddKey is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public bare;

    function setUp() public override {
        super.setUp();
        bare = new WOTSPlusImplementationHarness(payable(address(factory)));
    }

    function _makeKey(uint256 seed) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return WOTSPlus.WinternitzAddress({publicSeed: bytes32(seed), publicKeyHash: bytes32(seed + 1000)});
    }

    function _makeKeys(uint256 startSeed, uint256 count)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[] memory keys)
    {
        keys = new WOTSPlus.WinternitzAddress[](count);
        for (uint256 i = 0; i < count; i++) {
            keys[i] = _makeKey(startSeed + i * 2);
        }
    }

    function test_exposed_safeAddKey_addsToEmptySet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xaa00);

        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);

        assertEq(bare.keyCount(Codec.KeyType.Verification), 1);
        assertTrue(bare.isKey(Codec.KeyType.Verification, key));
    }

    function test_exposed_safeAddKey_addsToNonEmptySet() public {
        WOTSPlus.WinternitzAddress[] memory seed = _makeKeys(0xaa10, 3);
        bare.exposed_addKeys(HarnessKeyset.Recovery, seed);

        WOTSPlus.WinternitzAddress memory key = _makeKey(0xaa20);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);

        assertEq(bare.keyCount(Codec.KeyType.Recovery), 4);
        assertTrue(bare.isKey(Codec.KeyType.Recovery, key));
    }

    // The global uniqueness pre-check catches the in-set duplicate case before
    // `set.add` runs, so re-adding the same key reverts with `KeyInUse` rather
    // than `KeyAdditionFailed`.
    function test_exposed_safeAddKey_revertsWhen_keyAlreadyPresent() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xaa30);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
    }

    // ── Cross-keyset uniqueness (KeyInUse) ─────────────────────────────

    function test_exposed_safeAddKey_revertsWhen_keyInTransactionSet_targetRecovery() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb00);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);
    }

    function test_exposed_safeAddKey_revertsWhen_keyInTransactionSet_targetVerification() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb10);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
    }

    function test_exposed_safeAddKey_revertsWhen_keyInRecoverySet_targetTransaction() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb20);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);
    }

    function test_exposed_safeAddKey_revertsWhen_keyInRecoverySet_targetVerification() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb30);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
    }

    function test_exposed_safeAddKey_revertsWhen_keyInVerificationSet_targetTransaction() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb40);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);
    }

    function test_exposed_safeAddKey_revertsWhen_keyInVerificationSet_targetRecovery() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb50);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);
    }

    function test_exposed_safeAddKey_revertsWhen_keyEqualsDisasterRecoveryKey() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb60);
        bare.setDisasterRecoveryKey(key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);
    }

    function test_exposed_safeAddKey_revertsWhen_keyEqualsOwnershipKey() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb70);
        bare.setOwnershipKey(key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);
    }

    function test_exposed_safeAddKey_succeeds_whenGloballyUnique() public {
        // Populate every other slot with distinct keys, then confirm a fresh
        // key still admits.
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, _makeKey(0xcc00));
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, _makeKey(0xcc10));
        bare.exposed_safeAddKey(HarnessKeyset.Verification, _makeKey(0xcc20));
        bare.setDisasterRecoveryKey(_makeKey(0xcc30));
        bare.setOwnershipKey(_makeKey(0xcc40));

        WOTSPlus.WinternitzAddress memory fresh = _makeKey(0xcc50);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, fresh);

        assertTrue(bare.isKey(Codec.KeyType.Recovery, fresh));
    }

    // ── Library-level reverts (preempt the bool check) ─────────────────

    // Fill the Verification set to MAX_KEYS (10), then try to safeAdd one more.
    // Library's `add(set, key, cap)` reverts with ExceedsCapacity after a
    // successful insert; bool check never runs.
    function test_exposed_safeAddKey_revertsWhen_exceedsMaxKeys() public {
        WOTSPlus.WinternitzAddress[] memory fill = _makeKeys(0xaa40, 10);
        bare.exposed_addKeys(HarnessKeyset.Verification, fill);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 10);

        // Seed must not collide with any in `fill` (seeds 0xaa40, 0xaa42, ..., 0xaa52).
        WOTSPlus.WinternitzAddress memory extra = _makeKey(0xaa60);
        vm.expectRevert(Keyset.ExceedsCapacity.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, extra);
    }

    function test_exposed_safeAddKey_revertsWhen_zeroSeed() public {
        WOTSPlus.WinternitzAddress memory key =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(uint256(1))});

        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
    }

    function test_exposed_safeAddKey_revertsWhen_zeroHash() public {
        WOTSPlus.WinternitzAddress memory key =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(0)});

        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
    }
}
