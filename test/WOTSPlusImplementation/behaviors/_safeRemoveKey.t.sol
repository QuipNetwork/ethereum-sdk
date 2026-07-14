// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness, HarnessKeyset} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @dev Behaviour tests for `_safeRemoveKey(set, key)`. Wraps `set.remove(key)`
///      and reverts with `KeyRemovalFailed` if the underlying op returns false
///      (i.e. the key wasn't in the set). Defends a one-time-signature scheme
///      against silent under-rotation: emitting `KeyRotated` over a no-op would
///      leave a spent WOTS+ key live in the active set.
contract WOTSPlusImplementation__safeRemoveKey is WOTSPlusImplementationTest {
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

    function test_exposed_safeRemoveKey_removesPresentKey() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb00);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
        assertTrue(bare.isKey(Codec.KeyType.Verification, key));

        bare.exposed_safeRemoveKey(HarnessKeyset.Verification, key);

        assertEq(bare.keyCount(Codec.KeyType.Verification), 0);
        assertFalse(bare.isKey(Codec.KeyType.Verification, key));
    }

    function test_exposed_safeRemoveKey_removesFromMidSet() public {
        WOTSPlus.WinternitzAddress[] memory seed = _makeKeys(0xbb10, 5);
        bare.exposed_addKeys(HarnessKeyset.Recovery, seed);
        assertEq(bare.keyCount(Codec.KeyType.Recovery), 5);

        bare.exposed_safeRemoveKey(HarnessKeyset.Recovery, seed[2]);

        assertEq(bare.keyCount(Codec.KeyType.Recovery), 4);
        assertFalse(bare.isKey(Codec.KeyType.Recovery, seed[2]));
        // Other keys are untouched.
        for (uint256 i = 0; i < 5; i++) {
            if (i == 2) continue;
            assertTrue(bare.isKey(Codec.KeyType.Recovery, seed[i]));
        }
    }

    // ── Reverts ────────────────────────────────────────────────────────

    function test_exposed_safeRemoveKey_revertsWhen_setEmpty() public {
        WOTSPlus.WinternitzAddress memory stray = _makeKey(0xbb20);

        vm.expectRevert(IWOTSPlusImplementation.KeyRemovalFailed.selector);
        bare.exposed_safeRemoveKey(HarnessKeyset.Verification, stray);
    }

    function test_exposed_safeRemoveKey_revertsWhen_keyNotPresent() public {
        WOTSPlus.WinternitzAddress[] memory seed = _makeKeys(0xbb30, 3);
        bare.exposed_addKeys(HarnessKeyset.Recovery, seed);

        WOTSPlus.WinternitzAddress memory stray = _makeKey(0xbb40);

        vm.expectRevert(IWOTSPlusImplementation.KeyRemovalFailed.selector);
        bare.exposed_safeRemoveKey(HarnessKeyset.Recovery, stray);
    }

    // Removing the same key twice: first succeeds, second reverts.
    function test_exposed_safeRemoveKey_revertsWhen_alreadyRemoved() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xbb50);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);

        bare.exposed_safeRemoveKey(HarnessKeyset.Verification, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyRemovalFailed.selector);
        bare.exposed_safeRemoveKey(HarnessKeyset.Verification, key);
    }
}
