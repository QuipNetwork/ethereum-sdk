// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness, HarnessKeyset} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

/// @dev Behaviour tests for `_safeAddKey(set, key)`. Wraps `set.add(key, MAX_KEYS)`
///      and reverts with `KeyAdditionFailed` if the underlying op returns false.
///      Library-level reverts (`ZeroValueWinternitzAddress`, `ExceedsCapacity`)
///      preempt the bool check and bubble through unchanged.
contract QuipWallet__safeAddKey is QuipWalletTest {
    QuipWalletHarness public bare;

    function setUp() public override {
        super.setUp();
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

    function test_exposed_safeAddKey_revertsWhen_keyAlreadyPresent() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xaa30);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);

        vm.expectRevert(IQuipWallet.KeyAdditionFailed.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
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
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(uint256(1))
        });

        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
    }

    function test_exposed_safeAddKey_revertsWhen_zeroHash() public {
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(0)
        });

        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
    }
}
