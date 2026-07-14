// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness, HarnessKeyset} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @dev Behaviour tests for `_isKeySpent(key)` and `_enforceUnspentKey(key)`.
///      `_isKeySpent` consults the monotonic `isKeySpent` burn index, returning
///      true if `key` has EVER been installed in any slot — even if it has since
///      been removed. `_enforceUnspentKey` reverts `KeyInUse` when the index says
///      true. The monotonic property is the audit-driven fix for "WOTS+ key
///      reused after first exposure"; this file is the load-bearing regression
///      test for it.
contract WOTSPlusImplementation__isKeySpent is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public bare;

    function setUp() public override {
        super.setUp();
        bare = new WOTSPlusImplementationHarness(payable(address(factory)));
    }

    function _makeKey(uint256 seed) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return WOTSPlus.WinternitzAddress({publicSeed: bytes32(seed), publicKeyHash: bytes32(seed + 1000)});
    }

    function test_exposed_isKeySpent_returnsFalse_whenIndexEmpty() public view {
        assertFalse(bare.exposed_isKeySpent(_makeKey(0x01)));
    }

    function test_exposed_isKeySpent_returnsTrue_whenInTransactionSet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x10);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);
        assertTrue(bare.exposed_isKeySpent(key));
    }

    function test_exposed_isKeySpent_returnsTrue_whenInRecoverySet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x20);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);
        assertTrue(bare.exposed_isKeySpent(key));
    }

    function test_exposed_isKeySpent_returnsTrue_whenInVerificationSet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x30);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
        assertTrue(bare.exposed_isKeySpent(key));
    }

    function test_exposed_isKeySpent_returnsTrue_whenSetAsDisasterKey() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x40);
        bare.setDisasterRecoveryKey(key);
        assertTrue(bare.exposed_isKeySpent(key));
    }

    function test_exposed_isKeySpent_returnsTrue_whenSetAsOwnershipKey() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x50);
        bare.setOwnershipKey(key);
        assertTrue(bare.exposed_isKeySpent(key));
    }

    /// @dev Sanity: a key with a matching seed but a different hash is a
    ///      distinct entry in the burn index. Confirms the index keys are
    ///      `hash(publicSeed, publicKeyHash)`, not just one field.
    function test_exposed_isKeySpent_returnsFalse_onPartialMatch() public {
        WOTSPlus.WinternitzAddress memory stored = _makeKey(0x60);
        bare.setDisasterRecoveryKey(stored);

        WOTSPlus.WinternitzAddress memory probe =
            WOTSPlus.WinternitzAddress({publicSeed: stored.publicSeed, publicKeyHash: bytes32(uint256(0x9999))});
        assertFalse(bare.exposed_isKeySpent(probe));
    }

    /// @dev The audit-driven monotonic property: removing a key from a keyset
    ///      MUST NOT clear its burn flag. WOTS+ is one-time-use; a key whose
    ///      public form has appeared on-chain is permanently spent, so
    ///      `_isKeySpent` must keep returning true after removal.
    function test_exposed_isKeySpent_returnsTrue_afterKeyRemoved() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xd0);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);
        assertTrue(bare.exposed_isKeySpent(key));

        bare.burnKey(HarnessKeyset.Recovery, key);
        assertTrue(bare.exposed_isKeySpent(key));
    }

    /// @dev Zero-valued probes return false even if a fluky entry exists at
    ///      `isKeySpent[H(0,0)]`. Zero keys are intrinsically invalid and rejected
    ///      downstream by the keyset library's `ZeroValueWinternitzAddress`
    ///      check, so the burn check must not poison legitimate "is this fresh?"
    ///      probes against uninitialized slots.
    function test_exposed_isKeySpent_returnsFalse_whenZeroSeed() public view {
        WOTSPlus.WinternitzAddress memory key =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(uint256(0xabc))});
        assertFalse(bare.exposed_isKeySpent(key));
    }

    function test_exposed_isKeySpent_returnsFalse_whenZeroHash() public view {
        WOTSPlus.WinternitzAddress memory key =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(0xabc)), publicKeyHash: bytes32(0)});
        assertFalse(bare.exposed_isKeySpent(key));
    }

    /*──────────────────────── _enforceUnspentKey ─────────────────────────*/

    function test_exposed_enforceUnspentKey_passes_whenIndexEmpty() public view {
        bare.exposed_enforceUnspentKey(_makeKey(0x70));
    }

    function test_exposed_enforceUnspentKey_reverts_whenInTransactionSet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x80);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_enforceUnspentKey(key);
    }

    function test_exposed_enforceUnspentKey_reverts_whenInRecoverySet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x90);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_enforceUnspentKey(key);
    }

    function test_exposed_enforceUnspentKey_reverts_whenInVerificationSet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xa0);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_enforceUnspentKey(key);
    }

    function test_exposed_enforceUnspentKey_reverts_whenSetAsDisasterKey() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xb0);
        bare.setDisasterRecoveryKey(key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_enforceUnspentKey(key);
    }

    function test_exposed_enforceUnspentKey_reverts_whenSetAsOwnershipKey() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xc0);
        bare.setOwnershipKey(key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_enforceUnspentKey(key);
    }

    /// @dev The audit-driven property in revert form: after a key is added
    ///      then removed, attempting to re-install it via the standard add
    ///      path MUST revert `KeyInUse`. This is the precise path the
    ///      auditor's attack scenario walks (rotate-out, then re-add) and is
    ///      the regression test most likely to catch a future change that
    ///      accidentally drops the monotonic property.
    function test_exposed_enforceUnspentKey_reverts_afterKeyRemoved() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xe0);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);
        bare.burnKey(HarnessKeyset.Recovery, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_enforceUnspentKey(key);
    }

    function test_exposed_safeAddKey_reverts_whenReintroducingSpentKey() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xe1);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);
        bare.burnKey(HarnessKeyset.Transaction, key);

        // Try to re-install in the SAME keyset.
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);
    }

    function test_exposed_safeAddKey_reverts_whenReintroducingSpentKey_crossKeyset() public {
        // Spend a key in the Transaction set, then try to re-install it in
        // the Recovery set. Cross-keyset reuse is the most insidious form of
        // the attack and the one most likely to slip through a less-strict
        // freshness check.
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xe2);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);
        bare.burnKey(HarnessKeyset.Transaction, key);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);
    }
}
