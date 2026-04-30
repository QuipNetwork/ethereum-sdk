// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness, HarnessKeyset} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @dev Behaviour tests for `_isKeyInUse(key)` and `_enforceUnusedKey(key)`.
///      `_isKeyInUse` returns true if `key` is a member of any keyset
///      (transaction / recovery / verification) or matches either single PQ
///      key (disasterRecoveryKey, ownershipKey). `_enforceUnusedKey`
///      reverts `KeyInUse` when `_isKeyInUse` is true.
contract QuipWallet__isKeyInUse is QuipWalletTest {
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

    function test_exposed_isKeyInUse_returnsFalse_whenAllSlotsEmpty() public view {
        assertFalse(bare.exposed_isKeyInUse(_makeKey(0x01)));
    }

    function test_exposed_isKeyInUse_returnsTrue_whenInTransactionSet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x10);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);
        assertTrue(bare.exposed_isKeyInUse(key));
    }

    function test_exposed_isKeyInUse_returnsTrue_whenInRecoverySet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x20);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);
        assertTrue(bare.exposed_isKeyInUse(key));
    }

    function test_exposed_isKeyInUse_returnsTrue_whenInVerificationSet() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x30);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);
        assertTrue(bare.exposed_isKeyInUse(key));
    }

    function test_exposed_isKeyInUse_returnsTrue_whenEqualsDisasterRecoveryKey()
        public
    {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x40);
        bare.setDisasterRecoveryKey(key);
        assertTrue(bare.exposed_isKeyInUse(key));
    }

    function test_exposed_isKeyInUse_returnsTrue_whenEqualsOwnershipKey()
        public
    {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x50);
        bare.setOwnershipKey(key);
        assertTrue(bare.exposed_isKeyInUse(key));
    }

    // Sanity: a key with a matching seed but a different hash should NOT be
    // treated as the disaster/ownership key — both fields are part of the
    // identity.
    function test_exposed_isKeyInUse_returnsFalse_onPartialMatch() public {
        WOTSPlus.WinternitzAddress memory stored = _makeKey(0x60);
        bare.setDisasterRecoveryKey(stored);

        WOTSPlus.WinternitzAddress memory probe = WOTSPlus.WinternitzAddress({
            publicSeed: stored.publicSeed,
            publicKeyHash: bytes32(uint256(0x9999))
        });
        assertFalse(bare.exposed_isKeyInUse(probe));
    }

    function test_exposed_enforceUnusedKey_passes_whenAllSlotsEmpty()
        public
        view
    {
        bare.exposed_enforceUnusedKey(_makeKey(0x70));
    }

    function test_exposed_enforceUnusedKey_reverts_whenInTransactionSet()
        public
    {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x80);
        bare.exposed_safeAddKey(HarnessKeyset.Transaction, key);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        bare.exposed_enforceUnusedKey(key);
    }

    function test_exposed_enforceUnusedKey_reverts_whenInRecoverySet()
        public
    {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0x90);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        bare.exposed_enforceUnusedKey(key);
    }

    function test_exposed_enforceUnusedKey_reverts_whenInVerificationSet()
        public
    {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xa0);
        bare.exposed_safeAddKey(HarnessKeyset.Verification, key);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        bare.exposed_enforceUnusedKey(key);
    }

    function test_exposed_enforceUnusedKey_reverts_whenEqualsDisasterRecoveryKey()
        public
    {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xb0);
        bare.setDisasterRecoveryKey(key);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        bare.exposed_enforceUnusedKey(key);
    }

    function test_exposed_enforceUnusedKey_reverts_whenEqualsOwnershipKey()
        public
    {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xc0);
        bare.setOwnershipKey(key);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        bare.exposed_enforceUnusedKey(key);
    }

    // Removing a key (via the harness escape hatch) should restore uniqueness —
    // `_isKeyInUse` reflects current storage, not any sticky history.
    function test_exposed_isKeyInUse_returnsFalse_afterKeyRemoved() public {
        WOTSPlus.WinternitzAddress memory key = _makeKey(0xd0);
        bare.exposed_safeAddKey(HarnessKeyset.Recovery, key);
        assertTrue(bare.exposed_isKeyInUse(key));

        bare.burnKey(HarnessKeyset.Recovery, key);
        assertFalse(bare.exposed_isKeyInUse(key));
    }
}
