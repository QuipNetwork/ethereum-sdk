// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness, HarnessKeyset} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

/// @dev Tests for the generalized _addKeys / _clearKeys / _rotateKeys / _enforceContained /
///      _enforceUncontained primitives, exercised via the harness against all three sets.
contract QuipWallet__addKeys is QuipWalletTest {
    QuipWalletHarness public harnessProxy;
    QuipWalletHarness public bare;

    function setUp() public override {
        super.setUp();
        QuipWalletHarness harnessImpl = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        // Proxy initialized with 10 recovery keys + 5 transaction keys.
        (
            WOTSPlus.WinternitzAddress memory pub,
            bytes32 priv
        ) = _generateKeyPair("h-addkeys");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            priv,
            10
        );
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{
            value: INITIAL_DEPOSIT
        }(keccak256("h-addkeys-vault"), payable(ALICE), payload);
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

    /*────────────────────────────── _addKeys ──────────────────────────────*/

    function test_exposed_addKeys_verification_addsSingleKey() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xa000, 1);
        bare.exposed_addKeys(HarnessKeyset.Verification, keys);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 1);
        assertTrue(bare.isKey(Codec.KeyType.Verification, keys[0]));
    }

    function test_exposed_addKeys_recovery_addsMultipleKeys() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xb000, 3);
        bare.exposed_addKeys(HarnessKeyset.Recovery, keys);
        assertEq(bare.keyCount(Codec.KeyType.Recovery), 3);
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(bare.isKey(Codec.KeyType.Recovery, keys[i]));
        }
    }

    function test_exposed_addKeys_recovery_addsUpToMax() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xc000, 10);
        bare.exposed_addKeys(HarnessKeyset.Recovery, keys);
        assertEq(bare.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_exposed_addKeys_transaction_addsKey() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xd000, 2);
        bare.exposed_addKeys(HarnessKeyset.Transaction, keys);
        assertEq(bare.keyCount(Codec.KeyType.Transaction), 2);
    }

    function test_exposed_addKeys_revertsWhen_zeroSeedInKey() public {
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](1);
        keys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(uint256(1))
        });
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        bare.exposed_addKeys(HarnessKeyset.Recovery, keys);
    }

    function test_exposed_addKeys_revertsWhen_zeroHashInKey() public {
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](1);
        keys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(0)
        });
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        bare.exposed_addKeys(HarnessKeyset.Verification, keys);
    }

    function test_exposed_addKeys_revertsWhen_duplicateKey() public {
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](2);
        keys[0] = _makeKey(0xdead);
        keys[1] = _makeKey(0xdead);
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        bare.exposed_addKeys(HarnessKeyset.Recovery, keys);
    }

    // Proxy already has 10 recovery keys from init, so adding one exceeds cap.
    function test_exposed_addKeys_revertsWhen_exceedsMax() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xff00, 1);
        vm.expectRevert(Keyset.ExceedsCapacity.selector);
        harnessProxy.exposed_addKeys(HarnessKeyset.Recovery, keys);
    }

    function test_exposed_addKeys_emptyKeysIsNoop() public {
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](0);
        bare.exposed_addKeys(HarnessKeyset.Verification, keys);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 0);
    }

    function test_exposed_addKeys_revertsWhen_zeroBothInKey() public {
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](1);
        keys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        bare.exposed_addKeys(HarnessKeyset.Verification, keys);
    }

    // Adds a key, then attempts to add the same key again in a follow-up call.
    // The library returns false on "already present" with no side effect, and
    // `_addKeys` surfaces that as `DuplicateKey`.
    function test_exposed_addKeys_revertsWhen_duplicatesExistingMember() public {
        WOTSPlus.WinternitzAddress[] memory first = _makeKeys(0xaa00, 1);
        bare.exposed_addKeys(HarnessKeyset.Verification, first);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 1);

        WOTSPlus.WinternitzAddress[]
            memory again = new WOTSPlus.WinternitzAddress[](1);
        again[0] = first[0];
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        bare.exposed_addKeys(HarnessKeyset.Verification, again);
    }

    // Fill the Transaction set to MAX_KEYS (10), then try to add one more.
    function test_exposed_addKeys_transaction_revertsWhen_exceedsMax() public {
        WOTSPlus.WinternitzAddress[] memory fill = _makeKeys(0xe000, 10);
        bare.exposed_addKeys(HarnessKeyset.Transaction, fill);
        assertEq(bare.keyCount(Codec.KeyType.Transaction), 10);

        WOTSPlus.WinternitzAddress[] memory extra = _makeKeys(0xe100, 1);
        vm.expectRevert(Keyset.ExceedsCapacity.selector);
        bare.exposed_addKeys(HarnessKeyset.Transaction, extra);
    }

    // Fill the Verification set to MAX_KEYS (10), then try to add one more.
    function test_exposed_addKeys_verification_revertsWhen_exceedsMax() public {
        WOTSPlus.WinternitzAddress[] memory fill = _makeKeys(0xe200, 10);
        bare.exposed_addKeys(HarnessKeyset.Verification, fill);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 10);

        WOTSPlus.WinternitzAddress[] memory extra = _makeKeys(0xe300, 1);
        vm.expectRevert(Keyset.ExceedsCapacity.selector);
        bare.exposed_addKeys(HarnessKeyset.Verification, extra);
    }

    /*───────────────────────────── _clearKeys ─────────────────────────────*/

    function test_exposed_clearKeys_recovery_drains() public {
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        harnessProxy.exposed_clearKeys(HarnessKeyset.Recovery);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 0);
    }

    function test_exposed_clearKeys_transaction_drains() public {
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 5);
        harnessProxy.exposed_clearKeys(HarnessKeyset.Transaction);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 0);
    }

    function test_exposed_clearKeys_emptySetIsNoop() public {
        bare.exposed_clearKeys(HarnessKeyset.Verification);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 0);
    }

    function test_exposed_clearKeys_verification_drains() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xbeef, 4);
        bare.exposed_addKeys(HarnessKeyset.Verification, keys);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 4);
        bare.exposed_clearKeys(HarnessKeyset.Verification);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 0);
    }

    // After a clear, every previously-added member should no longer be contained.
    function test_exposed_clearKeys_membersAbsentAfter() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xcafe, 3);
        bare.exposed_addKeys(HarnessKeyset.Verification, keys);
        bare.exposed_clearKeys(HarnessKeyset.Verification);
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(bare.isKey(Codec.KeyType.Verification, keys[i]));
        }
    }

    // After a clear the underlying root/position slots should remain usable;
    // re-adding a prior element must succeed without reverting.
    function test_exposed_clearKeys_canReaddAfter() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xd00d, 2);
        bare.exposed_addKeys(HarnessKeyset.Verification, keys);
        bare.exposed_clearKeys(HarnessKeyset.Verification);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 0);
        bare.exposed_addKeys(HarnessKeyset.Verification, keys);
        assertEq(bare.keyCount(Codec.KeyType.Verification), 2);
    }

    /*──────────────────── _enforceContained / Uncontained ────────────────*/

    function test_exposed_enforceContained_recovery_revertsWhen_unknown()
        public
    {
        WOTSPlus.WinternitzAddress memory stray = _makeKey(0xbeef);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        harnessProxy.exposed_enforceContained(HarnessKeyset.Recovery, stray);
    }

    function test_exposed_enforceUncontained_recovery_revertsWhen_present()
        public
    {
        WOTSPlus.WinternitzAddress memory existing = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 0);
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        harnessProxy.exposed_enforceUncontained(
            HarnessKeyset.Recovery,
            existing
        );
    }

    function test_exposed_enforceContained_recovery_passesWhen_present()
        public
        view
    {
        WOTSPlus.WinternitzAddress memory existing = harnessProxy
            .keyAt(Codec.KeyType.Recovery, 0);
        harnessProxy.exposed_enforceContained(HarnessKeyset.Recovery, existing);
    }

    function test_exposed_enforceUncontained_recovery_passesWhen_absent()
        public
        view
    {
        WOTSPlus.WinternitzAddress memory stray = _makeKey(0xbabe);
        harnessProxy.exposed_enforceUncontained(HarnessKeyset.Recovery, stray);
    }
}
