// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @dev Behaviour tests for `_installInitialKeys(disaster, ownership, txn[5], rec[10])`.
///      Writes the two scalar keys, adds all 15 keyset members, then calls
///      `_verifyInitialState()` to assert the post-state invariants.
contract QuipWallet__installInitialKeys is QuipWalletTest {
    bytes32 constant STORAGE_BASE =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;

    /// @dev Factory pre-filled (slot 0) into a fresh harness so the trailing
    ///      `_verifyInitialState()` has a non-zero factory address to observe.
    ///      Callers that only want to trigger the mid-execution DuplicateKey
    ///      revert don't need it set.
    function _freshHarness(bool primeFactory) internal returns (QuipWalletHarness h) {
        h = new QuipWalletHarness(payable(address(factory)));
        if (primeFactory) {
            vm.store(
                address(h),
                STORAGE_BASE,
                bytes32(uint256(uint160(address(factory))))
            );
        }
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

    function _validTxn()
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[5] memory arr)
    {
        for (uint256 i = 0; i < 5; i++) arr[i] = _mkKey(0x1000 + i * 2);
    }

    function _validRec()
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[10] memory arr)
    {
        for (uint256 i = 0; i < 10; i++) arr[i] = _mkKey(0x2000 + i * 2);
    }

    function _validDisaster()
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory)
    {
        return _mkKey(0x3000);
    }

    function _validOwnership()
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory)
    {
        return _mkKey(0x4000);
    }

    function test_exposed_installInitialKeys_happyPath() public {
        QuipWalletHarness h = _freshHarness(true);
        h.exposed_installInitialKeys(
            _validDisaster(),
            _validOwnership(),
            _validTxn(),
            _validRec()
        );

        assertEq(h.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(h.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_exposed_installInitialKeys_revertsWhen_duplicateTxnKey()
        public
    {
        QuipWalletHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress[5] memory txn = _validTxn();
        txn[4] = txn[0]; // collide entries 0 and 4

        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        h.exposed_installInitialKeys(
            _validDisaster(),
            _validOwnership(),
            txn,
            _validRec()
        );
    }

    function test_exposed_installInitialKeys_revertsWhen_duplicateRecoveryKey()
        public
    {
        QuipWalletHarness h = _freshHarness(false);
        WOTSPlus.WinternitzAddress[10] memory rec = _validRec();
        rec[7] = rec[0];

        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        h.exposed_installInitialKeys(
            _validDisaster(),
            _validOwnership(),
            _validTxn(),
            rec
        );
    }

    // Happy inputs but no factory primed → `_verifyInitialState()` at the end
    // fires `ZeroAddressFactory`. Confirms the trailing invariant check runs.
    function test_exposed_installInitialKeys_revertsWhen_factoryUnset() public {
        QuipWalletHarness h = _freshHarness(false);
        vm.expectRevert(IQuipWallet.ZeroAddressFactory.selector);
        h.exposed_installInitialKeys(
            _validDisaster(),
            _validOwnership(),
            _validTxn(),
            _validRec()
        );
    }

    // `_installInitialKeys` adds disaster/ownership via plain SSTORE — zero
    // fields are not rejected at install time, but the trailing
    // `_verifyInitialState()` catches them.
    function test_exposed_installInitialKeys_revertsWhen_disasterKeyZero()
        public
    {
        QuipWalletHarness h = _freshHarness(true);
        WOTSPlus.WinternitzAddress memory zeroDisaster = WOTSPlus
            .WinternitzAddress({
                publicSeed: bytes32(0),
                publicKeyHash: bytes32(0)
            });
        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        h.exposed_installInitialKeys(
            zeroDisaster,
            _validOwnership(),
            _validTxn(),
            _validRec()
        );
    }

    function test_exposed_installInitialKeys_revertsWhen_ownershipKeyZero()
        public
    {
        QuipWalletHarness h = _freshHarness(true);
        WOTSPlus.WinternitzAddress memory zeroOwnership = WOTSPlus
            .WinternitzAddress({
                publicSeed: bytes32(0),
                publicKeyHash: bytes32(0)
            });
        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        h.exposed_installInitialKeys(
            _validDisaster(),
            zeroOwnership,
            _validTxn(),
            _validRec()
        );
    }
}
