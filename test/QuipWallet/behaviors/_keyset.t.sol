// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness, HarnessKeyset} from "../../harness/QuipWalletHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @dev Behaviour tests for the `_keyset(kind) → storage ref` helper.
///      The helper maps the `KeyType` enum to one of the three storage keysets.
///      Storage pointers can't cross the ABI boundary, so the harness exposes
///      `length()` and `contains()` via the helper's return — we verify the
///      mapping by (a) writing distinctive state into each set via the dedicated
///      harness exposures, then (b) asking `_keyset(kind)` for the count and
///      membership and checking it lines up.
contract QuipWallet__keyset is QuipWalletTest {
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

    function _mkArr(
        uint256 startSeed,
        uint256 n
    ) internal pure returns (WOTSPlus.WinternitzAddress[] memory arr) {
        arr = new WOTSPlus.WinternitzAddress[](n);
        for (uint256 i = 0; i < n; i++) {
            arr[i] = _makeKey(startSeed + i * 2);
        }
    }

    function test_exposed_keyset_transaction_selectsTransactionSet() public {
        WOTSPlus.WinternitzAddress[] memory txn = _mkArr(0x1000, 2);
        WOTSPlus.WinternitzAddress[] memory rec = _mkArr(0x2000, 3);
        WOTSPlus.WinternitzAddress[] memory ver = _mkArr(0x3000, 4);
        bare.exposed_addKeys(HarnessKeyset.Transaction, txn);
        bare.exposed_addKeys(HarnessKeyset.Recovery, rec);
        bare.exposed_addKeys(HarnessKeyset.Verification, ver);

        assertEq(bare.exposed_keysetLength(Codec.KeyType.Transaction), 2);
        // Members of the Transaction set register under `Transaction` but not
        // under `Recovery` or `Verification`.
        assertTrue(
            bare.exposed_keysetContains(Codec.KeyType.Transaction, txn[0])
        );
        assertFalse(
            bare.exposed_keysetContains(Codec.KeyType.Recovery, txn[0])
        );
        assertFalse(
            bare.exposed_keysetContains(Codec.KeyType.Verification, txn[0])
        );
    }

    function test_exposed_keyset_recovery_selectsRecoverySet() public {
        WOTSPlus.WinternitzAddress[] memory txn = _mkArr(0x1000, 2);
        WOTSPlus.WinternitzAddress[] memory rec = _mkArr(0x2000, 3);
        WOTSPlus.WinternitzAddress[] memory ver = _mkArr(0x3000, 4);
        bare.exposed_addKeys(HarnessKeyset.Transaction, txn);
        bare.exposed_addKeys(HarnessKeyset.Recovery, rec);
        bare.exposed_addKeys(HarnessKeyset.Verification, ver);

        assertEq(bare.exposed_keysetLength(Codec.KeyType.Recovery), 3);
        assertTrue(
            bare.exposed_keysetContains(Codec.KeyType.Recovery, rec[0])
        );
        assertFalse(
            bare.exposed_keysetContains(Codec.KeyType.Transaction, rec[0])
        );
        assertFalse(
            bare.exposed_keysetContains(Codec.KeyType.Verification, rec[0])
        );
    }

    function test_exposed_keyset_verification_selectsVerificationSet() public {
        WOTSPlus.WinternitzAddress[] memory txn = _mkArr(0x1000, 2);
        WOTSPlus.WinternitzAddress[] memory rec = _mkArr(0x2000, 3);
        WOTSPlus.WinternitzAddress[] memory ver = _mkArr(0x3000, 4);
        bare.exposed_addKeys(HarnessKeyset.Transaction, txn);
        bare.exposed_addKeys(HarnessKeyset.Recovery, rec);
        bare.exposed_addKeys(HarnessKeyset.Verification, ver);

        assertEq(bare.exposed_keysetLength(Codec.KeyType.Verification), 4);
        assertTrue(
            bare.exposed_keysetContains(Codec.KeyType.Verification, ver[0])
        );
        assertFalse(
            bare.exposed_keysetContains(Codec.KeyType.Transaction, ver[0])
        );
        assertFalse(
            bare.exposed_keysetContains(Codec.KeyType.Recovery, ver[0])
        );
    }

    function test_exposed_keyset_emptySetReportsZero() public view {
        assertEq(bare.exposed_keysetLength(Codec.KeyType.Transaction), 0);
        assertEq(bare.exposed_keysetLength(Codec.KeyType.Recovery), 0);
        assertEq(bare.exposed_keysetLength(Codec.KeyType.Verification), 0);
    }
}
