// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletStorage as Storage} from "../../../contracts/shrincs/ShrincsWalletStorage.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Storage-layout drift gate for `ShrincsWalletStorage.Layout` (ERC-7201). Pins, against
///      what the compiler actually emits: the namespace base (recomputed from the namespace
///      string), the slot of every field in declaration order, the packing of the two `uint32`s,
///      and the mapping bases — by writing sentinels through `Storage.layout()` and reading them
///      back with `vm.load` at the expected slot. A namespace rename, a field reorder, an
///      insertion or a type-width change fails here; appending a field at the end does not
///      (that is the upgrade-safe change). The upgrade tests derive their slot constants from
///      the same base, so this file is the one place that knows the offsets.
contract ShrincsWallet__storageLayout is ShrincsWalletTest {
    bytes32 internal constant BASE = Storage._SHRINCS_STORAGE_SLOT;

    // Declaration order of `Layout` (one slot each unless noted).
    uint256 internal constant F_WALLET_FACTORY = 0;
    uint256 internal constant F_SHRINCS_COMMITMENT = 1;
    uint256 internal constant F_ERC1271_COMMITMENT = 2;
    uint256 internal constant F_KEY_VERSION = 3;
    uint256 internal constant F_NONCE = 4;
    uint256 internal constant F_LEAF_STATE = 5; // statefulLeavesUsed (uint32) ‖ maxSignatures (uint32), packed
    uint256 internal constant F_USED_LEAF_BITMAP = 6; // mapping base
    uint256 internal constant F_SPENT_STATEFUL_TREES = 7; // mapping base
    uint256 internal constant F_SPENT_STATELESS_TREES = 8; // mapping base

    uint256 internal constant PROBE_KEY_VERSION = 0xB1;
    uint256 internal constant PROBE_WORD = 0xB2;
    bytes32 internal constant PROBE_STATEFUL_ID = bytes32(uint256(0xB3));
    bytes32 internal constant PROBE_STATELESS_ID = bytes32(uint256(0xB4));

    function _slot(uint256 field) internal pure returns (bytes32) {
        return bytes32(uint256(BASE) + field);
    }

    function _load(uint256 field) internal view returns (uint256) {
        return uint256(vm.load(WALLET, _slot(field)));
    }

    function test_storageLayout_baseDerivesFromNamespace() public pure {
        bytes32 expected = keccak256(abi.encode(uint256(keccak256("quip.storage.wallet.shrincs")) - 1)) &
            ~bytes32(uint256(0xff));
        assertEq(BASE, expected, "ERC-7201 base must be derived from the namespace string");
        assertEq(uint256(BASE) & 0xff, 0, "base is 256-slot aligned");
    }

    function test_storageLayout_layoutResolvesToBase() public view {
        assertEq(wallet.exposed_layoutSlot(), BASE);
    }

    function test_storageLayout_pinsEveryFieldSlot() public {
        wallet.harness_writeLayoutProbe(PROBE_KEY_VERSION, PROBE_WORD, PROBE_STATEFUL_ID, PROBE_STATELESS_ID);

        assertEq(_load(F_WALLET_FACTORY), 0xA1, "walletFactory");
        assertEq(_load(F_SHRINCS_COMMITMENT), 0xA2, "shrincsPublicKeyCommitment");
        assertEq(_load(F_ERC1271_COMMITMENT), 0xA3, "erc1271PublicKeyCommitment");
        assertEq(_load(F_KEY_VERSION), 0xA4, "keyVersion");
        assertEq(_load(F_NONCE), 0xA5, "nonce");
        // Two uint32s share one slot: statefulLeavesUsed in the low 4 bytes, maxSignatures next.
        assertEq(_load(F_LEAF_STATE), (uint256(0xA7) << 32) | 0xA6, "statefulLeavesUsed | maxSignatures packing");

        // Nested mapping: slot(keyVersion, word) = keccak(word . keccak(keyVersion . base+6)).
        bytes32 inner = keccak256(abi.encode(PROBE_KEY_VERSION, _slot(F_USED_LEAF_BITMAP)));
        bytes32 bitmapSlot = keccak256(abi.encode(PROBE_WORD, inner));
        assertEq(uint256(vm.load(WALLET, bitmapSlot)), 0xA8, "usedStatefulLeafBitmap");

        bytes32 statefulSlot = keccak256(abi.encode(PROBE_STATEFUL_ID, _slot(F_SPENT_STATEFUL_TREES)));
        assertEq(uint256(vm.load(WALLET, statefulSlot)), 1, "spentStatefulTrees");
        bytes32 statelessSlot = keccak256(abi.encode(PROBE_STATELESS_ID, _slot(F_SPENT_STATELESS_TREES)));
        assertEq(uint256(vm.load(WALLET, statelessSlot)), 1, "spentStatelessTrees");
    }

    /// @dev The probe wrote NOTHING outside the fields above: the slot after the last static
    ///      field (the three mapping bases are never written directly) and the one past the
    ///      layout are untouched.
    function test_storageLayout_probeTouchesOnlyDeclaredFields() public {
        wallet.harness_writeLayoutProbe(PROBE_KEY_VERSION, PROBE_WORD, PROBE_STATEFUL_ID, PROBE_STATELESS_ID);
        assertEq(_load(F_USED_LEAF_BITMAP), 0, "mapping base slot is never written");
        assertEq(_load(F_SPENT_STATEFUL_TREES), 0, "mapping base slot is never written");
        assertEq(_load(F_SPENT_STATELESS_TREES), 0, "mapping base slot is never written");
        assertEq(_load(F_SPENT_STATELESS_TREES + 1), 0, "nothing past the layout");
    }

    /// @dev The public getters read the same slots the probe wrote — the contract's own
    ///      accessors and the pinned offsets agree.
    function test_storageLayout_gettersReadPinnedSlots() public {
        wallet.harness_writeLayoutProbe(PROBE_KEY_VERSION, PROBE_WORD, PROBE_STATEFUL_ID, PROBE_STATELESS_ID);
        assertEq(wallet.walletFactory(), payable(address(uint160(0xA1))));
        assertEq(wallet.getShrincsPublicKeyCommitment(), bytes32(uint256(0xA2)));
        assertEq(wallet.getErc1271PublicKeyCommitment(), bytes32(uint256(0xA3)));
        assertEq(wallet.keyVersion(), 0xA4);
        assertEq(wallet.actionNonce(), 0xA5);
        assertEq(wallet.statefulLeavesUsed(), 0xA6);
        assertEq(wallet.maxSignatures(), 0xA7);
    }
}
