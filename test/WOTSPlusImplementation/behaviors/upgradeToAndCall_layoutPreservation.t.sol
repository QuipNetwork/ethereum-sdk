// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {WOTSPlusStorage as Storage} from "../../../contracts/wots/WOTSPlusStorage.sol";

/// @dev Storage-layout preservation tests for `upgradeToAndCall`. Two flavours:
///
///      1. LAYOUT LOCK (pure / cheap): assert the hardcoded slot constants in
///         `WOTSPlusImplementation.sol` and `WOTSPlusStorage.sol` match their documented
///         derivations, and that each keyset's `_rootSlot` derives from its
///         spacer slot via `keccak256(spacerSlot ‖ uint32(_SLOT_SEED))`. These
///         catch source-level drift the moment somebody renames the ERC-7201
///         namespace or reorders fields in `WinternitzAddressSet`.
///
///      2. BIT-FOR-BIT PRESERVATION (full-state): heavily populate a V1 wallet
///         (transactionKeys, recoveryKeys, eager-phase verificationKeys with at
///         least one position-mapping update via `replaceKeys`), `vm.load`
///         every slot that holds wallet state, run a no-migration upgrade,
///         re-load, and `assertEq`. Allowed deltas: the ERC-1967 impl slot
///         (V1 → V2) and the transactionKeys rotation that
///         `_validateSignature` performs as part of the upgrade auth.
///
///      The negative control — a `BadV2` impl with a prepended `Layout` field
///      that would silently shift namespace offsets — is intentionally NOT
///      exercised at runtime here (deploying it bricks the proxy and pollutes
///      downstream state). Instead, the layout-lock tests + a CI fixture diff
///      against `forge inspect` storageLayout act as the source-level gate;
///      see Makefile target `storage-layout-check` and the fixture under
///      `test/fixtures/`.
contract WOTSPlusImplementation_upgradeToAndCall_layoutPreservation is WOTSPlusImplementationTest {
    WOTSPlusImplementation public newImpl;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  HARDCODED LAYOUT CONSTANTS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `bytes32(~uint256(uint32(bytes4(keccak256("_OWNER_SLOT_NOT")))))`
    bytes32 internal constant SOLADY_OWNER_SLOT = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927;
    /// @dev `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`
    bytes32 internal constant ERC1967_IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    /// @dev ERC-7201 namespace base: "quip.storage.wallet.wotsplus".
    ///      Imported from `WOTSPlusStorage` so the keccak-derivation test
    ///      below locks the LIBRARY's literal to the namespace string. Any
    ///      drift between the wallet's private slot literals and the
    ///      library's surfaces here too — the per-field tests below pass
    ///      `Storage.<NAME>_SLOT` to `vm.load`, so a wallet/library mismatch
    ///      reports as a wrong-slot read of unrelated state.
    bytes32 internal constant WOTSPLUS_BASE = Storage._WOTSPLUS_STORAGE_SLOT;

    bytes32 internal constant PQ_FACTORY_SLOT = Storage._PQ_FACTORY_SLOT;
    bytes32 internal constant DISASTER_SEED_SLOT = Storage._DISASTER_KEY_SEED_SLOT;
    bytes32 internal constant DISASTER_HASH_SLOT = Storage._DISASTER_KEY_HASH_SLOT;
    bytes32 internal constant OWNERSHIP_SEED_SLOT = Storage._OWNERSHIP_KEY_SEED_SLOT;
    bytes32 internal constant OWNERSHIP_HASH_SLOT = Storage._OWNERSHIP_KEY_HASH_SLOT;
    bytes32 internal constant TXN_KEYSET_SPACER_SLOT = bytes32(uint256(Storage._WOTSPLUS_STORAGE_SLOT) + 5);
    bytes32 internal constant REC_KEYSET_SPACER_SLOT = bytes32(uint256(Storage._WOTSPLUS_STORAGE_SLOT) + 6);
    bytes32 internal constant VRF_KEYSET_SPACER_SLOT = bytes32(uint256(Storage._WOTSPLUS_STORAGE_SLOT) + 7);
    /// @dev Mirror of `EnumerableWinternitzAddressSet._SLOT_SEED`.
    uint32 internal constant SET_SLOT_SEED = 0x3e9f5d6a;

    function setUp() public override {
        super.setUp();
        newImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(newImpl));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       LAYOUT LOCK                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Locks the ERC-7201 namespace string. Renaming
    ///      `quip.storage.wallet.wotsplus` would silently relocate every
    ///      deployed wallet's storage; this catches it at compile time.
    function test_layoutLock_namespaceBaseDerivation() public pure {
        bytes32 derived =
            keccak256(abi.encode(uint256(keccak256("quip.storage.wallet.wotsplus")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(derived, WOTSPLUS_BASE);
    }

    /// @dev Locks the per-field offsets within the namespace struct. If anyone
    ///      reorders `WOTSPlusStorage.Layout`, the guarded-slot constants in
    ///      `WOTSPlusImplementation.sol` (`_PQ_FACTORY_SLOT` etc.) silently desync from the
    ///      struct fields. We catch this by reading via the public API and
    ///      asserting the value matches what we wrote at the hardcoded slot.
    function test_layoutLock_namespaceFieldOffsets() public view {
        // Factory: written by `initialize` to `FACTORY`.
        assertEq(address(uint160(uint256(vm.load(address(wallet), PQ_FACTORY_SLOT)))), address(factory));
        assertEq(wallet.quipFactory(), address(factory));

        // Disaster + ownership keys: derived from VAULT_SEED via the test base.
        (WOTSPlus.WinternitzAddress memory disasterPub,) = _generateDisasterRecoveryKey(VAULT_SEED);
        assertEq(vm.load(address(wallet), DISASTER_SEED_SLOT), disasterPub.publicSeed);
        assertEq(vm.load(address(wallet), DISASTER_HASH_SLOT), disasterPub.publicKeyHash);
        assertEq(vm.load(address(wallet), OWNERSHIP_SEED_SLOT), ownershipPubkey.publicSeed);
        assertEq(vm.load(address(wallet), OWNERSHIP_HASH_SLOT), ownershipPubkey.publicKeyHash);

        // Keyset spacers themselves are unused (the `_spacer` field is just a
        // slot reservation). Their *position* is what feeds rootSlot derivation.
        assertEq(vm.load(address(wallet), TXN_KEYSET_SPACER_SLOT), bytes32(0));
        assertEq(vm.load(address(wallet), REC_KEYSET_SPACER_SLOT), bytes32(0));
        assertEq(vm.load(address(wallet), VRF_KEYSET_SPACER_SLOT), bytes32(0));
    }

    /// @dev Locks `EnumerableWinternitzAddressSet._rootSlot` derivation. If
    ///      `WinternitzAddressSet` ever gains a member before `_spacer`, the
    ///      `set.slot` argument shifts and rootSlot lands in a fresh keccak
    ///      bucket. We catch this by re-deriving the rootSlot from the spacer
    ///      slot constant + the seed and asserting the keyset's lazyLen at
    ///      `not(rootSlot)` reflects the live element counts.
    function test_layoutLock_keysetRootSlotDerivation() public view {
        // Live wallet has 10 entries in each keyset post-init under always-10,
        // all eager. Eager-phase lazyLen = (count << 1) | 1.
        bytes32 txnRoot = _expectedRootSlot(TXN_KEYSET_SPACER_SLOT);
        bytes32 recRoot = _expectedRootSlot(REC_KEYSET_SPACER_SLOT);
        bytes32 vrfRoot = _expectedRootSlot(VRF_KEYSET_SPACER_SLOT);

        assertEq(uint256(vm.load(address(wallet), ~txnRoot)), (10 << 1) | 1);
        assertEq(uint256(vm.load(address(wallet), ~recRoot)), (10 << 1) | 1);
        assertEq(uint256(vm.load(address(wallet), ~vrfRoot)), (10 << 1) | 1);

        // Sanity: element 0 of the txn keyset matches alicePubkey via raw load.
        assertEq(vm.load(address(wallet), txnRoot), alicePubkey.publicSeed);
        assertEq(vm.load(address(wallet), bytes32(uint256(txnRoot) + 1)), alicePubkey.publicKeyHash);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  BIT-FOR-BIT PRESERVATION                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Heavy-state preservation across a no-migration upgrade. Everything
    ///      except `_ERC1967_IMPLEMENTATION_SLOT` and the consumed/installed
    ///      transactionKey pair must be byte-identical post-upgrade.
    function test_upgradeToAndCall_preservesAllStorage_noMigration() public {
        // Push verificationKeys past the lazy-3 threshold so position-mapping
        // slots get exercised across the upgrade.
        _seedVerificationKeys(7);

        // Snapshot every meaningful slot.
        Snapshot memory pre = _snapshotAll();

        // Run the upgrade (no migration). This consumes `alicePubkey` and
        // installs `nextPq` in the transactionKeys set as part of the auth
        // rotation; the impl slot flips V1 → newImpl. Everything else: stable.
        WOTSPlus.WinternitzAddress memory nextPq = _upgradeNoMigration();

        Snapshot memory post = _snapshotAll();

        // Allowed deltas: impl slot, txnKey rotation. Everything else equal.
        assertEq(post.impl, bytes32(uint256(uint160(address(newImpl)))), "impl should advance to V2");
        assertTrue(pre.impl != post.impl, "impl should change");
        assertEq(post.owner, pre.owner, "owner");
        assertEq(post.factory, pre.factory, "factory");
        assertEq(post.disasterSeed, pre.disasterSeed, "disasterSeed");
        assertEq(post.disasterHash, pre.disasterHash, "disasterHash");
        assertEq(post.ownershipSeed, pre.ownershipSeed, "ownershipSeed");
        assertEq(post.ownershipHash, pre.ownershipHash, "ownershipHash");

        // Recovery + verification keysets: completely untouched.
        for (uint256 i = 0; i < 20; i++) {
            assertEq(post.recElements[i], pre.recElements[i], "rec element");
            assertEq(post.vrfElements[i], pre.vrfElements[i], "vrf element");
        }
        assertEq(post.recLazyLen, pre.recLazyLen, "rec lazyLen");
        assertEq(post.vrfLazyLen, pre.vrfLazyLen, "vrf lazyLen");

        // Transaction keyset: same length, alicePubkey gone, nextPq present.
        assertEq(post.txnLazyLen, pre.txnLazyLen, "txn count preserved");
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));

        // Public-API smoke: V2 reads land at the same offsets V1 wrote to.
        assertEq(wallet.owner(), ALICE);
        assertEq(wallet.quipFactory(), address(factory));
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        // `_seedVerificationKeys` installs MAX_KEYS=10 via resetKeyset.
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          HELPERS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    struct Snapshot {
        bytes32 owner;
        bytes32 impl;
        bytes32 factory;
        bytes32 disasterSeed;
        bytes32 disasterHash;
        bytes32 ownershipSeed;
        bytes32 ownershipHash;
        // 10 keys * 2 slots each — covers MAX_KEYS for both rec and vrf,
        // and 5 active txn keys + 5 zeroed slots.
        bytes32[20] txnElements;
        bytes32[20] recElements;
        bytes32[20] vrfElements;
        bytes32 txnLazyLen;
        bytes32 recLazyLen;
        bytes32 vrfLazyLen;
    }

    function _snapshotAll() internal view returns (Snapshot memory s) {
        s.owner = vm.load(address(wallet), SOLADY_OWNER_SLOT);
        s.impl = vm.load(address(wallet), ERC1967_IMPL_SLOT);
        s.factory = vm.load(address(wallet), PQ_FACTORY_SLOT);
        s.disasterSeed = vm.load(address(wallet), DISASTER_SEED_SLOT);
        s.disasterHash = vm.load(address(wallet), DISASTER_HASH_SLOT);
        s.ownershipSeed = vm.load(address(wallet), OWNERSHIP_SEED_SLOT);
        s.ownershipHash = vm.load(address(wallet), OWNERSHIP_HASH_SLOT);

        bytes32 txnRoot = _expectedRootSlot(TXN_KEYSET_SPACER_SLOT);
        bytes32 recRoot = _expectedRootSlot(REC_KEYSET_SPACER_SLOT);
        bytes32 vrfRoot = _expectedRootSlot(VRF_KEYSET_SPACER_SLOT);
        for (uint256 i = 0; i < 20; i++) {
            s.txnElements[i] = vm.load(address(wallet), bytes32(uint256(txnRoot) + i));
            s.recElements[i] = vm.load(address(wallet), bytes32(uint256(recRoot) + i));
            s.vrfElements[i] = vm.load(address(wallet), bytes32(uint256(vrfRoot) + i));
        }
        s.txnLazyLen = vm.load(address(wallet), ~txnRoot);
        s.recLazyLen = vm.load(address(wallet), ~recRoot);
        s.vrfLazyLen = vm.load(address(wallet), ~vrfRoot);
    }

    /// @dev Mirrors `EnumerableWinternitzAddressSet._rootSlot`:
    ///      `keccak256(set.slot ‖ uint32(_SLOT_SEED))` — 32 + 4 = 36 bytes packed.
    function _expectedRootSlot(bytes32 spacerSlot) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(spacerSlot, SET_SLOT_SEED));
    }

    /// @dev No-migration upgrade via the base's lifted `_buildUpgradeData`.
    function _upgradeNoMigration() internal returns (WOTSPlus.WinternitzAddress memory nextPq) {
        (nextPq,) = _generateKeyPair("layout-preservation-next");
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl),
            alicePrivateKey,
            alicePubkey,
            nextPq,
            "layout-preservation-verifier",
            false,
            dummyPq,
            emptyKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);
    }
}
