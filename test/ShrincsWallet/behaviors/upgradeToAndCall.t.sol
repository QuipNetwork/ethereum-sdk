// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/WOTSPlusTestSigner.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlusCodec as WOTSCodec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {ShrincsWalletStorage as Storage} from "../../../contracts/shrincs/ShrincsWalletStorage.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

// ERC-1967 implementation slot (`uint256(keccak256("eip1967.proxy.implementation")) - 1`).
bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
// keyVersion slot (`ShrincsWalletStorage` base + 3) and the `usedStatefulLeafBitmap` mapping
// base (base + 6). The offsets are pinned by `_storageLayout.t.sol`; derive, never retype.
bytes32 constant KEY_VERSION_SLOT = bytes32(uint256(Storage._SHRINCS_STORAGE_SLOT) + 3);
bytes32 constant BITMAP_BASE_SLOT = bytes32(uint256(Storage._SHRINCS_STORAGE_SLOT) + 6);

contract DummyImpl {
    uint256 public marker;
}

/// @dev Minimal vetted implementation for upgrade paths that never dispatch post-upgrade calls:
///      a plain `proxiableUUID` plus a no-op `verifyUpgrade` probe.
contract MockUpgradeImpl {
    function proxiableUUID() external pure returns (bytes32) {
        return IMPL_SLOT;
    }

    function verifyUpgrade(address, bytes calldata) external view {}
}

/// @dev Malicious implementation whose `verifyUpgrade` tries to clear a used-leaf bitmap word —
///      the wallet's sole anti-replay state. The probe runs under STATICCALL, so the SSTORE
///      reverts at the EVM level; no snapshot/diff guard is involved.
contract MockTamperImpl {
    function verifyUpgrade(address, bytes calldata) external {
        // usedStatefulLeafBitmap[keyVersion = 0][wordIndex = 0] in the wallet's namespace.
        bytes32 slot = keccak256(abi.encode(uint256(0), keccak256(abi.encode(uint256(0), BITMAP_BASE_SLOT))));
        assembly {
            sstore(slot, 0)
        }
    }
}

/// @dev Implementation that returns the WRONG `proxiableUUID`, so `super.upgradeToAndCall` rejects
///      it with `UpgradeFailed` (after our SHRINCS gate + probe have passed).
contract MockBadUuidImpl {
    function proxiableUUID() external pure returns (bytes32) {
        return bytes32(uint256(1)); // not the ERC-1967 slot
    }

    function verifyUpgrade(address, bytes calldata) external view {}
}

/// @dev Implementation whose `verifyUpgrade` probe reverts; the wallet must bubble it.
contract MockRevertingProbeImpl {
    error ProbeReverted();

    function proxiableUUID() external pure returns (bytes32) {
        return IMPL_SLOT;
    }

    function verifyUpgrade(address, bytes calldata) external pure {
        revert ProbeReverted();
    }
}

/// @dev Implementation asserting the opaque probe vector arrives verbatim.
contract MockProbeCheckImpl {
    error WrongProbePayload();

    function proxiableUUID() external pure returns (bytes32) {
        return IMPL_SLOT;
    }

    function verifyUpgrade(address, bytes calldata payload) external pure {
        if (keccak256(payload) != keccak256(hex"c0ffee")) revert WrongProbePayload();
    }
}

/// @dev Implementation pinning the mid-upgrade ordering. Its `migrate` runs AFTER the probe and
///      may legitimately mutate state; it asserts the ERC-1967 slot still holds the PREVIOUS
///      implementation (the swap lands after `migrate`) and bumps the epoch as an observable
///      effect.
contract MockMigrateImpl {
    address internal immutable EXPECTED_OLD;

    constructor(address expectedOld) {
        EXPECTED_OLD = expectedOld;
    }

    function proxiableUUID() external pure returns (bytes32) {
        return IMPL_SLOT;
    }

    function verifyUpgrade(address, bytes calldata) external view {}

    function migrate(bytes calldata) external {
        uint256 installed;
        assembly {
            installed := sload(IMPL_SLOT)
        }
        require(address(uint160(installed)) == EXPECTED_OLD, "impl slot swapped before migrate");
        // Inline assembly only takes direct number constants; the slot is derived, so bind it first.
        bytes32 keyVersionSlot = KEY_VERSION_SLOT;
        assembly {
            sstore(keyVersionSlot, add(sload(keyVersionSlot), 1))
        }
    }
}

/// @dev Behavior tests for SHRINCS-gated `upgradeToAndCall`. Covers access + vetting reverts, the
///      stateful-sig leaf guards, the payload cross-bindings (impl / migrate-flag / migrator), the
///      STATICCALL probe defenses, `super.upgradeToAndCall`'s proxiableUUID check, and
///      both success paths (no-migrate impl swap, and migrate-during-upgrade). The wallet under
///      test is the base fixture's factory-deployed proxy, so upgrades swap the real ERC-1967
///      slot and post-upgrade dispatch follows it naturally.
contract ShrincsWallet_upgradeToAndCall is ShrincsWalletTest {
    event Upgraded(address indexed implementation);

    DummyImpl internal newImpl;

    function setUp() public override {
        super.setUp();
        newImpl = new DummyImpl();
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertTrue(address(newImpl).code.length > 0, "candidate implementation deployed");
        assertEq(
            factory.getVettedCodeIndex(address(newImpl).codehash),
            type(uint256).max,
            "candidate starts unvetted"
        );
    }

    function _pk() internal view returns (SHRINCS.PublicKey memory) {
        return _mainPk();
    }

    /// @dev Upgrade-auth blob binding the LIVE action nonce (the 5th head word the wallet's
    ///      `StaleActionNonce` gate checks against).
    function _data(SHRINCS.Signature memory sig) internal view returns (bytes memory) {
        return abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), bytes(""));
    }

    /// @dev Vets an implementation through the real factory as its owner.
    function _vet(address impl) internal {
        vm.prank(ADMIN);
        factory.vetImplementation(impl);
    }

    /// @dev Signs the UPGRADE context binding (impl, shouldMigrate, migrator) at leaf 1.
    function _signUpgrade(address impl, bool shouldMigrate, bytes memory migrator)
        internal
        view
        returns (SHRINCS.Signature memory)
    {
        bytes32 payloadHash = Codec.upgradePayloadHash(impl, shouldMigrate, keccak256(migrator));
        return _signStatefulAction(Codec.ACTION_UPGRADE, payloadHash, 1);
    }

    /* ───────────────────────────── access / vetting ───────────────────────────── */

    function test_upgrade_revertsWhen_notOwner() public {
        _vet(address(newImpl));
        bytes memory data = _data(_statefulSigWithLeaf(SIGN_BASE + 1));
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgrade_revertsWhen_implementationNotVetted() public {
        bytes memory data = _data(_statefulSigWithLeaf(SIGN_BASE + 1));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ImplementationNotVetted.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgrade_revertsWhen_implementationDeprecated() public {
        _vet(address(newImpl));
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(newImpl));
        bytes memory data = _data(_statefulSigWithLeaf(SIGN_BASE + 1));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ImplementationDeprecated.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    /* ───────────────────────────── leaf guards ───────────────────────────── */

    function test_upgrade_revertsWhen_leafZero() public {
        _vet(address(newImpl));
        bytes memory data = _data(_statefulSigWithLeaf(0));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgrade_revertsWhen_leafOverBudget() public {
        _vet(address(newImpl));
        bytes memory data = _data(_statefulSigWithLeaf(uint256(MAX_SIG) + 1));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgrade_revertsWhen_leafAlreadyUsed() public {
        MockUpgradeImpl impl = new MockUpgradeImpl();
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), false, "");
        bytes memory data = abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), bytes(""));
        wallet.harness_markLeafUsed(SIGN_BASE + 1); // the UPGRADE signature is leaf 1
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.upgradeToAndCall(address(impl), data);
    }

    /* ───────────────────────────── nonce gate ───────────────────────────── */

    /// @dev The blob's bound nonce must equal the live one; a superseded upgrade auth is
    ///      rejected by the cheap `StaleActionNonce` gate before any verification.
    function test_upgrade_revertsWhen_staleActionNonce() public {
        MockUpgradeImpl impl = new MockUpgradeImpl();
        _vet(address(impl));
        uint256 live = wallet.actionNonce();
        bytes memory data =
            abi.encode(_pk(), _signUpgrade(address(impl), false, ""), false, bytes(""), live + 1, bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StaleActionNonce.selector, live, live + 1));
        wallet.upgradeToAndCall(address(impl), data);
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed on stale blob nonce");
    }

    /* ───────────────────────── signature cross-binding ───────────────────────── */

    function test_upgrade_revertsWhen_invalidSignature() public {
        _vet(address(newImpl));
        bytes memory data = _data(_wrongContextStatefulSig());
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    /// @dev The UPGRADE signature binds one implementation address; presenting it for a different
    ///      (vetted — the two mocks share a codehash) implementation must fail verification.
    function test_upgrade_revertsWhen_implementationNotBound() public {
        MockUpgradeImpl signedImpl = new MockUpgradeImpl();
        MockUpgradeImpl other = new MockUpgradeImpl();
        _vet(address(other)); // codehash-scoped: vets `signedImpl` too
        SHRINCS.Signature memory sig = _signUpgrade(address(signedImpl), false, "");
        bytes memory data = abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(other), data);
    }

    /// @dev The signature binds `shouldMigrate = false`; flipping the flag changes the payload hash.
    function test_upgrade_revertsWhen_migrateFlagNotBound() public {
        MockUpgradeImpl impl = new MockUpgradeImpl();
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), false, "");
        bytes memory data = abi.encode(_pk(), sig, true, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(impl), data);
    }

    /// @dev The signature binds an EMPTY migrator payload; a non-empty one changes the payload hash.
    function test_upgrade_revertsWhen_migratorPayloadNotBound() public {
        MockUpgradeImpl impl = new MockUpgradeImpl();
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), false, "");
        bytes memory data = abi.encode(_pk(), sig, false, bytes(hex"dead"), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(impl), data);
    }

    /* ──────────────────────── probe + proxiableUUID defenses ──────────────────────── */

    /// @dev The audit scenario the STATICCALL probe forecloses structurally: a vetted-but-
    ///      malicious implementation clearing a used-leaf bitmap word from the probe. The
    ///      SSTORE reverts at the EVM level inside the static frame.
    function test_upgrade_revertsWhen_probeAttemptsStorageWrite() public {
        MockTamperImpl impl = new MockTamperImpl();
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), false, "");
        bytes memory data = abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert();
        wallet.upgradeToAndCall(address(impl), data);
    }

    /// @dev The blob's opaque probe vector reaches the new implementation verbatim.
    function test_upgrade_forwardsProbePayloadVerbatim() public {
        MockProbeCheckImpl impl = new MockProbeCheckImpl();
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), false, "");
        bytes memory data =
            abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), bytes(hex"c0ffee"));
        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(address(impl));
        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(impl), data);
    }

    function test_upgrade_revertsWhen_probeReverts() public {
        MockRevertingProbeImpl impl = new MockRevertingProbeImpl();
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), false, "");
        bytes memory data = abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(MockRevertingProbeImpl.ProbeReverted.selector);
        wallet.upgradeToAndCall(address(impl), data);
    }

    function test_upgrade_revertsWhen_proxiableUuidMismatch() public {
        MockBadUuidImpl impl = new MockBadUuidImpl();
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), false, "");
        bytes memory data = abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(UUPSUpgradeable.UpgradeFailed.selector);
        wallet.upgradeToAndCall(address(impl), data);
    }

    /* ───────────────────────────── success paths ───────────────────────────── */

    /// @dev Full real-shape upgrade: a freshly deployed (real) implementation, vetted through
    ///      the factory, authorized by the main key, probed with a real throwaway-bundle vector.
    ///      Post-upgrade views dispatch through the swapped slot to the new implementation.
    function test_upgrade_succeedsNoMigrate() public {
        ShrincsWalletHarness impl =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), false, "");
        bytes memory data =
            abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), _probeVectorFor(address(impl)));

        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(address(impl));
        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(impl), data);

        assertEq(
            address(uint160(uint256(vm.load(WALLET, IMPL_SLOT)))),
            address(impl),
            "ERC-1967 implementation slot updated"
        );
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 consumed");
        assertEq(wallet.keyVersion(), 0, "no-migrate leaves the epoch unchanged");
        assertEq(wallet.actionNonce(), 1, "consumed upgrade signature advances the action nonce");
    }

    /// @dev Full real-shape upgrade WITH migration: the bound migrator payload carries entirely
    ///      fresh bundles, and the new (real) implementation's `migrate` installs them
    ///      mid-upgrade — bumping the epoch and resetting the leaf accounting.
    function test_upgrade_succeedsWithMigrate() public {
        ShrincsWalletHarness impl =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        _vet(address(impl));
        (bytes memory migrator, bytes32 freshCommitment) = _freshInitPayload("post-migrate-keys");
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), true, migrator);
        assertEq(wallet.keyVersion(), 0, "epoch starts at 0");

        bytes memory data =
            abi.encode(_pk(), sig, true, migrator, wallet.actionNonce(), _probeVectorFor(address(impl)));
        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(address(impl));
        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(impl), data);

        assertEq(
            address(uint160(uint256(vm.load(WALLET, IMPL_SLOT)))), address(impl), "implementation slot updated"
        );
        assertEq(wallet.keyVersion(), 1, "migrate executed during the upgrade");
        assertEq(wallet.getShrincsPublicKeyCommitment(), freshCommitment, "fresh main bundle installed");
        assertEq(
            wallet.getErc1271PublicKeyCommitment(),
            _commitment32(_freshErc1271Pk("post-migrate-keys")),
            "fresh erc1271 bundle installed"
        );
        assertEq(wallet.statefulLeavesUsed(), 0, "new epoch resets the used-leaf counter");
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "new epoch reads a fresh bitmap namespace");
    }

    /// @dev Mid-upgrade ordering: `migrate` observes the ERC-1967 slot still holding the
    ///      PREVIOUS implementation (the swap lands in `super.upgradeToAndCall` AFTER migrate).
    function test_upgrade_migrateRunsBeforeSlotSwap() public {
        MockMigrateImpl impl = new MockMigrateImpl(address(walletImplementation));
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), true, "");

        bytes memory data = abi.encode(_pk(), sig, true, bytes(""), wallet.actionNonce(), bytes(""));
        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(address(impl));
        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(impl), data);

        // The tx succeeding proves migrate's slot assertion held; the epoch bump is its
        // observable side effect (read raw — the mock exposes no views).
        assertEq(
            address(uint160(uint256(vm.load(WALLET, IMPL_SLOT)))), address(impl), "implementation slot updated"
        );
        assertEq(uint256(vm.load(WALLET, KEY_VERSION_SLOT)), 1, "migrate executed during the upgrade");
    }

    /* ───────────────────────── cross-family upgrade ───────────────────────── */

    /// @dev Builds a fresh WOTS+ keypair from `seed`.
    function _wotsKey(bytes32 seed) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        (WOTSPlus.WinternitzAddress memory pub,) = WOTSPlusTestSigner.generateKeyPair(seed);
        return pub;
    }

    /// @dev Packed 2048-byte WOTS+ init/migrate payload: disaster ‖ ownership ‖ 10 txn ‖
    ///      10 recovery ‖ 10 verification keys, all distinct.
    function _wotsMigrator() internal pure returns (bytes memory payload) {
        payload = bytes.concat(
            _wotsKey("x-disaster").publicSeed, _wotsKey("x-disaster").publicKeyHash,
            _wotsKey("x-ownership").publicSeed, _wotsKey("x-ownership").publicKeyHash
        );
        for (uint256 i = 0; i < 30; i++) {
            WOTSPlus.WinternitzAddress memory k = _wotsKey(keccak256(abi.encode("x-set", i)));
            payload = bytes.concat(payload, k.publicSeed, k.publicKeyHash);
        }
    }

    /// @dev Full SHRINCS → WOTS+ upgrade through the frozen `IWallet` seam: the SHRINCS
    ///      wallet authorizes and vets, STATICCALLs the WOTS+ impl's context-free
    ///      `verifyUpgrade` (a WOTS+ vector the SHRINCS side never interprets), then
    ///      delegatecalls its `migrate`, gated by the wallet's OWN ERC-1967 pointer (which
    ///      mid-upgrade still holds the SHRINCS implementation), installing the WOTS+ keysets
    ///      and re-pinning the factory in the virgin namespace. Post-upgrade calls dispatch
    ///      through the swapped slot to the WOTS+ code.
    function test_upgrade_succeedsCrossFamily_shrincsToWots() public {
        WOTSPlusImplementation wotsImpl = new WOTSPlusImplementation(payable(address(factory)));
        _vet(address(wotsImpl));

        // WOTS+ probe vector: the family's `verifyUpgrade` decodes the full 6529-byte upgrade
        // payload and reads only the verifier slice [2272:2336) + its signature [2336:4480).
        // The throwaway key signs the WOTS+ verification digest, which binds the STATICCALL
        // target (`address(this)` during the probe is the WOTS+ impl itself) and the new impl.
        (WOTSPlus.WinternitzAddress memory probeKeyW, bytes32 probePriv) =
            WOTSPlusTestSigner.generateKeyPair("x-probe");
        bytes32 digest = WOTSCodec.verificationDigest(
            address(wotsImpl), block.chainid, address(wotsImpl), probeKeyW.publicSeed, probeKeyW.publicKeyHash
        );
        bytes32[67] memory sigElements =
            WOTSPlusTestSigner.sign(probePriv, WOTSPlus.WinternitzMessage({messageHash: digest}));
        bytes memory probePayload = bytes.concat(
            new bytes(2272),
            probeKeyW.publicSeed,
            probeKeyW.publicKeyHash,
            abi.encodePacked(sigElements),
            new bytes(6529 - 4480)
        );

        bytes memory migrator = _wotsMigrator();
        SHRINCS.Signature memory sig = _signStatefulAction(
            Codec.ACTION_UPGRADE,
            Codec.upgradePayloadHash(address(wotsImpl), true, keccak256(migrator)),
            1
        );
        bytes memory data = abi.encode(_pk(), sig, true, migrator, wallet.actionNonce(), probePayload);

        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(address(wotsImpl));
        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(wotsImpl), data);

        assertEq(
            address(uint160(uint256(vm.load(WALLET, IMPL_SLOT)))), address(wotsImpl), "ERC-1967 slot -> WOTS+ impl"
        );
        // Real proxy dispatch: post-upgrade calls run the WOTS+ implementation.
        WOTSPlusImplementation wotsWallet = WOTSPlusImplementation(payable(WALLET));

        assertEq(wotsWallet.owner(), OWNER, "classical owner carries across families");
        assertEq(wotsWallet.quipFactory(), address(factory), "migrate re-pinned the factory in the virgin namespace");
        WOTSPlus.WinternitzAddress memory own = wotsWallet.getOwnershipKey();
        assertEq(own.publicSeed, _wotsKey("x-ownership").publicSeed, "ownership key installed");
        WOTSPlus.WinternitzAddress memory dis = wotsWallet.getDisasterRecoveryKey();
        assertEq(dis.publicKeyHash, _wotsKey("x-disaster").publicKeyHash, "disaster key installed");
    }

    /* ──────────────── migrate gating: callable ONLY during an upgrade ──────────────── */

    /// @dev No upgrade in flight, no implementation installed (bare-implementation shape,
    ///      empty ERC-1967 slot): refused.
    function test_migrate_revertsWhen_calledDirectly_noImplementationInstalled() public {
        ShrincsWalletHarness bare =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        bare.migrate(_validInitPayload());
    }

    /// @dev No upgrade in flight on the LIVE factory-deployed wallet (real proxy steady state:
    ///      the installed implementation IS the code that runs): refused.
    function test_migrate_revertsWhen_calledDirectly_onLiveWallet() public {
        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        wallet.migrate(_validInitPayload());
    }

    /// @dev The gate's window CLOSES with the ERC-1967 swap: upgrade the wallet to a newly
    ///      deployed implementation, then a direct `migrate` — dispatched to the new code,
    ///      whose `_SELF` now equals the installed pointer — is refused.
    function test_migrate_revertsWhen_calledAfterUpgradeCompletes() public {
        ShrincsWalletHarness impl =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        _vet(address(impl));
        SHRINCS.Signature memory sig = _signUpgrade(address(impl), false, "");
        bytes memory data =
            abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), _probeVectorFor(address(impl)));

        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(impl), data);
        assertEq(
            address(uint160(uint256(vm.load(WALLET, IMPL_SLOT)))), address(impl), "upgrade completed"
        );

        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        wallet.migrate(_validInitPayload());
    }
}
