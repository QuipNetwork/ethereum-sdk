// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/WOTSPlusTestSigner.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlusCodec as WOTSCodec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

// ERC-1967 implementation slot (`uint256(keccak256("eip1967.proxy.implementation")) - 1`).
bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
// keyVersion slot (`ShrincsWalletStorage` base + 3).
bytes32 constant KEY_VERSION_SLOT = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc03;
// `usedStatefulLeafBitmap` mapping base (`ShrincsWalletStorage` base + 6).
bytes32 constant BITMAP_BASE_SLOT = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc06;

contract DummyImpl {
    uint256 public marker;
}

/// @dev Minimal vetted implementation for the upgrade success path. It is etched at the signed
///      implementation address (`0xBEEF`), so it needs a plain `proxiableUUID` (NO `notDelegated`
///      guard, which would revert when the bytecode's captured `__self` differs from the etched
///      address) plus a no-op `verifyUpgrade` probe.
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

/// @dev Implementation exercising the migrate branch. Its `migrate` runs AFTER the probe and
///      may legitimately mutate state; it asserts the mid-upgrade shape (the ERC-1967 slot
///      has not yet swapped to the new implementation) and bumps the epoch as an observable effect.
contract MockMigrateImpl {
    function proxiableUUID() external pure returns (bytes32) {
        return IMPL_SLOT;
    }

    function verifyUpgrade(address, bytes calldata) external view {}

    function migrate(bytes calldata) external {
        uint256 installed;
        assembly {
            installed := sload(IMPL_SLOT)
        }
        require(address(uint160(installed)) != address(0xBEEF), "impl slot swapped before migrate");
        assembly {
            sstore(KEY_VERSION_SLOT, add(sload(KEY_VERSION_SLOT), 1))
        }
    }
}

/// @dev Behavior tests for SHRINCS-gated `upgradeToAndCall`. Covers access + vetting reverts, the
///      stateful-sig leaf guards, the payload cross-bindings (impl / migrate-flag / migrator), the
///      STATICCALL probe defenses, `super.upgradeToAndCall`'s proxiableUUID check, and
///      both success paths (no-migrate impl swap, and migrate-during-upgrade).
contract ShrincsWallet_upgradeToAndCall is ShrincsWalletTest {
    event Upgraded(address indexed implementation);

    DummyImpl internal newImpl;

    function setUp() public override {
        super.setUp();
        newImpl = new DummyImpl();
    }

    function _pk() internal view returns (SHRINCS.PublicKey memory) {
        return _mainPk();
    }

    /// @dev Upgrade-auth blob binding the LIVE action nonce (the 5th head word the wallet's
    ///      `StaleActionNonce` gate checks against).
    function _data(SHRINCS.Signature memory sig) internal view returns (bytes memory) {
        return abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), bytes(""));
    }

    function _vet(address impl) internal {
        factory.vet(impl.codehash, 0);
    }

    /// @dev Etches `code` at the signed implementation address (`0xBEEF`) and vets it.
    function _installSignedImpl(bytes memory code) internal returns (address impl) {
        impl = address(0xBEEF);
        vm.etch(impl, code);
        _vet(impl);
    }

    /// @dev Signs the UPGRADE context binding (impl 0xBEEF, shouldMigrate, migrator) at leaf 1.
    function _signUpgrade(bool shouldMigrate, bytes memory migrator)
        internal
        view
        returns (SHRINCS.Signature memory)
    {
        bytes32 payloadHash = Codec.upgradePayloadHash(address(0xBEEF), shouldMigrate, keccak256(migrator));
        return _signStatefulAction(Codec.ACTION_UPGRADE, payloadHash, 1);
    }

    function _upgradeSig() internal view returns (SHRINCS.Signature memory) {
        return _signUpgrade(false, "");
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
        factory.setDeprecated(address(newImpl).codehash, true);
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
        address impl = _installSignedImpl(address(new MockUpgradeImpl()).code);
        bytes memory data = abi.encode(_pk(), _upgradeSig(), false, bytes(""), wallet.actionNonce(), bytes(""));
        wallet.harness_markLeafUsed(SIGN_BASE + 1); // the UPGRADE signature is leaf 1
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.upgradeToAndCall(impl, data);
    }

    /* ───────────────────────────── nonce gate ───────────────────────────── */

    /// @dev The blob's bound nonce must equal the live one; a superseded upgrade auth is
    ///      rejected by the cheap `StaleActionNonce` gate before any verification.
    function test_upgrade_revertsWhen_staleActionNonce() public {
        address impl = _installSignedImpl(address(new MockUpgradeImpl()).code);
        uint256 live = wallet.actionNonce();
        bytes memory data = abi.encode(_pk(), _upgradeSig(), false, bytes(""), live + 1, bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StaleActionNonce.selector, live, live + 1));
        wallet.upgradeToAndCall(impl, data);
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

    /// @dev The UPGRADE signature binds `newImplementation = 0xBEEF`; presenting it for a different
    ///      (vetted) implementation must fail verification.
    function test_upgrade_revertsWhen_implementationNotBound() public {
        MockUpgradeImpl other = new MockUpgradeImpl();
        _vet(address(other));
        bytes memory data = abi.encode(_pk(), _upgradeSig(), false, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(other), data);
    }

    /// @dev The signature binds `shouldMigrate = false`; flipping the flag changes the payload hash.
    function test_upgrade_revertsWhen_migrateFlagNotBound() public {
        address impl = _installSignedImpl(address(new MockUpgradeImpl()).code);
        bytes memory data = abi.encode(_pk(), _upgradeSig(), true, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(impl, data);
    }

    /// @dev The signature binds an EMPTY migrator payload; a non-empty one changes the payload hash.
    function test_upgrade_revertsWhen_migratorPayloadNotBound() public {
        address impl = _installSignedImpl(address(new MockUpgradeImpl()).code);
        bytes memory data = abi.encode(_pk(), _upgradeSig(), false, bytes(hex"dead"), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(impl, data);
    }

    /* ──────────────────────── probe + proxiableUUID defenses ──────────────────────── */

    /// @dev The audit scenario the STATICCALL probe forecloses structurally: a vetted-but-
    ///      malicious implementation clearing a used-leaf bitmap word from the probe. The
    ///      SSTORE reverts at the EVM level inside the static frame.
    function test_upgrade_revertsWhen_probeAttemptsStorageWrite() public {
        address impl = _installSignedImpl(address(new MockTamperImpl()).code);
        bytes memory data = abi.encode(_pk(), _upgradeSig(), false, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert();
        wallet.upgradeToAndCall(impl, data);
    }

    /// @dev The blob's opaque probe vector reaches the new implementation verbatim.
    function test_upgrade_forwardsProbePayloadVerbatim() public {
        address impl = _installSignedImpl(address(new MockProbeCheckImpl()).code);
        bytes memory data =
            abi.encode(_pk(), _upgradeSig(), false, bytes(""), wallet.actionNonce(), bytes(hex"c0ffee"));
        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(impl);
        vm.prank(OWNER);
        wallet.upgradeToAndCall(impl, data);
    }

    function test_upgrade_revertsWhen_probeReverts() public {
        address impl = _installSignedImpl(address(new MockRevertingProbeImpl()).code);
        bytes memory data = abi.encode(_pk(), _upgradeSig(), false, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(MockRevertingProbeImpl.ProbeReverted.selector);
        wallet.upgradeToAndCall(impl, data);
    }

    function test_upgrade_revertsWhen_proxiableUuidMismatch() public {
        address impl = _installSignedImpl(address(new MockBadUuidImpl()).code);
        bytes memory data = abi.encode(_pk(), _upgradeSig(), false, bytes(""), wallet.actionNonce(), bytes(""));
        vm.prank(OWNER);
        vm.expectRevert(UUPSUpgradeable.UpgradeFailed.selector);
        wallet.upgradeToAndCall(impl, data);
    }

    /* ───────────────────────────── success paths ───────────────────────────── */

    function test_upgrade_succeedsNoMigrate() public {
        address impl = _installSignedImpl(address(new MockUpgradeImpl()).code);
        bytes memory data = abi.encode(_pk(), _upgradeSig(), false, bytes(""), wallet.actionNonce(), bytes(""));

        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(impl);
        vm.prank(OWNER);
        wallet.upgradeToAndCall(impl, data);

        assertEq(address(uint160(uint256(vm.load(WALLET, IMPL_SLOT)))), impl, "ERC-1967 implementation slot updated");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 consumed");
        assertEq(wallet.keyVersion(), 0, "no-migrate leaves the epoch unchanged");
        assertEq(wallet.actionNonce(), 1, "consumed upgrade signature advances the action nonce");
    }

    function test_upgrade_succeedsWithMigrate() public {
        address impl = _installSignedImpl(address(new MockMigrateImpl()).code);
        SHRINCS.Signature memory sig = _signUpgrade(true, "");
        assertEq(wallet.keyVersion(), 0, "epoch starts at 0");

        bytes memory data = abi.encode(_pk(), sig, true, bytes(""), wallet.actionNonce(), bytes(""));
        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(impl);
        vm.prank(OWNER);
        wallet.upgradeToAndCall(impl, data);

        // `migrate` ran mid-upgrade (before the ERC-1967 swap) and bumped the epoch.
        assertEq(wallet.keyVersion(), 1, "migrate executed during the upgrade");
        assertEq(address(uint160(uint256(vm.load(WALLET, IMPL_SLOT)))), impl, "implementation slot updated");
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
    ///      delegatecalls its `migrate`, gated by the wallet's OWN ERC-1967 pointer, which
    ///      installs the WOTS+ keysets and re-pins the factory in the virgin namespace.
    function test_upgrade_succeedsCrossFamily_shrincsToWots() public {
        WOTSPlusImplementation wotsImpl = new WOTSPlusImplementation(payable(address(factory)));
        _vet(address(wotsImpl));

        // The etched test wallet has no ERC-1967 pointer (a real proxy always does); seed the
        // pre-upgrade implementation so the WOTS+ `migrate` gate sees an upgrade in flight.
        vm.store(WALLET, IMPL_SLOT, bytes32(uint256(uint160(address(0xD00D)))));

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
        // The test wallet is etched code (not a proxy), so emulate the proxy's post-upgrade
        // dispatch by etching the new implementation's code; storage stays at WALLET.
        vm.etch(WALLET, address(wotsImpl).code);
        WOTSPlusImplementation wotsWallet = WOTSPlusImplementation(payable(WALLET));

        assertEq(wotsWallet.owner(), OWNER, "classical owner carries across families");
        assertEq(wotsWallet.quipFactory(), address(factory), "migrate re-pinned the factory in the virgin namespace");
        WOTSPlus.WinternitzAddress memory own = wotsWallet.getOwnershipKey();
        assertEq(own.publicSeed, _wotsKey("x-ownership").publicSeed, "ownership key installed");
        WOTSPlus.WinternitzAddress memory dis = wotsWallet.getDisasterRecoveryKey();
        assertEq(dis.publicKeyHash, _wotsKey("x-disaster").publicKeyHash, "disaster key installed");
    }

    /* ──────────────── migrate gating: callable ONLY during an upgrade ──────────────── */

    /// @dev Real probe vector for `target`: a throwaway bundle signing the recomputed digest.
    function _probeVectorFor(address target) internal returns (bytes memory) {
        (SHRINCS.SigningKey memory probeKey, SHRINCS.PublicKey memory probePk, bool ok) =
            SHRINCSTestSigner.keygen("gate-probe-throwaway", MAX_SIG);
        assertTrue(ok, "probe keygen");
        bytes32 c = _commitment32(probePk);
        bytes32 digest = Codec.probeDigest(target);
        (SHRINCS.Signature memory sf, bool okS) = SHRINCSTestSigner.signStatefulRawAtLeaf(
            probeKey, SIGN_BASE + 1, abi.encodePacked(SHRINCS.statefulRawMessageHash(c, digest))
        );
        assertTrue(okS, "probe stateful sign");
        SPHINCSPlusC.Signature memory sl =
            _signStatelessRaw(probeKey, probePk, abi.encodePacked(SHRINCS.statelessRawMessageHash(c, digest)));
        return abi.encode(probePk, sf, sl);
    }

    /// @dev No upgrade in flight, no implementation installed (bare shape): refused.
    function test_migrate_revertsWhen_calledDirectly_noImplementationInstalled() public {
        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        wallet.migrate(_validInitPayload());
    }

    /// @dev Rebinds the suite's `wallet` to a REAL ERC-1967 proxy over a fresh implementation
    ///      (so upgrades swap the slot and dispatch follows it naturally), installed with the
    ///      base fixture's keys — every base signing helper then targets the proxy.
    function _deployProxyWallet() internal {
        ShrincsWalletHarness impl =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        wallet = ShrincsWalletHarness(payable(LibClone.deployERC1967(address(impl))));
        wallet.harness_install(OWNER, mainCommitment, erc1271Commitment, MAX_SIG);
        wallet.harness_spendTrees(mainPk);
        wallet.harness_spendTrees(erc1271Pk);
    }

    /// @dev No upgrade in flight on a LIVE wallet (real proxy steady state: the installed
    ///      implementation IS the code that runs): refused.
    function test_migrate_revertsWhen_calledDirectly_onLiveWallet() public {
        _deployProxyWallet();
        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        wallet.migrate(_validInitPayload());
    }

    /// @dev The gate's window CLOSES with the ERC-1967 swap: upgrade a REAL proxy wallet to a
    ///      newly deployed implementation, then a direct `migrate` — dispatched to the new
    ///      code, whose `_SELF` now equals the installed pointer — is refused.
    function test_migrate_revertsWhen_calledAfterUpgradeCompletes() public {
        _deployProxyWallet();
        ShrincsWalletHarness newWalletImpl =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        address impl = address(newWalletImpl);
        _vet(impl);
        bytes32 payloadHash = Codec.upgradePayloadHash(impl, false, keccak256(bytes("")));
        SHRINCS.Signature memory sig = _signStatefulAction(Codec.ACTION_UPGRADE, payloadHash, 1);
        bytes memory data =
            abi.encode(_pk(), sig, false, bytes(""), wallet.actionNonce(), _probeVectorFor(impl));

        vm.prank(OWNER);
        wallet.upgradeToAndCall(impl, data);
        assertEq(
            address(uint160(uint256(vm.load(address(wallet), IMPL_SLOT)))), impl, "upgrade completed"
        );

        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        wallet.migrate(_validInitPayload());
    }
}
