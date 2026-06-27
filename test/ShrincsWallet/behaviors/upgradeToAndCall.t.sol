// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

// ERC-1967 implementation slot (`uint256(keccak256("eip1967.proxy.implementation")) - 1`).
bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
// Guarded keyVersion slot (`ShrincsWalletStorage` base + 3).
bytes32 constant KEY_VERSION_SLOT = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc03;
// Guarded nonce slot (`ShrincsWalletStorage` base + 4).
bytes32 constant NONCE_SLOT = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc04;

contract DummyImpl {
    uint256 public marker;
}

/// @dev Minimal vetted implementation for the upgrade success path. It is etched at the signed
///      implementation address (`0xBEEF`), so it needs a plain `proxiableUUID` (NO `notDelegated`
///      guard, which would revert when the bytecode's captured `__self` differs from the etched
///      address) plus a no-op `verifyUpgrade` reachability probe that touches no guarded slot.
contract MockUpgradeImpl {
    function proxiableUUID() external pure returns (bytes32) {
        return IMPL_SLOT;
    }

    function verifyUpgrade(address, bytes calldata) external {}
}

/// @dev Malicious implementation whose delegatecalled `verifyUpgrade` writes a guarded slot (the
///      nonce slot, guard index 6), so the post-probe `_assertGuardedSlotsUnchanged` reverts
///      `GuardedSlotTampered(6)`.
contract MockTamperImpl {
    function verifyUpgrade(address, bytes calldata) external {
        assembly {
            sstore(NONCE_SLOT, 0xdead)
        }
    }
}

/// @dev Implementation that returns the WRONG `proxiableUUID`, so `super.upgradeToAndCall` rejects
///      it with `UpgradeFailed` (after our SHRINCS gate + verify probe have passed).
contract MockBadUuidImpl {
    function proxiableUUID() external pure returns (bytes32) {
        return bytes32(uint256(1)); // not the ERC-1967 slot
    }

    function verifyUpgrade(address, bytes calldata) external {}
}

/// @dev Implementation whose `verifyUpgrade` reachability probe reverts; the wallet must bubble it.
contract MockRevertingProbeImpl {
    error ProbeReverted();

    function proxiableUUID() external pure returns (bytes32) {
        return IMPL_SLOT;
    }

    function verifyUpgrade(address, bytes calldata) external pure {
        revert ProbeReverted();
    }
}

/// @dev Implementation exercising the migrate branch. Its `migrate` runs AFTER the guarded-slot
///      assertion, so it may legitimately mutate guarded state; it asserts the transient upgrade
///      guard is set (proving the `tstore` wrapping) and bumps the epoch as an observable effect.
contract MockMigrateImpl {
    function proxiableUUID() external pure returns (bytes32) {
        return IMPL_SLOT;
    }

    function verifyUpgrade(address, bytes calldata) external {}

    function migrate(bytes calldata) external {
        uint256 guardSlot = uint256(keccak256("quip.shrincs.wallet.upgrade.guard")) - 1;
        uint256 g;
        assembly {
            g := tload(guardSlot)
        }
        require(g == 1, "upgrade guard not set during migrate");
        assembly {
            sstore(KEY_VERSION_SLOT, add(sload(KEY_VERSION_SLOT), 1))
        }
    }
}

/// @dev Behavior tests for SHRINCS-gated `upgradeToAndCall`. Covers access + vetting reverts, the
///      stateful-sig leaf guards, the payload cross-bindings (impl / migrate-flag / migrator), the
///      verify-probe + guarded-slot defenses, `super.upgradeToAndCall`'s proxiableUUID check, and
///      both success paths (no-migrate impl swap, and migrate-during-upgrade).
contract ShrincsWallet_upgradeToAndCall is ShrincsWalletTest {
    event Upgraded(address indexed implementation);

    DummyImpl internal newImpl;

    function setUp() public override {
        super.setUp();
        newImpl = new DummyImpl();
    }

    function _pk() internal view returns (ShrincsTypes.PublicKey memory) {
        return _parsePublicKey(".mainKey");
    }

    function _data(ShrincsTypes.StatefulSignature memory sig) internal view returns (bytes memory) {
        return abi.encode(_pk(), sig, false, bytes(""));
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

    function _upgradeSig() internal view returns (ShrincsTypes.StatefulSignature memory) {
        return _parseStatefulSignature(".cases.upgrade.signature");
    }

    /* ───────────────────────────── access / vetting ───────────────────────────── */

    function test_upgrade_revertsWhen_notOwner() public {
        _vet(address(newImpl));
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.upgradeToAndCall(address(newImpl), _data(_statefulSigWithLeaf(1)));
    }

    function test_upgrade_revertsWhen_implementationNotVetted() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ImplementationNotVetted.selector);
        wallet.upgradeToAndCall(address(newImpl), _data(_statefulSigWithLeaf(1)));
    }

    function test_upgrade_revertsWhen_implementationDeprecated() public {
        _vet(address(newImpl));
        factory.setDeprecated(address(newImpl).codehash, true);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ImplementationDeprecated.selector);
        wallet.upgradeToAndCall(address(newImpl), _data(_statefulSigWithLeaf(1)));
    }

    /* ───────────────────────────── leaf guards ───────────────────────────── */

    function test_upgrade_revertsWhen_leafZero() public {
        _vet(address(newImpl));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.upgradeToAndCall(address(newImpl), _data(_statefulSigWithLeaf(0)));
    }

    function test_upgrade_revertsWhen_leafOverBudget() public {
        _vet(address(newImpl));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.upgradeToAndCall(address(newImpl), _data(_statefulSigWithLeaf(uint256(MAX_SIG) + 1)));
    }

    function test_upgrade_revertsWhen_leafAlreadyUsed() public {
        address impl = _installSignedImpl(address(new MockUpgradeImpl()).code);
        wallet.harness_markLeafUsed(1); // the UPGRADE vector is leaf 1
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.upgradeToAndCall(impl, abi.encode(_pk(), _upgradeSig(), false, bytes("")));
    }

    /* ───────────────────────── signature cross-binding ───────────────────────── */

    function test_upgrade_revertsWhen_invalidSignature() public {
        _vet(address(newImpl));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(newImpl), _data(_wrongContextStatefulSig()));
    }

    /// @dev The UPGRADE signature binds `newImplementation = 0xBEEF`; presenting it for a different
    ///      (vetted) implementation must fail verification.
    function test_upgrade_revertsWhen_implementationNotBound() public {
        MockUpgradeImpl other = new MockUpgradeImpl();
        _vet(address(other));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(other), abi.encode(_pk(), _upgradeSig(), false, bytes("")));
    }

    /// @dev The signature binds `shouldMigrate = false`; flipping the flag changes the payload hash.
    function test_upgrade_revertsWhen_migrateFlagNotBound() public {
        address impl = _installSignedImpl(address(new MockUpgradeImpl()).code);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(impl, abi.encode(_pk(), _upgradeSig(), true, bytes("")));
    }

    /// @dev The signature binds an EMPTY migrator payload; a non-empty one changes the payload hash.
    function test_upgrade_revertsWhen_migratorPayloadNotBound() public {
        address impl = _installSignedImpl(address(new MockUpgradeImpl()).code);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(impl, abi.encode(_pk(), _upgradeSig(), false, bytes(hex"dead")));
    }

    /* ──────────────────────── probe + proxiableUUID defenses ──────────────────────── */

    function test_upgrade_guardedSlotTampered() public {
        address impl = _installSignedImpl(address(new MockTamperImpl()).code);
        // The verify-probe delegatecall mutates the guarded nonce slot (index 6) ⇒ revert.
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.GuardedSlotTampered.selector, 6));
        wallet.upgradeToAndCall(impl, abi.encode(_pk(), _upgradeSig(), false, bytes("")));
    }

    function test_upgrade_revertsWhen_verifyUpgradeProbeReverts() public {
        address impl = _installSignedImpl(address(new MockRevertingProbeImpl()).code);
        vm.prank(OWNER);
        vm.expectRevert(MockRevertingProbeImpl.ProbeReverted.selector);
        wallet.upgradeToAndCall(impl, abi.encode(_pk(), _upgradeSig(), false, bytes("")));
    }

    function test_upgrade_revertsWhen_proxiableUuidMismatch() public {
        address impl = _installSignedImpl(address(new MockBadUuidImpl()).code);
        vm.prank(OWNER);
        vm.expectRevert(UUPSUpgradeable.UpgradeFailed.selector);
        wallet.upgradeToAndCall(impl, abi.encode(_pk(), _upgradeSig(), false, bytes("")));
    }

    /* ───────────────────────────── success paths ───────────────────────────── */

    function test_upgrade_succeedsNoMigrate() public {
        address impl = _installSignedImpl(address(new MockUpgradeImpl()).code);

        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(impl);
        vm.prank(OWNER);
        wallet.upgradeToAndCall(impl, abi.encode(_pk(), _upgradeSig(), false, bytes("")));

        assertEq(address(uint160(uint256(vm.load(WALLET, IMPL_SLOT)))), impl, "ERC-1967 implementation slot updated");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
        assertEq(wallet.keyVersion(), 0, "no-migrate leaves the epoch unchanged");
    }

    function test_upgrade_succeedsWithMigrate() public {
        address impl = _installSignedImpl(address(new MockMigrateImpl()).code);
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.upgradeMigrate.signature");
        assertEq(wallet.keyVersion(), 0, "epoch starts at 0");

        vm.expectEmit(true, false, false, false, address(wallet));
        emit Upgraded(impl);
        vm.prank(OWNER);
        wallet.upgradeToAndCall(impl, abi.encode(_pk(), sig, true, bytes("")));

        // `migrate` ran inside the transient upgrade guard (it requires the flag) and bumped the epoch.
        assertEq(wallet.keyVersion(), 1, "migrate executed during the upgrade");
        assertEq(address(uint160(uint256(vm.load(WALLET, IMPL_SLOT)))), impl, "implementation slot updated");
    }
}
