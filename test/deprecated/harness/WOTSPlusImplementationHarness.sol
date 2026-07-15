// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusStorage as Storage} from "../../../contracts/deprecated/wots/WOTSPlusStorage.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/deprecated/wots/EnumerableWinternitzAddressSet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";

/// @dev Enum mirroring the three keyset storage slots so harness tests can target any of them.
enum HarnessKeyset {
    Transaction,
    Recovery,
    Verification
}

contract WOTSPlusImplementationHarness is WOTSPlusImplementation {
    using Keyset for Keyset.WinternitzAddressSet;

    constructor(address payable factory_) WOTSPlusImplementation(factory_) {}

    function _set(HarnessKeyset kind) internal view returns (Keyset.WinternitzAddressSet storage) {
        Storage.Layout storage $ = Storage.layout();
        if (kind == HarnessKeyset.Transaction) return $.transactionKeys;
        if (kind == HarnessKeyset.Recovery) return $.recoveryKeys;
        return $.verificationKeys;
    }

    /// @dev Test-only setup helper that bulk-installs an array of keys via
    ///      the burn-index-checked `_safeAddKey` primitive. Replaces the
    ///      retired `_addKeys` wallet helper. Callers that exceed `MAX_KEYS`
    ///      or supply a historically-spent key get the corresponding
    ///      `_safeAddKey` revert (`KeyAdditionFailed` / `KeyInUse`).
    function exposed_addKeys(HarnessKeyset kind, WOTSPlus.WinternitzAddress[] calldata keys) external {
        Keyset.WinternitzAddressSet storage set = _set(kind);
        for (uint256 i = 0; i < keys.length; i++) {
            _safeAddKey(set, keys[i]);
        }
    }

    function exposed_clearKeys(HarnessKeyset kind) external {
        _clearKeys(_set(kind));
    }

    /// @dev Test-only escape hatch: removes `key` from the selected keyset
    ///      without going through the normal auth flow. Used to set up
    ///      arbitrary keyset states (e.g. open a slot in a full set) for
    ///      tests that target downstream behaviour and don't want to thread
    ///      a full WOTS+-authenticated rotation through setup. NOT a path
    ///      that exists on the production contract.
    function burnKey(HarnessKeyset kind, WOTSPlus.WinternitzAddress calldata key) external {
        _safeRemoveKey(_set(kind), key);
    }

    function exposed_rotateKeys(
        HarnessKeyset kind,
        WOTSPlus.WinternitzAddress calldata currentKey,
        WOTSPlus.WinternitzAddress calldata nextKey
    ) external {
        _rotateKeys(_set(kind), currentKey, nextKey);
    }

    function exposed_safeAddKey(HarnessKeyset kind, WOTSPlus.WinternitzAddress calldata key) external {
        _safeAddKey(_set(kind), key);
    }

    function exposed_safeRemoveKey(HarnessKeyset kind, WOTSPlus.WinternitzAddress calldata key) external {
        _safeRemoveKey(_set(kind), key);
    }

    function exposed_enforceContained(HarnessKeyset kind, WOTSPlus.WinternitzAddress calldata key) external view {
        _enforceContained(_set(kind), key);
    }

    function exposed_enforceUncontained(HarnessKeyset kind, WOTSPlus.WinternitzAddress calldata key) external view {
        _enforceUncontained(_set(kind), key);
    }

    function exposed_isKeySpent(WOTSPlus.WinternitzAddress calldata key) external view returns (bool) {
        return _isKeySpent(key);
    }

    function exposed_enforceUnspentKey(WOTSPlus.WinternitzAddress calldata key) external view {
        _enforceUnspentKey(key);
    }

    function exposed_enforceDifferentKeys(WOTSPlus.WinternitzAddress calldata a, WOTSPlus.WinternitzAddress calldata b)
        external
        pure
    {
        _enforceDifferentKeys(a, b);
    }

    /// @dev Test-only escape hatch: writes the disaster recovery key directly so
    ///      tests can stage cross-keyset uniqueness scenarios without going through
    ///      `_installInitialKeys` (which also requires keyset payloads). Routes
    ///      through `_setDisasterRecoveryKey` so the monotonic `isKeySpent` index is
    ///      marked just as it would be in production.
    function setDisasterRecoveryKey(WOTSPlus.WinternitzAddress calldata key) external {
        _setDisasterRecoveryKey(key);
    }

    /// @dev Test-only escape hatch: writes the ownership key directly. See
    ///      `setDisasterRecoveryKey` for rationale.
    function setOwnershipKey(WOTSPlus.WinternitzAddress calldata key) external {
        _setOwnershipKey(key);
    }

    function exposed_verifyInitialState() external view {
        _verifyInitialState();
    }

    function exposed_guardInitializeOwner() external pure returns (bool) {
        return _guardInitializeOwner();
    }

    function exposed_authorizeUpgrade(address newImpl) external {
        _authorizeUpgrade(newImpl);
    }

    function exposed_upgradeGuard() external view returns (uint256) {
        return _upgradeGuard();
    }

    function exposed_upgradeGuardInContext() external returns (uint256) {
        // _UPGRADE_GUARD_SLOT is private; replicate the derivation
        uint256 slot = uint256(keccak256("quip.wallet.upgrade.guard")) - 1;
        assembly {
            tstore(slot, 1)
        }
        uint256 v = _upgradeGuard();
        assembly {
            tstore(slot, 0)
        }
        return v;
    }

    function exposed_validateSignature(ERC4337.PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        returns (uint256)
    {
        return _validateSignature(userOp, userOpHash);
    }

    function exposed_verifyAndRotate(
        HarnessKeyset kind,
        WOTSPlus.WinternitzAddress calldata currentKey,
        WOTSPlus.WinternitzAddress calldata nextKey,
        WOTSPlus.WinternitzElements calldata pqSig,
        bytes32 digest
    ) external {
        _verifyAndRotate(_set(kind), currentKey, nextKey, pqSig, digest);
    }

    /// @dev Exposes `_keyset` by returning the set's length — a proxy observation since
    ///      storage references cannot cross the ABI boundary. Pairing this with
    ///      `exposed_keysetContains` is sufficient to verify the correct set is selected.
    function exposed_keysetLength(Codec.KeyType kind) external view returns (uint256) {
        return _keyset(kind).length();
    }

    function exposed_keysetContains(Codec.KeyType kind, WOTSPlus.WinternitzAddress calldata key)
        external
        view
        returns (bool)
    {
        return _keyset(kind).contains(key);
    }

    function exposed_verifyImplementationSig(
        address newImplementation,
        WOTSPlus.WinternitzAddress calldata verifier,
        WOTSPlus.WinternitzElements calldata verifySig
    ) external view {
        _verifyImplementationSig(newImplementation, verifier, verifySig);
    }

    function exposed_collectExecuteFee() external {
        _collectExecuteFee();
    }

    function exposed_reinitializeAndTransferOwnership(bytes calldata payload) external {
        _reinitializeAndTransferOwnership(payload);
    }

    function exposed_installInitialKeys(
        WOTSPlus.WinternitzAddress calldata disasterRecoveryKey,
        WOTSPlus.WinternitzAddress calldata ownershipKey,
        WOTSPlus.WinternitzAddress[10] calldata transactionKeys,
        WOTSPlus.WinternitzAddress[10] calldata recoveryKeys,
        WOTSPlus.WinternitzAddress[10] calldata verificationKeys
    ) external {
        _installInitialKeys(disasterRecoveryKey, ownershipKey, transactionKeys, recoveryKeys, verificationKeys);
    }

    function exposed_snapshotGuardedSlots() external view returns (bytes32[7] memory) {
        return _snapshotGuardedSlots();
    }

    function exposed_assertGuardedSlotsUnchanged(bytes32[7] memory snapshot) external view {
        _assertGuardedSlotsUnchanged(snapshot);
    }

    /// @dev Drives `migrate(bytes)` in the upgrade tstore context so tests can
    ///      exercise the happy path + post-guard revert branches without a full
    ///      `upgradeToAndCall` round-trip. Transient storage is contract-scoped,
    ///      so the tstore set here is visible when the `this.migrate` call
    ///      re-enters this same contract.
    function exposed_migrateInUpgradeContext(bytes calldata payload) external {
        uint256 slot = 0x490d87f9a8524f6238d75626265800824e3fa88e60bc82c13f11bbd9042ed677;
        assembly {
            tstore(slot, 1)
        }
        this.migrate(payload);
        assembly {
            tstore(slot, 0)
        }
    }
}
