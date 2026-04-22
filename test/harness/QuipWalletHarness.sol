// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWallet} from "../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusStorage as Storage} from "../../contracts/storage/WOTSPlusStorage.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../contracts/libraries/EnumerableWinternitzAddressSet.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/WOTSPlusCodec.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";

/// @dev Enum mirroring the three keyset storage slots so harness tests can target any of them.
enum HarnessKeyset {
    Transaction,
    Recovery,
    Verification
}

contract QuipWalletHarness is QuipWallet {
    using Keyset for Keyset.WinternitzAddressSet;

    constructor(address payable factory_) QuipWallet(factory_) {}

    function _set(
        HarnessKeyset kind
    ) internal view returns (Keyset.WinternitzAddressSet storage) {
        Storage.Layout storage $ = Storage.layout();
        if (kind == HarnessKeyset.Transaction) return $.transactionKeys;
        if (kind == HarnessKeyset.Recovery) return $.recoveryKeys;
        return $.verificationKeys;
    }

    function exposed_addKeys(
        HarnessKeyset kind,
        WOTSPlus.WinternitzAddress[] calldata keys
    ) external {
        _addKeys(_set(kind), keys);
    }

    function exposed_clearKeys(HarnessKeyset kind) external {
        _clearKeys(_set(kind));
    }

    function exposed_rotateKeys(
        HarnessKeyset kind,
        WOTSPlus.WinternitzAddress calldata currentKey,
        WOTSPlus.WinternitzAddress calldata nextKey
    ) external {
        _rotateKeys(_set(kind), currentKey, nextKey);
    }

    function exposed_enforceContained(
        HarnessKeyset kind,
        WOTSPlus.WinternitzAddress calldata key
    ) external view {
        _enforceContained(_set(kind), key);
    }

    function exposed_enforceUncontained(
        HarnessKeyset kind,
        WOTSPlus.WinternitzAddress calldata key
    ) external view {
        _enforceUncontained(_set(kind), key);
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
        // _UPGRADE_GUARD_SLOT is private; replicate the constant
        uint256 slot = 0x490d87f9a8524f6238d75626265800824e3fa88e60bc82c13f11bbd9042ed677;
        assembly {
            tstore(slot, 1)
        }
        uint256 v = _upgradeGuard();
        assembly {
            tstore(slot, 0)
        }
        return v;
    }

    function exposed_validateSignature(
        ERC4337.PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
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

    function exposed_manageKeys(bytes calldata payload, bool replace) external {
        _manageKeys(payload, replace);
    }

    /// @dev Exposes `_keyset` by returning the set's length — a proxy observation since
    ///      storage references cannot cross the ABI boundary. Pairing this with
    ///      `exposed_keysetContains` is sufficient to verify the correct set is selected.
    function exposed_keysetLength(
        Codec.KeyType kind
    ) external view returns (uint256) {
        return _keyset(kind).length();
    }

    function exposed_keysetContains(
        Codec.KeyType kind,
        WOTSPlus.WinternitzAddress calldata key
    ) external view returns (bool) {
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

    function exposed_reinitializeAndTransferOwnership(
        bytes calldata payload,
        bool isHandover
    ) external {
        _reinitializeAndTransferOwnership(payload, isHandover);
    }

    function exposed_installInitialKeys(
        WOTSPlus.WinternitzAddress calldata disasterRecoveryKey,
        WOTSPlus.WinternitzAddress calldata ownershipKey,
        WOTSPlus.WinternitzAddress[5] calldata transactionKeys,
        WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
    ) external {
        _installInitialKeys(
            disasterRecoveryKey,
            ownershipKey,
            transactionKeys,
            recoveryKeys
        );
    }

    function exposed_snapshotGuardedSlots()
        external
        view
        returns (bytes32[7] memory)
    {
        return _snapshotGuardedSlots();
    }

    function exposed_assertGuardedSlotsUnchanged(
        bytes32[7] memory snapshot
    ) external view {
        _assertGuardedSlotsUnchanged(snapshot);
    }

    /// @dev Drives `migrate(bytes)` in the upgrade tstore context so tests can
    ///      exercise the happy path + post-guard revert branches without a full
    ///      `upgradeToAndCall` round-trip. Transient storage is contract-scoped,
    ///      so the tstore set here is visible when the `this.migrate` call
    ///      re-enters this same contract.
    function exposed_migrateInUpgradeContext(
        bytes calldata payload
    ) external {
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
