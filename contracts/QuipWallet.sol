// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";
import {LibCall} from "solady-0.1.26/src/utils/LibCall.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "./interfaces/IQuipWallet.sol";
import {IQuipFactory} from "./interfaces/IQuipFactory.sol";
import {WOTSPlusCodec as Codec} from "./WOTSPlusCodec.sol";
import {WOTSPlusStorage as Storage} from "./storage/WOTSPlusStorage.sol";

/// @title QuipWallet
contract QuipWallet is IQuipWallet, ERC4337, Initializable {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    uint256 public constant MAX_RECOVERY_KEYS = 10;
    address payable public immutable FACTORY;

    /// @dev uint256(keccak256("quip.wallet.upgrade.guard")) - 1
    /// Transient storage slot used to gate `migrate` to the `upgradeToAndCall` context.
    /// @notice REQUIRES EIP-1153 (transient storage opcodes TSTORE/TLOAD).
    uint256 private constant _UPGRADE_GUARD_SLOT =
        0x490d87f9a8524f6238d75626265800824e3fa88e60bc82c13f11bbd9042ed677;

    /// @dev uint256(keccak256("quip.wallet.erc4337.nextPqOwner.seed")) - 1
    /// Transient storage slot for passing nextPqOwner.publicSeed from validateUserOp to execution.
    uint256 private constant _NEXT_PQ_SEED_TSLOT =
        uint256(keccak256("quip.wallet.erc4337.nextPqOwner.seed")) - 1;

    /// @dev uint256(keccak256("quip.wallet.erc4337.nextPqOwner.hash")) - 1
    /// Transient storage slot for passing nextPqOwner.publicKeyHash from validateUserOp to execution.
    uint256 private constant _NEXT_PQ_HASH_TSLOT =
        uint256(keccak256("quip.wallet.erc4337.nextPqOwner.hash")) - 1;

    /// @dev PQ storage base slot (ERC-7201 namespace: quip.storage.wallet.wotsplus).
    /// quipFactory at base+0, pqOwner.publicSeed at base+1, pqOwner.publicKeyHash at base+2.
    bytes32 private constant _PQ_FACTORY_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;
    bytes32 private constant _PQ_OWNER_SEED_SLOT =
        bytes32(uint256(_PQ_FACTORY_SLOT) + 1);
    bytes32 private constant _PQ_OWNER_HASH_SLOT =
        bytes32(uint256(_PQ_FACTORY_SLOT) + 2);

    constructor(address payable factory_) {
        if (factory_ == address(0)) revert ZeroAddressFactory();
        FACTORY = factory_;
        _disableInitializers();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    INTERNAL OVERRIDES                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev EIP-712 domain name and version for ERC-1271 signature validation.
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "QuipWallet";
        version = "1";
    }

    /// @dev WOTS+ signature validation for ERC-4337 UserOps.
    /// Verifies the PQ signature against the current pqOwner and stores
    /// nextPqOwner in transient storage for the execution phase.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeUserOpSignature(userOp.signature);

        if (nextPqOwner.publicSeed == bytes32(0) || nextPqOwner.publicKeyHash == bytes32(0))
            return 1;

        Storage.Layout storage $ = Storage.layout();

        if (
            nextPqOwner.publicSeed == $.pqOwner.publicSeed &&
            nextPqOwner.publicKeyHash == $.pqOwner.publicKeyHash
        ) return 1;

        bytes32 digest = Codec.erc4337ExecuteDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            userOpHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            return 1;

        bytes32 seed = nextPqOwner.publicSeed;
        bytes32 hash_ = nextPqOwner.publicKeyHash;
        uint256 seedSlot = _NEXT_PQ_SEED_TSLOT;
        uint256 hashSlot = _NEXT_PQ_HASH_TSLOT;
        assembly {
            tstore(seedSlot, seed)
            tstore(hashSlot, hash_)
        }

        return 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   ERC-4337 EXECUTION                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc ERC4337
    /// @dev Overridden to enforce PQ auth via forced key rotation from transient storage.
    /// The inner call is isolated so its revert does not undo the rotation.
    /// Owner must use `execute(bytes)` which has inline PQ auth.
    function execute(address target, uint256 value, bytes calldata data)
        public
        payable
        override
        onlyEntryPoint
        returns (bytes memory result)
    {
        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress memory curPqOwner = $.pqOwner;
        WOTSPlus.WinternitzAddress memory nextPqOwner = _consumePqKeyRotation();

        uint256 fee = getExecuteFee();
        if (fee > 0 && address(this).balance >= fee) {
            SafeTransferLib.safeTransferETH($.quipFactory, fee);
        }

        bytes32 dataHash = EfficientHashLib.hashCalldata(data);
        bool success;
        (success, result) = _tryCallContract(target, value, data);

        emit PqExecution(block.timestamp, curPqOwner, nextPqOwner, target, value, dataHash);

        if (!success) {
            emit ExecutionReverted(target, value, dataHash, result);
        }
    }

    /// @inheritdoc ERC4337
    /// @dev Overridden to enforce PQ auth. Single key rotation covers the entire batch.
    /// Each call in the batch is isolated individually via `_tryCallContract`.
    function executeBatch(Call[] calldata calls)
        public
        payable
        override
        onlyEntryPoint
        returns (bytes[] memory results)
    {
        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress memory curPqOwner = $.pqOwner;
        WOTSPlus.WinternitzAddress memory nextPqOwner = _consumePqKeyRotation();

        uint256 fee = getExecuteFee();
        if (fee > 0 && address(this).balance >= fee) {
            SafeTransferLib.safeTransferETH($.quipFactory, fee);
        }

        uint256 len = calls.length;
        results = new bytes[](len);
        for (uint256 i; i < len; ++i) {
            bool success;
            (success, results[i]) = _tryCallContract(calls[i].target, calls[i].value, calls[i].data);
            if (!success) {
                bytes32 callDataHash = EfficientHashLib.hashCalldata(calls[i].data);
                emit ExecutionReverted(calls[i].target, calls[i].value, callDataHash, results[i]);
            }
        }

        bytes32 batchHash = EfficientHashLib.hash(abi.encode(calls));
        emit PqExecution(block.timestamp, curPqOwner, nextPqOwner, address(0), 0, batchHash);
    }

    /// @inheritdoc ERC4337
    /// @dev Overridden to enforce PQ auth + snapshot-and-restore guard for PQ storage.
    /// Critical slots (owner, implementation, factory, pqOwner) are restored if the
    /// delegatecall modifies them. Recovery keys are verified but cannot be reliably
    /// restored if corrupted — the `_FINAL_RECOURSE_KEY` (see TODO.md) is the backstop.
    function delegateExecute(address delegate, bytes calldata data)
        public
        payable
        override
        onlyEntryPoint
        returns (bytes memory result)
    {
        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress memory curPqOwner = $.pqOwner;
        WOTSPlus.WinternitzAddress memory nextPqOwner = _consumePqKeyRotation();

        bool success;
        (success, result) = _guardedDelegateCall(delegate, data);

        bytes32 dataHash = EfficientHashLib.hashCalldata(data);
        emit PqExecution(block.timestamp, curPqOwner, nextPqOwner, delegate, 0, dataHash);

        if (!success) {
            emit ExecutionReverted(delegate, 0, dataHash, result);
        }
    }

    /// @inheritdoc ERC4337
    /// @dev Overridden to enforce PQ auth + extended guard that also blocks PQ storage slots.
    /// Soft guard: blocked writes emit `ExecutionReverted` instead of reverting (key safety).
    function storageStore(bytes32 storageSlot, bytes32 storageValue)
        public
        payable
        override
        onlyEntryPoint
    {
        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress memory curPqOwner = $.pqOwner;
        WOTSPlus.WinternitzAddress memory nextPqOwner = _consumePqKeyRotation();

        bytes32 dataHash = EfficientHashLib.hash(storageSlot, storageValue);

        // Soft guard: block writes to protected slots without reverting
        if (
            storageSlot == _OWNER_SLOT ||
            storageSlot == _ERC1967_IMPLEMENTATION_SLOT ||
            storageSlot == _PQ_FACTORY_SLOT ||
            storageSlot == _PQ_OWNER_SEED_SLOT ||
            storageSlot == _PQ_OWNER_HASH_SLOT
        ) {
            emit PqExecution(block.timestamp, curPqOwner, nextPqOwner, address(this), 0, dataHash);
            emit ExecutionReverted(address(this), 0, dataHash, "");
            return;
        }

        assembly {
            sstore(storageSlot, storageValue)
        }

        emit PqExecution(block.timestamp, curPqOwner, nextPqOwner, address(this), 0, dataHash);
    }

    /// @inheritdoc ERC4337
    /// @dev Overridden to enforce PQ auth. The withdrawal is isolated so its revert
    /// does not undo the key rotation.
    function withdrawDepositTo(address to, uint256 amount)
        public
        payable
        override
        onlyEntryPoint
    {
        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress memory curPqOwner = $.pqOwner;
        WOTSPlus.WinternitzAddress memory nextPqOwner = _consumePqKeyRotation();

        address ep = entryPoint();
        bool success;
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x14, to)
            mstore(0x34, amount)
            mstore(0x00, 0x205c2878000000000000000000000000) // `withdrawTo(address,uint256)`.
            success := mul(extcodesize(ep), call(gas(), ep, 0, 0x10, 0x44, codesize(), 0x00))
            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.
        }

        bytes32 dataHash = EfficientHashLib.hash(bytes32(uint256(uint160(to))), bytes32(amount));
        emit PqExecution(block.timestamp, curPqOwner, nextPqOwner, ep, amount, dataHash);

        if (!success) {
            emit ExecutionReverted(ep, amount, dataHash, "");
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          PUBLIC                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipWallet
    function renounceOwnership() public payable override(IQuipWallet, Ownable) onlyOwner {
        revert RenounceDisabled();
    }

    /// @inheritdoc IQuipWallet
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) public initializer {
        if (msg.sender != FACTORY) revert InvalidFactory();
        if (newOwner == address(0)) revert ZeroAddressOwner();

        (
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        ) = Codec.decodeInit(payload);
        _enforceNonZeroPqOwner(newPqOwner);

        _initializeOwner(newOwner);
        Storage.Layout storage $ = Storage.layout();
        $.quipFactory = FACTORY;
        $.pqOwner = newPqOwner;

        _addRecoveryKeys(recoveryKeys);
        _verifyInitialState();

        emit WalletInitialized(FACTORY, newOwner, newPqOwner, recoveryKeys);
    }

    /// @inheritdoc IQuipWallet
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) public payable override(IQuipWallet, UUPSUpgradeable) onlyOwner {
        Storage.Layout storage $ = Storage.layout();
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeUpgradeAuth(data);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);

        bytes32 digest = Codec.upgradeDigest(
            address(this),
            block.chainid,
            newImplementation,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(this.verifyUpgrade, (newImplementation, data))
        );

        $.pqOwner = nextPqOwner;

        (bool shouldMigrate, bytes calldata migratorPayload) = Codec.decodeUpgradeMigration(data);
        if (shouldMigrate) {
            uint256 slot = _UPGRADE_GUARD_SLOT;
            assembly { tstore(slot, 1) }
            // abi.encodeCall re-serializes migratorPayload into fresh calldata,
            // so migrate's decodeInit reads from offset 0 of the init layout
            // regardless of where the slice sat in the original upgrade payload.
            LibCall.delegateCallContract(
                newImplementation,
                abi.encodeCall(this.migrate, (migratorPayload))
            );
            assembly { tstore(slot, 0) }
        }

        super.upgradeToAndCall(newImplementation, data[0:0]);
    }

    /// @inheritdoc IQuipWallet
    function changePqOwner(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeChangePqOwner(payload);

        _enforceNonZeroPqOwner(newPqOwner);
        _enforceDifferentPqOwner(newPqOwner);

        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress memory oldPqOwner = $.pqOwner;
        bytes32 digest = Codec.keyRotationDigest(
            address(this),
            block.chainid,
            oldPqOwner.publicSeed,
            oldPqOwner.publicKeyHash,
            newPqOwner.publicSeed,
            newPqOwner.publicKeyHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        $.pqOwner = newPqOwner;

        emit PqOwnerChanged(oldPqOwner, newPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function execute(bytes calldata payload) public payable onlyOwner returns (bytes memory) {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            address target,
            uint256 value,
            bytes calldata data
        ) = Codec.decodeExecute(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);

        uint256 fee = getExecuteFee();
        if (address(this).balance < value + fee)
            revert InsufficientBalance(value + fee, address(this).balance);

        Storage.Layout storage $ = Storage.layout();
        bytes32 dataHash = EfficientHashLib.hashCalldata(data);
        bytes32 digest = Codec.executeDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            target,
            value,
            dataHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        WOTSPlus.WinternitzAddress memory curPqOwner = $.pqOwner;
        $.pqOwner = nextPqOwner;

        if (fee > 0) SafeTransferLib.safeTransferETH($.quipFactory, fee);

        bytes memory result;
        if (data.length == 0) {
            if (value > 0) SafeTransferLib.safeTransferETH(target, value);
        } else {
            result = LibCall.callContract(target, value, data);
        }

        emit PqExecution(block.timestamp, curPqOwner, nextPqOwner, target, value, dataHash);

        return result;
    }

    /// @inheritdoc IQuipWallet
    function recoverWallet(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata recoveryKey,
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeRecoverWallet(payload);

        Storage.Layout storage $ = Storage.layout();
        bytes32 keyHash = EfficientHashLib.hash(recoveryKey.publicSeed, recoveryKey.publicKeyHash);
        if (!$.recoveryKeyHashes.contains(keyHash))
            revert RecoveryKeyNotFound();

        _enforceNonZeroPqOwner(newPqOwner);
        _enforceDifferentPqOwner(newPqOwner);

        bytes32 digest = Codec.keyRotationDigest(
            address(this),
            block.chainid,
            recoveryKey.publicSeed,
            recoveryKey.publicKeyHash,
            newPqOwner.publicSeed,
            newPqOwner.publicKeyHash
        );

        if (!WOTSPlus.verify(recoveryKey, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        $.recoveryKeyHashes.remove(keyHash);
        $.pqOwner = newPqOwner;

        emit PqRecovery(recoveryKey, newPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function addRecoveryKeys(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
        ) = Codec.decodeKeyManagement(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);
        if (getRecoveryKeyCount() + newRecoveryKeys.length > MAX_RECOVERY_KEYS)
            revert RecoveryKeyLimitExceeded();

        Storage.Layout storage $ = Storage.layout();
        bytes32 keysHash = EfficientHashLib.hash(abi.encode(newRecoveryKeys));
        bytes32 digest = Codec.keyManagementDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            keysHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        _addRecoveryKeys(newRecoveryKeys);

        $.pqOwner = nextPqOwner;

        emit RecoveryKeysAdded(nextPqOwner, newRecoveryKeys.length);
    }

    /// @inheritdoc IQuipWallet
    function replenishRecoveryKeys(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
        ) = Codec.decodeKeyManagement(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);
        if (newRecoveryKeys.length > MAX_RECOVERY_KEYS)
            revert RecoveryKeyLimitExceeded();

        Storage.Layout storage $ = Storage.layout();
        bytes32 keysHash = EfficientHashLib.hash(abi.encode(newRecoveryKeys));
        bytes32 digest = Codec.keyManagementDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            keysHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        uint256 clearLen = $.recoveryKeyHashes.length();
        for (uint256 i = 0; i < clearLen; ++i) {
            $.recoveryKeyHashes.remove($.recoveryKeyHashes.at(0));
        }

        _addRecoveryKeys(newRecoveryKeys);

        $.pqOwner = nextPqOwner;

        emit RecoveryKeysReplenished(nextPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function recoveryUpgrade(address newImplementation, bytes calldata payload) public onlyOwner {
        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(this.verifyRecoveryUpgrade, (newImplementation, payload))
        );

        (
            WOTSPlus.WinternitzAddress calldata recoveryKey,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeRecoveryUpgradeData(payload);

        Storage.Layout storage $ = Storage.layout();

        bytes32 keyHash = EfficientHashLib.hash(recoveryKey.publicSeed, recoveryKey.publicKeyHash);
        if (!$.recoveryKeyHashes.contains(keyHash))
            revert RecoveryKeyNotFound();

        bytes32 digest = Codec.upgradeRecoveryDigest(
            address(this),
            block.chainid,
            newImplementation,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            recoveryKey.publicSeed,
            recoveryKey.publicKeyHash
        );

        if (!WOTSPlus.verify(recoveryKey, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        $.recoveryKeyHashes.remove(keyHash);

        super.upgradeToAndCall(newImplementation, payload[0:0]);

        emit RecoveryUpgrade(newImplementation, recoveryKey);
    }

    /// @inheritdoc IQuipWallet
    function migrate(bytes calldata payload) external {
        if (_upgradeGuard() == 0) revert NotUpgrading();
        (
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        ) = Codec.decodeInit(payload);
        _enforceNonZeroPqOwner(newPqOwner);

        Storage.Layout storage $ = Storage.layout();
        $.pqOwner = newPqOwner;

        uint256 clearLen = $.recoveryKeyHashes.length();
        for (uint256 i = 0; i < clearLen; ++i) {
            $.recoveryKeyHashes.remove($.recoveryKeyHashes.at(0));
        }
        _addRecoveryKeys(recoveryKeys);
        _verifyInitialState();

        emit WalletMigrated(newPqOwner);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         VIEWS                                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipWallet
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) public view {
        bytes32 implCodehash = newImplementation.codehash;
        IQuipFactory factory = IQuipFactory(FACTORY);
        if (factory.getVettedCodeIndex(implCodehash) == type(uint256).max)
            revert ImplementationNotVetted();
        if (factory.deprecatedImpls(implCodehash))
            revert ImplementationDeprecated();

        (
            WOTSPlus.WinternitzAddress calldata verifier,
            WOTSPlus.WinternitzElements calldata verifySig
        ) = Codec.decodeUpgradeVerification(data);

        bytes32 digest = Codec.verificationDigest(
            address(this),
            block.chainid,
            newImplementation,
            verifier.publicSeed,
            verifier.publicKeyHash
        );

        if (!WOTSPlus.verify(verifier, WOTSPlus.WinternitzMessage({ messageHash: digest }), verifySig))
            revert InvalidSignature();
    }

    /// @inheritdoc IQuipWallet
    function verifyRecoveryUpgrade(
        address newImplementation,
        bytes calldata data
    ) public view {
        bytes32 implCodehash = newImplementation.codehash;
        IQuipFactory factory = IQuipFactory(FACTORY);
        if (factory.getVettedCodeIndex(implCodehash) == type(uint256).max)
            revert ImplementationNotVetted();
        if (factory.deprecatedImpls(implCodehash))
            revert ImplementationDeprecated();
    }

    /// @inheritdoc IQuipWallet
    function quipFactory() public view returns (address payable) {
        return Storage.layout().quipFactory;
    }

    /// @inheritdoc IQuipWallet
    function pqOwner()
        public
        view
        returns (bytes32 publicSeed, bytes32 publicKeyHash)
    {
        Storage.Layout storage $ = Storage.layout();
        return ($.pqOwner.publicSeed, $.pqOwner.publicKeyHash);
    }

    /// @inheritdoc IQuipWallet
    function getRecoveryKeyCount() public view returns (uint256) {
        return Storage.layout().recoveryKeyHashes.length();
    }

    /// @inheritdoc IQuipWallet
    function getRecoveryKeyHashAt(uint256 index) public view returns (bytes32) {
        return Storage.layout().recoveryKeyHashes.at(index);
    }

    /// @inheritdoc IQuipWallet
    function isRecoveryKey(bytes32 keyHash) public view returns (bool) {
        return Storage.layout().recoveryKeyHashes.contains(keyHash);
    }

    /// @inheritdoc IQuipWallet
    function version() public view returns (uint256) {
        address impl;
        assembly {
            impl := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
        return IQuipFactory(FACTORY).getVettedCodeIndex(impl.codehash);
    }

    /// @inheritdoc IQuipWallet
    function getExecuteFee() public view returns (uint256) {
        return IQuipFactory(Storage.layout().quipFactory).executeFee();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        INTERNALS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _enforceNonZeroPqOwner(
        WOTSPlus.WinternitzAddress calldata pqOwner
    ) internal pure {
        if (
            pqOwner.publicSeed == bytes32(0) ||
            pqOwner.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqOwner();
    }

    function _enforceDifferentPqOwner(
        WOTSPlus.WinternitzAddress calldata nextPqOwner
    ) internal view {
        Storage.Layout storage $ = Storage.layout();
        if (
            nextPqOwner.publicSeed == $.pqOwner.publicSeed &&
            nextPqOwner.publicKeyHash == $.pqOwner.publicKeyHash
        ) revert PqOwnerReuse();
    }

    /// @dev Validates and adds recovery keys to the set. Reverts if any key has zero fields,
    ///      is a duplicate, or if the set would exceed `MAX_RECOVERY_KEYS`.
    function _addRecoveryKeys(
        WOTSPlus.WinternitzAddress[] calldata keys
    ) internal {
        if (keys.length == 0) revert EmptyRecoveryKeys();
        EnumerableSetLib.Bytes32Set storage hashes = Storage
            .layout()
            .recoveryKeyHashes;
        uint256 len = keys.length;
        for (uint256 i = 0; i < len; ++i) {
            if (
                keys[i].publicSeed == bytes32(0) ||
                keys[i].publicKeyHash == bytes32(0)
            ) {
                revert ZeroValuePqOwner();
            }
            bytes32 keyHash = EfficientHashLib.hash(keys[i].publicSeed, keys[i].publicKeyHash);
            if (!hashes.add(keyHash, MAX_RECOVERY_KEYS)) revert DuplicateRecoveryKey();
        }
    }

    /// @dev Fixed-size overload used by initialize (codec returns WinternitzAddress[10]).
    function _addRecoveryKeys(
        WOTSPlus.WinternitzAddress[10] calldata keys
    ) internal {
        EnumerableSetLib.Bytes32Set storage hashes = Storage
            .layout()
            .recoveryKeyHashes;
        for (uint256 i = 0; i < MAX_RECOVERY_KEYS; ++i) {
            if (
                keys[i].publicSeed == bytes32(0) ||
                keys[i].publicKeyHash == bytes32(0)
            ) {
                revert ZeroValuePqOwner();
            }
            bytes32 keyHash = EfficientHashLib.hash(keys[i].publicSeed, keys[i].publicKeyHash);
            if (!hashes.add(keyHash, MAX_RECOVERY_KEYS)) revert DuplicateRecoveryKey();
        }
    }

    function _verifyInitialState() internal view {
        Storage.Layout storage $ = Storage.layout();
        if ($.quipFactory == address(0)) revert ZeroAddressFactory();
        if (
            $.pqOwner.publicSeed == bytes32(0) ||
            $.pqOwner.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqOwner();
        if ($.recoveryKeyHashes.length() != MAX_RECOVERY_KEYS) revert IncorrectRecoveryKeyAmount();
    }

    /// @dev Snapshots critical storage, executes an isolated delegatecall, then restores
    ///      any slots corrupted by the delegatecall. Recovery keys are verified via
    ///      digest comparison; corruption emits `RecoveryKeysCorrupted`.
    function _guardedDelegateCall(address delegate, bytes calldata data)
        internal
        returns (bool success, bytes memory result)
    {
        Storage.Layout storage $ = Storage.layout();

        // Snapshot critical slots (after rotation — $.pqOwner is already the new key)
        bytes32 ownerSlotValue;
        bytes32 implSlotValue;
        assembly {
            ownerSlotValue := sload(_OWNER_SLOT)
            implSlotValue := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
        address payable savedFactory = $.quipFactory;
        bytes32 savedPqSeed = $.pqOwner.publicSeed;
        bytes32 savedPqHash = $.pqOwner.publicKeyHash;
        bytes32 savedRecoveryDigest = _recoveryKeysDigest();

        // Isolated delegatecall
        (success, result) = _tryDelegateCallContract(delegate, data);

        // Restore critical slots if corrupted
        assembly {
            if iszero(eq(sload(_OWNER_SLOT), ownerSlotValue)) {
                sstore(_OWNER_SLOT, ownerSlotValue)
            }
            if iszero(eq(sload(_ERC1967_IMPLEMENTATION_SLOT), implSlotValue)) {
                sstore(_ERC1967_IMPLEMENTATION_SLOT, implSlotValue)
            }
        }
        if ($.quipFactory != savedFactory) $.quipFactory = savedFactory;
        if ($.pqOwner.publicSeed != savedPqSeed) $.pqOwner.publicSeed = savedPqSeed;
        if ($.pqOwner.publicKeyHash != savedPqHash) $.pqOwner.publicKeyHash = savedPqHash;

        // Verify recovery keys (cannot reliably restore EnumerableSetLib internals)
        if (_recoveryKeysDigest() != savedRecoveryDigest) {
            emit RecoveryKeysCorrupted();
        }
    }

    /// @dev Computes a digest over the recovery key set (length + all element hashes).
    function _recoveryKeysDigest() internal view returns (bytes32) {
        EnumerableSetLib.Bytes32Set storage hashes = Storage.layout().recoveryKeyHashes;
        uint256 len = hashes.length();
        bytes32[] memory elements = new bytes32[](len);
        for (uint256 i; i < len; ++i) {
            elements[i] = hashes.at(i);
        }
        return EfficientHashLib.hash(abi.encodePacked(len, elements));
    }

    /// @dev Reads nextPqOwner from transient storage (set by _validateSignature),
    ///      clears transient storage, validates the key, and rotates $.pqOwner.
    /// @return nextPqOwner The new PQ owner after rotation.
    function _consumePqKeyRotation()
        internal
        returns (WOTSPlus.WinternitzAddress memory nextPqOwner)
    {
        uint256 seedSlot = _NEXT_PQ_SEED_TSLOT;
        uint256 hashSlot = _NEXT_PQ_HASH_TSLOT;
        bytes32 seed;
        bytes32 hash_;
        assembly {
            seed := tload(seedSlot)
            hash_ := tload(hashSlot)
            tstore(seedSlot, 0)
            tstore(hashSlot, 0)
        }
        if (seed == bytes32(0) || hash_ == bytes32(0)) revert TransientStorageEmpty();

        nextPqOwner = WOTSPlus.WinternitzAddress({
            publicSeed: seed,
            publicKeyHash: hash_
        });

        Storage.Layout storage $ = Storage.layout();
        if (
            nextPqOwner.publicSeed == $.pqOwner.publicSeed &&
            nextPqOwner.publicKeyHash == $.pqOwner.publicKeyHash
        ) revert PqOwnerReuse();

        $.pqOwner = nextPqOwner;
    }

    /// @dev Non-reverting variant of Solady's callContract pattern.
    /// Same assembly as ERC4337.execute — calldatacopy + call — but returns
    /// (bool, bytes) instead of reverting on failure.
    function _tryCallContract(address target, uint256 value, bytes calldata data)
        internal
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            let m := result
            calldatacopy(m, data.offset, data.length)
            success := call(gas(), target, value, m, data.length, codesize(), 0x00)
            mstore(result, returndatasize())
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize())
            mstore(0x40, add(o, returndatasize()))
        }
    }

    /// @dev Non-reverting variant of Solady's delegateCallContract pattern.
    /// Same assembly as ERC4337.delegateExecute — calldatacopy + delegatecall — but returns
    /// (bool, bytes) instead of reverting on failure.
    function _tryDelegateCallContract(address target, bytes calldata data)
        internal
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            let m := result
            calldatacopy(m, data.offset, data.length)
            success := delegatecall(gas(), target, m, data.length, codesize(), 0x00)
            mstore(result, returndatasize())
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize())
            mstore(0x40, add(o, returndatasize()))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        PRIVATES                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _upgradeGuard() internal view returns (uint256 v) {
        uint256 slot = _UPGRADE_GUARD_SLOT;
        assembly { v := tload(slot) }
    }
}
