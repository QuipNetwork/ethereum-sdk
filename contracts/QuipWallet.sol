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

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";
import {LibCall} from "solady-0.1.26/src/utils/LibCall.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {IQuipWallet} from "./interfaces/IQuipWallet.sol";
import {IQuipFactory} from "./interfaces/IQuipFactory.sol";
import {WOTSPlusCodec as Codec} from "./WOTSPlusCodec.sol";
import {WOTSPlusStorage as Storage} from "./storage/WOTSPlusStorage.sol";

contract QuipWallet is IQuipWallet, Ownable, UUPSUpgradeable, Initializable {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    uint256 public constant MAX_RECOVERY_KEYS = 10;
    address payable public immutable FACTORY;

    /// @dev uint256(keccak256("quip.wallet.upgrade.guard")) - 1
    /// Transient storage slot used to gate `migrate` to the `upgradeToAndCall` context.
    uint256 private constant _UPGRADE_GUARD_SLOT =
        0x490d87f9a8524f6238d75626265800824e3fa88e60bc82c13f11bbd9042ed677;

    constructor(address payable factory_) {
        if (factory_ == address(0)) revert ZeroAddressFactory();
        FACTORY = factory_;
        // When the factory switches to proxy deployment, uncomment:
        // _disableInitializers();
    }

    receive() external payable {}

    fallback() external payable {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    INTERNAL OVERRIDES                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          PUBLIC                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Disabled; always reverts.
    function renounceOwnership() public payable override onlyOwner {
        revert RenounceDisabled();
    }

    /// @inheritdoc IQuipWallet
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) public initializer {
        if (msg.sender != FACTORY) revert InvalidFactory();
        if (newOwner == address(0)) revert ZeroAddressOwner();

        WOTSPlus.WinternitzAddress calldata newPqOwner = Codec.extractPqOwner(
            payload
        );
        if (
            newPqOwner.publicSeed == bytes32(0) ||
            newPqOwner.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqOwner();

        _initializeOwner(newOwner);
        Storage.Layout storage $ = Storage.layout();
        $.quipFactory = FACTORY;
        $.pqOwner = newPqOwner;

        WOTSPlus.WinternitzAddress[10] calldata recoveryKeys = Codec
            .extractInitRecoveryKeys(payload);
        _addRecoveryKeys(recoveryKeys);

        emit WalletInitialized(FACTORY, newOwner, newPqOwner, recoveryKeys);
    }

    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) public payable override {
        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(this.verifyUpgrade, (newImplementation, data))
        );

        (bool shouldMigrate, bytes calldata migratorPayload) = Codec.extractMigrators(data);
        if (shouldMigrate) {
            uint256 slot = _UPGRADE_GUARD_SLOT;
            assembly { tstore(slot, 1) }
            LibCall.delegateCallContract(
                newImplementation,
                abi.encodeCall(this.migrate, (migratorPayload))
            );
            assembly { tstore(slot, 0) }
        }

        super.upgradeToAndCall(newImplementation, data[0:0]);
    }

    /// @inheritdoc IQuipWallet
    function changePqOwner(
        WOTSPlus.WinternitzAddress calldata newPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig
    ) public onlyOwner {
        Storage.Layout storage $ = Storage.layout();
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                $.pqOwner.publicSeed,
                $.pqOwner.publicKeyHash,
                newPqOwner.publicSeed,
                newPqOwner.publicKeyHash
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify($.pqOwner, message, pqSig))
            revert InvalidSignature();
        $.pqOwner = newPqOwner;
    }

    /// @inheritdoc IQuipWallet
    function transferWithWinternitz(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable to,
        uint256 value
    ) public payable onlyOwner {
        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress memory curPqOwner = $.pqOwner;

        uint256 fee = getTransferFee();

        if (address(this).balance < value + fee)
            revert InsufficientBalance(value + fee, address(this).balance);

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                curPqOwner.publicSeed,
                curPqOwner.publicKeyHash,
                nextPqOwner.publicSeed,
                nextPqOwner.publicKeyHash,
                to,
                value
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify($.pqOwner, message, pqSig))
            revert InvalidSignature();
        $.pqOwner = nextPqOwner;

        SafeTransferLib.safeTransferETH(to, value);
        SafeTransferLib.safeTransferETH($.quipFactory, fee);

        emit pqTransfer(value, block.timestamp, curPqOwner, nextPqOwner, to);
    }

    /// @inheritdoc IQuipWallet
    function executeWithWinternitz(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable target,
        bytes calldata opdata
    ) public payable onlyOwner returns (bytes memory) {
        uint256 fee = getExecuteFee();
        if (address(this).balance < fee)
            revert InsufficientBalance(fee, address(this).balance);

        uint256 forwardValue = msg.value > fee ? msg.value - fee : 0;

        Storage.Layout storage $ = Storage.layout();
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                $.pqOwner.publicSeed,
                $.pqOwner.publicKeyHash,
                nextPqOwner.publicSeed,
                nextPqOwner.publicKeyHash,
                target,
                opdata
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify($.pqOwner, message, pqSig))
            revert InvalidSignature();
        $.pqOwner = nextPqOwner;
        SafeTransferLib.safeTransferETH($.quipFactory, fee);

        return LibCall.callContract(target, forwardValue, opdata);
    }

    /// @inheritdoc IQuipWallet
    function recoverWallet(
        WOTSPlus.WinternitzAddress calldata recoveryKey,
        WOTSPlus.WinternitzAddress calldata newPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig
    ) public onlyOwner {
        Storage.Layout storage $ = Storage.layout();
        bytes32 keyHash = EfficientHashLib.hash(recoveryKey.publicSeed, recoveryKey.publicKeyHash);
        if (!$.recoveryKeyHashes.contains(keyHash))
            revert RecoveryKeyNotFound();

        if (
            newPqOwner.publicSeed == bytes32(0) ||
            newPqOwner.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqOwner();

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                recoveryKey.publicSeed,
                recoveryKey.publicKeyHash,
                newPqOwner.publicSeed,
                newPqOwner.publicKeyHash
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify(recoveryKey, message, pqSig))
            revert InvalidSignature();

        $.recoveryKeyHashes.remove(keyHash);
        $.pqOwner = newPqOwner;

        emit pqRecovery(recoveryKey, newPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function addRecoveryKeys(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
    ) public onlyOwner {
        if (
            nextPqOwner.publicSeed == bytes32(0) ||
            nextPqOwner.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqOwner();

        Storage.Layout storage $ = Storage.layout();
        bytes32 keysHash = keccak256(abi.encode(newRecoveryKeys));
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                $.pqOwner.publicSeed,
                $.pqOwner.publicKeyHash,
                nextPqOwner.publicSeed,
                nextPqOwner.publicKeyHash,
                keysHash
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify($.pqOwner, message, pqSig))
            revert InvalidSignature();

        _addRecoveryKeys(newRecoveryKeys);

        $.pqOwner = nextPqOwner;

        emit RecoveryKeysAdded(nextPqOwner, newRecoveryKeys.length);
    }

    /// @inheritdoc IQuipWallet
    function replenishRecoveryKeys(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
    ) public onlyOwner {
        if (
            nextPqOwner.publicSeed == bytes32(0) ||
            nextPqOwner.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqOwner();
        if (newRecoveryKeys.length > MAX_RECOVERY_KEYS)
            revert RecoveryKeyLimitExceeded();

        Storage.Layout storage $ = Storage.layout();
        bytes32 keysHash = keccak256(abi.encode(newRecoveryKeys));
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                $.pqOwner.publicSeed,
                $.pqOwner.publicKeyHash,
                nextPqOwner.publicSeed,
                nextPqOwner.publicKeyHash,
                keysHash
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify($.pqOwner, message, pqSig))
            revert InvalidSignature();

        uint256 clearLen = $.recoveryKeyHashes.length();
        for (uint256 i = 0; i < clearLen; ++i) {
            $.recoveryKeyHashes.remove($.recoveryKeyHashes.at(0));
        }

        _addRecoveryKeys(newRecoveryKeys);

        $.pqOwner = nextPqOwner;

        emit RecoveryKeysReplenished(nextPqOwner);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         VIEWS                                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Verifies a PQ signature authorizing an upgrade.
    /// @dev Data layout: [0:64) pqSigner (WinternitzAddress), [64:2208) pqSig (WinternitzElements).
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) public view {
        WOTSPlus.WinternitzAddress calldata pqSigner = Codec.extractPqOwner(
            data
        );
        WOTSPlus.WinternitzElements calldata pqSig = Codec.extractPqSig(data);

        Storage.Layout storage $ = Storage.layout();
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                newImplementation,
                $.pqOwner.publicSeed,
                $.pqOwner.publicKeyHash,
                pqSigner.publicSeed,
                pqSigner.publicKeyHash
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify($.pqOwner, message, pqSig))
            revert InvalidSignature();
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
    function getTransferFee() public view returns (uint256) {
        return IQuipFactory(Storage.layout().quipFactory).transferFee();
    }

    /// @inheritdoc IQuipWallet
    function getExecuteFee() public view returns (uint256) {
        return IQuipFactory(Storage.layout().quipFactory).executeFee();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        INTERNALS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Validates and adds recovery keys to the set. Reverts if any key has zero fields
    ///      or if the set would exceed `MAX_RECOVERY_KEYS`.
    function _addRecoveryKeys(
        WOTSPlus.WinternitzAddress[] calldata keys
    ) internal {
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
            hashes.add(keyHash, MAX_RECOVERY_KEYS);
        }
    }

    /// @inheritdoc IQuipWallet
    function migrate(bytes calldata payload) external {
        if (_upgradeGuard() == 0) revert NotUpgrading();
        WOTSPlus.WinternitzAddress calldata newPqOwner = Codec.extractPqOwner(payload);
        if (
            newPqOwner.publicSeed == bytes32(0) ||
            newPqOwner.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqOwner();

        Storage.Layout storage $ = Storage.layout();
        $.pqOwner = newPqOwner;

        uint256 clearLen = $.recoveryKeyHashes.length();
        for (uint256 i = 0; i < clearLen; ++i) {
            $.recoveryKeyHashes.remove($.recoveryKeyHashes.at(0));
        }

        WOTSPlus.WinternitzAddress[10] calldata recoveryKeys = Codec.extractInitRecoveryKeys(payload);
        _addRecoveryKeys(recoveryKeys);
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
            hashes.add(keyHash, MAX_RECOVERY_KEYS);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        PRIVATES                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _upgradeGuard() private view returns (uint256 v) {
        uint256 slot = _UPGRADE_GUARD_SLOT;
        assembly { v := tload(slot) }
    }
}
