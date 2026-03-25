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

import "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";
import {LibCall} from "solady-0.1.26/src/utils/LibCall.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";
import "./interfaces/IQuipWallet.sol";
import "./interfaces/IQuipFactory.sol";
import {WOTSPlusCodec as Codec} from "./WOTSPlusCodec.sol";

contract QuipWallet is IQuipWallet, Ownable, UUPSUpgradeable, Initializable {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /// @inheritdoc IQuipWallet
    address payable public quipFactory;
    /// @inheritdoc IQuipWallet
    WOTSPlus.WinternitzAddress public pqOwner;

    uint256 public constant MAX_RECOVERY_KEYS = 10;
    EnumerableSetLib.Bytes32Set internal _recoveryKeyHashes;

    receive() external payable {}

    fallback() external payable {}

    constructor() {
        // When the factory switches to proxy deployment, uncomment:
        // _disableInitializers();
    }

    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }

    function renounceOwnership() public payable override onlyOwner {
        revert RenounceDisabled();
    }

    /// @inheritdoc IQuipWallet
    function initialize(
        address payable factory_,
        address payable newOwner,
        bytes calldata payload
    ) public initializer {
        WOTSPlus.WinternitzAddress calldata newPqOwner = Codec.extractPqOwner(payload);
        if (newPqOwner.publicSeed == bytes32(0) || newPqOwner.publicKeyHash == bytes32(0)) revert InvalidPqOwner();

        quipFactory = factory_;
        _initializeOwner(newOwner);
        pqOwner = newPqOwner;

        WOTSPlus.WinternitzAddress[10] calldata recoveryKeys = Codec.extractInitRecoveryKeys(payload);
        _addRecoveryKeys(recoveryKeys);

        emit WalletInitialized(factory_, newOwner, newPqOwner, recoveryKeys);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      UUPS UPGRADE                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function upgradeToAndCall(address newImplementation, bytes calldata data)
        public
        payable
        override
    {
        _verifyUpgradeTx(newImplementation, data);
        super.upgradeToAndCall(newImplementation, data);
    }

    function _verifyUpgradeTx(address newImplementation, bytes calldata data) internal view {
        (
            WOTSPlus.WinternitzElements memory pqSig,
            WOTSPlus.WinternitzAddress memory pqSigner,
        ) = _extractVerifiers(data);

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                newImplementation,
                pqOwner.publicSeed,
                pqOwner.publicKeyHash,
                pqSigner.publicSeed,
                pqSigner.publicKeyHash
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify(pqOwner, message, pqSig)) revert InvalidSignature();
    }

    function _extractVerifiers(bytes calldata data)
        internal
        pure
        returns (
            WOTSPlus.WinternitzElements memory pqSig,
            WOTSPlus.WinternitzAddress memory pqSigner,
            bool isRequired
        )
    {
        (WOTSPlus.WinternitzAddress memory nextPqOwner, WOTSPlus.WinternitzElements memory sig) =
            abi.decode(data, (WOTSPlus.WinternitzAddress, WOTSPlus.WinternitzElements));
        return (sig, nextPqOwner, true);
    }

    /// @inheritdoc IQuipWallet
    function changePqOwner(
        WOTSPlus.WinternitzAddress calldata newPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig
    ) public onlyOwner {
        // Include chain ID and wallet address to prevent cross-chain and cross-wallet replay attacks.
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                pqOwner.publicSeed,
                pqOwner.publicKeyHash,
                newPqOwner.publicSeed,
                newPqOwner.publicKeyHash
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify(pqOwner, message, pqSig)) revert InvalidSignature();
        pqOwner = newPqOwner;
    }

    /// @inheritdoc IQuipWallet
    function transferWithWinternitz(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable to,
        uint256 value
    ) public payable onlyOwner {
        WOTSPlus.WinternitzAddress memory curPqOwner = pqOwner;

        uint256 fee = getTransferFee();

        if (address(this).balance < value + fee) revert InsufficientBalance(value + fee, address(this).balance);

        // Include chain ID and wallet address to prevent cross-chain and cross-wallet replay attacks.
        bytes memory msgData = abi.encodePacked(
            block.chainid,
            address(this),
            pqOwner.publicSeed,
            pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            to,
            value
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: keccak256(msgData)
        });

        if (!WOTSPlus.verify(pqOwner, message, pqSig)) revert InvalidSignature();
        pqOwner = nextPqOwner;

        SafeTransferLib.safeTransferETH(to, value);
        SafeTransferLib.safeTransferETH(quipFactory, fee);

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
        if (address(this).balance < fee) revert InsufficientBalance(fee, address(this).balance);

        uint256 forwardValue = msg.value > fee ? msg.value - fee : 0;

        // Include chain ID and wallet address to prevent cross-chain and cross-wallet replay attacks.
        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: keccak256(
                abi.encodePacked(
                    block.chainid,
                    address(this),
                    pqOwner.publicSeed,
                    pqOwner.publicKeyHash,
                    nextPqOwner.publicSeed,
                    nextPqOwner.publicKeyHash,
                    target,
                    opdata
                )
            )
        });

        if (!WOTSPlus.verify(pqOwner, message, pqSig)) revert InvalidSignature();
        pqOwner = nextPqOwner;
        SafeTransferLib.safeTransferETH(quipFactory, fee);

        // Reverts from `target` are bubbled up directly.
        return LibCall.callContract(target, forwardValue, opdata);
    }

    /// @inheritdoc IQuipWallet
    function recoverWallet(
        WOTSPlus.WinternitzAddress calldata recoveryKey,
        WOTSPlus.WinternitzAddress calldata newPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig
    ) public onlyOwner {
        bytes32 keyHash = keccak256(abi.encode(recoveryKey.publicSeed, recoveryKey.publicKeyHash));
        if (!_recoveryKeyHashes.contains(keyHash)) revert RecoveryKeyNotFound();

        if (newPqOwner.publicSeed == bytes32(0) || newPqOwner.publicKeyHash == bytes32(0)) revert InvalidPqOwner();

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

        if (!WOTSPlus.verify(recoveryKey, message, pqSig)) revert InvalidSignature();

        _recoveryKeyHashes.remove(keyHash);
        pqOwner = newPqOwner;

        emit pqRecovery(recoveryKey, newPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function addRecoveryKeys(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
    ) public onlyOwner {
        if (nextPqOwner.publicSeed == bytes32(0) || nextPqOwner.publicKeyHash == bytes32(0)) revert InvalidPqOwner();

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                pqOwner.publicSeed,
                pqOwner.publicKeyHash,
                nextPqOwner.publicSeed,
                nextPqOwner.publicKeyHash,
                keccak256(abi.encode(newRecoveryKeys))
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify(pqOwner, message, pqSig)) revert InvalidSignature();

        _addRecoveryKeys(newRecoveryKeys);

        pqOwner = nextPqOwner;

        emit RecoveryKeysAdded(nextPqOwner, newRecoveryKeys.length);
    }

    /// @inheritdoc IQuipWallet
    function replenishRecoveryKeys(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
    ) public onlyOwner {
        if (nextPqOwner.publicSeed == bytes32(0) || nextPqOwner.publicKeyHash == bytes32(0)) revert InvalidPqOwner();
        if (newRecoveryKeys.length > MAX_RECOVERY_KEYS) revert RecoveryKeyLimitExceeded();

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                pqOwner.publicSeed,
                pqOwner.publicKeyHash,
                nextPqOwner.publicSeed,
                nextPqOwner.publicKeyHash,
                keccak256(abi.encode(newRecoveryKeys))
            )
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify(pqOwner, message, pqSig)) revert InvalidSignature();

        uint256 clearLen = _recoveryKeyHashes.length();
        for (uint256 i = 0; i < clearLen; ++i) {
            _recoveryKeyHashes.remove(_recoveryKeyHashes.at(0));
        }

        _addRecoveryKeys(newRecoveryKeys);

        pqOwner = nextPqOwner;

        emit RecoveryKeysReplenished(nextPqOwner);
    }

    /// @dev Validates and adds recovery keys to the set. Reverts if any key has zero fields
    ///      or if the set would exceed `MAX_RECOVERY_KEYS`.
    function _addRecoveryKeys(WOTSPlus.WinternitzAddress[] calldata keys) internal {
        uint256 len = keys.length;
        for (uint256 i = 0; i < len; ++i) {
            if (keys[i].publicSeed == bytes32(0) || keys[i].publicKeyHash == bytes32(0)) {
                revert InvalidPqOwner();
            }
            bytes32 keyHash = keccak256(abi.encode(keys[i].publicSeed, keys[i].publicKeyHash));
            _recoveryKeyHashes.add(keyHash, MAX_RECOVERY_KEYS);
        }
    }

    /// @dev Fixed-size overload used by initialize (codec returns WinternitzAddress[10]).
    function _addRecoveryKeys(WOTSPlus.WinternitzAddress[10] calldata keys) internal {
        for (uint256 i = 0; i < MAX_RECOVERY_KEYS; ++i) {
            if (keys[i].publicSeed == bytes32(0) || keys[i].publicKeyHash == bytes32(0)) {
                revert InvalidPqOwner();
            }
            bytes32 keyHash = keccak256(abi.encode(keys[i].publicSeed, keys[i].publicKeyHash));
            _recoveryKeyHashes.add(keyHash, MAX_RECOVERY_KEYS);
        }
    }

    /// @inheritdoc IQuipWallet
    function getRecoveryKeyCount() public view returns (uint256) {
        return _recoveryKeyHashes.length();
    }

    /// @inheritdoc IQuipWallet
    function getRecoveryKeyHashAt(uint256 index) public view returns (bytes32) {
        return _recoveryKeyHashes.at(index);
    }

    /// @inheritdoc IQuipWallet
    function isRecoveryKey(bytes32 keyHash) public view returns (bool) {
        return _recoveryKeyHashes.contains(keyHash);
    }

    /// @inheritdoc IQuipWallet
    function getTransferFee() public view returns (uint256) {
        return IQuipFactory(quipFactory).transferFee();
    }

    /// @inheritdoc IQuipWallet
    function getExecuteFee() public view returns (uint256) {
        return IQuipFactory(quipFactory).executeFee();
    }
}
