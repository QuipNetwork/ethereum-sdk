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

import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";
// NOTE: OpenZeppelin 5.6.0-rc.1 is a pre-release version. Pin to a stable release before mainnet.
import {Ownable as OZOwnable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable2Step.sol";
import {IQuipFactory} from "./interfaces/IQuipFactory.sol";
import {IQuipWallet} from "./interfaces/IQuipWallet.sol";

/// @title QuipFactory
contract QuipFactory is IQuipFactory, Ownable2Step {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /// @inheritdoc IQuipFactory
    uint256 public immutable MAX_FEE;

    /// @inheritdoc IQuipFactory
    uint256 public creationFee = 0;
    /// @inheritdoc IQuipFactory
    uint256 public executeFee = 0;

    /// @inheritdoc IQuipFactory
    mapping(bytes32 vaultId => address wallet) public wallets;

    /// @inheritdoc IQuipFactory
    mapping(address wallet => bytes32 vaultId) public vaultIdOf;

    /// @inheritdoc IQuipFactory
    mapping(address wallet => address owner) public walletOwner;

    /// @dev Per-owner set of vaultIds. Tracks CURRENT classical owner — the
    ///      `transferOwnership(bytes)` flow on a wallet calls back into
    ///      `updateWalletOwner` to move the entry between owners. Exposed
    ///      via `getVaultIdCount` / `getVaultIdAt` / `getVaultIdIndex` /
    ///      `getVaultIds` / `getWallets`.
    mapping(address owner => EnumerableSetLib.Bytes32Set) internal _vaultIds;

    /// @dev Insertion-ordered set of vetted implementation codehashes.
    ///      Deprecated entries remain in the set to preserve index stability.
    EnumerableSetLib.Bytes32Set private _vettedCode;

    /// @inheritdoc IQuipFactory
    mapping(bytes32 codehash => address walletImplementation)
        public vettedWalletImpls;

    /// @inheritdoc IQuipFactory
    mapping(bytes32 codehash => bool isDeprecated) public deprecatedImpls;

    /// @inheritdoc IQuipFactory
    address public latestWalletImpl;

    constructor(
        address payable initialOwner,
        uint256 maxFee_
    ) payable OZOwnable(initialOwner) {
        if (maxFee_ == 0) revert ZeroMaxFee();
        MAX_FEE = maxFee_;
    }

    receive() external payable {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                EXTERNAL STATE-CHANGING                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipFactory
    function vetImplementation(address impl) external onlyOwner {
        bytes32 codehash = impl.codehash;
        if (codehash == 0) revert EmptyCode();
        if (!_vettedCode.add(codehash)) revert AlreadyVetted();
        vettedWalletImpls[codehash] = impl;
        // A freshly-added entry is, by construction, at `length() - 1` — the
        // most recently inserted slot that `_findLatestActive` would return —
        // so it is unconditionally the new latest active implementation.
        latestWalletImpl = impl;
        emit ImplementationVetted(impl, codehash);
    }

    /// @inheritdoc IQuipFactory
    function undeprecateImplementation(address impl) external onlyOwner {
        bytes32 codehash = impl.codehash;
        if (!_vettedCode.contains(codehash)) revert ImplementationNotVetted();
        if (!deprecatedImpls[codehash]) revert NotDeprecated();
        deprecatedImpls[codehash] = false;
        // Re-bind the address pointer so a redeploy of the same bytecode at a
        // different address can replace the original. Same-codehash means same
        // behavior, so this is a benign address swap, not a security boundary.
        vettedWalletImpls[codehash] = impl;
        // Recompute via the insertion-order backward scan: if the reactivated
        // entry is at the highest index among non-deprecated entries it becomes
        // the latest, otherwise the previously latest entry is preserved.
        latestWalletImpl = _findLatestActive();
        emit ImplementationUndeprecated(impl, codehash);
    }

    /// @inheritdoc IQuipFactory
    function deprecateImplementation(address impl) external onlyOwner {
        bytes32 codehash = impl.codehash;
        if (!_vettedCode.contains(codehash)) revert ImplementationNotVetted();
        deprecatedImpls[codehash] = true;
        emit ImplementationSunset(impl, codehash);
        if (latestWalletImpl == impl) {
            latestWalletImpl = _findLatestActive();
        }
    }

    /// @inheritdoc IQuipFactory
    function deployLatestWalletProxy(
        bytes32 vaultId,
        address payable to,
        bytes calldata payload
    ) external payable returns (address) {
        if (latestWalletImpl == address(0)) revert NoActiveImplementation();
        return _deployProxy(latestWalletImpl, vaultId, to, payload);
    }

    /// @inheritdoc IQuipFactory
    function deploySpecificWalletProxy(
        bytes32 vaultId,
        uint256 index,
        address payable to,
        bytes calldata payload
    ) external payable returns (address) {
        bytes32 codehash = _vettedCode.at(index);
        if (deprecatedImpls[codehash]) revert ImplementationDeprecated();
        return _deployProxy(vettedWalletImpls[codehash], vaultId, to, payload);
    }

    /// @inheritdoc IQuipFactory
    function setCreationFee(uint256 newFee) external onlyOwner {
        if (newFee > MAX_FEE) revert FeeExceedsMax(newFee, MAX_FEE);
        uint256 oldFee = creationFee;
        creationFee = newFee;
        emit CreationFeeUpdated(oldFee, newFee);
    }

    /// @inheritdoc IQuipFactory
    function setExecuteFee(uint256 newFee) external onlyOwner {
        if (newFee > MAX_FEE) revert FeeExceedsMax(newFee, MAX_FEE);
        uint256 oldFee = executeFee;
        executeFee = newFee;
        emit ExecuteFeeUpdated(oldFee, newFee);
    }

    /// @inheritdoc IQuipFactory
    function withdraw(uint256 amount) external onlyOwner {
        if (address(this).balance < amount) {
            revert InsufficientBalance(amount, address(this).balance);
        }
        SafeTransferLib.forceSafeTransferETH(owner(), amount);
        emit Withdrawn(owner(), amount);
    }

    /// @inheritdoc IQuipFactory
    function updateWalletOwner(address newOwner) external {
        bytes32 vaultId = vaultIdOf[msg.sender];
        if (vaultId == bytes32(0)) revert OnlyWallet();
        if (newOwner == address(0)) revert ZeroAddressOwner();
        // Authoritative read — the factory's own source of truth for
        // who currently owns this wallet. The wallet does not get to pass
        // a (potentially wrong) `oldOwner`.
        address oldOwner = walletOwner[msg.sender];
        if (oldOwner == newOwner) revert SameOwner();
        // NB:
        // Pins the callback to the tail of the wallet's PQ-authenticated
        // ownership-transfer flow — per the vetting contract (`IQuipWallet`
        // natspec, rule 2), the only path a vetted implementation may have
        // that produces `wallet.owner() == newOwner` in the same transaction.
        if (IQuipWallet(msg.sender).owner() != newOwner) {
            revert OwnerStateMismatch();
        }

        walletOwner[msg.sender] = newOwner;
        // Both mutations MUST succeed: `oldOwner` came from the factory's
        // authoritative `walletOwner` mapping so its set must contain
        // `vaultId`; `newOwner` cannot already hold it because vaultIds are
        // globally unique (CREATE3) and each lives in at most one owner's
        // set at a time. A `false` return here means the registry diverged
        // from `walletOwner` somehow — revert loudly.
        if (!_vaultIds[oldOwner].remove(vaultId)) revert RegistryDesync();
        if (!_vaultIds[newOwner].add(vaultId)) revert RegistryDesync();
        emit WalletOwnerChanged(vaultId, oldOwner, newOwner);
    }

    /// @inheritdoc IQuipFactory
    function renounceOwnership()
        public
        override(IQuipFactory, OZOwnable)
        onlyOwner
    {
        revert RenounceDisabled();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   EXTERNAL VIEWS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipFactory
    function getVettedCodeCount() external view returns (uint256) {
        return _vettedCode.length();
    }

    /// @inheritdoc IQuipFactory
    function getVettedCodeAt(uint256 index) external view returns (bytes32) {
        return _vettedCode.at(index);
    }

    /// @inheritdoc IQuipFactory
    function getVettedCodeIndex(
        bytes32 codehash
    ) external view returns (uint256) {
        return _vettedCode.indexOf(codehash);
    }

    /// @inheritdoc IQuipFactory
    function getVaultIdCount(address owner_) external view returns (uint256) {
        return _vaultIds[owner_].length();
    }

    /// @inheritdoc IQuipFactory
    function getVaultIdAt(
        address owner_,
        uint256 index
    ) external view returns (bytes32) {
        return _vaultIds[owner_].at(index);
    }

    /// @inheritdoc IQuipFactory
    function getVaultIdIndex(
        address owner_,
        bytes32 vaultId
    ) external view returns (uint256) {
        return _vaultIds[owner_].indexOf(vaultId);
    }

    /// @inheritdoc IQuipFactory
    function getVaultIds(
        address owner_
    ) external view returns (bytes32[] memory) {
        return _vaultIds[owner_].values();
    }

    /// @inheritdoc IQuipFactory
    function getWallets(
        address owner_
    ) external view returns (address[] memory walletAddrs) {
        bytes32[] memory ids = _vaultIds[owner_].values();
        walletAddrs = new address[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            walletAddrs[i] = wallets[ids[i]];
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Iterates backwards through the vetted set to find the latest
    ///      non-deprecated implementation. Returns `address(0)` if none found.
    ///      Solady's EnumerableSetLib stores entries in contiguous slots in
    ///      insertion order, so `at(length() - 1)` is the most recently added.
    function _findLatestActive() internal view returns (address) {
        uint256 len = _vettedCode.length();
        for (uint256 i = len; i > 0; ) {
            unchecked {
                --i;
            }
            bytes32 codehash = _vettedCode.at(i);
            if (!deprecatedImpls[codehash]) {
                return vettedWalletImpls[codehash];
            }
        }
        return address(0);
    }

    /// @dev Deploys a Solady minimal ERC-1967 proxy via CREATE3, initializes it,
    ///      and forwards deposited ETH (minus creation fee) to the wallet.
    function _deployProxy(
        address impl,
        bytes32 vaultId,
        address payable to,
        bytes calldata payload
    ) internal returns (address) {
        // Solady minimal ERC-1967 proxy initcode (95 bytes).
        // See: LibClone.deployDeterministicERC1967
        bytes memory proxyInitcode = abi.encodePacked(
            hex"603d3d8160223d3973",
            impl,
            hex"6009",
            hex"5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076",
            hex"cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3"
        );

        if (to == address(0)) revert ZeroAddressOwner();
        if (vaultId == bytes32(0)) revert ZeroVaultId();
        if (msg.value < creationFee) {
            revert InsufficientCreationFee(msg.value, creationFee);
        }
        uint256 contractValue = msg.value - creationFee;
        address contractAddr = CREATE3.deployDeterministic(
            proxyInitcode,
            vaultId
        );

        IQuipWallet(contractAddr).initialize(to, payload);
        SafeTransferLib.safeTransferETH(contractAddr, contractValue);
        wallets[vaultId] = contractAddr;
        vaultIdOf[contractAddr] = vaultId;
        walletOwner[contractAddr] = to;
        // `.add` cannot return false here: vaultId is unique per CREATE3,
        // and a fresh contract address never appeared in any set before.
        // Guard anyway against future Solady changes.
        if (!_vaultIds[to].add(vaultId)) revert RegistryDesync();

        emit QuipCreated(
            msg.value,
            block.timestamp,
            vaultId,
            to,
            impl,
            contractAddr
        );

        return contractAddr;
    }
}
