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
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {IWalletFactory} from "./interfaces/IWalletFactory.sol";
import {IWallet} from "./interfaces/IWallet.sol";
import {WalletFactoryStorage as Storage} from "./storage/WalletFactoryStorage.sol";

/// @title WalletFactory
/// @notice UUPS-upgradeable behind an ERC-1967 proxy. The PROXY address is the
///         permanent factory identity: every wallet bakes it in as an immutable
///         (callback, upgrade-gating, and fee reads all target it), and CREATE3
///         wallet addressing derives from it — so wallet addresses are stable
///         across factory upgrades (CREATE3 ignores initcode and `address(this)`
///         is the proxy). The registry lives in ERC-7201 namespaced storage
///         (`WalletFactoryStorage`) whose layout is append-only across upgrades.
///         The owner is expected to be a post-quantum wallet; upgrades are
///         authorized by `onlyOwner` and thus PQ-secured upstream.
contract WalletFactory is IWalletFactory, Ownable, UUPSUpgradeable, Initializable {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /// @inheritdoc IWalletFactory
    /// @dev Per-IMPLEMENTATION immutable: it lives in implementation code, not
    ///      proxy storage, so an upgrade can change the cap. The wallet-side
    ///      floor of protection is the signed `maxFee` committed in every
    ///      execute digest — no factory state can raise what a wallet pays.
    uint256 public immutable MAX_FEE;

    constructor(uint256 maxFee_) payable {
        if (maxFee_ == 0) revert ZeroMaxFee();
        MAX_FEE = maxFee_;
        _disableInitializers();
    }

    receive() external payable {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   INTERNAL OVERRIDES                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Guard owner initialization to prevent re-initialization. The factory inherits Solady
    ///      `Ownable` directly (not the `ERC4337` base that supplies this override), so it MUST
    ///      override `_guardInitializeOwner => true` itself: `_initializeOwner` then reverts
    ///      `AlreadyInitialized` on a second call (defence in depth alongside the `initializer`
    ///      modifier).
    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }

    /// @inheritdoc IWalletFactory
    function initialize(address payable initialOwner) external initializer {
        if (initialOwner == address(0)) revert ZeroAddressOwner();
        _initializeOwner(initialOwner);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                EXTERNAL STATE-CHANGING                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IWalletFactory
    function vetImplementation(address impl) external onlyOwner {
        Storage.Layout storage $ = Storage.layout();

        if (impl.code.length == 0) revert EmptyCode();
        bytes32 codehash = impl.codehash;
        if (!$.vettedCode.add(codehash)) revert AlreadyVetted();
        $.vettedWalletImpls[codehash] = impl;
        // A freshly-added entry is, by construction, at `length() - 1` — the
        // most recently inserted slot that `_findLatestActive` would return —
        // so it is unconditionally the new latest active implementation.
        $.latestWalletImpl = impl;
        emit ImplementationVetted(impl, codehash);
    }

    /// @inheritdoc IWalletFactory
    function undeprecateImplementation(address impl) external onlyOwner {
        Storage.Layout storage $ = Storage.layout();
        bytes32 codehash = impl.codehash;
        if (!$.vettedCode.contains(codehash)) revert ImplementationNotVetted();
        if (!$.deprecatedImpls[codehash]) revert NotDeprecated();
        $.deprecatedImpls[codehash] = false;
        // Re-bind the pointer to any address carrying the vetted bytes (same code,
        // same behaviour). A self-assign for the deployed wallet families: their
        // code embeds `address(this)` in immutables, so a redeploy is a new,
        // unvetted codehash (vet it as a new entry, then deprecate the old).
        $.vettedWalletImpls[codehash] = impl;
        // Recompute via the insertion-order backward scan: if the reactivated
        // entry is at the highest index among non-deprecated entries it becomes
        // the latest, otherwise the previously latest entry is preserved.
        $.latestWalletImpl = _findLatestActive();
        emit ImplementationUndeprecated(impl, codehash);
    }

    /// @inheritdoc IWalletFactory
    function deprecateImplementation(address impl) external onlyOwner {
        Storage.Layout storage $ = Storage.layout();
        bytes32 codehash = impl.codehash;
        if (!$.vettedCode.contains(codehash)) revert ImplementationNotVetted();
        $.deprecatedImpls[codehash] = true;
        emit ImplementationSunset(impl, codehash);
        // Deprecation is codehash-scoped, and the same codehash may live at
        // multiple addresses, so compare the stored latest's EXTCODEHASH.
        if ($.latestWalletImpl.codehash == codehash) {
            $.latestWalletImpl = _findLatestActive();
        }
    }

    /// @inheritdoc IWalletFactory
    function deployLatestWalletProxy(
        bytes32 commitment,
        address payable to,
        bytes calldata payload
    ) external payable returns (address) {
        address impl = Storage.layout().latestWalletImpl;
        if (impl == address(0)) revert NoActiveImplementation();
        return _deployProxy(impl, commitment, to, payload);
    }

    /// @inheritdoc IWalletFactory
    function deploySpecificWalletProxy(
        bytes32 commitment,
        uint256 index,
        address payable to,
        bytes calldata payload
    ) external payable returns (address) {
        Storage.Layout storage $ = Storage.layout();
        bytes32 codehash = $.vettedCode.at(index);
        if ($.deprecatedImpls[codehash]) revert ImplementationDeprecated();
        return _deployProxy($.vettedWalletImpls[codehash], commitment, to, payload);
    }

    /// @inheritdoc IWalletFactory
    function setCreationFee(uint256 newFee) external onlyOwner {
        if (newFee > MAX_FEE) revert FeeExceedsMax(newFee, MAX_FEE);
        Storage.Layout storage $ = Storage.layout();
        uint256 oldFee = $.creationFee;
        $.creationFee = newFee;
        emit CreationFeeUpdated(oldFee, newFee);
    }

    /// @inheritdoc IWalletFactory
    function setExecuteFee(uint256 newFee) external onlyOwner {
        if (newFee > MAX_FEE) revert FeeExceedsMax(newFee, MAX_FEE);
        Storage.Layout storage $ = Storage.layout();
        uint256 oldFee = $.executeFee;
        $.executeFee = newFee;
        emit ExecuteFeeUpdated(oldFee, newFee);
    }

    /// @inheritdoc IWalletFactory
    function withdraw(uint256 amount) external onlyOwner {
        if (address(this).balance < amount) {
            revert InsufficientBalance(amount, address(this).balance);
        }
        SafeTransferLib.forceSafeTransferETH(owner(), amount);
        emit Withdrawn(owner(), amount);
    }

    /// @inheritdoc IWalletFactory
    function updateWalletOwner(address newOwner) external {
        Storage.Layout storage $ = Storage.layout();
        bytes32 commitment = $.commitmentOf[msg.sender];
        if (commitment == bytes32(0)) revert OnlyWallet();
        if (newOwner == address(0)) revert ZeroAddressOwner();
        // Authoritative read — the factory's own source of truth for
        // who currently owns this wallet. The wallet does not get to pass
        // a (potentially wrong) `oldOwner`.
        address oldOwner = $.walletOwner[msg.sender];
        if (oldOwner == newOwner) revert SameOwner();
        // NB:
        // Pins the callback to the tail of the wallet's PQ-authenticated
        // ownership-transfer flow — per the vetting contract (`IWallet`
        // natspec, rule 2), the only path a vetted implementation may have
        // that produces `wallet.owner() == newOwner` in the same transaction.
        if (IWallet(msg.sender).owner() != newOwner) {
            revert OwnerStateMismatch();
        }

        $.walletOwner[msg.sender] = newOwner;
        // Both mutations MUST succeed: `oldOwner` came from the factory's
        // authoritative `walletOwner` mapping so its set must contain
        // `commitment`; `newOwner` cannot already hold it because commitments are
        // globally unique (CREATE3) and each lives in at most one owner's
        // set at a time. A `false` return here means the registry diverged
        // from `walletOwner` somehow — revert loudly.
        if (!$.commitments[oldOwner].remove(commitment)) revert RegistryDesync();
        if (!$.commitments[newOwner].add(commitment)) revert RegistryDesync();
        emit WalletOwnerChanged(commitment, oldOwner, newOwner);
    }

    /// @notice Disabled; always reverts with `RenounceDisabled`.
    function renounceOwnership() public payable override(Ownable) onlyOwner {
        revert RenounceDisabled();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   EXTERNAL VIEWS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IWalletFactory
    function creationFee() external view returns (uint256) {
        return Storage.layout().creationFee;
    }

    /// @inheritdoc IWalletFactory
    function executeFee() external view returns (uint256) {
        return Storage.layout().executeFee;
    }

    /// @inheritdoc IWalletFactory
    function wallets(bytes32 salt) external view returns (address) {
        return Storage.layout().wallets[salt];
    }

    /// @inheritdoc IWalletFactory
    function commitmentOf(address wallet) external view returns (bytes32) {
        return Storage.layout().commitmentOf[wallet];
    }

    /// @inheritdoc IWalletFactory
    function walletOwner(address wallet) external view returns (address) {
        return Storage.layout().walletOwner[wallet];
    }

    /// @inheritdoc IWalletFactory
    function vettedWalletImpls(
        bytes32 codehash
    ) external view returns (address walletImplementation) {
        return Storage.layout().vettedWalletImpls[codehash];
    }

    /// @inheritdoc IWalletFactory
    function deprecatedImpls(
        bytes32 codehash
    ) external view returns (bool isDeprecated) {
        return Storage.layout().deprecatedImpls[codehash];
    }

    /// @inheritdoc IWalletFactory
    function latestWalletImpl() external view returns (address) {
        return Storage.layout().latestWalletImpl;
    }

    /// @inheritdoc IWalletFactory
    function getVettedCodeCount() external view returns (uint256) {
        return Storage.layout().vettedCode.length();
    }

    /// @inheritdoc IWalletFactory
    function getVettedCodeAt(uint256 index) external view returns (bytes32) {
        return Storage.layout().vettedCode.at(index);
    }

    /// @inheritdoc IWalletFactory
    function getVettedCodeIndex(
        bytes32 codehash
    ) external view returns (uint256) {
        return Storage.layout().vettedCode.indexOf(codehash);
    }

    /// @inheritdoc IWalletFactory
    function getCommitmentCount(address owner_) external view returns (uint256) {
        return Storage.layout().commitments[owner_].length();
    }

    /// @inheritdoc IWalletFactory
    function getCommitmentAt(
        address owner_,
        uint256 index
    ) external view returns (bytes32) {
        return Storage.layout().commitments[owner_].at(index);
    }

    /// @inheritdoc IWalletFactory
    function getCommitmentIndex(
        address owner_,
        bytes32 commitment
    ) external view returns (uint256) {
        return Storage.layout().commitments[owner_].indexOf(commitment);
    }

    /// @inheritdoc IWalletFactory
    function getCommitments(
        address owner_
    ) external view returns (bytes32[] memory) {
        return Storage.layout().commitments[owner_].values();
    }

    /// @inheritdoc IWalletFactory
    function getWallets(
        address owner_
    ) external view returns (address[] memory walletAddrs) {
        Storage.Layout storage $ = Storage.layout();
        bytes32[] memory ids = $.commitments[owner_].values();
        walletAddrs = new address[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            walletAddrs[i] = $.wallets[ids[i]];
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev UUPS upgrade authorization. The owner is expected to be a
    ///      post-quantum wallet, so the upgrade call is PQ-secured upstream.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Iterates backwards through the vetted set to find the latest
    ///      non-deprecated implementation. Returns `address(0)` if none found.
    ///      Solady's EnumerableSetLib stores entries in contiguous slots in
    ///      insertion order, so `at(length() - 1)` is the most recently added.
    function _findLatestActive() internal view returns (address) {
        Storage.Layout storage $ = Storage.layout();
        uint256 len = $.vettedCode.length();
        for (uint256 i = len; i > 0; ) {
            unchecked {
                --i;
            }
            bytes32 codehash = $.vettedCode.at(i);
            if (!$.deprecatedImpls[codehash]) {
                return $.vettedWalletImpls[codehash];
            }
        }
        return address(0);
    }

    /// @dev Deploys a Solady minimal ERC-1967 proxy via CREATE3, initializes it,
    ///      and forwards deposited ETH (minus creation fee) to the wallet.
    ///      Runs behind the factory's own proxy: `address(this)` is the proxy
    ///      address, so CREATE3 wallet addresses are stable across factory
    ///      upgrades.
    function _deployProxy(
        address impl,
        bytes32 commitment,
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
        if (commitment == bytes32(0)) revert ZeroCommitment();
        Storage.Layout storage $ = Storage.layout();
        if (msg.value < $.creationFee) {
            revert InsufficientCreationFee(msg.value, $.creationFee);
        }
        uint256 contractValue = msg.value - $.creationFee;

        // CREATE3 salt is the full-width identity commitment. SHRINCS wallets
        // recompute and validate it during initialization.
        address contractAddr = CREATE3.deployDeterministic(
            proxyInitcode,
            commitment
        );

        // Publish the reverse `commitmentOf` entry (also the `OnlyWallet` gate for the ownership
        // callback) BEFORE the call, keyed by address.
        $.commitmentOf[contractAddr] = commitment;

        IWallet(contractAddr).initialize(to, payload);
        SafeTransferLib.safeTransferETH(contractAddr, contractValue);
        $.wallets[commitment] = contractAddr;
        $.walletOwner[contractAddr] = to;
        // `.add` cannot return false here: the salt is unique per CREATE3, and a fresh contract
        // address never appeared in any set before. Guard anyway against future Solady changes.
        if (!$.commitments[to].add(commitment)) revert RegistryDesync();

        emit WalletDeployed(
            msg.value,
            block.timestamp,
            commitment,
            to,
            impl,
            contractAddr
        );

        return contractAddr;
    }
}
