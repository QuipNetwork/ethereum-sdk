// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactory} from "../../contracts/WalletFactory.sol";

/// @dev Deploy like production: `new WalletFactoryHarness(maxFee)` gives an
///      implementation (initializers disabled), so tests must front it with an
///      ERC-1967 proxy (e.g. `LibClone.deployERC1967`) and call `initialize`.
contract WalletFactoryHarness is WalletFactory {
    constructor(uint256 maxFee_) payable WalletFactory(maxFee_) {}

    function exposed_findLatestActive() external view returns (address) {
        return _findLatestActive();
    }

    /// @dev Wraps the owner-initialization guard (overridden to `true` because the factory inherits
    ///      Solady `Ownable` directly, not the `ERC4337` base that supplies the override).
    function exposed_guardInitializeOwner() external pure returns (bool) {
        return _guardInitializeOwner();
    }

    function exposed_deployProxy(
        address impl,
        bytes32 vaultId,
        bytes32 commitment,
        address payable to,
        bytes calldata payload
    ) external payable returns (address) {
        return _deployProxy(impl, vaultId, commitment, to, payload);
    }
}
