// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactory} from "../../contracts/QuipFactory.sol";

/// @dev Deploy like production: `new QuipFactoryHarness(maxFee)` gives an
///      implementation (initializers disabled), so tests must front it with an
///      ERC-1967 proxy (e.g. `LibClone.deployERC1967`) and call `initialize`.
contract QuipFactoryHarness is QuipFactory {
    constructor(uint256 maxFee_) payable QuipFactory(maxFee_) {}

    function exposed_findLatestActive() external view returns (address) {
        return _findLatestActive();
    }

    function exposed_deployProxy(address impl, bytes32 vaultId, address payable to, bytes calldata payload)
        external
        payable
        returns (address)
    {
        return _deployProxy(impl, vaultId, to, payload);
    }
}
