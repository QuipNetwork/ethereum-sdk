// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactory} from "../../contracts/QuipFactory.sol";

contract QuipFactoryHarness is QuipFactory {
    constructor(
        address payable initialOwner,
        uint256 maxFee_
    ) payable QuipFactory(initialOwner, maxFee_) {}

    function exposed_findLatestActive() external view returns (address) {
        return _findLatestActive();
    }

    function exposed_deployProxy(
        address impl,
        bytes32 vaultId,
        address payable to,
        bytes calldata payload
    ) external payable returns (address) {
        return _deployProxy(impl, vaultId, to, payload);
    }
}
