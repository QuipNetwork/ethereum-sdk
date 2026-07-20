// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {WalletFactory} from "../contracts/WalletFactory.sol";
import {CreateXHelpers} from "./CreateXHelpers.sol";

/**
 * @title DeployFactoryBase
 * @dev WalletFactory deploy step (impl + ERC-1967 proxy) via sender-guarded
 *      CreateX CREATE3, shared by `DeployWalletFactory` and `DeployAll`.
 *      Addresses depend on (CreateX, DEPLOY_OPERATOR, salt) — identical on every
 *      chain for the same operator, independent of constructor args.
 *
 *      The PROXY address is the permanent factory identity: wallets bake it in as
 *      an immutable and CREATE3 wallet addressing derives from it, so it survives
 *      implementation upgrades.
 */
abstract contract DeployFactoryBase is CreateXHelpers {
    string internal constant FACTORY_IMPL_SALT = "QUIP:WalletFactory:Impl:V1.0.0-beta";
    string internal constant FACTORY_PROXY_SALT = "QUIP:WalletFactory:Proxy:V1.0.0-beta";

    function _deployFactoryViaCreateX(
        address operator,
        uint256 pk,
        address owner,
        uint256 maxFee
    ) internal returns (address proxy) {
        bytes memory implCode = abi.encodePacked(type(WalletFactory).creationCode, abi.encode(maxFee));
        address impl = _createXDeploy(operator, pk, implCode, bytes(FACTORY_IMPL_SALT), "WalletFactory impl");

        bytes memory initData = abi.encodeCall(WalletFactory.initialize, (payable(owner)));
        bytes memory proxyCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
        proxy = _createXDeploy(operator, pk, proxyCode, bytes(FACTORY_PROXY_SALT), "WalletFactory proxy");

        // Anti-squat: whatever sits at the canonical proxy address must be an
        // ERC-1967 proxy. A freshly deployed proxy points at `impl`; a proxy that
        // pre-existed may legitimately point at a NEWER impl (UUPS upgrade), so we
        // require a non-zero impl slot and surface the current target.
        address current = address(uint160(uint256(vm.load(proxy, ERC1967_IMPL_SLOT))));
        require(current != address(0), "WalletFactory: code at proxy address is not an ERC-1967 proxy");
        if (current != impl) {
            console.log("  - WalletFactory proxy impl (upgraded since this build):", current);
        }
    }
}
