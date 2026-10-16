// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {WalletFactory} from "../contracts/WalletFactory.sol";
import {DeployConstants} from "./Constants.sol";
import {CreateXHelpers} from "./CreateXHelpers.sol";

/// Getter surface used for the post-deploy identity check. A public immutable's
/// auto-generated getter has no `.selector` on the contract type, so the
/// selectors come from this minimal interface.
interface IFactoryIdentity {
    function MAX_FEE() external view returns (uint256);
}

/**
 * @title DeployFactoryBase
 * @dev WalletFactory deploy step (impl + ERC-1967 proxy) via sender-guarded
 *      CreateX CREATE3, used by `01_DeployFactory.s.sol` (and reused by
 *      `02_DeployShrincs` for canonical-address derivation). Addresses depend
 *      on (CreateX, DEPLOY_OPERATOR, salt) — identical on every chain for the
 *      same operator, independent of constructor args. Salts live in
 *      `DeployConstants`.
 *
 *      The PROXY address is the permanent factory identity: wallets bake it in as
 *      an immutable and CREATE3 wallet addressing derives from it, so it survives
 *      implementation upgrades.
 */
abstract contract DeployFactoryBase is CreateXHelpers {
    function _deployFactoryViaCreateX(
        address operator,
        uint256 pk,
        address owner,
        uint256 maxFee
    ) internal returns (address proxy) {
        bytes memory implCode = abi.encodePacked(type(WalletFactory).creationCode, abi.encode(maxFee));
        address impl =
            _createXDeploy(operator, pk, implCode, bytes(DeployConstants.FACTORY_IMPL_SALT), "WalletFactory impl");

        // Identity, on both the fresh and the idempotent-skip path: `MAX_FEE` is a
        // constructor-set immutable, so this proves the code at the canonical impl
        // address is THIS build's factory and not a stale one deployed under a
        // different fee bound.
        require(
            _readUint(impl, IFactoryIdentity.MAX_FEE.selector, "WalletFactory impl") == maxFee,
            "WalletFactory impl: MAX_FEE at the canonical address does not match this build"
        );

        bytes memory initData = abi.encodeCall(WalletFactory.initialize, (payable(owner)));
        bytes memory proxyCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
        proxy =
            _createXDeploy(operator, pk, proxyCode, bytes(DeployConstants.FACTORY_PROXY_SALT), "WalletFactory proxy");

        _assertErc1967Proxy(proxy, impl, "WalletFactory proxy");
    }
}
