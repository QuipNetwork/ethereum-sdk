// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {Deployer} from "../contracts/Deployer.sol";
import {QuipFactory} from "../contracts/QuipFactory.sol";
import {QuipPaymaster} from "../contracts/QuipPaymaster.sol";
import {WOTSPlusImplementation} from "../contracts/wots/WOTSPlusImplementation.sol";
import {DeployHelpers} from "./DeployHelpers.sol";

/**
 * @title DeployWotsBase
 * @dev WOTS+ family deploy steps (shared by `DeployAllWots` and `DeployAll`):
 *      the WOTSPlus library, the shared QuipFactory, the WOTSPlusImplementation
 *      wallet impl (+ factory vetting), and the QuipPaymaster (impl + proxy).
 *
 *      Because QuipFactory and WOTSPlusImplementation link the WOTSPlus library
 *      at their CREATE3 address, every inheritor MUST be run with
 *      `FOUNDRY_PROFILE=deploy` (see foundry.toml `[profile.deploy].libraries`).
 *      Salts match `script/PredictAddresses.s.sol` (V1.1).
 */
abstract contract DeployWotsBase is DeployHelpers {
    bytes32 internal constant WOTSPLUS_SALT = keccak256("QUIP:WOTSPlus:V1.1");
    // V2: the factory became UUPS (impl + ERC-1967 proxy). Fresh salts are
    // REQUIRED — CREATE3 addresses ignore initcode, so reusing the V1.1 salt
    // on a chain that already has the non-upgradeable factory would silently
    // skip deployment and leave the old factory in place.
    bytes32 internal constant FACTORY_IMPL_SALT = keccak256("QUIP:QuipFactory:Impl:V2");
    bytes32 internal constant FACTORY_PROXY_SALT = keccak256("QUIP:QuipFactory:Proxy:V2");
    bytes32 internal constant WOTS_IMPL_SALT = keccak256("QUIP:WOTSPlusImplementation:V1.1");
    bytes32 internal constant QUIP_PAYMASTER_IMPL_SALT = keccak256("QUIP:QuipPaymaster:Impl:V1.1");
    bytes32 internal constant QUIP_PAYMASTER_PROXY_SALT = keccak256("QUIP:QuipPaymaster:Proxy:V1.1");

    function _deployWotsPlusLib(Deployer deployer, uint256 pk) internal returns (address) {
        return _create3(deployer, pk, type(WOTSPlus).creationCode, WOTSPLUS_SALT, "WOTSPlus");
    }

    /// Deploy the shared QuipFactory (used by BOTH the WOTS+ and Shrincs
    /// families) as impl + ERC-1967 proxy. The PROXY address is the factory
    /// identity — wallets bake it in and CREATE3 wallet addressing derives
    /// from it, surviving implementation upgrades.
    function _deployFactory(Deployer deployer, uint256 pk, address owner, uint256 maxFee)
        internal
        returns (address factory)
    {
        bytes memory implCode = abi.encodePacked(type(QuipFactory).creationCode, abi.encode(maxFee));
        address impl = _create3(deployer, pk, implCode, FACTORY_IMPL_SALT, "QuipFactory impl");
        bytes memory initData = abi.encodeCall(QuipFactory.initialize, (payable(owner)));
        bytes memory proxyCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
        factory = _create3(deployer, pk, proxyCode, FACTORY_PROXY_SALT, "QuipFactory proxy");
        require(QuipFactory(payable(factory)).owner() == owner, "QuipFactory owner mismatch");
    }

    /// Deploy + vet the WOTSPlusImplementation wallet impl against `factory`.
    /// Vetting sets `latestWalletImpl`, so call this LAST when WOTS+ must remain
    /// the `deployLatestWalletProxy` default.
    function _deployWotsImplAndVet(Deployer deployer, uint256 pk, address factory) internal returns (address impl) {
        bytes memory code =
            abi.encodePacked(type(WOTSPlusImplementation).creationCode, abi.encode(payable(factory)));
        impl = _create3(deployer, pk, code, WOTS_IMPL_SALT, "WOTSPlusImplementation");
        _vetIfNeeded(factory, pk, impl, "WOTSPlusImplementation");
    }

    function _deployQuipPaymaster(Deployer deployer, uint256 pk, address paymasterOwner) internal returns (address proxy) {
        address impl = _create3(deployer, pk, type(QuipPaymaster).creationCode, QUIP_PAYMASTER_IMPL_SALT, "QuipPaymaster impl");
        bytes memory initData = abi.encodeCall(QuipPaymaster.initialize, (paymasterOwner));
        bytes memory proxyCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
        proxy = _create3(deployer, pk, proxyCode, QUIP_PAYMASTER_PROXY_SALT, "QuipPaymaster proxy");
        require(QuipPaymaster(payable(proxy)).owner() == paymasterOwner, "QuipPaymaster owner mismatch");
    }

    /// Full WOTS+ family deploy. Returns the shared factory. WOTS+ is vetted last
    /// here, so `latestWalletImpl == WOTSPlusImplementation` on completion.
    function _deployWotsAll(
        Deployer deployer,
        uint256 pk,
        address factoryOwner,
        uint256 maxFee,
        address paymasterOwner
    ) internal returns (address factory) {
        _deployWotsPlusLib(deployer, pk);
        factory = _deployFactory(deployer, pk, factoryOwner, maxFee);
        _deployWotsImplAndVet(deployer, pk, factory);
        _deployQuipPaymaster(deployer, pk, paymasterOwner);
    }
}
