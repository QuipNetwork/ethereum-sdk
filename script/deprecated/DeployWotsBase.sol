// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {Deployer} from "../../contracts/deprecated/Deployer.sol";
import {WalletFactory} from "../../contracts/WalletFactory.sol";
import {QuipPaymaster} from "../../contracts/deprecated/QuipPaymaster.sol";
import {WOTSPlusImplementation} from "../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {DeployerCreate3} from "./DeployerCreate3.sol";

/**
 * @title DeployWotsBase
 * @dev WOTS+ family deploy steps (shared by `DeployAllWots` and `DeployAll`):
 *      the WOTSPlus library, the shared WalletFactory, the WOTSPlusImplementation
 *      wallet impl (+ factory vetting), and the QuipPaymaster (impl + proxy).
 *
 *      Because WalletFactory and WOTSPlusImplementation link the WOTSPlus library
 *      at their CREATE3 address, every inheritor MUST be run with
 *      `FOUNDRY_PROFILE=deploy` (see foundry.toml `[profile.deploy].libraries`).
 *      Salts match `script/PredictAddresses.s.sol` (V1.1).
 */
abstract contract DeployWotsBase is DeployerCreate3 {
    bytes32 internal constant WOTSPLUS_SALT = keccak256("QUIP:WOTSPlus:V1.1");
    // LEGACY: the factory now deploys via CreateX sender-guarded salts
    // (script/DeployFactoryBase.sol) — these Deployer-derived V2 salts and
    // `_deployFactory` below remain only for historical reproduction of the
    // Deployer-era derivation and are not called by any orchestrator.
    bytes32 internal constant LEGACY_FACTORY_IMPL_SALT = keccak256("QUIP:WalletFactory:Impl:V2");
    bytes32 internal constant LEGACY_FACTORY_PROXY_SALT = keccak256("QUIP:WalletFactory:Proxy:V2");
    bytes32 internal constant WOTS_IMPL_SALT = keccak256("QUIP:WOTSPlusImplementation:V1.1");
    bytes32 internal constant QUIP_PAYMASTER_IMPL_SALT = keccak256("QUIP:QuipPaymaster:Impl:V1.1");
    bytes32 internal constant QUIP_PAYMASTER_PROXY_SALT = keccak256("QUIP:QuipPaymaster:Proxy:V1.1");

    function _deployWotsPlusLib(Deployer deployer, uint256 pk) internal returns (address) {
        return _create3(deployer, pk, type(WOTSPlus).creationCode, WOTSPLUS_SALT, "WOTSPlus");
    }

    /// Deploy the shared WalletFactory (used by BOTH the WOTS+ and Shrincs
    /// families) as impl + ERC-1967 proxy. The PROXY address is the factory
    /// identity — wallets bake it in and CREATE3 wallet addressing derives
    /// from it, surviving implementation upgrades.
    function _deployFactory(Deployer deployer, uint256 pk, address owner, uint256 maxFee)
        internal
        returns (address factory)
    {
        bytes memory implCode = abi.encodePacked(type(WalletFactory).creationCode, abi.encode(maxFee));
        address impl = _create3(deployer, pk, implCode, LEGACY_FACTORY_IMPL_SALT, "WalletFactory impl");
        bytes memory initData = abi.encodeCall(WalletFactory.initialize, (payable(owner)));
        bytes memory proxyCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
        factory = _create3(deployer, pk, proxyCode, LEGACY_FACTORY_PROXY_SALT, "WalletFactory proxy");
        require(WalletFactory(payable(factory)).owner() == owner, "WalletFactory owner mismatch");
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
