// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Deployer} from "../contracts/Deployer.sol";
import {QuipFactory} from "../contracts/QuipFactory.sol";
import {QuipPaymaster} from "../contracts/QuipPaymaster.sol";

/**
 * @title DeployAll
 * @dev Orchestrates deployment of WOTSPlus, QuipFactory, and QuipPaymaster
 *      via the existing Deployer contract. The Deployer must already exist
 *      (deployed separately via DeployDeployer.s.sol, which now bootstraps
 *      via CreateX — no fresh-EOA / nonce-1 ritual required).
 *
 *      All four downstream deploys (WOTSPlus library, QuipFactory,
 *      QuipPaymaster impl, ERC1967 proxy for the paymaster) go through
 *      `Deployer.deploy(bytecode, salt)` → solady CREATE3. Their addresses
 *      depend only on (Deployer, salt); they're identical on every chain.
 *
 *      QuipWallet implementation + factory-side vetting is intentionally
 *      separate — see DeployImplementation.s.sol + VetImplementation.s.sol.
 *      Wallet impls evolve per release; bundling them here would conflate
 *      one-time infra deploy with per-release vetting.
 *
 *      IMPORTANT: this script must be run with `FOUNDRY_PROFILE=deploy` so
 *      QuipFactory's bytecode has the WOTSPlus library linked at compile
 *      time. The `[profile.deploy].libraries` line in foundry.toml pins
 *      WOTSPlus at its CREATE3 address.
 *
 * Usage:
 *   FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      - Operations wallet private key
 *   DEPLOYER_ADDRESS - Deployer contract address (per-chain, bootstrapped via DeployDeployer)
 *   FACTORY_OWNER    - Initial owner of QuipFactory
 *   MAX_FEE          - Maximum wallet-creation fee (wei)
 *   PAYMASTER_OWNER  - Initial owner of the paymaster proxy
 */
contract DeployAll is Script {
    bytes32 internal constant WOTSPLUS_SALT = keccak256("QUIP:WOTSPlus:V1.1");
    bytes32 internal constant FACTORY_SALT = keccak256("QUIP:QuipFactory:V1.1");
    bytes32 internal constant PAYMASTER_IMPL_SALT = keccak256("QUIP:QuipPaymaster:Impl:V1.1");
    bytes32 internal constant PAYMASTER_PROXY_SALT = keccak256("QUIP:QuipPaymaster:Proxy:V1.1");

    function run() external {
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address factoryOwner = vm.envAddress("FACTORY_OWNER");
        uint256 maxFee = vm.envUint("MAX_FEE");
        address paymasterOwner = vm.envAddress("PAYMASTER_OWNER");

        require(deployerAddr.code.length > 0, "Deployer contract not found. Run DeployDeployer first.");
        require(factoryOwner != address(0), "FACTORY_OWNER must be non-zero");
        require(maxFee != 0, "MAX_FEE must be non-zero");
        require(paymasterOwner != address(0), "PAYMASTER_OWNER must be non-zero");

        Deployer deployer = Deployer(deployerAddr);

        console.log("=== Quip Network Full Deployment ===");
        console.log("Deployer contract:", deployerAddr);
        console.log("Factory owner:    ", factoryOwner);
        console.log("Max fee:          ", maxFee);
        console.log("Paymaster owner:  ", paymasterOwner);

        address wotsAddr = _deployWotsPlus(deployer, privateKey);
        address factoryAddr = _deployFactory(deployer, privateKey, factoryOwner, maxFee);
        address paymasterImpl = _deployPaymasterImpl(deployer, privateKey);
        address paymasterProxy = _deployPaymasterProxy(deployer, privateKey, paymasterImpl, paymasterOwner);

        console.log("\n=== Deployment Summary ===");
        console.log("Deployer:         ", deployerAddr);
        console.log("WOTSPlus:         ", wotsAddr);
        console.log("QuipFactory:      ", factoryAddr);
        console.log("QuipPaymaster:    ", paymasterProxy);
        console.log("(impl:            ", paymasterImpl);
        console.log(")");
    }

    function _deployWotsPlus(Deployer deployer, uint256 privateKey) internal returns (address deployed) {
        console.log("\n--- WOTSPlus ---");
        address expected = CREATE3.predictDeterministicAddress(WOTSPLUS_SALT, address(deployer));
        console.log("Expected:", expected);

        if (expected.code.length > 0) {
            console.log("Already deployed.");
            return expected;
        }

        vm.startBroadcast(privateKey);
        deployed = deployer.deploy(type(WOTSPlus).creationCode, WOTSPLUS_SALT);
        vm.stopBroadcast();
        require(deployed == expected, "WOTSPlus address mismatch");
        console.log("Deployed at:", deployed);
    }

    function _deployFactory(
        Deployer deployer,
        uint256 privateKey,
        address owner,
        uint256 maxFee
    ) internal returns (address deployed) {
        console.log("\n--- QuipFactory ---");
        address expected = CREATE3.predictDeterministicAddress(FACTORY_SALT, address(deployer));
        console.log("Expected:", expected);

        if (expected.code.length > 0) {
            console.log("Already deployed.");
            return expected;
        }

        bytes memory bytecode = abi.encodePacked(
            type(QuipFactory).creationCode,
            abi.encode(owner, maxFee)
        );
        vm.startBroadcast(privateKey);
        deployed = deployer.deploy(bytecode, FACTORY_SALT);
        vm.stopBroadcast();
        require(deployed == expected, "QuipFactory address mismatch");
        require(QuipFactory(payable(deployed)).owner() == owner, "Factory owner mismatch");
        console.log("Deployed at:", deployed);
    }

    function _deployPaymasterImpl(Deployer deployer, uint256 privateKey) internal returns (address impl) {
        console.log("\n--- QuipPaymaster impl ---");
        address expected = CREATE3.predictDeterministicAddress(PAYMASTER_IMPL_SALT, address(deployer));
        console.log("Expected:", expected);

        if (expected.code.length > 0) {
            console.log("Already deployed.");
            return expected;
        }

        vm.startBroadcast(privateKey);
        impl = deployer.deploy(type(QuipPaymaster).creationCode, PAYMASTER_IMPL_SALT);
        vm.stopBroadcast();
        require(impl == expected, "Paymaster impl address mismatch");
        console.log("Deployed at:", impl);
    }

    function _deployPaymasterProxy(
        Deployer deployer,
        uint256 privateKey,
        address impl,
        address owner
    ) internal returns (address proxy) {
        console.log("\n--- QuipPaymaster proxy ---");
        address expected = CREATE3.predictDeterministicAddress(PAYMASTER_PROXY_SALT, address(deployer));
        console.log("Expected:", expected);

        if (expected.code.length > 0) {
            console.log("Already deployed.");
            require(
                QuipPaymaster(payable(expected)).owner() == owner,
                "Paymaster owner mismatch on existing proxy"
            );
            return expected;
        }

        bytes memory initData = abi.encodeCall(QuipPaymaster.initialize, (owner));
        bytes memory proxyBytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, initData)
        );
        vm.startBroadcast(privateKey);
        proxy = deployer.deploy(proxyBytecode, PAYMASTER_PROXY_SALT);
        vm.stopBroadcast();
        require(proxy == expected, "Paymaster proxy address mismatch");
        require(
            QuipPaymaster(payable(proxy)).owner() == owner,
            "Paymaster owner not set during initialize"
        );
        console.log("Deployed at:", proxy);
    }
}
