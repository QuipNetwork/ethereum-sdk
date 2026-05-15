// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {Deployer} from "../contracts/Deployer.sol";
import {QuipPaymaster} from "../contracts/QuipPaymaster.sol";

/**
 * @title DeployAll
 * @dev Orchestrates deployment of WOTSPlus, QuipFactory, and QuipPaymaster
 *      via the existing Deployer contract. The Deployer must already exist
 *      (deployed separately via DeployDeployer.s.sol).
 *
 *      QuipWallet implementation deploy + vetting is intentionally NOT part
 *      of this script — see DeployImplementation.s.sol + VetImplementation.s.sol.
 *      Wallet impls evolve per release; bundling them into DeployAll would
 *      conflate one-time infra deploy with per-release vetting.
 *
 *      WOTSPlus + QuipFactory deploy from frozen release bytecode (committed
 *      under deployments/bytecode/) for cross-chain address determinism.
 *      QuipPaymaster (impl + ERC1967 proxy) deploys from in-tree
 *      `type().creationCode` — the paymaster is upgradeable via UUPS so impl
 *      bytecode pinning is a softer requirement than for WOTSPlus and the
 *      factory.
 *
 * Usage:
 *   forge script script/DeployAll.s.sol --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      - Operations wallet private key
 *   DEPLOYER_ADDRESS - Deployer contract address
 *   PAYMASTER_OWNER  - Initial owner of the paymaster proxy
 */
contract DeployAll is Script {
    bytes32 internal constant PAYMASTER_IMPL_SALT = keccak256("QUIP:QuipPaymaster:Impl:V1");
    bytes32 internal constant PAYMASTER_PROXY_SALT = keccak256("QUIP:QuipPaymaster:Proxy:V1");

    function run() external {
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address paymasterOwner = vm.envAddress("PAYMASTER_OWNER");
        require(paymasterOwner != address(0), "PAYMASTER_OWNER must be non-zero");
        require(deployerAddr.code.length > 0, "Deployer contract not found. Run DeployDeployer.s.sol first.");

        Deployer deployer = Deployer(deployerAddr);

        console.log("=== Quip Network Full Deployment ===");
        console.log("Deployer contract:", deployerAddr);
        console.log("Paymaster owner:  ", paymasterOwner);

        address wotsAddr = _deployRelease(deployer, privateKey, "WOTSPlus.sol");
        address factoryAddr = _deployRelease(deployer, privateKey, "QuipFactory.sol");
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

    /// @dev Deploys a release contract (WOTSPlus or QuipFactory) from
    ///      committed bytecode artifacts. Skips deploy if the predicted
    ///      address already has code.
    function _deployRelease(
        Deployer deployer,
        uint256 privateKey,
        string memory contractDir
    ) internal returns (address deployed) {
        console.log(string.concat("\n--- ", contractDir, " ---"));
        (bytes memory bytecode, bytes32 salt, address expectedAddr) = _loadRelease(contractDir);

        if (expectedAddr.code.length > 0) {
            console.log("Already deployed at:", expectedAddr);
            return expectedAddr;
        }

        vm.startBroadcast(privateKey);
        deployed = deployer.deploy(bytecode, salt);
        vm.stopBroadcast();
        require(deployed == expectedAddr, "Address mismatch");
        console.log("Deployed at:", deployed);
    }

    /// @dev Deploys the QuipPaymaster implementation under
    ///      `keccak256("QUIP:QuipPaymaster:Impl:V1")`. The impl's constructor
    ///      runs `_disableInitializers()`, so the impl is intentionally inert.
    function _deployPaymasterImpl(
        Deployer deployer,
        uint256 privateKey
    ) internal returns (address impl) {
        console.log("\n--- QuipPaymaster impl ---");
        address expectedImpl = CREATE3.predictDeterministicAddress(
            PAYMASTER_IMPL_SALT,
            address(deployer)
        );
        console.log("Expected impl:", expectedImpl);

        if (expectedImpl.code.length > 0) {
            console.log("Paymaster implementation already deployed.");
            return expectedImpl;
        }

        vm.startBroadcast(privateKey);
        impl = deployer.deploy(type(QuipPaymaster).creationCode, PAYMASTER_IMPL_SALT);
        vm.stopBroadcast();
        require(impl == expectedImpl, "Paymaster impl address mismatch");
        console.log("Paymaster impl deployed at:", impl);
    }

    /// @dev Deploys an ERC1967 proxy in front of `impl` and atomically calls
    ///      `initialize(owner)` via the proxy's constructor delegatecall.
    function _deployPaymasterProxy(
        Deployer deployer,
        uint256 privateKey,
        address impl,
        address owner
    ) internal returns (address proxy) {
        console.log("\n--- QuipPaymaster proxy ---");
        address expectedProxy = CREATE3.predictDeterministicAddress(
            PAYMASTER_PROXY_SALT,
            address(deployer)
        );
        console.log("Expected proxy:", expectedProxy);

        if (expectedProxy.code.length > 0) {
            console.log("Paymaster proxy already deployed.");
            require(
                QuipPaymaster(payable(expectedProxy)).owner() == owner,
                "Paymaster owner mismatch on existing proxy"
            );
            return expectedProxy;
        }

        bytes memory initData = abi.encodeCall(QuipPaymaster.initialize, (owner));
        bytes memory proxyBytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, initData)
        );
        vm.startBroadcast(privateKey);
        proxy = deployer.deploy(proxyBytecode, PAYMASTER_PROXY_SALT);
        vm.stopBroadcast();
        require(proxy == expectedProxy, "Paymaster proxy address mismatch");
        require(
            QuipPaymaster(payable(proxy)).owner() == owner,
            "Paymaster owner not set during initialize"
        );
        console.log("Paymaster proxy deployed at:", proxy);
    }

    /// @dev Reads the release bundle for `contractDir` (e.g. "WOTSPlus.sol").
    ///      Indirects through `latest.json` so the active release pointer
    ///      lives in version control alongside the bytecode.
    function _loadRelease(string memory contractDir)
        internal
        view
        returns (bytes memory bytecode, bytes32 salt, address expectedAddr)
    {
        string memory latestJson = vm.readFile(
            string.concat("deployments/bytecode/", contractDir, "/latest.json")
        );
        string memory releaseFile = vm.parseJsonString(latestJson, ".file");
        string memory releaseJson = vm.readFile(
            string.concat("deployments/bytecode/", contractDir, "/", releaseFile)
        );

        bytecode = vm.parseJsonBytes(releaseJson, ".creationBytecode");
        salt = vm.parseJsonBytes32(releaseJson, ".salt");
        expectedAddr = vm.parseJsonAddress(releaseJson, ".address");
    }
}
