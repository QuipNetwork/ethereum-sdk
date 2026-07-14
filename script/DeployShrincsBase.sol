// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {Deployer} from "../contracts/Deployer.sol";
import {ShrincsPaymaster} from "../contracts/ShrincsPaymaster.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {ShrincsWallet} from "../contracts/shrincs/ShrincsWallet.sol";
import {DeployHelpers} from "./DeployHelpers.sol";

/**
 * @title DeployShrincsBase
 * @dev Shrincs family deploy steps (shared by `DeployAllShrincs` and `DeployAll`):
 *      the ShrincsWallet impl (+ vetting on the shared QuipFactory), and the
 *      ShrincsPaymaster (impl + proxy, initialized with its verifier key).
 *
 *      The Shrincs contracts have NO library link references, so an inheritor that
 *      deploys ONLY Shrincs needs no `FOUNDRY_PROFILE=deploy`. The shared
 *      QuipFactory must already exist (it is WOTS+-family infra). Salts match
 *      `script/PredictAddresses.s.sol` (V1.0).
 */
abstract contract DeployShrincsBase is DeployHelpers {
    /// Canonical CREATE3 address of the deployed `SHRINCS256sKeccak` ERC-7913 verifier
    /// (hashsigs-solidity `DEPLOYMENTS.md`; same address on every chain). Pinned as an
    /// immutable by the ShrincsWallet and ShrincsPaymaster implementation constructors.
    address internal constant SHRINCS_EXTERNAL_VERIFIER = 0xb76f5acfa4f1e993b36C9c72eD7514eC2c80F00A;

    bytes32 internal constant SHRINCS_WALLET_SALT = keccak256("QUIP:ShrincsWallet:V1.0");
    bytes32 internal constant SHRINCS_PAYMASTER_IMPL_SALT = keccak256("QUIP:ShrincsPaymaster:Impl:V1.0");
    bytes32 internal constant SHRINCS_PAYMASTER_PROXY_SALT = keccak256("QUIP:ShrincsPaymaster:Proxy:V1.0");

    /// Verifier-key parameters the ShrincsPaymaster bakes in at `initialize`
    /// (a non-zero commitment + budget are REQUIRED — `initialize` reverts otherwise).
    struct ShrincsVerifier {
        address paymasterOwner;
        bytes32 commitment;
        uint32 hashSuite;
        uint32 maxSignatures;
    }

    /// Read the ShrincsPaymaster verifier-key config from the environment.
    /// `SHRINCS_VERIFIER_HASH_SUITE` defaults to `HASH_SUITE_KECCAK_256` (the only
    /// suite the on-chain library verifies).
    function _shrincsVerifierFromEnv() internal view returns (ShrincsVerifier memory v) {
        v = ShrincsVerifier({
            paymasterOwner: vm.envAddress("SHRINCS_PAYMASTER_OWNER"),
            commitment: vm.envBytes32("SHRINCS_VERIFIER_COMMITMENT"),
            hashSuite: uint32(
                vm.envOr("SHRINCS_VERIFIER_HASH_SUITE", uint256(HashSuite.HASH_SUITE_ID))
            ),
            maxSignatures: uint32(vm.envUint("SHRINCS_VERIFIER_MAX_SIGNATURES"))
        });
    }

    /// Deploy + vet the ShrincsWallet impl against `factory`. NOTE: vetting sets
    /// `latestWalletImpl` to this impl, so on a chain where WOTS+ must remain the
    /// `deployLatestWalletProxy` default, vet a WOTS+ impl AFTER this (the Shrincs
    /// SDK always uses `deploySpecificWalletProxy`, so it is order-independent).
    function _deployShrincsImplAndVet(Deployer deployer, uint256 pk, address factory) internal returns (address impl) {
        _requireExists(factory, "QuipFactory");
        bytes memory code =
            abi.encodePacked(type(ShrincsWallet).creationCode, abi.encode(factory, SHRINCS_EXTERNAL_VERIFIER));
        impl = _create3(deployer, pk, code, SHRINCS_WALLET_SALT, "ShrincsWallet");
        _vetIfNeeded(factory, pk, impl, "ShrincsWallet");
    }

    function _deployShrincsPaymaster(Deployer deployer, uint256 pk, ShrincsVerifier memory v)
        internal
        returns (address proxy)
    {
        require(v.paymasterOwner != address(0), "SHRINCS paymaster owner zero");
        require(v.commitment != bytes32(0), "SHRINCS verifier commitment zero");
        require(v.maxSignatures != 0, "SHRINCS verifier maxSignatures zero");

        bytes memory implCode =
            abi.encodePacked(type(ShrincsPaymaster).creationCode, abi.encode(SHRINCS_EXTERNAL_VERIFIER));
        address impl = _create3(deployer, pk, implCode, SHRINCS_PAYMASTER_IMPL_SALT, "ShrincsPaymaster impl");
        bytes memory initData = abi.encodeCall(
            ShrincsPaymaster.initialize, (v.paymasterOwner, v.commitment, v.hashSuite, v.maxSignatures)
        );
        bytes memory proxyCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
        proxy = _create3(deployer, pk, proxyCode, SHRINCS_PAYMASTER_PROXY_SALT, "ShrincsPaymaster proxy");
        require(ShrincsPaymaster(payable(proxy)).owner() == v.paymasterOwner, "ShrincsPaymaster owner mismatch");
    }

    /// Full Shrincs family deploy against an existing shared `factory`.
    function _deployShrincsAll(Deployer deployer, uint256 pk, address factory, ShrincsVerifier memory v) internal {
        _deployShrincsImplAndVet(deployer, pk, factory);
        _deployShrincsPaymaster(deployer, pk, v);
    }
}
