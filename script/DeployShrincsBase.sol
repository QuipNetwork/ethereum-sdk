// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {SHRINCS256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS256sKeccak.sol";
import {Deployer} from "../contracts/Deployer.sol";
import {ShrincsPaymaster} from "../contracts/ShrincsPaymaster.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
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
 *      `script/PredictAddresses.s.sol` (V1.1 — bumped for the external-verifier
 *      implementations; CREATE3 reuses an address per salt, so new impl code
 *      needs a new salt on chains that already hold the V1.0 deploys).
 */
abstract contract DeployShrincsBase is DeployHelpers {
    /// Canonical CREATE3 address of the deployed `SHRINCS256sKeccak` ERC-7913 verifier
    /// (hashsigs-solidity `DEPLOYMENTS.md`; same address on every chain). Pinned as an
    /// immutable by the ShrincsWallet and ShrincsPaymaster implementation constructors.
    /// A fresh chain must FIRST run the dep's own CREATE3 deploys — sibling before
    /// SHRINCS (`SHRINCSVerifier.verifyStateless` reverts on empty sibling code):
    ///   FOUNDRY_PROFILE=production forge script script/DeploySPHINCSPlusC256sKeccak.s.sol ...
    ///   FOUNDRY_PROFILE=production forge script script/DeploySHRINCS256sKeccak.s.sol ...
    /// (full commands in the dep's `DEPLOYMENTS.md`).
    address internal constant SHRINCS_EXTERNAL_VERIFIER = 0xb76f5acfa4f1e993b36C9c72eD7514eC2c80F00A;

    /// Both implementation salts bind the verifier scheme identifier — the
    /// constant `PROFILE_TAG()` the deployed verifier exposes to differentiate
    /// cryptographic schemes (== `SHRINCSParams.PROFILE_ID`, the hash of
    /// "shrincs-256s-keccak" under this build's `shrincs-profile/` remapping).
    /// The impls hard-pin the verifier as an immutable, so an impl built against
    /// a different scheme MUST land at a different CREATE3 address; folding the
    /// tag into the salt makes that structural instead of relying on a manual
    /// version bump. `_requireExpectedVerifierScheme` cross-checks the live
    /// verifier at deploy time.
    bytes32 internal constant SHRINCS_WALLET_SALT =
        keccak256(abi.encodePacked("QUIP:ShrincsWallet:V1.1:", SHRINCSParams.PROFILE_ID));
    bytes32 internal constant SHRINCS_PAYMASTER_IMPL_SALT =
        keccak256(abi.encodePacked("QUIP:ShrincsPaymaster:Impl:V1.1:", SHRINCSParams.PROFILE_ID));
    // Proxy salt bumped WITH the impl: SHRINCS is testnet-only, so a fresh proxy
    // (re-initialized from env) is simpler than a UUPS upgrade of the V1.0 proxy.
    // (No PROFILE_TAG: the ERC-1967 proxy is scheme-agnostic — schemes change
    // under it via impl deploys.)
    bytes32 internal constant SHRINCS_PAYMASTER_PROXY_SALT = keccak256("QUIP:ShrincsPaymaster:Proxy:V1.1");

    /// The hardcoded verifier address must actually host the scheme the impls
    /// (and the salts above) were built for: read the deployed verifier's
    /// constant `PROFILE_TAG()` and require it to match this build's profile.
    function _requireExpectedVerifierScheme() internal view {
        _requireExists(SHRINCS_EXTERNAL_VERIFIER, "SHRINCS256sKeccak");
        require(
            SHRINCS256sKeccak(SHRINCS_EXTERNAL_VERIFIER).PROFILE_TAG() == SHRINCSParams.PROFILE_ID,
            "SHRINCS verifier scheme mismatch"
        );
    }

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
        _requireExpectedVerifierScheme();
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
        _requireExpectedVerifierScheme();

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
