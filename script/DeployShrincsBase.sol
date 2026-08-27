// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SHRINCS256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS256sKeccak.sol";
import {ShrincsPaymaster} from "../contracts/ShrincsPaymaster.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWallet} from "../contracts/shrincs/ShrincsWallet.sol";
import {DeployConstants} from "./Constants.sol";
import {CreateXHelpers} from "./CreateXHelpers.sol";
import {DeployHelpers} from "./DeployHelpers.sol";

/// Getter surface used for the post-deploy identity checks. Both members are
/// public immutables, whose auto-generated getters have no `.selector` on the
/// contract type — hence this minimal interface.
interface IShrincsIdentity {
    function FACTORY() external view returns (address);
    function SHRINCS_VERIFIER() external view returns (address);
}

/**
 * @title DeployShrincsBase
 * @dev Shrincs family deploy steps (used by `02_DeployShrincs.s.sol` and the
 *      deploy tests): the ShrincsWallet impl (+ vetting on the shared
 *      WalletFactory), and the ShrincsPaymaster (impl + proxy, initialized with
 *      its verifier key).
 *
 *      The Shrincs contracts have NO library link references, so an inheritor that
 *      deploys ONLY Shrincs needs no `FOUNDRY_PROFILE=deploy`. The shared
 *      WalletFactory must already exist. Deploys go straight through CreateX with
 *      sender-guarded salts (`CreateXHelpers`) — addresses are a function of
 *      (CreateX, DEPLOY_OPERATOR, salt preimage). Salts and the pinned external
 *      verifier live in `DeployConstants` (V1.1 — bumped for the
 *      external-verifier implementations; CREATE3 reuses an address per salt, so
 *      new impl code needs a new salt on chains that already hold the V1.0
 *      deploys).
 */
abstract contract DeployShrincsBase is DeployHelpers, CreateXHelpers {
    /// The pinned verifier address must actually host the scheme the impls
    /// (and the salts in `DeployConstants`) were built for: read the deployed
    /// verifier's constant `PROFILE_TAG()` and require it to match this
    /// build's profile.
    function _requireExpectedVerifierScheme() internal view {
        _requireExists(DeployConstants.SHRINCS_EXTERNAL_VERIFIER, "SHRINCS256sKeccak");
        require(
            SHRINCS256sKeccak(DeployConstants.SHRINCS_EXTERNAL_VERIFIER).PROFILE_TAG()
                == SHRINCSParams.PROFILE_ID,
            "SHRINCS verifier scheme mismatch"
        );
    }

    /// Verifier-key parameters the ShrincsPaymaster bakes in at `initialize`. The
    /// full public-key bundle is required — `initialize` derives the commitment and
    /// the stateful leaf budget from it on-chain (the budget is never a trusted
    /// free parameter).
    struct ShrincsVerifier {
        address paymasterOwner;
        SHRINCS.PublicKey publicKey;
        uint32 hashSuite;
    }

    /// Read the ShrincsPaymaster verifier-key config from the environment.
    /// `SHRINCS_VERIFIER_PUBLIC_KEY` is the abi-encoded `SHRINCS.PublicKey` tuple
    /// emitted by `scripts/gen-shrincs-paymaster-verifier.mjs`.
    /// `SHRINCS_VERIFIER_HASH_SUITE` defaults to `HASH_SUITE_KECCAK_256` (the only
    /// suite the on-chain library verifies).
    function _shrincsVerifierFromEnv() internal view returns (ShrincsVerifier memory v) {
        v = ShrincsVerifier({
            paymasterOwner: vm.envAddress("SHRINCS_PAYMASTER_OWNER"),
            publicKey: abi.decode(vm.envBytes("SHRINCS_VERIFIER_PUBLIC_KEY"), (SHRINCS.PublicKey)),
            hashSuite: uint32(
                vm.envOr("SHRINCS_VERIFIER_HASH_SUITE", uint256(HashSuite.HASH_SUITE_ID))
            )
        });
    }

    /// Deploy + vet the ShrincsWallet impl against `factory`. Vetting sets
    /// `latestWalletImpl` to this impl — the intended end state of a fresh
    /// deploy now that the WOTS+ family is sunset. (The Shrincs SDK always
    /// uses `deploySpecificWalletProxy`, so it is order-independent anyway.)
    function _deployShrincsImplAndVet(address operator, uint256 pk, address factory)
        internal
        returns (address impl)
    {
        _requireExists(factory, "WalletFactory");
        _requireExpectedVerifierScheme();
        bytes memory code = abi.encodePacked(
            type(ShrincsWallet).creationCode,
            abi.encode(factory, DeployConstants.SHRINCS_EXTERNAL_VERIFIER)
        );
        impl = _createXDeploy(
            operator, pk, code, DeployConstants.shrincsWalletSalt(), "ShrincsWallet"
        );
        // Identity, on both the fresh and the idempotent-skip path: both are
        // constructor-set immutables, so this proves we are about to VET this
        // build's wallet and not a stale impl left at the canonical address by an
        // earlier partial run (vetting also sets `latestWalletImpl`).
        require(
            _readAddress(impl, IShrincsIdentity.FACTORY.selector, "ShrincsWallet") == factory,
            "ShrincsWallet: FACTORY immutable does not match the canonical factory"
        );
        require(
            _readAddress(impl, IShrincsIdentity.SHRINCS_VERIFIER.selector, "ShrincsWallet")
                == DeployConstants.SHRINCS_EXTERNAL_VERIFIER,
            "ShrincsWallet: SHRINCS_VERIFIER immutable does not match the pinned verifier"
        );
        _vetIfNeeded(factory, pk, impl, "ShrincsWallet");
    }

    function _deployShrincsPaymaster(address operator, uint256 pk, ShrincsVerifier memory v)
        internal
        returns (address proxy)
    {
        require(v.paymasterOwner != address(0), "SHRINCS paymaster owner zero");
        // Shallow shape check only: `initialize` performs the deep validation
        // (embedded-commitment recompute + budget decode) during forge's
        // pre-broadcast simulation, so a malformed bundle fails before any tx.
        require(v.publicKey.publicKeyCommitment.length == 32, "SHRINCS verifier public key malformed");
        _requireExpectedVerifierScheme();

        bytes memory implCode = abi.encodePacked(
            type(ShrincsPaymaster).creationCode,
            abi.encode(DeployConstants.SHRINCS_EXTERNAL_VERIFIER)
        );
        address impl = _createXDeploy(
            operator,
            pk,
            implCode,
            DeployConstants.shrincsPaymasterImplSalt(),
            "ShrincsPaymaster impl"
        );
        // Identity, on both the fresh and the idempotent-skip path: the verifier is
        // a constructor-set immutable, so this proves the proxy below is about to
        // delegate to THIS build's implementation.
        require(
            _readAddress(impl, IShrincsIdentity.SHRINCS_VERIFIER.selector, "ShrincsPaymaster impl")
                == DeployConstants.SHRINCS_EXTERNAL_VERIFIER,
            "ShrincsPaymaster impl: SHRINCS_VERIFIER immutable does not match the pinned verifier"
        );
        bytes memory initData = abi.encodeCall(
            ShrincsPaymaster.initialize,
            (v.paymasterOwner, v.publicKey, v.hashSuite)
        );
        bytes memory proxyCode =
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
        proxy = _createXDeploy(
            operator,
            pk,
            proxyCode,
            bytes(DeployConstants.SHRINCS_PAYMASTER_PROXY_SALT),
            "ShrincsPaymaster proxy"
        );
        // Identity before the owner check: on the idempotent-skip path the owner
        // read alone would happily accept any contract that answers `owner()`.
        _assertErc1967Proxy(proxy, impl, "ShrincsPaymaster proxy");
        require(
            ShrincsPaymaster(payable(proxy)).owner() == v.paymasterOwner,
            "ShrincsPaymaster owner mismatch"
        );
    }
}
