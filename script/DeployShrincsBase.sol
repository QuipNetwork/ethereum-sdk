// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
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
 *      verifier live in `DeployConstants` — proxies at `V1.0.0` (permanent
 *      identity), implementations at `V1.0.0-beta` (rev'd when the verifier or
 *      impl code changes; CREATE3 reuses an address per salt, so new impl code
 *      needs a new salt on chains that already hold the prior deploys).
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
        // In-place upgrade path: the proxy already exists (idempotent skip) but
        // delegates to an earlier impl of this generation. Storage is ERC-7201
        // append-only, so a plain UUPS upgrade with no re-init moves it to THIS
        // build's impl.
        //
        // The upgrade is direction-blind on its own — it would move the proxy to
        // whatever impl the CHECKOUT BEING RUN builds — so it is gated twice:
        //  1. `current` must be a predecessor this build knows (the retired
        //     `-beta.1` impl). Re-running an older checkout against an upgraded
        //     proxy therefore reverts instead of silently downgrading it.
        //  2. `_authorizeUpgrade` is `onlyOwner`. The paymaster owner is meant to
        //     become a post-quantum wallet, which the deploy key is not, so a
        //     non-owner broadcaster SKIPS the upgrade with the exact call to hand
        //     to the owner. The whole deploy must stay runnable after ownership
        //     moves; `_assertErc1967Proxy` below reports the still-stale impl.
        address current = _erc1967Impl(proxy);
        if (current != impl) {
            require(current != address(0), "ShrincsPaymaster proxy: not an ERC-1967 proxy");
            require(
                current == DeployConstants.RETIRED_SHRINCS_PAYMASTER_IMPL_BETA1,
                "ShrincsPaymaster proxy: live impl is neither this build nor a known predecessor"
            );
            address proxyOwner = ShrincsPaymaster(payable(proxy)).owner();
            if (proxyOwner == vm.addr(pk)) {
                vm.startBroadcast(pk);
                ShrincsPaymaster(payable(proxy)).upgradeToAndCall(impl, "");
                vm.stopBroadcast();
                console.log("  - ShrincsPaymaster proxy upgraded from:", current);
                console.log("  - ShrincsPaymaster proxy upgraded to:  ", impl);
            } else {
                console.log("  - WARNING: ShrincsPaymaster proxy upgrade SKIPPED.");
                console.log("    The broadcast key is not the proxy owner, and the upgrade is onlyOwner.");
                console.log("    The owner must send upgradeToAndCall(impl, \"\") to proxy:", proxy);
                console.log("    impl argument:", impl);
                console.log("    owner that must send it:", proxyOwner);
            }
        }
        // Final identity gate, on every path: fresh deploy, idempotent skip,
        // just-upgraded, and upgrade-skipped. It requires a non-zero ERC-1967
        // implementation slot, which foreign code that merely answers `owner()`
        // would not have, and it REPORTS rather than rejects a divergent impl —
        // the skipped-upgrade path above deliberately leaves the proxy on its
        // predecessor.
        _assertErc1967Proxy(proxy, impl, "ShrincsPaymaster proxy");
        require(
            ShrincsPaymaster(payable(proxy)).owner() == v.paymasterOwner,
            "ShrincsPaymaster owner mismatch"
        );
    }
}
