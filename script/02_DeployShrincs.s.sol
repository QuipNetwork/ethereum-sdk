// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {DeployConstants} from "./Constants.sol";
import {DeployFactoryBase} from "./DeployFactoryBase.sol";
import {DeployShrincsBase} from "./DeployShrincsBase.sol";
import {IVettingFactory} from "./DeployHelpers.sol";

/**
 * @title DeployShrincs
 * @dev STEP 2 of 2 (run `01_DeployFactory.s.sol` first). Deploys the full
 *      Shrincs family straight through CreateX (sender-guarded CREATE3): the
 *      ShrincsWallet impl (vetted on the shared WalletFactory) and the
 *      ShrincsPaymaster (impl + proxy, initialized with its verifier key).
 *      Idempotent. The Shrincs contracts have no library links, so this needs
 *      no `FOUNDRY_PROFILE=deploy`.
 *
 *      The WalletFactory is located EXCLUSIVELY at its canonical address,
 *      derived from (CreateX, DEPLOY_OPERATOR, proxy salt) — the same
 *      derivation `01_DeployFactory` deploys to. There is deliberately NO
 *      env override: a stale/wrong variable must never be able to redirect a
 *      broadcast (foundry auto-loads `.env`). Deploying against a
 *      non-canonical factory is a code change, not a config change.
 *
 *      Before broadcasting anything the script proves the factory is ours:
 *      code exists at the canonical address, it is an ERC-1967 proxy, and its
 *      owner is the operator (vetting is `onlyOwner` — without this check a
 *      wrong owner would fail mid-run, after the impl deploy).
 *
 *      Vetting the ShrincsWallet sets the factory's `latestWalletImpl` to it —
 *      the intended end state now that the WOTS+ family is sunset.
 *
 * Usage:
 *   forge script script/02_DeployShrincs.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY                     - Factory-owner key; MUST be DEPLOY_OPERATOR's
 *   DEPLOY_OPERATOR                 - Canonical deploy operator (sender-guarded salts)
 *   SHRINCS_PAYMASTER_OWNER         - Initial ShrincsPaymaster proxy owner
 *   SHRINCS_VERIFIER_PUBLIC_KEY     - abi-encoded SHRINCS.PublicKey bundle (from
 *                                     scripts/gen-shrincs-paymaster-verifier.mjs);
 *                                     commitment + leaf budget are derived from it
 *   SHRINCS_VERIFIER_HASH_SUITE     - Optional; defaults to the keccak suite id
 */
contract DeployShrincs is DeployShrincsBase, DeployFactoryBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address operator = vm.envAddress("DEPLOY_OPERATOR");

        // Fail fast, before any deploy step runs half-way.
        require(vm.addr(pk) == operator, "PRIVATE_KEY is not DEPLOY_OPERATOR's key");
        require(CREATEX.code.length > 0, "CreateX not deployed on this chain");

        // The canonical factory address is a pure function of the operator —
        // exactly what 01_DeployFactory deploys. No env override, ever.
        address factory = _predictCreateX(operator, bytes(DeployConstants.FACTORY_PROXY_SALT));
        require(
            factory.code.length > 0,
            "WalletFactory not found at canonical address - run 01_DeployFactory first"
        );
        // Prove the code there is OUR factory before broadcasting anything:
        // an ERC-1967 proxy whose owner is the operator. (Vetting is
        // `onlyOwner` — without this a wrong owner fails mid-run, after the
        // impl deploy.)
        require(
            vm.load(factory, ERC1967_IMPL_SLOT) != bytes32(0),
            "canonical factory address does not host an ERC-1967 proxy"
        );
        require(
            IVettingFactory(factory).owner() == operator,
            "DEPLOY_OPERATOR is not the factory owner (vetting is onlyOwner)"
        );

        console.log("=== 02_DeployShrincs ===");
        console.log("CreateX:        ", CREATEX);
        console.log("Deploy operator:", operator);
        console.log("WalletFactory (canonical, derived):", factory);

        address impl = _deployShrincsImplAndVet(operator, pk, factory);
        address paymaster = _deployShrincsPaymaster(operator, pk, _shrincsVerifierFromEnv());

        IVettingFactory f = IVettingFactory(factory);
        require(f.getVettedCodeIndex(impl.codehash) != NOT_VETTED, "ShrincsWallet not vetted");
        address latest = f.latestWalletImpl();
        if (latest != impl) {
            // A newer impl may legitimately have been vetted after this build's —
            // surface it loudly, but keep re-runs idempotent (no revert).
            console.log("WARNING: latestWalletImpl is not this build's ShrincsWallet");
        }

        console.log("=== 02_DeployShrincs done ===");
        console.log("WalletFactory:          ", factory);
        console.log("ShrincsWallet impl:     ", impl);
        console.log("ShrincsPaymaster proxy: ", paymaster);
        console.log("latestWalletImpl:       ", latest);
    }
}
