// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {DeployConstants} from "./Constants.sol";
import {DeployShrincsBase} from "./DeployShrincsBase.sol";
import {IVettingFactory} from "./DeployHelpers.sol";

/**
 * @title DeployShrincsWallet
 * @dev Ops utility: deploys the ShrincsWallet impl and vets it on the shared
 *      WalletFactory — the wallet half of `02_DeployShrincs.s.sol`, with no
 *      ShrincsPaymaster. Use it on a chain that needs user wallets but not gas
 *      sponsorship: vetting sets `latestWalletImpl`, which is what makes
 *      `deployLatestWalletProxy` resolve. Idempotent, and it lands on the same
 *      canonical address as `02` (same salt, same helper), so a later full `02`
 *      run on the same chain skips the impl and only adds the paymaster.
 *
 *      Unnumbered on purpose: the numbered scripts are the canonical two-step
 *      pipeline, this is an alternative step 2 — not a step 3.
 *
 *      Like `02`, the WalletFactory is located EXCLUSIVELY at its canonical
 *      address, derived from (CreateX, DEPLOY_OPERATOR, proxy salt). There is
 *      deliberately NO env override: a stale variable must never be able to
 *      redirect a broadcast (foundry auto-loads `.env`). Deploying against a
 *      non-canonical factory is a code change, not a config change.
 *
 *      The Shrincs contracts link no libraries, so this needs no
 *      `FOUNDRY_PROFILE=deploy`.
 *
 * Usage:
 *   forge script script/DeployShrincsWallet.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      - Factory-owner key; MUST be DEPLOY_OPERATOR's (vetting is onlyOwner)
 *   DEPLOY_OPERATOR  - Canonical deploy operator (sender-guarded salts)
 */
contract DeployShrincsWallet is DeployShrincsBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address operator = vm.envAddress("DEPLOY_OPERATOR");

        // Fail fast, before any deploy step runs half-way. The canonical-operator
        // check comes FIRST: the key check below only proves the env var and the
        // key agree with each other, which a stale operator would also satisfy.
        require(
            operator == DeployConstants.CANONICAL_OPERATOR,
            "DEPLOY_OPERATOR is not the canonical operator"
        );
        require(vm.addr(pk) == operator, "PRIVATE_KEY is not DEPLOY_OPERATOR's key");
        require(CREATEX.code.length > 0, "CreateX not deployed on this chain");

        // The canonical factory address is a pure function of the operator —
        // exactly what 01_DeployFactory deploys. No env override, ever.
        address factory = _predictCreateX(operator, bytes(DeployConstants.FACTORY_PROXY_SALT));
        require(
            factory.code.length > 0,
            "WalletFactory not found at canonical address - run 01_DeployFactory first"
        );
        // Prove the code there is OUR factory before broadcasting anything: an
        // ERC-1967 proxy whose owner is the operator. (Vetting is `onlyOwner` —
        // without this a wrong owner fails mid-run, after the impl deploy.)
        require(
            vm.load(factory, ERC1967_IMPL_SLOT) != bytes32(0),
            "canonical factory address does not host an ERC-1967 proxy"
        );
        require(
            IVettingFactory(factory).owner() == operator,
            "DEPLOY_OPERATOR is not the factory owner (vetting is onlyOwner)"
        );

        console.log("=== DeployShrincsWallet ===");
        console.log("CreateX:        ", CREATEX);
        console.log("Deploy operator:", operator);
        console.log("WalletFactory (canonical, derived):", factory);

        address impl = _deployShrincsImplAndVet(operator, pk, factory);

        IVettingFactory f = IVettingFactory(factory);
        require(f.getVettedCodeIndex(impl.codehash) != NOT_VETTED, "ShrincsWallet not vetted");
        address latest = f.latestWalletImpl();
        if (latest != impl) {
            // A newer impl may legitimately have been vetted after this build's —
            // surface it loudly, but keep re-runs idempotent (no revert).
            console.log("WARNING: latestWalletImpl is not this build's ShrincsWallet");
        }

        console.log("=== DeployShrincsWallet done ===");
        console.log("WalletFactory:      ", factory);
        console.log("ShrincsWallet impl: ", impl);
        console.log("latestWalletImpl:   ", latest);
        console.log("No ShrincsPaymaster deployed - run 02_DeployShrincs for sponsorship.");
    }
}
