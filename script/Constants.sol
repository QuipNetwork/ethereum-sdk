// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

/**
 * @title DeployConstants
 * @dev Single source of truth for every LIVE deployment constant: pinned
 *      singleton addresses, contract versions, and CREATE3 salt preimages.
 *      The deploy bases, the numbered entrypoints (`01_DeployFactory`,
 *      `02_DeployShrincs`) and `PredictAddresses` all read from here.
 *
 *      Deliberately NOT covered:
 *      - `script/deprecated/` (sunset WOTS+ family) keeps its own frozen salts.
 *      - `test/script/Deploy.t.sol` keeps independent literal copies as a
 *        tripwire — a drift here fails its address asserts.
 *
 *      NOTE: the salt strings repeat the version literals on purpose —
 *      `string.concat` is not allowed in constant initializers, and turning
 *      the salts into runtime-composed functions would weaken the "grep for
 *      the exact preimage" property. Keep versions and salts in sync by hand.
 */
library DeployConstants {
    // ── Pinned singletons ────────────────────────────────────────────

    /// Canonical CreateX singleton. Same address on every chain
    /// (Nick's-method presigned deployment).
    address internal constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

    /// Canonical CREATE3 address of the deployed `SHRINCS256sKeccak` ERC-7913
    /// verifier (hashsigs-solidity `DEPLOYMENTS.md`; same address on every
    /// chain). Pinned as an immutable by the ShrincsWallet and ShrincsPaymaster
    /// implementation constructors. A fresh chain must FIRST run the dep's own
    /// CreateX deploys — sibling before SHRINCS (`SHRINCSVerifier.verifyStateless`
    /// reverts on empty sibling code):
    ///   FOUNDRY_PROFILE=production forge script script/DeploySPHINCSPlusC256sKeccak.s.sol ...
    ///   FOUNDRY_PROFILE=production forge script script/DeploySHRINCS256sKeccak.s.sol ...
    /// (full commands in the dep's `DEPLOYMENTS.md`).
    address internal constant SHRINCS_EXTERNAL_VERIFIER = 0x9154dA0BA19600C543a8c5ed1B1c44af415B5688;

    // ── Versions ─────────────────────────────────────────────────────

    string internal constant FACTORY_VERSION = "V1.0.0-beta";

    // The wallet and the paymaster version INDEPENDENTLY — each contract's salt
    // moves only when its own bytecode does. The wallet is unchanged since its
    // V1.1 deploy; the paymaster rolled to V1.0.1-beta when `initialize` began
    // taking the full public-key bundle (the commitment + leaf budget are now
    // derived on-chain rather than passed in), which changed its bytecode.
    // V1.0.1-beta is NOT "newer than" V1.1 as a version string — it re-bases the
    // paymaster onto the same `-beta` scheme the factory already uses. Salts are
    // opaque preimages, so only uniqueness matters.
    string internal constant SHRINCS_WALLET_VERSION = "V1.1";
    string internal constant SHRINCS_PAYMASTER_VERSION = "V1.0.1-beta";

    // ── Salt preimages (sender-guarded CreateX CREATE3) ──────────────
    // The deployed address is a function of (CreateX, DEPLOY_OPERATOR,
    // preimage) — identical on every chain for the same operator.

    string internal constant FACTORY_IMPL_SALT = "QUIP:WalletFactory:Impl:V1.0.0-beta";
    string internal constant FACTORY_PROXY_SALT = "QUIP:WalletFactory:Proxy:V1.0.0-beta";

    // Proxy salt bumped WITH the impl: SHRINCS is testnet-only, so a fresh proxy
    // (re-initialized from env) is simpler than a UUPS upgrade of the live one.
    // (No PROFILE_TAG: the ERC-1967 proxy is scheme-agnostic — schemes change
    // under it via impl deploys.)
    // The retired V1.1 pair stays live on Base Sepolia running the pre-rework
    // code; see DEPLOYMENTS.md. Do NOT reuse those preimages — their CREATE3
    // addresses are permanently occupied there.
    string internal constant SHRINCS_PAYMASTER_PROXY_SALT =
        "QUIP:ShrincsPaymaster:Proxy:V1.0.1-beta";

    /// Both implementation salts bind the verifier scheme identifier — the
    /// constant `PROFILE_TAG()` the deployed verifier exposes to differentiate
    /// cryptographic schemes (== `SHRINCSParams.PROFILE_ID`, the hash of
    /// "shrincs-256s-keccak" under this build's `shrincs-profile/` remapping).
    /// The impls hard-pin the verifier as an immutable, so an impl built against
    /// a different scheme MUST land at a different CREATE3 address; folding the
    /// tag into the salt makes that structural instead of relying on a manual
    /// version bump. `DeployShrincsBase._requireExpectedVerifierScheme`
    /// cross-checks the live verifier at deploy time.
    function shrincsWalletSalt() internal pure returns (bytes memory) {
        return abi.encodePacked("QUIP:ShrincsWallet:V1.1:", SHRINCSParams.PROFILE_ID);
    }

    function shrincsPaymasterImplSalt() internal pure returns (bytes memory) {
        return abi.encodePacked(
            "QUIP:ShrincsPaymaster:Impl:V1.0.1-beta:", SHRINCSParams.PROFILE_ID
        );
    }
}
