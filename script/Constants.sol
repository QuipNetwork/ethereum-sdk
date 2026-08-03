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

    /// The one account every LIVE canonical address derives from (sender-guarded
    /// salts: address = f(CreateX, operator, preimage)).
    ///
    /// PINNED, not read from the environment, on purpose. The scripts also check
    /// `vm.addr(PRIVATE_KEY) == DEPLOY_OPERATOR`, but that only proves the key and
    /// the env var agree with EACH OTHER: a stale or mistyped `DEPLOY_OPERATOR`
    /// plus its matching key predicts, deploys, and self-asserts a perfectly
    /// consistent result — at a DIFFERENT address than the one `DEPLOYMENTS.md`
    /// and the SDK publish. Comparing against this constant is what makes that
    /// failure loud instead of silent.
    ///
    /// Changing it re-derives EVERY live address: bump the constant, re-run
    /// `PredictAddresses`, regenerate the SDK (`make release`), and update
    /// `DEPLOYMENTS.md` + `src/v1/shrincs/addresses.ts` together.
    address internal constant CANONICAL_OPERATOR = 0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26;

    /// Canonical CREATE3 address of the deployed `SHRINCS256sKeccak` ERC-7913
    /// verifier (hashsigs-solidity `DEPLOYMENTS.md`), pinned as an immutable by
    /// the ShrincsWallet and ShrincsPaymaster implementation constructors.
    ///
    /// A fresh chain must FIRST run the dep's own CreateX deploys — sibling
    /// before SHRINCS (`SHRINCSVerifier.verifyStateless` reverts on empty sibling
    /// code):
    ///   FOUNDRY_PROFILE=production forge script script/DeploySPHINCSPlusC256sKeccak.s.sol ...
    ///   FOUNDRY_PROFILE=production forge script script/DeploySHRINCS256sKeccak.s.sol ...
    /// (full commands in the dep's `DEPLOYMENTS.md`). Live on Base mainnet
    /// (8453); its stateless delegate is `0x97B3726F44e3B7521199CE4e0fC160A32A597d31`.
    address internal constant SHRINCS_EXTERNAL_VERIFIER =
        0xE6F2970bA30d59e8288b7007bA755828372457c3;

    // ── Versions ─────────────────────────────────────────────────────
    //
    // ONE SCHEME, TWO SUFFIXES, applied uniformly:
    //   proxies          V1.0.0        — the permanent public identity. A proxy
    //                                    address is meant never to move again;
    //                                    code changes happen under it via UUPS.
    //   implementations  V1.0.0-beta   — the churning half. Impls are replaced
    //                                    (new verifier, new code, new vetting),
    //                                    so they carry the prerelease suffix.
    //
    // Salt strings are OPAQUE preimages — only uniqueness matters, so the split
    // is legibility, not semantics. `V1.0.0` is not "newer than" `V1.0.0-beta`;
    // they name different roles.
    //
    // This generation replaces the mixed V1.0.0-beta / V1.1 / V1.0.1-beta set,
    // which is retired: the Shrincs impls had to move regardless (the verifier
    // address they bake in as an immutable changed — see
    // SHRINCS_EXTERNAL_VERIFIER above), and the rest follows for consistency.
    // The prior generation stays live on Base Sepolia and OP Sepolia at its own
    // addresses; those preimages are permanently occupied there and must never
    // be reused. See DEPLOYMENTS.md.

    string internal constant PROXY_VERSION = "V1.0.0";
    string internal constant IMPL_VERSION = "V1.0.0-beta";

    // ── Salt preimages (sender-guarded CreateX CREATE3) ──────────────
    // The deployed address is a function of (CreateX, DEPLOY_OPERATOR,
    // preimage) — identical on every chain for the same operator.

    string internal constant FACTORY_IMPL_SALT = "QUIP:WalletFactory:Impl:V1.0.0-beta";
    string internal constant FACTORY_PROXY_SALT = "QUIP:WalletFactory:Proxy:V1.0.0";

    // (No PROFILE_TAG on proxy salts: an ERC-1967 proxy is scheme-agnostic —
    // schemes change under it via impl deploys.)
    string internal constant SHRINCS_PAYMASTER_PROXY_SALT =
        "QUIP:ShrincsPaymaster:Proxy:V1.0.0";

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
        return abi.encodePacked("QUIP:ShrincsWallet:Impl:V1.0.0-beta:", SHRINCSParams.PROFILE_ID);
    }

    function shrincsPaymasterImplSalt() internal pure returns (bytes memory) {
        return abi.encodePacked(
            "QUIP:ShrincsPaymaster:Impl:V1.0.0-beta:", SHRINCSParams.PROFILE_ID
        );
    }
}
