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
    /// (full commands in the dep's `DEPLOYMENTS.md`).
    ///
    /// This is the V4 verifier (`QUIP:SHRINCS256sKeccak:V4.0`, hashsigs-solidity
    /// MR !26 — raw ERC-7913 signatures bound to the full public-key commitment)
    /// with its stateless delegate `QUIP:SPHINCSPlusC256sKeccak:V3.0` at
    /// `0xe52707C5D76E2F7c3314cF3dcc340eB9BbAE3864`. Live on Base Sepolia
    /// (84532) and OP Sepolia (11155420) since 2026-08-27 — runtime codehashes
    /// match the dep's DEPLOYMENTS.md (`0xe9319929…` / `0xe8d1cd07…`); not yet
    /// on Base mainnet, where `02_DeployShrincs` refuses to broadcast until
    /// hashsigs-solidity has deployed the pair. The previous (V2) pair, live on
    /// all three chains, is `0xE6F2970bA30d59e8288b7007bA755828372457c3` +
    /// `0x97B3726F44e3B7521199CE4e0fC160A32A597d31`; see DEPLOYMENTS.md.
    address internal constant SHRINCS_EXTERNAL_VERIFIER =
        0xF2f9E6D692da41b089c3c261c41509669eEc5567;

    // ── Versions ─────────────────────────────────────────────────────
    //
    // ONE SCHEME, TWO SUFFIXES, applied uniformly:
    //   proxies          V1.0.1        — the public identity of a generation.
    //                                    Plain version, no prerelease suffix:
    //                                    a proxy is just a proxy, code changes
    //                                    happen under it via UUPS.
    //   implementations  V1.0.1-beta.1.N — the churning half. Impls are replaced
    //                                    (new verifier, new code, new vetting),
    //                                    so they carry the prerelease suffix,
    //                                    bumped npm-style (`-beta`, `-beta.1`,
    //                                    `-beta.2`, ...) on every relocation
    //                                    within a generation.
    //
    // Salt strings are OPAQUE preimages — only uniqueness matters, so the split
    // is legibility, not semantics. `V1.0.1` is not "newer than" `V1.0.1-beta.1`;
    // they name different roles.
    //
    // V1.0.1 is a full redeploy of every contract, everywhere. The V1.0.0 /
    // V1.0.0-beta generation (Base mainnet, Base Sepolia, OP Sepolia) was a
    // production-testing deployment and is retired whole: the V4 verifier
    // relocated (SHRINCS_EXTERNAL_VERIFIER above), the WalletFactory code
    // changed since the 2026-08-03 deploy (e3r commitment-bound deploy salts,
    // deploy authorization, codehash deprecation), and rather than upgrade the
    // old proxies in place we move the proxies too, so every wallet address
    // derives fresh from the new factory. Impls start at `-beta.1`, not
    // `-beta`: `QUIP:ShrincsPaymaster:Impl:V1.0.1-beta:` was already consumed
    // on the testnets, and the suffix is kept uniform across impls. CREATE3 ignores
    // initcode and `CreateXHelpers` skips an occupied address, so every retired
    // preimage must never be reused — see DEPLOYMENTS.md.
    //
    // `-beta.2` (Shrincs impls only): the spent-tree registries fix (a stateful
    // or stateless tree can never be re-installed on a wallet/paymaster —
    // INVARIANTS §25). Storage is ERC-7201 append-only, so the proxies stay put
    // and `02_DeployShrincs` upgrades them in place on chains that already hold
    // the generation; on a fresh chain (Base mainnet) it lands as the first
    // impl. The WalletFactory code did not change, so its impl salt stays at
    // `-beta.1`. Retired impl addresses live in DEPLOYMENTS.md.

    string internal constant PROXY_VERSION = "V1.0.1";
    string internal constant IMPL_VERSION = "V1.0.1-beta.2";

    // ── Salt preimages (sender-guarded CreateX CREATE3) ──────────────
    // The deployed address is a function of (CreateX, DEPLOY_OPERATOR,
    // preimage) — identical on every chain for the same operator.

    string internal constant FACTORY_IMPL_SALT = "QUIP:WalletFactory:Impl:V1.0.1-beta.1";
    string internal constant FACTORY_PROXY_SALT = "QUIP:WalletFactory:Proxy:V1.0.1";

    // (No PROFILE_TAG on proxy salts: an ERC-1967 proxy is scheme-agnostic —
    // schemes change under it via impl deploys.)
    string internal constant SHRINCS_PAYMASTER_PROXY_SALT =
        "QUIP:ShrincsPaymaster:Proxy:V1.0.1";

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
        return abi.encodePacked("QUIP:ShrincsWallet:Impl:V1.0.1-beta.2:", SHRINCSParams.PROFILE_ID);
    }

    function shrincsPaymasterImplSalt() internal pure returns (bytes memory) {
        return abi.encodePacked(
            "QUIP:ShrincsPaymaster:Impl:V1.0.1-beta.2:", SHRINCSParams.PROFILE_ID
        );
    }
}
