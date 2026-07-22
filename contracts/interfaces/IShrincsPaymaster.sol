// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

// prettier-ignore
import {IPaymaster} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";

/// @title IShrincsPaymaster
/// @notice An ERC-4337 verifying paymaster that authorizes gas sponsorship with a single global
///         SHRINCS stateful verifier key. The paymaster operator (the sponsor) holds one key and
///         signs every userOp it is willing to sponsor; the sponsorship signature is bound to the
///         specific userOp (including `userOp.sender`), so one key safely covers all wallets.
///         Anti-replay is a keyVersion-namespaced used-leaf bitmap: each stateful leaf is
///         consumable once, in ANY order, so out-of-order userOp landing never reverts.
interface IShrincsPaymaster is IPaymaster {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ERRORS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when the owner address is zero.
    error ZeroAddressOwner();
    /// @notice Thrown when the external SHRINCS verifier address is zero at implementation
    ///         deployment.
    error ZeroAddressVerifier();
    /// @notice Thrown when the caller is not the ERC-4337 EntryPoint.
    error InvalidEntryPoint();
    /// @notice Thrown when registering a verifier key with a zero `maxSignatures` budget, which can
    ///         never authorize a stateful signature.
    error ZeroMaxSignatures();
    /// @notice Thrown when registering a verifier key with a hash suite other than the
    ///         compiled keccak `HashSuite.HASH_SUITE_ID` (the only suite this implementation
    ///         verifies; SHRINCS binds it into every canonical message hash).
    error UnsupportedHashSuite();
    /// @notice Thrown by `initialize` when the presented bundle is malformed (field lengths, or an
    ///         embedded commitment that does not recompute), and by `rotateStatefulKey` when the
    ///         presented current bundle does not match the installed commitment, the rotation
    ///         target is malformed, or the target's declared commitment does not match the
    ///         recomputed next-bundle commitment.
    error CommitmentMismatch();
    /// @notice Thrown when `markLeavesUsed` is called with an empty target array (burning nothing
    ///         is almost certainly a client bug).
    error EmptyLeaves();
    /// @notice Thrown when a `markLeavesUsed` target leaf is zero or exceeds the installed key's
    ///         `maxSignatures` budget.
    /// @param leaf The out-of-range target leaf.
    error LeafOutOfRange(uint32 leaf);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         EVENTS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted once when the paymaster proxy is initialized.
    event PaymasterInitialized(address indexed owner);

    /// @notice Emitted once when the initial global SHRINCS verifier key is registered at
    ///         `initialize` (epoch 0). Rotations emit `KeyRotated` instead.
    /// @param previousCommitment The prior verifier commitment (always zero at initialization).
    /// @param newCommitment The installed verifier commitment.
    /// @param hashSuite The hash-suite id the key was validated against.
    /// @param maxSignatures The installed key's stateful leaf budget.
    /// @param keyVersion The verifier-key epoch (always 0 at initialization).
    event ShrincsVerifierSet(
        bytes32 previousCommitment,
        bytes32 indexed newCommitment,
        uint32 hashSuite,
        uint32 maxSignatures,
        uint256 keyVersion
    );

    /// @notice Emitted when the global verifier key's stateful subkey is rotated (mirrors the
    ///         wallet's `KeyRotated`, plus the new budget so rotations are fully observable).
    /// @param previousCommitment The rotated-out verifier commitment.
    /// @param nextCommitment The installed verifier commitment.
    /// @param keyVersion The new verifier-key epoch.
    /// @param maxSignatures The installed key's stateful leaf budget (decoded from the new
    ///        stateful subkey's encoding — each rotation may change it).
    event KeyRotated(
        bytes32 indexed previousCommitment,
        bytes32 indexed nextCommitment,
        uint256 keyVersion,
        uint32 maxSignatures
    );

    /// @notice Emitted when `markLeavesUsed` revokes a previously unused leaf.
    /// @param leaf The revoked stateful leaf index.
    /// @param keyVersion The verifier-key epoch the leaf was revoked under.
    event LeafRevoked(uint32 indexed leaf, uint256 indexed keyVersion);

    /// @notice Emitted when a `markLeavesUsed` target was already consumed (idempotent skip —
    ///         a sponsorship racing its own revocation must not brick the batch).
    /// @param leaf The skipped stateful leaf index.
    /// @param keyVersion The verifier-key epoch the skip happened under.
    event LeafRevocationSkipped(uint32 indexed leaf, uint256 indexed keyVersion);

    /// @notice Emitted on every consumed sponsorship signature (leaf marked used).
    /// @param wallet The sponsored wallet (`userOp.sender`).
    /// @param leaf The consumed stateful leaf index.
    /// @param keyVersion The verifier-key epoch the signature was valid under.
    event SponsorshipVerified(
        address indexed wallet,
        uint32 leaf,
        uint256 keyVersion
    );

    /// @notice Emitted (and rolled back on EntryPoint revert) on each validation failure.
    event PaymasterValidationRejected(
        address indexed wallet,
        PaymasterValidationFailure reason
    );

    /// @notice Emitted from `postOp` for every sponsored UserOp's gas accounting.
    event UserOpSponsored(
        address indexed wallet,
        PostOpMode indexed mode,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    );

    /// @notice Discriminates `validatePaymasterUserOp` rejection reasons (surfaced to
    ///         simulators; ERC-4337 forbids reverting with a reason from validation).
    enum PaymasterValidationFailure {
        MalformedPayload,
        /// @dev The signature's leaf index has already been consumed in the current epoch.
        StaleStatefulLeaf,
        InvalidSignature,
        /// @dev The signature's leaf index is zero or exceeds the registered key's `maxSignatures`.
        StatefulBudgetExhausted
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Initializes the paymaster proxy with an owner AND its initial global SHRINCS verifier
    ///         key. Callable once. The paymaster always has a verifier from this point on — there is
    ///         no way to unset it (only rotate via `rotateStatefulKey`). The full public-key bundle
    ///         is required (not just its commitment) so the installed commitment and stateful leaf
    ///         budget are DERIVED from validated key material, exactly like `rotateStatefulKey` and
    ///         the wallet's `initialize` — the budget is never a trusted free parameter.
    /// @param owner_ The paymaster owner.
    /// @param publicKey The initial verifier public-key bundle. Its embedded commitment must
    ///        recompute (`SHRINCS.validPublicKey`); the stateful leaf budget is decoded from
    ///        `publicKey.statefulPublicKey`.
    /// @param hashSuite The verifier key's hash-suite id (client-agreement
    ///        check; must be `HASH_SUITE_KECCAK_256`).
    function initialize(
        address owner_,
        SHRINCS.PublicKey calldata publicKey,
        uint32 hashSuite
    ) external;

    /// @notice Rotates ONLY the stateful subkey of the global SHRINCS verifier key, carrying the
    ///         current bundle's stateless half (pkSeed, hypertreeRoot) into the next commitment —
    ///         the stateless half is never rotated here (it is inert: the paymaster only ever
    ///         verifies stateful sponsorship signatures). Owner-only fiat rotation: no signature
    ///         from the current key is required, so a compromised or lost sponsorship key can
    ///         never block its own replacement. No PQ signature (and no rotation nonce) is needed
    ///         on this path because the owner is expected to be a post-quantum wallet (e.g. a
    ///         ShrincsWallet), so the authorizing call is already PQ-secured upstream; replay is
    ///         prevented by the current-bundle pin (rotation is compare-and-swap: after it
    ///         applies, the installed commitment changes and a replay fails the pin).
    ///         Bumps the verifier epoch (fresh leaf-bitmap
    ///         namespace), resets the leaf-used counter, and installs the new stateful budget
    ///         decoded from `nextStatefulKey.statefulPublicKey`. Cannot unset the key.
    /// @param currentPublicKey The full currently installed public-key bundle; pinned against the
    ///        stored commitment so its stateless half is trustworthy to carry forward.
    /// @param nextStatefulKey The replacement stateful subkey and the declared next-bundle
    ///        commitment, which MUST equal the recomputed one (the fiat path's end-to-end guard
    ///        against installing a mistyped commitment nobody can sign for).
    function rotateStatefulKey(
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.StatefulRotationTarget calldata nextStatefulKey
    ) external;

    /// @notice Marks stateful leaves as consumed in the current epoch without verifying anything —
    ///         owner-only revocation of outstanding sponsorship signatures (e.g. signed but
    ///         no-longer-wanted sponsorships, or containment after a backend double-sign).
    ///         Idempotent per leaf: already-used targets (including duplicates within the batch)
    ///         are skipped with `LeafRevocationSkipped`, never reverted; out-of-range targets
    ///         revert the whole batch (client bug, not a race). Revocation only ever shrinks the
    ///         set of accepted signatures.
    /// @param leaves The stateful leaf indices to revoke (1-based, each ≤ `maxSignatures`).
    function markLeavesUsed(uint32[] calldata leaves) external;

    /// @notice Deposits ETH into the EntryPoint for this paymaster.
    function deposit() external payable;

    /// @notice Withdraws ETH from the EntryPoint deposit. Owner-only.
    function withdrawTo(address payable to, uint256 amount) external;

    /// @notice Adds stake to the EntryPoint. Owner-only.
    function addStake(uint32 unstakeDelaySec) external payable;

    /// @notice Begins the EntryPoint unstake delay. Owner-only.
    function unlockStake() external;

    /// @notice Withdraws unlocked stake from the EntryPoint. Owner-only.
    function withdrawStake(address payable to) external;

    /// @notice Returns the registered global verifier state. `hashSuite` is always
    ///         `HASH_SUITE_KECCAK_256`: the id is not stored — registration rejects every
    ///         other suite.
    function getShrincsVerifier()
        external
        view
        returns (
            bytes32 commitment,
            uint32 hashSuite,
            uint256 keyVersion,
            uint32 maxSignatures,
            uint32 statefulLeavesUsed
        );

    /// @notice Whether stateful `leaf` has been consumed in the current verifier epoch.
    function isStatefulLeafUsed(uint256 leaf) external view returns (bool);

    /// @notice Sponsorship signatures remaining before the verifier key must be rotated.
    function remainingStatefulSignatures() external view returns (uint32);

    /// @notice Returns the paymaster's EntryPoint deposit balance.
    function getDeposit() external view returns (uint256);
}
