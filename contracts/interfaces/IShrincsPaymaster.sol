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
    /// @notice Thrown when registering a zero verifier commitment.
    error ZeroCommitment();
    /// @notice Thrown when registering a verifier key with a zero `maxSignatures` budget, which can
    ///         never authorize a stateful signature.
    error ZeroMaxSignatures();
    /// @notice Thrown when registering a verifier key with a hash suite other than the
    ///         compiled keccak `HashSuite.HASH_SUITE_ID` (the only suite this implementation
    ///         verifies; SHRINCS binds it into every canonical message hash).
    error UnsupportedHashSuite();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         EVENTS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted once when the paymaster proxy is initialized.
    event PaymasterInitialized(address indexed owner);

    /// @notice Emitted when the global SHRINCS verifier key is (re)registered.
    /// @param previousCommitment The prior verifier commitment (zero on first registration).
    /// @param newCommitment The installed verifier commitment.
    /// @param hashSuite The hash-suite id the key was validated against.
    /// @param maxSignatures The installed key's stateful leaf budget.
    /// @param keyVersion The new verifier-key epoch.
    event ShrincsVerifierSet(
        bytes32 previousCommitment,
        bytes32 indexed newCommitment,
        uint32 hashSuite,
        uint32 maxSignatures,
        uint256 keyVersion
    );

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
    ///         no way to unset it (only rotate via `setShrincsVerifier`).
    /// @param owner_ The paymaster owner.
    /// @param commitment The initial verifier-key bundle commitment.
    /// @param hashSuite The verifier key's hash-suite id (client-agreement
    ///        check; must be `HASH_SUITE_KECCAK_256`).
    /// @param maxSignatures The key's stateful leaf budget.
    function initialize(
        address owner_,
        bytes32 commitment,
        uint32 hashSuite,
        uint32 maxSignatures
    ) external;

    /// @notice Rotates the global SHRINCS verifier key. Owner-only. Bumps the verifier epoch (fresh
    ///         leaf-bitmap namespace) and resets the leaf-used counter. Cannot unset the key.
    /// @param commitment The verifier-key bundle commitment.
    /// @param hashSuite The verifier key's hash-suite id (client-agreement
    ///        check; must be `HASH_SUITE_KECCAK_256`).
    /// @param maxSignatures The key's stateful leaf budget.
    function setShrincsVerifier(
        bytes32 commitment,
        uint32 hashSuite,
        uint32 maxSignatures
    ) external;

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
