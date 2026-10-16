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

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {IWallet} from "../../interfaces/IWallet.sol";

/// @title IShrincsWallet
/// @notice A smart-contract wallet whose operations are authorized by SHRINCS
///         hash-based signatures, providing post-quantum security for ETH transfers
///         and arbitrary calls. Normal operations use the cheap stateful path
///         (leaf-indexed, bounded by `maxSignatures`); break-glass recovery uses the
///         stateless path. A separate, dedicated stateless key backs ERC-1271.
///         Extends `IWallet` — the factory-facing surface whose natspec
///         states the behavioral vetting contract this implementation upholds.
interface IShrincsWallet is IWallet {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ERRORS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when the factory address is zero.
    error ZeroAddressFactory();
    /// @notice Thrown when the external SHRINCS verifier address is zero at implementation
    ///         deployment (see `getShrincsVerifier`).
    error ZeroAddressVerifier();
    /// @notice Thrown at implementation deployment when the pinned verifier's `PROFILE_TAG`
    ///         does not match the `SHRINCSParams.PROFILE_ID` this wallet was compiled under —
    ///         wiring a wrong-profile verifier would silently break every signature check,
    ///         and the EIP-712 domain name embeds `PROFILE_NAME` on the strength of this guard.
    error VerifierProfileMismatch();
    /// @notice Thrown when the owner address is zero.
    error ZeroAddressOwner();
    /// @notice Thrown when the caller is not the immutable factory.
    error InvalidFactory();

    /// @notice Thrown when a SHRINCS signature fails verification (stateful or stateless).
    error InvalidSignature();
    /// @notice Thrown when a supplied public-key bundle (main or ERC-1271) fails shape
    ///         validation or does not recompute to the declared/installed commitment.
    error CommitmentMismatch();
    /// @notice Thrown when an install payload declares a hash suite other than
    ///         the compiled keccak `HashSuite.HASH_SUITE_ID` (the only suite this
    ///         implementation verifies; SHRINCS binds it into every canonical message hash).
    error UnsupportedHashSuite();
    /// @notice Thrown when a decoded stateful public key declares `maxSignatures == 0`,
    ///         which can never produce a valid stateful signature.
    error ZeroMaxSignatures();
    /// @notice The stateful tree was installed on this wallet before. Trees are one-time
    ///         material for the wallet's lifetime; re-installing one would reset its leaf bitmap.
    /// @param treeId `keccak256(pkSeed ‖ root)` of the 68-byte stateful key (budget excluded).
    error StatefulTreeSpent(bytes32 treeId);
    /// @notice The stateless tree was installed on this wallet before.
    /// @param treeId `keccak256(pkSeed ‖ hypertreeRoot)`.
    error StatelessTreeSpent(bytes32 treeId);
    /// @notice Thrown when the V1 commitment (salt) does not recompute from the install payload.
    error IdentityMismatch();

    /// @notice Thrown when a stateful signature's leaf index has already been consumed in the
    ///         current key epoch (used-leaf bitmap anti-replay).
    error StaleStatefulLeaf();
    /// @notice Thrown when an upgrade-auth blob binds an action nonce that no longer matches the
    ///         wallet's live one (the signed upgrade was superseded by a later consumed action).
    error StaleActionNonce(uint256 expected, uint256 provided);
    /// @notice Thrown when a stateful signature's leaf index is zero or exceeds the installed
    ///         key's `maxSignatures` budget (the key must be rotated via `rotateKey`).
    error StatefulBudgetExhausted();
    /// @notice Thrown when `markLeavesUsed` is called with an empty target array. Burning the
    ///         authorizing leaf for nothing is almost certainly a mistake; a deliberate
    ///         single-leaf burn already exists via the empty `execute` path.
    error EmptyLeaves();
    /// @notice Thrown when a `markLeavesUsed` target leaf is zero or exceeds the installed key's
    ///         `maxSignatures` budget — a client bug, not a race, so the whole batch reverts.
    error LeafOutOfRange(uint32 leaf);

    /// @notice Thrown when `renounceOwnership` is called (always reverts).
    error RenounceDisabled();
    /// @notice Thrown when the classical `withdrawDepositTo(address,uint256)` is called directly.
    /// @dev Only the SHRINCS-authenticated `withdrawDepositTo(bytes)` path is permitted.
    error ClassicalWithdrawDisabled();
    /// @notice Thrown when the classical `transferOwnership(address)` is called directly.
    /// @dev Only the SHRINCS-authenticated `transferOwnership(bytes)` path is permitted.
    error ClassicalTransferOwnershipDisabled();
    /// @notice Thrown when the incoming classical owner's acceptance signature over
    ///         `quipSignedHashEcdsaTarget(transferOwnershipPayloadHash(newOwner, nextCommitment))`
    ///         does not verify for `newOwner` (ECDSA, or ERC-1271 for a contract owner). A
    ///         mistyped `newOwner` cannot produce it, so the handover reverts instead of
    ///         stranding the wallet.
    error InvalidOwnerAcceptance();
    /// @notice Thrown when the incoming key bundle's stateful acceptance signature does not
    ///         verify against `nextCommitment`, or names a leaf outside
    ///         `[1, nextKey.maxSignatures]`. A bundle its holder cannot sign with cannot be
    ///         installed.
    error InvalidKeyAcceptance();
    /// @notice Thrown when a self-call-only helper (`userOpEnvelope`, `erc1271Envelope`) is
    ///         called by anyone other than the wallet itself.
    error SelfCallOnly();
    /// @notice Thrown when any of Solady's inherited two-step ownership handover entry
    ///         points is called. This wallet supports only the SHRINCS-authenticated
    ///         `transferOwnership(bytes)` path, which cryptographically commits to `newOwner`.
    error OwnershipHandoverDisabled();

    /// @notice Thrown when the upgrade target's codehash is not in the factory's vetted set.
    error ImplementationNotVetted();
    /// @notice Thrown when the upgrade target's codehash has been deprecated.
    error ImplementationDeprecated();
    /// @notice Thrown when `migrate` is called outside the `upgradeToAndCall` context.
    error NotUpgrading();

    /// @notice Thrown when `storageStore` is called. Raw storage writes are disabled because they
    ///         could clear consumed-leaf bits in the bitmap and re-enable
    ///         one-time-signature replay.
    error StorageStoreDisabled();
    /// @notice Thrown when `delegateExecute` is called. Running un-vetted bytecode in the wallet's
    ///         storage context is disabled; use `executeBatch` for batching.
    error DelegateExecuteDisabled();

    /// @notice Thrown when the factory's live execute fee exceeds the `maxFee` ceiling the signer
    ///         authorized. Fee decreases never trigger this; only an increase past the signed cap.
    error ExecuteFeeExceedsCap(uint256 fee, uint256 maxFee);
    /// @notice Thrown when the inherited un-capped `execute(address,uint256,bytes)` /
    ///         `executeBatch(Call[])` selectors are called. Only the `maxFee`-capped variants are
    ///         permitted, so every execution path carries a signer-authorized fee ceiling.
    error StandardExecuteDisabled();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         EVENTS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a wallet is initialized with its factory, owner, and SHRINCS keys.
    /// @param factory The WalletFactory that created this wallet.
    /// @param owner The classical owner address (ERC-1271 ECDSA gate + factory registry only).
    /// @param shrincsPublicKeyCommitment The installed main-key bundle commitment.
    /// @param erc1271PublicKeyCommitment The installed ERC-1271 verifier-key commitment.
    event WalletInitialized(
        address indexed factory,
        address indexed owner,
        bytes32 indexed shrincsPublicKeyCommitment,
        bytes32 erc1271PublicKeyCommitment
    );

    /// @notice Emitted when a stateful signature is consumed (its leaf marked used).
    /// @param leaf The consumed stateful leaf index.
    /// @param keyVersion The installed-key epoch the signature was valid under.
    event StatefulSignatureVerified(
        uint32 indexed leaf,
        uint256 indexed keyVersion
    );

    /// @notice Emitted in place of `ExecutionSucceeded` when `execute(bytes)` is signed with
    ///         `value == 0 && data.length == 0` — a deliberate leaf consumption with no call.
    /// @param leaf The consumed stateful leaf index.
    event LeafConsumedOnly(uint32 indexed leaf);

    /// @notice Emitted for each target leaf freshly marked used by `markLeavesUsed`.
    /// @param leaf The revoked stateful leaf index.
    /// @param keyVersion The key epoch whose bitmap the revocation applies to.
    event LeafRevoked(uint32 indexed leaf, uint256 indexed keyVersion);

    /// @notice Emitted for each `markLeavesUsed` target leaf that was already used (a landed
    ///         action racing its revocation, a duplicate in the array, or the authorizing leaf
    ///         itself) — skipped rather than reverting the batch.
    /// @param leaf The already-used target leaf index.
    /// @param keyVersion The key epoch whose bitmap was checked.
    event LeafRevocationSkipped(uint32 indexed leaf, uint256 indexed keyVersion);

    /// @notice Emitted when an execution call succeeds.
    /// @param target The recipient or contract address.
    /// @param value The ETH value sent to the target.
    /// @param dataHash The keccak256 hash of the calldata.
    event ExecutionSucceeded(
        address indexed target,
        uint256 value,
        bytes32 dataHash
    );

    /// @notice Emitted when the dedicated ERC-1271 stateless verifier key is (re)installed.
    /// @param oldCommitment The previous ERC-1271 verifier commitment.
    /// @param newCommitment The installed ERC-1271 verifier commitment.
    event Erc1271KeySet(bytes32 oldCommitment, bytes32 newCommitment);

    /// @notice Emitted when the main SHRINCS key is rotated (stateful `rotateKey` or
    ///         stateless break-glass `recoverWallet`).
    /// @param previousCommitment The rotated-out main-key commitment.
    /// @param nextCommitment The installed main-key commitment.
    /// @param keyVersion The new installed-key epoch.
    event KeyRotated(
        bytes32 indexed previousCommitment,
        bytes32 indexed nextCommitment,
        uint256 keyVersion
    );

    /// @notice Emitted when PQ state is migrated during an upgrade.
    /// @param shrincsPublicKeyCommitment The reinstalled main-key commitment.
    /// @param keyVersion The new installed-key epoch.
    event WalletMigrated(
        bytes32 indexed shrincsPublicKeyCommitment,
        uint256 keyVersion
    );

    /// @notice Discriminates the reasons `_validateSignature` returns `validationData == 1`.
    /// @dev Surfaced to off-chain simulators via `UserOpValidationRejected` since ERC-4337
    ///      forbids reverting with a reason from `validateUserOp`.
    enum UserOpValidationFailure {
        BadSignatureLength,
        StaleStatefulLeaf,
        StatefulBudgetExhausted,
        InvalidSignature,
        InvalidEcdsaSignature,
        /// @dev The `userOp.signature` blob's ABI framing is malformed (a top-level or nested
        ///      tail offset / length runs past the blob), detected by the `userOpEnvelope`
        ///      self-staticcall reverting. Appended last: earlier values are wire-stable.
        MalformedSignature
    }

    /// @notice Emitted on each `validationData == 1` exit of `_validateSignature`.
    /// @param reason The classification of the rejection.
    event UserOpValidationRejected(UserOpValidationFailure indexed reason);

    /// @notice Discriminates the reasons `isValidSignature` returns the ERC-1271 failure magic,
    ///         plus an `Ok` success sentinel surfaced by `debugIsValidSignature`.
    enum Erc1271ValidationResult {
        Ok,
        BadSignatureLength,
        InvalidEcdsaSignature,
        InvalidShrincsSignature,
        MalformedErc1271Payload
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Initializes the wallet. Called once by the factory. Records all four installed
    ///         trees — both halves of the main bundle AND of the dedicated ERC-1271 bundle — as
    ///         spent (`StatefulTreeSpent` / `StatelessTreeSpent` on any later re-install). A
    ///         payload whose ERC-1271 bundle shares any tree with the main bundle reverts: the
    ///         contract-signing key must never be the recovery authority.
    /// @param newOwner The classical owner (ERC-1271 ECDSA gate + factory registry only).
    /// @param payload ABI-encoded `(bytes32 commitment, bytes32 pkSeed, PublicKey mainBundle,
    ///        uint32 hashSuite, PublicKey erc1271Bundle, uint32 erc1271HashSuite)`; the ERC-1271
    ///        commitment is derived on-chain from `erc1271Bundle`.
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) external override;

    /// @notice Re-installs PQ state during an upgrade. Only valid inside `upgradeToAndCall`.
    ///         All four trees in the payload (main and ERC-1271 bundles) must be strictly fresh
    ///         (never held by this wallet) and are recorded as spent; reverts
    ///         `StatefulTreeSpent` / `StatelessTreeSpent`. Same payload layout as `initialize`.
    function migrate(bytes calldata payload) external override;

    /// @notice SHRINCS-gated UUPS upgrade. Authorized by a stateful signature from the main key.
    ///         The `data` blob carries the action nonce the signer bound; it must equal the live
    ///         `actionNonce()` or the call reverts `StaleActionNonce`. STATICCALLs the NEW
    ///         implementation's `verifyUpgrade` probe before switching.
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) external payable;

    /// @notice A PROBE (the frozen `IWallet` seam): context-free SHRINCS self-test,
    ///         STATICCALLed on the NEW implementation during `upgradeToAndCall`.
    /// @param newImplementation The upgrade target; the probe digest is its hashed word.
    /// @param data The probe vector `abi.encode(PublicKey bundle, Signature statefulSig,
    ///        SPHINCSPlusC.Signature statelessSig)` — or, deployed-implementation compat, a
    ///        full upgrade-auth blob whose `probePayload` field carries that vector. The
    ///        digest must verify under BOTH halves of the (throwaway) bundle or the call
    ///        reverts `InvalidSignature`.
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view override;

    /// @notice Executes a single call authorized by a stateful SHRINCS signature.
    /// @param publicKey The main-key bundle (re-validated against the installed commitment).
    /// @param signature The stateful signature; its leaf must be unused in the current epoch.
    /// @param target The call target.
    /// @param value The ETH value to send.
    /// @param data The calldata to execute.
    /// @param maxFee The signed fee ceiling. Execution charges the factory's LIVE fee and
    ///        reverts `ExecuteFeeExceedsCap` only if it exceeds this cap — so a fee decrease
    ///        between signing and landing succeeds (charging the lower fee), and only an
    ///        increase past the cap rejects.
    function execute(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 maxFee
    ) external payable;

    /// @notice Withdraws from the EntryPoint deposit, authorized by a stateful SHRINCS signature.
    function withdrawDepositTo(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        address to,
        uint256 amount
    ) external payable;

    /// @notice Atomic full ownership handover to a new party. Installs an entirely FRESH key
    ///         bundle (new stateless recovery root) for the new owner AND sets the new classical
    ///         owner in one action, so the prior owner retains neither spend nor break-glass
    ///         authority. Requires BOTH current-owner signatures: the STATELESS recovery signature
    ///         authorizing the fresh bundle, and the STATEFUL signature cross-binding `newOwner`
    ///         to that bundle (so the two cannot be mixed across attempts) — AND both halves of
    ///         the incoming party's acceptance: `newOwner`'s classical signature and a stateful
    ///         signature from `nextKey` itself, each over `(newOwner, nextKey.commitment)`. The
    ///         acceptance proves the recipient controls both keys it will operate the wallet
    ///         with; without it a mistyped `newOwner` or an unusable bundle would strand the
    ///         wallet with every path — recovery included — gated behind a party that does not
    ///         exist. Consumes one stateful leaf and one stateless-budget unit from the current
    ///         key, plus the acceptance leaf of the incoming key (recorded used in the new epoch);
    ///         bumps the key epoch and notifies the factory registry. Both trees of `nextKey` must
    ///         be fresh and are recorded as spent (reverts `StatefulTreeSpent` /
    ///         `StatelessTreeSpent`).
    /// @param currentPublicKey The current main-key bundle (re-validated against the commitment).
    /// @param ownerBindingSignature Stateful signature over `(newOwner, nextKey.commitment)`.
    /// @param recoverySignature Stateless recovery signature authorizing the fresh bundle.
    /// @param nextKey The new owner's replacement full key bundle.
    /// @param newOwner The incoming classical owner (ERC-1271 ECDSA gate + factory registry).
    /// @param keyAcceptance Stateful signature by `nextKey` under `ACTION_TRANSFER_OWNERSHIP`
    ///        over `(newOwner, nextKey.commitment)` at nonce 0 / epoch 0, verified against
    ///        `nextKey.commitment` (not the installed one). Its leaf is spent in the new epoch.
    /// @param ownerAcceptance `newOwner`'s signature over
    ///        `quipSignedHashEcdsaTarget(transferOwnershipPayloadHash(newOwner,
    ///        nextKey.commitment))` (ECDSA for an EOA; ERC-1271 for a contract).
    function transferOwnership(
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.Signature calldata ownerBindingSignature,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.RotationTarget calldata nextKey,
        address newOwner,
        SHRINCS.Signature calldata keyAcceptance,
        bytes calldata ownerAcceptance
    ) external payable;

    /// @notice (Re)installs the dedicated ERC-1271 stateless verifier key, authorized by a
    ///         stateful SHRINCS action from the main key. The new bundle's commitment is derived
    ///         on-chain and both of its trees are recorded as spent BEFORE the signature check,
    ///         so any bundle sharing a tree with anything this wallet ever held (the current or
    ///         a former main key, or a former ERC-1271 key) reverts `StatefulTreeSpent` /
    ///         `StatelessTreeSpent` without consuming a leaf.
    /// @param publicKey The current main-key bundle (re-validated against the commitment).
    /// @param signature Stateful signature over `setErc1271KeyPayloadHash(commitment, suite)`.
    /// @param newErc1271Key The full replacement ERC-1271 bundle (only its stateless half signs).
    /// @param newErc1271HashSuite Must equal the compiled `HashSuite.HASH_SUITE_ID`.
    function setErc1271Key(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        SHRINCS.PublicKey calldata newErc1271Key,
        uint32 newErc1271HashSuite
    ) external payable;

    /// @notice Batch leaf revocation: marks the target leaves used in the CURRENT key epoch's
    ///         bitmap, authorized by one stateful SHRINCS signature from a different leaf.
    ///         OTS hygiene primitive — a leaf whose one-time key signed a message that will
    ///         never land (superseded by the nonce) must be burned so it can never sign a
    ///         second, different message.
    /// @dev Surgical by design: the authorizing leaf is consumed but the action nonce is NOT
    ///      advanced, so outstanding signed material at non-revoked leaves stays valid (unlike
    ///      every other landed action). Already-used targets — races, duplicates, or the
    ///      authorizing leaf itself — are skipped with `LeafRevocationSkipped`; out-of-range
    ///      targets revert `LeafOutOfRange`; an empty array reverts `EmptyLeaves`. A revocation
    ///      signed under epoch E is invalid after any rotation (the context binds `keyVersion`).
    /// @param publicKey The main-key bundle (re-validated against the installed commitment).
    /// @param signature The authorizing stateful signature; its leaf must be unused and SHOULD
    ///        not be one of the targets (clients must never sign with a leaf being revoked —
    ///        that is the key reuse this function exists to prevent).
    /// @param leaves The target leaf indices to revoke (order-sensitive in the signed payload).
    function markLeavesUsed(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        uint32[] calldata leaves
    ) external payable;

    /// @notice Routine stateful rotation of the main key's stateful subkey (reusing the
    ///         stateless recovery root). Authorized by a stateful signature; resets the leaf
    ///         budget. Use before `maxSignatures` is exhausted. The next stateful tree must be
    ///         fresh (never held, under any budget) and is recorded as spent; reverts
    ///         `StatefulTreeSpent`.
    /// @param currentPublicKey The current main-key bundle (re-validated against the commitment).
    /// @param signature The stateful signature authorizing the rotation.
    /// @param nextStatefulKey The replacement stateful subkey target.
    function rotateKey(
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.Signature calldata signature,
        SHRINCS.StatefulRotationTarget calldata nextStatefulKey
    ) external payable;

    /// @notice Break-glass wallet recovery: authorized by a STATELESS signature from the main
    ///         key's recovery half, it installs an entirely fresh key bundle (new stateful key
    ///         AND new stateless recovery root). Use when the stateful key is exhausted or
    ///         compromised. Ownership is unchanged; for a handover to a new party use
    ///         `transferOwnership`. Both trees of `nextKey` must be fresh and are recorded as
    ///         spent (reverts `StatefulTreeSpent` / `StatelessTreeSpent`).
    /// @param currentPublicKey The current main-key bundle (re-validated against the commitment).
    /// @param recoverySignature The stateless recovery signature authorizing the rotation.
    /// @param nextKey The replacement full key bundle.
    function recoverWallet(
        SHRINCS.PublicKey calldata currentPublicKey,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.RotationTarget calldata nextKey
    ) external payable;

    /// @notice Self-call target of `isValidSignature`: re-encodes the SHRINCS half of an
    ///         ERC-1271 blob into the verifier envelope `abi.encode(publicKey, signature)`.
    /// @dev Callable only by the wallet itself (`SelfCallOnly`). It exists purely to put a call
    ///      boundary around the nested-calldata reads: the codec bounds-checks only a blob's
    ///      top-level tail offsets, and a nested offset past calldatasize makes Solidity's
    ///      calldata accessors revert. Wrapping the re-encode in `try this.erc1271Envelope`
    ///      lets `isValidSignature` map that revert to `0xffffffff` instead of propagating it to
    ///      the relying contract that staticcalled it (INVARIANTS §19).
    function erc1271Envelope(
        bytes calldata signature
    ) external view returns (bytes memory);

    /// @notice Self-call target of `validateUserOp`: decodes the hybrid `userOp.signature` blob
    ///         `abi.encode(PublicKey, Signature, bytes ecdsaSig)`, derives the stateful leaf
    ///         index, and re-encodes the SHRINCS half into the verifier envelope
    ///         `abi.encode(publicKey, signature)`.
    /// @dev Callable only by the wallet itself (`SelfCallOnly`). Twin of `erc1271Envelope` for
    ///      the ERC-4337 path: the codec bounds-checks only a blob's top-level tail offsets, and
    ///      a nested offset past calldatasize makes Solidity's calldata accessors revert at the
    ///      first field read (`_leafIndex`, the re-encode). Running every such read behind
    ///      `try this.userOpEnvelope` lets `_validateSignature` map that revert — and the codec's
    ///      own `MalformedPayload` — to `validationData == 1` + `MalformedSignature` instead of
    ///      reverting out of validation (INVARIANTS §19). Inside the self-call the blob is the
    ///      whole calldata, so the compiler's check is effectively against the blob's own end.
    /// @return leaf The stateful leaf index the signature reveals (`authPath.length`).
    /// @return envelope `abi.encode(publicKey, signature)`.
    /// @return ecdsaSig The owner's ECDSA co-signature bytes carried in the blob.
    function userOpEnvelope(
        bytes calldata signature
    )
        external
        view
        returns (uint32 leaf, bytes memory envelope, bytes memory ecdsaSig);

    /// @notice Off-chain diagnostic variant of `isValidSignature` returning the failure branch.
    /// @dev ERC-1271 `isValidSignature(bytes32,bytes)` itself is inherited from the ERC1271 base
    ///      and overridden by the wallet (stateless SHRINCS verify against the dedicated verifier
    ///      key AND classical `owner()` ECDSA); it is not redeclared here to avoid an
    ///      override clash.
    function debugIsValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (Erc1271ValidationResult);

    /// @notice The EIP-712 typed-data target the ERC-1271 ECDSA half must sign. Also the
    ///         target the INCOMING owner signs to accept a `transferOwnership` handover, with
    ///         `hash = transferOwnershipPayloadHash(newOwner, nextCommitment)`: the wallet
    ///         (verifying contract) and chain id ride in the domain, and the commitment can be
    ///         installed here at most once, so the acceptance authorizes exactly one install and
    ///         cannot go stale while the current owner keeps transacting.
    function quipSignedHashEcdsaTarget(
        bytes32 hash
    ) external view returns (bytes32);

    /// @notice The EIP-712 typed-data target the owner's userOp ECDSA co-signature must sign.
    /// @dev Every `userOp.signature` carries `(PublicKey, Signature, bytes ecdsaSig)`;
    ///      `_validateSignature` requires `ecdsaSig` to recover `owner()` over this target
    ///      BEFORE the SHRINCS verify — the two-key AND-gate holds on the EntryPoint route
    ///      exactly as `onlyOwner` + SHRINCS holds on the direct route. The typehash domain is
    ///      deliberately distinct from `quipSignedHashEcdsaTarget`'s so an ERC-1271 message
    ///      signature can never double as a userOp co-signature.
    function quipUserOpHashEcdsaTarget(
        bytes32 userOpHash
    ) external view returns (bytes32);

    /// @notice The classical owner (ERC-1271 ECDSA gate + factory registry).
    function owner() external view override returns (address);

    /// @notice The factory's vetted-code index for this wallet's current implementation.
    function version() external view returns (uint256);

    /// @notice The per-operation execute fee charged by the factory.
    function getExecuteFee() external view returns (uint256);

    /// @notice The immutable factory address.
    function walletFactory() external view returns (address payable);

    /// @notice The installed main-key bundle commitment.
    function getShrincsPublicKeyCommitment() external view returns (bytes32);

    /// @notice The installed ERC-1271 verifier-key commitment.
    function getErc1271PublicKeyCommitment() external view returns (bytes32);

    /// @notice The hash-suite id the installed main key was validated against. Always the
    ///         compiled keccak `HashSuite.HASH_SUITE_ID`: the id is not stored —
    ///         install/rotate paths reject every other suite.
    function getHashSuite() external view returns (uint32);

    /// @notice The hash-suite id the installed ERC-1271 verifier key was validated against.
    ///         Always the compiled keccak `HashSuite.HASH_SUITE_ID`: the id is not stored —
    ///         install/rotate paths reject every other suite.
    function getErc1271HashSuite() external view returns (uint32);

    /// @notice The pinned external SHRINCS verifier this implementation delegates all
    ///         signature cryptography to (an `immutable` set at implementation deployment).
    ///         The verifier is trustless by construction — no owner, no storage, no
    ///         upgradability — so pinning it grants it no authority: it can only answer
    ///         "does this signature verify over this hash", and all statefulness (leaf
    ///         bitmap, nonce, keyVersion, commitment installs) stays in the wallet.
    function getShrincsVerifier() external view returns (address);

    /// @notice Whether stateful `leafIndex` has been consumed in the current key epoch.
    function isStatefulLeafUsed(uint256 leafIndex) external view returns (bool);

    /// @notice The raw 256-bit used-leaf bitmap word `wordIndex` for the current key epoch.
    ///         Bit `b` (0..255) of the returned word is leaf `wordIndex * 256 + b`; a set bit
    ///         means that leaf is consumed. Lets a client read 256 leaves per call instead of
    ///         one leaf per call. Out-of-range or all-free words read as 0.
    function statefulLeafBitmapWord(
        uint256 wordIndex
    ) external view returns (uint256);

    /// @notice Count of stateful leaves consumed in the current key epoch.
    function statefulLeavesUsed() external view returns (uint32);

    /// @notice The installed main key's stateful signature budget.
    function maxSignatures() external view returns (uint32);

    /// @notice Stateful signatures remaining before the main key must be rotated.
    function remainingStatefulSignatures() external view returns (uint32);

    /// @notice The installed-key epoch.
    function keyVersion() external view returns (uint256);

    /// @notice The SHRINCS action/rotation nonce (distinct from the EntryPoint nonce). Bound
    ///         into every signed context — actions, rotations, ERC-1271, and upgrades — and
    ///         advanced on every consumed signature, so any landed action supersedes all
    ///         outstanding signed material. Sole exception: `markLeavesUsed` consumes its
    ///         authorizing signature without advancing (surgical revocation).
    function actionNonce() external view returns (uint256);
}
