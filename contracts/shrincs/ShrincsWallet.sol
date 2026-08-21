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

import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";
import {LibCall} from "solady-0.1.26/src/utils/LibCall.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {ECDSA} from "solady-0.1.26/src/utils/ECDSA.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {SHRINCSVerifier} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCSVerifier.sol";
// prettier-ignore
import {
    IERC7913SignatureVerifier
} from "@quip.network/hashsigs-solidity-0.2.0/contracts/interfaces/IERC7913SignatureVerifier.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {IShrincsWallet} from "./interfaces/IShrincsWallet.sol";
import {IWalletFactory} from "../interfaces/IWalletFactory.sol";
import {ShrincsWalletCodec as Codec} from "./ShrincsWalletCodec.sol";
import {ShrincsWalletStorage as Storage} from "./ShrincsWalletStorage.sol";

/// @dev Every concrete SHRINCS verifier exposes its compiled profile identity as a public
///      constant (it cannot live on the abstract `SHRINCSVerifier` base — constants are not
///      virtual/overridable there). Minimal profile-agnostic surface for the constructor's
///      drift guard.
interface ISHRINCSProfileTag {
    function PROFILE_TAG() external view returns (bytes32);
}

/// @title ShrincsWallet
/// @notice A post-quantum ERC-4337 smart-account wallet authorized by SHRINCS hash-based
///         signatures. Normal operations use the cheap stateful path (leaf-indexed,
///         MonotonicIndex anti-replay, bounded by `maxSignatures`). Routine key rotation
///         (`rotateKey`) is stateful; the main key's stateless half is reserved as break-glass
///         recovery authority (`recoverWallet`). ERC-1271 uses a separate dedicated stateless
///         verifier key plus a classical `owner()` ECDSA AND-gate.
//          The inline verifier calls (at `_validateSignature`, `verifyUpgrade`,
//          `_verifyStatefulAndConsume`, `_checkErc1271Signature`) and `_statelessRotate` below
//          are the ONLY paths to signature cryptography: canonical message hash computed locally,
//          everything else delegated to the pinned SHRINCS_VERIFIER. The full delegation model —
//          hash/envelope equivalence with the inlined library, which checks live where, revert
//          model, ERC-7562 — is documented in SDK_README.md ("External verifier delegation") and
//          INVARIANTS.md invariant 19.
contract ShrincsWallet is IShrincsWallet, ERC4337, Initializable {
    /// @dev The immutable WalletFactory that deploys and registers this wallet.
    address payable public immutable FACTORY;

    /// @dev The pinned external SHRINCS verifier all signature cryptography is delegated to
    ///      (the dep's deployed `SHRINCS256sKeccak` ERC-7913 verifier — trustless: no owner,
    ///      no storage, no upgradability). The wallet keeps the pure work local — context
    ///      builds, canonical message hashes, commitment recomputes — and every piece of
    ///      state (leaf bitmap, nonce, keyVersion, installed commitments).
    address public immutable SHRINCS_VERIFIER;

    /// @dev Reserved leaf range for deploy authorizations (e3r). Leaves `[1..MAX_DEPLOY_CHAINS]`
    ///      of the main key are carved out for per-chain deploy signatures (indexed by the
    ///      factory's `quipDeployChainIndex`); normal stateful SIGNING is restricted to
    ///      `(MAX_DEPLOY_CHAINS .. maxSignatures]`. Keeping the two regions disjoint guarantees a
    ///      signing leaf can never collide with a deploy leaf, so no one-time secret is ever
    ///      revealed twice. MUST equal the SDK `MAX_DEPLOY_CHAINS`.
    uint32 public constant MAX_DEPLOY_CHAINS = 32;

    /// @dev Transient storage slot gating `migrate` to the `upgradeToAndCall` context.
    /// @notice REQUIRES EIP-1153 (TSTORE/TLOAD).
    uint256 private constant _UPGRADE_GUARD_SLOT =
        uint256(keccak256("quip.shrincs.wallet.upgrade.guard")) - 1;

    /// @dev EIP-712 type hash nesting the ERC-1271 `hash` before ECDSA recovery, binding the
    ///      classical signature to this wallet's domain (mirrors Safe's `SafeMessage`).
    bytes32 private constant _QUIP_SIGNED_HASH_TYPEHASH =
        keccak256("QuipSignedHash(bytes32 hash)");

    /// @dev EIP-712 type hash nesting the ERC-4337 `userOpHash` before ECDSA recovery — the
    ///      owner's userOp co-signature target. DELIBERATELY distinct from
    ///      `_QUIP_SIGNED_HASH_TYPEHASH`: if the two ECDSA surfaces shared a domain, an owner's
    ///      ERC-1271 message signature over an attacker-chosen hash H (harvestable by a dApp
    ///      requesting a "message signature") would double as the userOp co-signature for any
    ///      userOp with `userOpHash == H`.
    bytes32 private constant _QUIP_USER_OP_HASH_TYPEHASH =
        keccak256("QuipUserOpHash(bytes32 userOpHash)");

    /// @dev SHRINCS guarded-slot values mirrored as direct hex literals. `ShrincsWalletStorage`
    ///      holds the canonical copies; Solidity's inline assembly (the guard snapshot/check below)
    ///      accepts only a direct number constant or a reference to one — NOT a library member
    ///      (`Storage.X`) or a `base + N` expression — so these must be retyped here rather than
    ///      aliased. `test/fixtures/ShrincsWallet.storageLayout.json` pins each `Layout` field's
    ///      slot and fails the suite if this mirror drifts from the field order.
    bytes32 private constant _SHRINCS_FACTORY_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc00;
    bytes32 private constant _SHRINCS_COMMITMENT_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc01;
    bytes32 private constant _ERC1271_COMMITMENT_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc02;
    bytes32 private constant _KEY_VERSION_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc03;
    bytes32 private constant _NONCE_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc04;
    bytes32 private constant _LEAF_STATE_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc05;

    constructor(address payable factory_, address shrincsVerifier_) {
        if (factory_ == address(0)) revert ZeroAddressFactory();
        if (shrincsVerifier_ == address(0)) revert ZeroAddressVerifier();
        // Profile drift guard: the wallet is compiled under SHRINCSParams (array sizes,
        // digest layout) and its EIP-712 domain name embeds PROFILE_NAME — the pinned
        // verifier must be the verifier for that exact profile.
        if (
            ISHRINCSProfileTag(shrincsVerifier_).PROFILE_TAG() !=
            SHRINCSParams.PROFILE_ID
        ) revert VerifierProfileMismatch();
        FACTORY = factory_;
        SHRINCS_VERIFIER = shrincsVerifier_;
        _disableInitializers();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   INTERNAL OVERRIDES                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev EIP-712 domain name/version for the ERC-1271 ECDSA half. The name embeds the
    ///      pinned verifier's profile identity (`SHRINCSParams.PROFILE_NAME`, whose keccak
    ///      equals the verifier's `PROFILE_TAG` — enforced by the constructor guard), so a
    ///      classical owner signature can cross neither wallet families (the WOTS+ wallet
    ///      signs under "QuipWallet") nor SHRINCS profiles.
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = string.concat(
            "QuipShrincsWallet/",
            SHRINCSParams.PROFILE_NAME,
            "/v1"
        );
        version = "1";
    }

    /// @dev Hybrid authority: every PQ-authorized owner entry point is gated by BOTH the
    ///      classical `owner()` (`onlyOwner`) AND a SHRINCS signature. Upgrades keep the
    ///      classical `onlyOwner` gate here in addition to the stateful signature verified in
    ///      `upgradeToAndCall`.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev ERC-4337 hybrid validation: owner-ECDSA co-signature AND stateful SHRINCS
    ///      signature, with MonotonicIndex leaf advance. State is advanced during validation
    ///      (the revealed stateful leaf is consumed regardless of whether the execution phase
    ///      later succeeds). Never reverts on signature failure — returns 1 so the EntryPoint's
    ///      refund accounting stays clean.
    ///
    ///      By convention `userOp.signature` is the ABI encoding of `(PublicKey publicKey,
    ///      StatefulSignature signature, bytes ecdsaSig)` — the SHRINCS structs plus the
    ///      owner's ECDSA co-signature over `quipUserOpHashEcdsaTarget(userOpHash)`. The ECDSA
    ///      check runs FIRST (cheap check before the expensive SHRINCS verify), and its failure
    ///      consumes nothing — leaf and nonce are untouched.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256) {
        // two reasons for check:
        // 1. call would fail on decode (checks first 3 x bytes32 = 96 bytes)
        //    if length check didn't exist
        // 2. solidity encodes offset as one word per dynamic type at the `head` of
        //    the encoded data; three bytes32 words means three dynamic types at the `tail`
        //    of the encoded data - namely SHRINCS.PublicKey, SHRINCS.Signature, and the
        //    ECDSA co-signature bytes - so this validation is an indication that three
        //    dynamic types exist and the three bytes32 words contain their offsets
        if (userOp.signature.length < 0x60) {
            emit UserOpValidationRejected(
                UserOpValidationFailure.BadSignatureLength
            );
            return 1;
        }
        // Fail-closed policy for a malformed signature. Two failure classes are
        // handled differently on purpose:
        //   - Too short to hold the three offsets: SOFT fail (the `return 1`
        //     above). The bundler drops the op as SIG_VALIDATION_FAILED without
        //     penalising the sender.
        //   - Long enough to pass that check but carrying an offset that runs
        //     past the payload: HARD `MalformedPayload` revert from the codec
        //     below. Such an offset cannot come from an honest client, and
        //     decoding it could read adjacent calldata, so reverting to reject
        //     the op outright is the intended fail-closed behaviour, not a soft
        //     rejection.
        (
            SHRINCS.PublicKey calldata pk,
            SHRINCS.Signature calldata sig,
            bytes calldata ecdsaSig
        ) = Codec.decodeUserOpSignature(userOp.signature);

        // Hybrid gate half 1: the classical owner co-signs the exact userOpHash under the
        // dedicated userOp EIP-712 domain (see _QUIP_USER_OP_HASH_TYPEHASH). ERC-7562 clean:
        // ecrecover is an allowed precompile and the owner slot is the wallet's own storage.
        address recovered = ECDSA.tryRecoverCalldata(
            quipUserOpHashEcdsaTarget(userOpHash),
            ecdsaSig
        );
        if (recovered == address(0) || recovered != owner()) {
            emit UserOpValidationRejected(
                UserOpValidationFailure.InvalidEcdsaSignature
            );
            return 1;
        }

        Storage.Layout storage $ = Storage.layout();
        uint256 epoch = $.keyVersion;
        uint32 leaf = _leafIndex(sig);
        // Signing budget excludes the reserved deploy-leaf range `[1..MAX_DEPLOY_CHAINS]` (e3r).
        if (leaf <= MAX_DEPLOY_CHAINS || leaf > $.maxSignatures) {
            emit UserOpValidationRejected(
                UserOpValidationFailure.StatefulBudgetExhausted
            );
            return 1;
        }
        if (_isStatefulLeafUsed($, epoch, leaf)) {
            emit UserOpValidationRejected(
                UserOpValidationFailure.StaleStatefulLeaf
            );
            return 1;
        }

        // The live action nonce is bound in addition to the EntryPoint nonce (inside userOpHash)
        // and the one-time leaf: consuming ANY wallet signature supersedes every outstanding
        // signed authorization, so in-flight ops are strictly serialized by signing order.
        //
        // Fee pricing lives in the execution phase — the signer's `maxFee` ceiling rides in 
        // `callData` (covered by userOpHash), so reading the factory's mutable live fee here 
        // for ERC7562 compliance
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            _shrincsDomainSeparator(),
            $.nonce,
            epoch,
            Codec.ACTION_ERC4337_EXECUTE,
            Codec.erc4337PayloadHash(userOpHash)
        );
        // Stateful verification via the pinned verifier: canonical action hash computed
        // locally, bundle checks + crypto delegated (see EXTERNAL VERIFIER DELEGATION).
        bytes32 commitment = $.shrincsPublicKeyCommitment;
        if (
            !_tryVerifyStateful(
                commitment,
                SHRINCS.statefulActionMessageHash(commitment, ctx),
                abi.encode(pk, sig)
            )
        ) {
            emit UserOpValidationRejected(
                UserOpValidationFailure.InvalidSignature
            );
            return 1;
        }

        // anti-replay: consume the leaf and advance the nonce before execution runs.
        _markStatefulLeafUsed($, epoch, leaf);
        unchecked {
            $.statefulLeavesUsed += 1;
            $.nonce += 1;
        }
        emit StatefulSignatureVerified(leaf, epoch);
        return 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                ERC-4337 EXECUTION                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Fee-capped ERC-4337 execution. `maxFee` is the signer's fee ceiling: it rides in
    ///      `callData`, so the SHRINCS signature over userOpHash binds it with no digest work,
    ///      and validation never has to read the factory's live fee (ERC-7562). A live fee above
    ///      the cap reverts here — in the execution phase, after the leaf was consumed during
    ///      validation (an inherent property of stateful signatures; see ERC7562_COMPLIANCE.md).
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 maxFee
    ) public payable onlyEntryPoint returns (bytes memory result) {
        _collectExecuteFee(maxFee);
        result = super.execute(target, value, data);
    }

    /// @dev Fee-capped ERC-4337 batch execution; see `execute` for the `maxFee` semantics.
    ///      One fee per batch, not per call.
    function executeBatch(
        Call[] calldata calls,
        uint256 maxFee
    ) public payable onlyEntryPoint returns (bytes[] memory results) {
        _collectExecuteFee(maxFee);
        results = super.executeBatch(calls);
    }

    /// @dev Disabled. The inherited un-capped selector would let an op skip the signer's
    ///      `maxFee` ceiling; only the fee-capped variant above is callable.
    function execute(
        address,
        uint256,
        bytes calldata
    ) public payable override returns (bytes memory) {
        revert StandardExecuteDisabled();
    }

    /// @dev Disabled. See `execute(address,uint256,bytes)`.
    function executeBatch(
        Call[] calldata
    ) public payable override returns (bytes[] memory) {
        revert StandardExecuteDisabled();
    }

    /// @dev Disabled. `delegateExecute` is the only entry point that would run UN-vetted bytecode
    ///      in this wallet's storage context (contrast `upgradeToAndCall`, which gates on the
    ///      factory's vetted codehash set), and an arbitrary delegate could clear consumed-leaf
    ///      bits in `usedStatefulLeafBitmap` — which lives outside the guarded-slot perimeter — and
    ///      re-enable replay of one-time signatures. Batch via `executeBatch` instead.
    function delegateExecute(
        address,
        bytes calldata
    ) public payable override returns (bytes memory) {
        revert DelegateExecuteDisabled();
    }

    /// @dev Disabled. Arbitrary storage writes could clear consumed-leaf bits in
    ///      `usedStatefulLeafBitmap` and re-enable replay of one-time signatures; no wallet feature
    ///      requires raw slot writes.
    function storageStore(bytes32, bytes32) public payable override {
        revert StorageStoreDisabled();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       EXTERNAL                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IShrincsWallet
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) external initializer {
        if (msg.sender != FACTORY) revert InvalidFactory();
        if (newOwner == address(0)) revert ZeroAddressOwner();

        (
            bytes32 commitment,
            bytes32 erc1271Commitment,
            uint32 maxSignatures
        ) = _decodeAndValidateInstall(payload);

        // e3r: the address is bound to `commitment` through the CREATE3 salt, and only the
        // main-key holder can authorize the deploy. Verify the embedded deploy signature
        // BEFORE committing any state (reverts leave nothing behind).
        _verifyDeployAuthorization(newOwner, commitment, erc1271Commitment, payload);

        _initializeOwner(newOwner);
        Storage.Layout storage $ = Storage.layout();
        $.walletFactory = FACTORY;
        $.shrincsPublicKeyCommitment = commitment;
        $.erc1271StatelessCommitment = erc1271Commitment;
        $.maxSignatures = maxSignatures;
        // Epoch 0's leaf bitmap is empty by default; statefulLeavesUsed starts at 0.

        emit WalletInitialized(
            FACTORY,
            newOwner,
            commitment,
            erc1271Commitment
        );
    }

    /// @inheritdoc IShrincsWallet
    function migrate(bytes calldata payload) external {
        if (_upgradeGuard() == 0) revert NotUpgrading();

        (
            bytes32 commitment,
            bytes32 erc1271Commitment,
            uint32 maxSignatures
        ) = _decodeAndValidateInstall(payload);

        Storage.Layout storage $ = Storage.layout();
        // No-drift invariant: re-establish the guarded `_SHRINCS_FACTORY_SLOT` snapshot to this
        // (the new) implementation's immutable `FACTORY`. `migrate` runs in the new impl's code, so
        // `FACTORY` is the new source of truth; pinning storage to it keeps the snapshot slot and
        // the `walletFactory()` getter from ever diverging from the immutable after an upgrade.
        $.walletFactory = FACTORY;
        $.shrincsPublicKeyCommitment = commitment;
        $.erc1271StatelessCommitment = erc1271Commitment;
        $.maxSignatures = maxSignatures;
        // The action nonce is deliberately NOT advanced here: the `keyVersion` bump below
        // already invalidates every outstanding signed context.
        unchecked {
            $.keyVersion += 1;
        }
        // New epoch ⇒ fresh (empty) leaf bitmap namespace; reset the per-epoch used counter.
        $.statefulLeavesUsed = 0;

        emit WalletMigrated(commitment, $.keyVersion);
    }

    /// @inheritdoc IShrincsWallet
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) public payable override(IShrincsWallet, UUPSUpgradeable) onlyOwner {
        // Vet implementation locally BEFORE any delegatecall.
        bytes32 implCodehash = newImplementation.codehash;
        IWalletFactory factory = IWalletFactory(FACTORY);
        if (factory.getVettedCodeIndex(implCodehash) == type(uint256).max) {
            revert ImplementationNotVetted();
        }
        if (factory.deprecatedImpls(implCodehash))
            revert ImplementationDeprecated();

        (
            SHRINCS.PublicKey calldata pk,
            SHRINCS.Signature calldata sig,
            bool shouldMigrate,
            bytes calldata migratorPayload,
            uint256 blobNonce
        ) = Codec.decodeUpgradeAuth(data);

        uint256 liveNonce = Storage.layout().nonce;
        if (blobNonce != liveNonce)
            revert StaleActionNonce(liveNonce, blobNonce);

        bytes32 payloadHash = Codec.upgradePayloadHash(
            newImplementation,
            shouldMigrate,
            EfficientHashLib.hashCalldata(migratorPayload)
        );

        // The guard snapshot is taken AFTER the nonce advance, so the
        // guarded nonce slot (idx 6) is checked against its post-advance value
        _verifyStatefulAndAdvance(pk, sig, Codec.ACTION_UPGRADE, payloadHash);

        // verifyUpgrade is view here, but executes the NEW impl's bytecode in our storage context.
        bytes32[8] memory verifyGuard = _snapshotGuardedSlots();
        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(this.verifyUpgrade, (newImplementation, data))
        );
        _assertGuardedSlotsUnchanged(verifyGuard);

        if (shouldMigrate) {
            uint256 slot = _UPGRADE_GUARD_SLOT;
            assembly {
                tstore(slot, 1)
            }
            LibCall.delegateCallContract(
                newImplementation,
                abi.encodeCall(this.migrate, (migratorPayload))
            );
            assembly {
                tstore(slot, 0)
            }
        }

        super.upgradeToAndCall(newImplementation, data[0:0]);
    }

    /// @inheritdoc IShrincsWallet
    function execute(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 maxFee
    ) external payable onlyOwner {
        bytes32 dataHash = EfficientHashLib.hashCalldata(data);
        bytes32 payloadHash = Codec.executePayloadHash(
            target,
            value,
            dataHash,
            maxFee
        );

        // SECURITY — CEI. The leaf advance is the Effect that blocks replay; every line below is
        // an Interaction. Unlike the 4337 path, a cap-exceeded revert here rolls the whole call
        // back — leaf and nonce included.
        uint32 leaf = _verifyStatefulAndAdvance(
            publicKey,
            signature,
            Codec.ACTION_EXECUTE,
            payloadHash
        );
        _collectExecuteFee(maxFee);

        // only reason this path exists is because the caller made 
        // an error (empty data) and the leaf must be consumed either way
        if (value == 0 && data.length == 0) {
            emit LeafConsumedOnly(leaf);
            return;
        }
        if (data.length == 0) {
            SafeTransferLib.safeTransferETH(target, value);
        } else {
            LibCall.callContract(target, value, data);
        }
        emit ExecutionSucceeded(target, value, dataHash);
    }

    /// @inheritdoc IShrincsWallet
    function withdrawDepositTo(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        address to,
        uint256 amount
    ) external payable onlyOwner {
        bytes32 payloadHash = Codec.withdrawPayloadHash(to, amount);
        _verifyStatefulAndAdvance(
            publicKey,
            signature,
            Codec.ACTION_WITHDRAW,
            payloadHash
        );
        ERC4337.withdrawDepositTo(to, amount);
    }

    /// @inheritdoc IShrincsWallet
    function transferOwnership(
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.Signature calldata ownerBindingSignature,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.RotationTarget calldata nextKey,
        address newOwner
    ) external payable onlyOwner {
        if (newOwner == address(0)) revert ZeroAddressOwner();

        Storage.Layout storage $ = Storage.layout();

        // A genuine handover must hand the NEW owner an entirely fresh bundle (new stateless
        // recovery root).
        // this rotation context MUST be built and verified BEFORE
        // `_verifyStatefulAndAdvance` below, which advances `$.nonce` — both client signatures
        // bind the pre-call nonce N, and the call nets +2 (core +1, install block +1).
        SHRINCS.RotationContext memory rctx = Codec.buildRotationContext(
            Codec.rotationDomainSeparator(
                _shrincsDomainSeparator(),
                Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP
            ),
            $.nonce,
            $.keyVersion
        );
        bytes32 nextCommitment = _statelessRotate(
            $.shrincsPublicKeyCommitment,
            currentPublicKey,
            rctx,
            recoverySignature,
            nextKey
        );
        if (nextCommitment == bytes32(0)) revert InvalidSignature();

        // The current STATEFUL key separately signs the handover, cross-binding `newOwner` to the
        // incoming bundle so the two signatures cannot be paired across distinct handover attempts.
        // Verified against the CURRENT commitment (before the swap below) and consumes a leaf.
        _verifyStatefulAndAdvance(
            currentPublicKey,
            ownerBindingSignature,
            Codec.ACTION_TRANSFER_OWNERSHIP,
            Codec.transferOwnershipPayloadHash(newOwner, nextCommitment)
        );

        // statelessRotate already validated the bundle; decode only to cache the leaf budget.
        (UXMSS.StatefulPublicKey memory decoded, ) = SHRINCS
            .decodeStatefulPublicKey(nextKey.statefulPublicKey);

        // Install the fresh bundle AND the new classical owner together — the atomic handover.
        bytes32 prev = $.shrincsPublicKeyCommitment;
        $.shrincsPublicKeyCommitment = nextCommitment;
        $.maxSignatures = decoded.maxSignatures;
        unchecked {
            $.nonce += 1;
            $.keyVersion += 1;
        }
        // New epoch ⇒ fresh (empty) leaf bitmap namespace; reset the per-epoch used counter.
        $.statefulLeavesUsed = 0;
        _setOwner(newOwner);
        // Tail callback; factory pins the predicate `owner() == newOwner`.
        IWalletFactory(FACTORY).updateWalletOwner(newOwner);
        emit KeyRotated(prev, nextCommitment, $.keyVersion);
    }

    /// @inheritdoc IShrincsWallet
    function setErc1271Key(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        bytes32 newErc1271Commitment,
        uint32 newErc1271HashSuite
    ) external payable onlyOwner {
        if (newErc1271Commitment == bytes32(0)) revert ZeroErc1271Commitment();
        if (newErc1271HashSuite != HashSuite.HASH_SUITE_ID)
            revert UnsupportedHashSuite();
        bytes32 payloadHash = Codec.setErc1271KeyPayloadHash(
            newErc1271Commitment,
            newErc1271HashSuite
        );
        _verifyStatefulAndAdvance(
            publicKey,
            signature,
            Codec.ACTION_SET_ERC1271_KEY,
            payloadHash
        );

        Storage.Layout storage $ = Storage.layout();
        bytes32 old = $.erc1271StatelessCommitment;
        $.erc1271StatelessCommitment = newErc1271Commitment;
        emit Erc1271KeySet(old, newErc1271Commitment);
    }

    /// @inheritdoc IShrincsWallet
    function rotateKey(
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.Signature calldata signature,
        SHRINCS.StatefulRotationTarget calldata nextStatefulKey
    ) external payable onlyOwner {
        if (
            nextStatefulKey.statefulPublicKey.length !=
            SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES
        ) {
            revert CommitmentMismatch();
        }
        (UXMSS.StatefulPublicKey memory decoded, bool ok) = SHRINCS
            .decodeStatefulPublicKey(nextStatefulKey.statefulPublicKey);
        if (!ok || decoded.maxSignatures == 0) revert ZeroMaxSignatures();

        // Recompute the next bundle commitment, reusing the current (verified) stateless root.
        // `currentPublicKey` is validated against the installed commitment inside
        // `_verifyStatefulAndAdvance`, so its pkSeed/hypertreeRoot are trustworthy.
        bytes32 nextCommitment = SHRINCS.publicKeyCommitmentFromParts(
            nextStatefulKey.statefulPublicKey,
            currentPublicKey.pkSeed,
            currentPublicKey.hypertreeRoot
        );
        bytes32 payloadHash = Codec.rotateKeyPayloadHash(nextCommitment);

        _verifyStatefulAndAdvance(
            currentPublicKey,
            signature,
            Codec.ACTION_ROTATE_KEY,
            payloadHash
        );

        Storage.Layout storage $ = Storage.layout();
        bytes32 prev = $.shrincsPublicKeyCommitment;
        $.shrincsPublicKeyCommitment = nextCommitment;
        $.maxSignatures = decoded.maxSignatures;
        // The action nonce already advanced (+1) inside `_verifyStatefulAndAdvance` above.
        unchecked {
            $.keyVersion += 1;
        }
        // New epoch ⇒ fresh (empty) leaf bitmap namespace; reset the per-epoch used counter.
        $.statefulLeavesUsed = 0;
        emit KeyRotated(prev, nextCommitment, $.keyVersion);
    }

    /// @inheritdoc IShrincsWallet
    function recoverWallet(
        SHRINCS.PublicKey calldata currentPublicKey,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.RotationTarget calldata nextKey
    ) external payable onlyOwner {
        Storage.Layout storage $ = Storage.layout();

        // Recovery-tagged rotation domain: a signature over this context is valid ONLY here,
        // never as the recovery half of a `transferOwnership` bundle (and vice versa).
        SHRINCS.RotationContext memory ctx = Codec.buildRotationContext(
            Codec.rotationDomainSeparator(
                _shrincsDomainSeparator(),
                Codec.ROTATION_DOMAIN_RECOVER_WALLET
            ),
            $.nonce,
            $.keyVersion
        );

        bytes32 nextCommitment = _statelessRotate(
            $.shrincsPublicKeyCommitment,
            currentPublicKey,
            ctx,
            recoverySignature,
            nextKey
        );
        if (nextCommitment == bytes32(0)) revert InvalidSignature();

        // statelessRotate already validated the next bundle (length + maxSignatures != 0 +
        // declared==computed commitment); decode here only to cache the leaf budget.
        (UXMSS.StatefulPublicKey memory decoded, ) = SHRINCS
            .decodeStatefulPublicKey(nextKey.statefulPublicKey);

        bytes32 prev = $.shrincsPublicKeyCommitment;
        $.shrincsPublicKeyCommitment = nextCommitment;
        $.maxSignatures = decoded.maxSignatures;
        unchecked {
            $.nonce += 1;
            $.keyVersion += 1;
        }
        // New epoch ⇒ fresh (empty) leaf bitmap namespace; reset the per-epoch used counter.
        $.statefulLeavesUsed = 0;
        emit KeyRotated(prev, nextCommitment, $.keyVersion);
    }

    /// @inheritdoc IShrincsWallet
    function markLeavesUsed(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        uint32[] calldata leaves
    ) external payable onlyOwner {
        // Burning the authorizing leaf for nothing is almost certainly a client bug; a
        // deliberate single-leaf burn already exists via the empty `execute` path.
        if (leaves.length == 0) revert EmptyLeaves();

        // Commit to the exact target array: one 32-byte word per leaf index, in order.
        uint256 n = leaves.length;
        bytes32[] memory words = EfficientHashLib.malloc(n);
        for (uint256 i = 0; i < n; ++i) {
            EfficientHashLib.set(words, i, uint256(leaves[i]));
        }
        bytes32 payloadHash = Codec.markLeavesUsedPayloadHash(
            EfficientHashLib.hash(words)
        );

        // Deliberate carve-out: consume the authorizing leaf WITHOUT advancing the action
        // nonce. Revocation only ever shrinks the set of valid signatures, so it has nothing
        // to supersede — outstanding signed material at non-revoked leaves (an in-flight op,
        // ERC-1271 approvals) stays valid. Replay of this call is blocked by the authorizing
        // leaf's bitmap bit alone. Mass invalidation remains available via the empty
        // `execute` `LeafConsumedOnly` path, which does advance the nonce.
        _verifyStatefulAndConsume(
            publicKey,
            signature,
            Codec.ACTION_MARK_LEAVES_USED,
            payloadHash
        );

        // Marking loop: idempotent Effects only, no Interactions. Already-used targets
        // (including duplicates and the just-consumed authorizing leaf) are skipped, not
        // reverted — a pending action racing its own revocation must not brick the batch
        // and force burning another authorizing leaf.
        Storage.Layout storage $ = Storage.layout();
        uint256 epoch = $.keyVersion;
        for (uint256 i = 0; i < n; ++i) {
            uint32 leaf = leaves[i];
            // Out-of-range is a client bug, not a race — fail the whole batch loudly. The
            // reserved deploy-leaf range `[1..MAX_DEPLOY_CHAINS]` is not part of the signing
            // budget, so it is not a valid revocation target (e3r).
            if (leaf <= MAX_DEPLOY_CHAINS || leaf > $.maxSignatures)
                revert LeafOutOfRange(leaf);
            if (_isStatefulLeafUsed($, epoch, leaf)) {
                emit LeafRevocationSkipped(leaf, epoch);
                continue;
            }
            _markStatefulLeafUsed($, epoch, leaf);
            unchecked {
                // Bounded by `maxSignatures`: every mark is a unique in-range leaf.
                $.statefulLeavesUsed += 1;
            }
            emit LeafRevoked(leaf, epoch);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  DISABLED CLASSICAL                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Classical ownership renounce is disabled — a SHRINCS wallet always has an owner for
    ///      the ERC-1271 ECDSA gate and factory registry.
    function renounceOwnership() public payable override(Ownable) onlyOwner {
        revert RenounceDisabled();
    }

    /// @dev Classical `transferOwnership(address)` is disabled; use the SHRINCS-authenticated
    ///      `transferOwnership(PublicKey,StatefulSignature,address)`.
    function transferOwnership(address) public payable override {
        revert ClassicalTransferOwnershipDisabled();
    }

    /// @dev Two-step ownership handover is disabled.
    function requestOwnershipHandover() public payable override {
        revert OwnershipHandoverDisabled();
    }

    /// @dev Disabled; see `requestOwnershipHandover`.
    function cancelOwnershipHandover() public payable override {
        revert OwnershipHandoverDisabled();
    }

    /// @dev Disabled; see `requestOwnershipHandover`.
    function completeOwnershipHandover(address) public payable override {
        revert OwnershipHandoverDisabled();
    }

    /// @dev Classical EntryPoint-deposit withdrawal is disabled; use the SHRINCS-authenticated
    ///      `withdrawDepositTo(PublicKey,StatefulSignature,address,uint256)`.
    function withdrawDepositTo(address, uint256) public payable override {
        revert ClassicalWithdrawDisabled();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        VIEWS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev ERC-1271 validation: stateless SHRINCS verify against the dedicated verifier key AND
    ///      classical `owner()` ECDSA. View-safe (no leaf consumed). The live action nonce is
    ///      bound into the verified context, so a blob is valid only until the wallet's next
    ///      consumed signature — sign as late as possible and re-sign after any wallet action.
    ///      `setErc1271Key` remains the mass-invalidation of last resort.
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view override returns (bytes4) {
        return
            _checkErc1271Signature(hash, signature) ==
                Erc1271ValidationResult.Ok
                ? bytes4(0x1626ba7e)
                : bytes4(0xffffffff);
    }

    /// @inheritdoc IShrincsWallet
    function debugIsValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (Erc1271ValidationResult) {
        return _checkErc1271Signature(hash, signature);
    }

    /// @inheritdoc IShrincsWallet
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view {
        // Reachability probe: re-run the stateful verify over the upgrade context as proof the
        // new impl's SHRINCS verifier is reachable in this storage context. Self-consistency,
        // not authorization (the authorization already happened in `upgradeToAndCall`).
        (
            SHRINCS.PublicKey calldata pk,
            SHRINCS.Signature calldata sig,
            bool shouldMigrate,
            bytes calldata migratorPayload,
            uint256 blobNonce
        ) = Codec.decodeUpgradeAuth(data);

        Storage.Layout storage $ = Storage.layout();
        // Rebuild the context from the BLOB-borne nonce, never the live one: at the SDK's
        // pre-flight staticcall the live nonce equals the blob's, but in the post-consumption
        // delegatecall from `upgradeToAndCall` the live nonce has already advanced past it —
        // a live-nonce read here would make the same signature fail to re-verify and brick
        // every upgrade. Freshness was already enforced by the `StaleActionNonce` gate.
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            _shrincsDomainSeparator(),
            blobNonce,
            $.keyVersion,
            Codec.ACTION_UPGRADE,
            Codec.upgradePayloadHash(
                newImplementation,
                shouldMigrate,
                EfficientHashLib.hashCalldata(migratorPayload)
            )
        );
        // Stateful verification via the pinned verifier (the probe proves the NEW impl's
        // pinned verifier is reachable; see EXTERNAL VERIFIER DELEGATION).
        bytes32 commitment = $.shrincsPublicKeyCommitment;
        if (
            !_tryVerifyStateful(
                commitment,
                SHRINCS.statefulActionMessageHash(commitment, ctx),
                abi.encode(pk, sig)
            )
        ) revert InvalidSignature();
    }

    /// @inheritdoc IShrincsWallet
    function quipSignedHashEcdsaTarget(
        bytes32 hash
    ) public view returns (bytes32) {
        return
            _hashTypedData(
                keccak256(abi.encode(_QUIP_SIGNED_HASH_TYPEHASH, hash))
            );
    }

    /// @inheritdoc IShrincsWallet
    function quipUserOpHashEcdsaTarget(
        bytes32 userOpHash
    ) public view returns (bytes32) {
        return
            _hashTypedData(
                keccak256(abi.encode(_QUIP_USER_OP_HASH_TYPEHASH, userOpHash))
            );
    }

    /// @inheritdoc IShrincsWallet
    function owner()
        public
        view
        override(IShrincsWallet, Ownable)
        returns (address)
    {
        return Ownable.owner();
    }

    /// @dev Two-step handover is disabled, so no handover is ever pending.
    function ownershipHandoverExpiresAt(
        address
    ) public pure override returns (uint256) {
        return 0;
    }

    /// @inheritdoc IShrincsWallet
    function version() external view returns (uint256) {
        address impl = _msgImplementation();
        return IWalletFactory(FACTORY).getVettedCodeIndex(impl.codehash);
    }

    /// @inheritdoc IShrincsWallet
    function getExecuteFee() public view returns (uint256) {
        // The immutable `FACTORY` is the single source of truth for the factory address (same
        // anchor as `msg.sender == FACTORY` access control and upgrade vetting), so fees are read
        // from and paid to it — never the mutable `$.walletFactory` snapshot slot, which could
        // diverge from the immutable after an upgrade to a differently-compiled implementation.
        return IWalletFactory(FACTORY).executeFee();
    }

    /// @inheritdoc IShrincsWallet
    function walletFactory() external view returns (address payable) {
        // Exposes the guarded `_SHRINCS_FACTORY_SLOT` snapshot value, which `initialize`/`migrate`
        // re-establish to `FACTORY`, so it is invariantly equal to the immutable source of truth.
        return Storage.layout().walletFactory;
    }

    /// @inheritdoc IShrincsWallet
    function getShrincsPublicKeyCommitment() external view returns (bytes32) {
        return Storage.layout().shrincsPublicKeyCommitment;
    }

    /// @inheritdoc IShrincsWallet
    function getErc1271Commitment() external view returns (bytes32) {
        return Storage.layout().erc1271StatelessCommitment;
    }

    /// @inheritdoc IShrincsWallet
    function getHashSuite() external pure returns (uint32) {
        // Not stored: install/rotate paths reject anything but this suite.
        return HashSuite.HASH_SUITE_ID;
    }

    /// @inheritdoc IShrincsWallet
    function getErc1271HashSuite() external pure returns (uint32) {
        // Not stored: install/rotate paths reject anything but this suite.
        return HashSuite.HASH_SUITE_ID;
    }

    /// @inheritdoc IShrincsWallet
    function getShrincsVerifier() external view returns (address) {
        return SHRINCS_VERIFIER;
    }

    /// @inheritdoc IShrincsWallet
    function isStatefulLeafUsed(
        uint256 leafIndex
    ) external view returns (bool) {
        Storage.Layout storage $ = Storage.layout();
        return _isStatefulLeafUsed($, $.keyVersion, leafIndex);
    }

    /// @inheritdoc IShrincsWallet
    function statefulLeavesUsed() external view returns (uint32) {
        return Storage.layout().statefulLeavesUsed;
    }

    /// @inheritdoc IShrincsWallet
    function maxSignatures() external view returns (uint32) {
        return Storage.layout().maxSignatures;
    }

    /// @inheritdoc IShrincsWallet
    function remainingStatefulSignatures() external view returns (uint32) {
        Storage.Layout storage $ = Storage.layout();
        // Saturating: the leaf bitmap is the real anti-replay mechanism; this
        // counter is advisory, so it must never revert even if it ever drifts
        // above `maxSignatures`.
        if ($.statefulLeavesUsed >= $.maxSignatures) return 0;
        return $.maxSignatures - $.statefulLeavesUsed;
    }

    /// @inheritdoc IShrincsWallet
    function keyVersion() external view returns (uint256) {
        return Storage.layout().keyVersion;
    }

    /// @inheritdoc IShrincsWallet
    function actionNonce() external view returns (uint256) {
        return Storage.layout().nonce;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNALS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The stateful leaf index a SHRINCS signature reveals is encoded as its
    ///      authentication-path length. Single derivation point for every stateful verify path.
    function _leafIndex(
        SHRINCS.Signature calldata signature
    ) internal pure returns (uint32) {
        return uint32(signature.authPath.length);
    }

    /// @dev Decodes and fully validates an install/migrate key-bundle payload — the block shared
    ///      byte-for-byte by `initialize` and `migrate`: non-zero ERC-1271 commitment, declared
    ///      hash suites, main-bundle shape + commitment recompute, and a non-zero leaf budget.
    ///      Returns exactly the three values both callers persist. Pure: touches no storage.
    function _decodeAndValidateInstall(
        bytes calldata payload
    )
        internal
        pure
        returns (
            bytes32 commitment,
            bytes32 erc1271Commitment,
            uint32 maxSignatures
        )
    {
        SHRINCS.PublicKey calldata pk;
        uint32 hashSuite;
        uint32 erc1271HashSuite;
        (
            commitment,
            ,
            pk,
            hashSuite,
            erc1271Commitment,
            erc1271HashSuite
        ) = Codec.decodeInit(payload);

        if (erc1271Commitment == bytes32(0)) revert ZeroErc1271Commitment();

        // The SHRINCS library hardcodes HASH_SUITE_KECCAK_256 into every canonical message
        // hash, so the declared suites are a client-agreement check, not a dispatch choice.
        if (
            hashSuite != HashSuite.HASH_SUITE_ID ||
            erc1271HashSuite != HashSuite.HASH_SUITE_ID
        ) revert UnsupportedHashSuite();

        // Validate the supplied main bundle's fixed shape and the declared commitment
        // (validPublicKey already checks the embedded commitment recomputes).
        if (!SHRINCS.validPublicKey(pk)) revert CommitmentMismatch();
        if (SHRINCS.publicKeyCommitment(pk) != commitment)
            revert CommitmentMismatch();

        (UXMSS.StatefulPublicKey memory decoded, bool ok) = SHRINCS
            .decodeStatefulPublicKey(pk.statefulPublicKey);
        if (!ok || decoded.maxSignatures == 0) revert ZeroMaxSignatures();
        maxSignatures = decoded.maxSignatures;
    }

    /// @dev Core stateful verify + bitmap leaf consume shared by every stateful path. Reverts on
    ///      a zero/over-budget/already-consumed leaf or invalid signature; on success marks the
    ///      leaf used in the current epoch's bitmap (an Effect), returning the consumed leaf.
    ///      Does NOT advance the action nonce — that is `_verifyStatefulAndAdvance`'s job. Only
    ///      `markLeavesUsed` consumes without advancing: revocation is pure denial (the set of
    ///      valid signatures strictly shrinks), so it has nothing to supersede, and the consumed
    ///      leaf's bitmap bit alone is its anti-replay guard.
    function _verifyStatefulAndConsume(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        bytes32 actionType,
        bytes32 payloadHash
    ) internal returns (uint32 leaf) {
        Storage.Layout storage $ = Storage.layout();
        uint256 epoch = $.keyVersion;
        leaf = _leafIndex(signature);
        // Signing budget excludes the reserved deploy-leaf range `[1..MAX_DEPLOY_CHAINS]` (e3r).
        if (leaf <= MAX_DEPLOY_CHAINS || leaf > $.maxSignatures)
            revert StatefulBudgetExhausted();
        if (_isStatefulLeafUsed($, epoch, leaf)) revert StaleStatefulLeaf();

        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            _shrincsDomainSeparator(),
            $.nonce,
            epoch,
            actionType,
            payloadHash
        );
        // Stateful verification via the pinned verifier: canonical action hash computed
        // locally, bundle checks + crypto delegated
        bytes32 commitment = $.shrincsPublicKeyCommitment;
        if (
            !_tryVerifyStateful(
                commitment,
                SHRINCS.statefulActionMessageHash(commitment, ctx),
                abi.encode(publicKey, signature)
            )
        ) revert InvalidSignature();

        _markStatefulLeafUsed($, epoch, leaf);
        unchecked {
            $.statefulLeavesUsed += 1;
        }
        emit StatefulSignatureVerified(leaf, epoch);
    }

    /// @dev `_verifyStatefulAndConsume` plus the action-nonce advance — the default for every
    ///      authorizing stateful path except `markLeavesUsed` (see the consume variant's note).
    function _verifyStatefulAndAdvance(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        bytes32 actionType,
        bytes32 payloadHash
    ) internal returns (uint32 leaf) {
        leaf = _verifyStatefulAndConsume(
            publicKey,
            signature,
            actionType,
            payloadHash
        );
        unchecked {
            Storage.layout().nonce += 1;
        }
    }

    /// @dev The wallet's policy boundary for the verifier's revert-as-rejection channel.
    ///      hashsigs 0.2.0 dropped the library's shape/canonicity walk: garbage signature
    ///      internals (attacker-controlled array lengths inside `userOp.signature` or an
    ///      ERC-1271 blob) REVERT inside the verifier instead of returning 0xffffffff, and
    ///      the dep is explicit that "a caller that needs a boolean must treat a revert as
    ///      its own policy decision". This wallet's contract is never-revert validation
    ///      (ERC-4337 returns 1) and never-revert ERC-1271, so EVERY verifier revert maps
    ///      to "invalid signature". Accepted trade-off: an inner out-of-gas is also
    ///      reported as an invalid signature instead of propagating.
    function _tryVerifyStateful(
        bytes32 expectedCommitment,
        bytes32 messageHash,
        bytes memory envelope
    ) internal view returns (bool) {
        try
            IERC7913SignatureVerifier(SHRINCS_VERIFIER).verify(
                abi.encodePacked(expectedCommitment),
                messageHash,
                envelope
            )
        returns (bytes4 result) {
            return result == IERC7913SignatureVerifier.verify.selector;
        } catch {
            return false;
        }
    }

    /// @dev Stateless twin of `_tryVerifyStateful` (identical revert policy), targeting the
    ///      verifier's `verifyStateless` entrypoint.
    function _tryVerifyStateless(
        bytes32 expectedCommitment,
        bytes32 messageHash,
        bytes memory envelope
    ) internal view returns (bool) {
        try
            SHRINCSVerifier(SHRINCS_VERIFIER).verifyStateless(
                abi.encodePacked(expectedCommitment),
                messageHash,
                envelope
            )
        returns (bytes4 result) {
            return result == IERC7913SignatureVerifier.verify.selector;
        } catch {
            return false;
        }
    }

    /// @dev External-verifier image of `SHRINCS.statelessRotate` (SHRINCS.sol). Division of
    ///      labor: the pinned verifier re-runs the CURRENT-bundle checks (commitment match +
    ///      shape, inside `prepareStatelessDelegation`) plus the FORS-C/hypertree crypto, so
    ///      the wallet keeps only what the verifier can never see — the rotation TARGET.
    ///      `nextKey`'s structural validation also keeps `fullRotationMessageHash`'s packed
    ///      preimage canonical, and the declared-vs-recomputed equality is the authorization
    ///      semantics: the signature binds the DECLARED commitment bytes (via the message
    ///      hash), the wallet installs the RECOMPUTED value — equality makes those the same
    ///      thing. Returns the next bundle commitment, or bytes32(0) on any failure.
    function _statelessRotate(
        bytes32 expectedCommitment,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext memory ctx,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.RotationTarget calldata nextKey
    ) private view returns (bytes32) {
        // The replacement bundle's four fields have fixed widths.
        if (
            nextKey.statefulPublicKey.length !=
            SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES
        ) return bytes32(0);
        if (nextKey.publicKeyCommitment.length != 32) return bytes32(0);
        if (nextKey.pkSeed.length != 32) return bytes32(0);
        if (nextKey.hypertreeRoot.length != 32) return bytes32(0);
        {
            // Reject unusable zero-budget replacement stateful keys.
            (
                UXMSS.StatefulPublicKey memory decodedNext,
                bool ok
            ) = SHRINCS.decodeStatefulPublicKey(nextKey.statefulPublicKey);
            if (!ok || decodedNext.maxSignatures == 0) return bytes32(0);
        }
        bytes32 computedNext = SHRINCS.publicKeyCommitmentFromParts(
            nextKey.statefulPublicKey,
            nextKey.pkSeed,
            nextKey.hypertreeRoot
        );

        bytes32 declaredNext = abi.decode(
            nextKey.publicKeyCommitment,
            (bytes32)
        );
        if (declaredNext != computedNext) return bytes32(0);

        // The stateless recovery signature must authorize exactly the canonical
        // full-rotation message.
        bytes32 messageHash = SHRINCS.fullRotationMessageHash(
            expectedCommitment,
            currentPublicKey,
            ctx,
            nextKey
        );
        if (
            !_tryVerifyStateless(
                expectedCommitment,
                messageHash,
                abi.encode(currentPublicKey, recoverySignature)
            )
        ) return bytes32(0);

        return computedNext;
    }

    /// @dev Returns whether stateful `leafIndex` has been consumed in the given key epoch.
    function _isStatefulLeafUsed(
        Storage.Layout storage $,
        uint256 keyVersion_,
        uint256 leafIndex
    ) internal view returns (bool) {
        return
            ($.usedStatefulLeafBitmap[keyVersion_][leafIndex >> 8] &
                (uint256(1) << (leafIndex & 0xff))) != 0;
    }

    /// @dev Marks stateful `leafIndex` consumed in the given key epoch.
    function _markStatefulLeafUsed(
        Storage.Layout storage $,
        uint256 keyVersion_,
        uint256 leafIndex
    ) internal {
        $.usedStatefulLeafBitmap[keyVersion_][leafIndex >> 8] |=
            uint256(1) <<
            (leafIndex & 0xff);
    }

    /// @dev Shared core for `isValidSignature` and `debugIsValidSignature`. Order: length →
    ///      ECDSA (owner) → stateless SHRINCS (dedicated verifier key).
    function _checkErc1271Signature(
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (Erc1271ValidationResult) {
        if (signature.length < 0x60)
            return Erc1271ValidationResult.BadSignatureLength;
        (
            SHRINCS.PublicKey calldata pk,
            SPHINCSPlusC.Signature calldata sig,
            bytes calldata ecdsaSig
        ) = Codec.decodeErc1271Signature(signature);

        address recovered = ECDSA.tryRecoverCalldata(
            quipSignedHashEcdsaTarget(hash),
            ecdsaSig
        );
        if (recovered == address(0) || recovered != owner()) {
            return Erc1271ValidationResult.InvalidEcdsaSignature;
        }

        // Zero-hash membrane: `hash` is the only caller-supplied context field anywhere in
        // the wallet (it rides in `payloadHash` below). The inlined library path rejected
        // payloadHash == 0 inside `validActionContext`; the external verifier never sees
        // the context, so the check lives here.
        if (hash == bytes32(0))
            return Erc1271ValidationResult.InvalidShrincsSignature;

        Storage.Layout storage $ = Storage.layout();
        // Binds the LIVE action nonce: every consumed wallet signature invalidates all
        // outstanding ERC-1271 blobs (intended supersession — integrators re-sign after actions).
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            _shrincsDomainSeparator(),
            $.nonce,
            $.keyVersion,
            Codec.ACTION_ERC1271,
            hash
        );
        // Stateless verification via the pinned verifier: canonical stateless action hash
        // computed locally; bundle checks + FORS-C/hypertree crypto delegated
        if (
            !_tryVerifyStateless(
                $.erc1271StatelessCommitment,
                SHRINCS.statelessActionMessageHash(
                    $.erc1271StatelessCommitment,
                    ctx
                ),
                abi.encode(pk, sig)
            )
        ) return Erc1271ValidationResult.InvalidShrincsSignature;

        return Erc1271ValidationResult.Ok;
    }

    /// @dev Sends the per-op execute fee to the factory, if any. Reads the LIVE fee once and
    ///      charges it, reverting only if it exceeds the signer's `maxFee` ceiling — so a fee
    ///      decrease between signing and landing succeeds at the lower price.
    function _collectExecuteFee(uint256 maxFee) internal {
        uint256 fee = getExecuteFee();
        if (fee > maxFee) revert ExecuteFeeExceedsCap(fee, maxFee);
        if (fee > 0) {
            // Paid to the immutable `FACTORY` — the single source of truth — matching the fee
            // read in `getExecuteFee`, so the amount charged and its recipient can never diverge.
            SafeTransferLib.safeTransferETH(FACTORY, fee);
        }
    }

    /// @dev Verifies the deploy authorization embedded in the `initialize` payload (e3r).
    ///      Runs during `initialize`, where `msg.sender == FACTORY` (checked by the caller).
    ///      Steps:
    ///        1. Cross-check the CREATE3 salt commitment (`FACTORY.pendingDeployCommitment()`,
    ///           the value the factory salted the address with) against the main commitment the
    ///           payload installs. A mismatch means the address was bound to a DIFFERENT key
    ///           than the one being installed — reject (`CommitmentMismatch`).
    ///        2. Read the factory's authoritative deploy context: `vaultId` (the reverse
    ///           registry entry set before this call), the reserved `quipDeployChainIndex`, and
    ///           the declared `deployMode`.
    ///        3. Rebuild the deploy `ActionContext` (bound to chainId + FACTORY via
    ///           `DEPLOY_DOMAIN_TAG`, `nonce`/`keyVersion` = 0 since the wallet is fresh) and
    ///           verify the embedded main-key signature against the installed commitment:
    ///           stateful → a signature at reserved deploy leaf `quipDeployChainIndex`; stateless
    ///           → a chainId-bound stateless signature. No leaf is consumed and no nonce is
    ///           advanced — the `initializer` guard makes the deploy inherently one-time.
    function _verifyDeployAuthorization(
        address newOwner,
        bytes32 commitment,
        bytes32 erc1271Commitment,
        bytes calldata payload
    ) private view {
        IWalletFactory factory = IWalletFactory(FACTORY);
        if (factory.pendingDeployCommitment() != commitment)
            revert CommitmentMismatch();

        bytes32 vaultId = factory.vaultIdOf(address(this));
        uint16 quipDeployChainIndex = factory.quipDeployChainIndex();
        IWalletFactory.DeployMode mode = factory.deployMode();

        bytes calldata deployAuth = Codec.decodeInitDeployAuth(payload);

        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            _deployDomainSeparator(),
            0,
            0,
            Codec.ACTION_DEPLOY,
            Codec.deployPayloadHash(
                vaultId,
                newOwner,
                erc1271Commitment,
                quipDeployChainIndex
            )
        );

        if (mode == IWalletFactory.DeployMode.Stateful) {
            // Verify FIRST: `_tryVerifyStateful` treats any malformed/short/garbage envelope as a
            // rejection (returns false), so an absent or bad deploy signature reverts here rather
            // than hard-reverting inside the decoder below.
            if (
                !_tryVerifyStateful(
                    commitment,
                    SHRINCS.statefulActionMessageHash(commitment, ctx),
                    deployAuth
                )
            ) revert InvalidDeployAuthorization();
            // A valid signature guarantees a well-formed envelope, so decoding it to read the
            // revealed leaf is safe. Enforce it used the reserved deploy leaf
            // `quipDeployChainIndex` (the envelope shares the `abi.encode(PublicKey,
            // SHRINCS.Signature)` shape of a
            // sponsorship blob, so reuse that decoder).
            (, SHRINCS.Signature calldata deploySig) = Codec
                .decodeSponsorshipSignature(deployAuth);
            if (_leafIndex(deploySig) != quipDeployChainIndex)
                revert InvalidDeployAuthorization();
        } else {
            if (
                !_tryVerifyStateless(
                    commitment,
                    SHRINCS.statelessActionMessageHash(commitment, ctx),
                    deployAuth
                )
            ) revert InvalidDeployAuthorization();
        }
    }

    /// @dev The deploy signing domain (e3r): tag + chainId + FACTORY. Bound to the factory (not
    ///      `address(this)`) because the deploy signature is produced before the wallet address
    ///      exists; the factory is the authority that supplies chainId + `quipDeployChainIndex`.
    function _deployDomainSeparator() internal view returns (bytes32) {
        return
            EfficientHashLib.hash(
                Codec.DEPLOY_DOMAIN_TAG,
                bytes32(block.chainid),
                bytes32(uint256(uint160(address(FACTORY))))
            );
    }

    /// @dev The wallet's canonical SHRINCS signing domain: tag + chainId + this wallet.
    function _shrincsDomainSeparator() internal view returns (bytes32) {
        return
            EfficientHashLib.hash(
                Codec.DOMAIN_TAG,
                bytes32(block.chainid),
                bytes32(uint256(uint160(address(this))))
            );
    }

    /// @dev The currently installed implementation address (ERC-1967 slot).
    function _msgImplementation() internal view returns (address impl) {
        assembly {
            impl := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /// @dev Reads the transient upgrade guard flag.
    function _upgradeGuard() internal view returns (uint256 v) {
        uint256 slot = _UPGRADE_GUARD_SLOT;
        assembly {
            v := tload(slot)
        }
    }

    /// @dev Snapshots the eight guarded slots: owner, ERC-1967 impl, factory, main commitment,
    ///      ERC-1271 commitment, keyVersion, nonce, packed leaf-state word.
    function _snapshotGuardedSlots()
        internal
        view
        returns (bytes32[8] memory snapshot)
    {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(snapshot, sload(_OWNER_SLOT))
            mstore(add(snapshot, 0x20), sload(_ERC1967_IMPLEMENTATION_SLOT))
            mstore(add(snapshot, 0x40), sload(_SHRINCS_FACTORY_SLOT))
            mstore(add(snapshot, 0x60), sload(_SHRINCS_COMMITMENT_SLOT))
            mstore(add(snapshot, 0x80), sload(_ERC1271_COMMITMENT_SLOT))
            mstore(add(snapshot, 0xa0), sload(_KEY_VERSION_SLOT))
            mstore(add(snapshot, 0xc0), sload(_NONCE_SLOT))
            mstore(add(snapshot, 0xe0), sload(_LEAF_STATE_SLOT))
        }
    }

    /// @dev Reverts with `GuardedSlotTampered(slotIndex)` if any guarded slot changed since the
    ///      snapshot. Index mapping documented on the error in `IShrincsWallet`.
    function _assertGuardedSlotsUnchanged(
        bytes32[8] memory snapshot
    ) internal view {
        bytes4 selector = GuardedSlotTampered.selector;
        /// @solidity memory-safe-assembly
        assembly {
            function revertWithIndex(sel, idx) {
                mstore(0x00, sel)
                mstore(0x04, idx)
                revert(0x00, 0x24)
            }
            if iszero(eq(mload(snapshot), sload(_OWNER_SLOT))) {
                revertWithIndex(selector, 0)
            }
            if iszero(
                eq(
                    mload(add(snapshot, 0x20)),
                    sload(_ERC1967_IMPLEMENTATION_SLOT)
                )
            ) {
                revertWithIndex(selector, 1)
            }
            if iszero(eq(mload(add(snapshot, 0x40)), sload(_SHRINCS_FACTORY_SLOT))) {
                revertWithIndex(selector, 2)
            }
            if iszero(
                eq(mload(add(snapshot, 0x60)), sload(_SHRINCS_COMMITMENT_SLOT))
            ) {
                revertWithIndex(selector, 3)
            }
            if iszero(
                eq(mload(add(snapshot, 0x80)), sload(_ERC1271_COMMITMENT_SLOT))
            ) {
                revertWithIndex(selector, 4)
            }
            if iszero(
                eq(mload(add(snapshot, 0xa0)), sload(_KEY_VERSION_SLOT))
            ) {
                revertWithIndex(selector, 5)
            }
            if iszero(eq(mload(add(snapshot, 0xc0)), sload(_NONCE_SLOT))) {
                revertWithIndex(selector, 6)
            }
            if iszero(eq(mload(add(snapshot, 0xe0)), sload(_LEAF_STATE_SLOT))) {
                revertWithIndex(selector, 7)
            }
        }
    }
}
