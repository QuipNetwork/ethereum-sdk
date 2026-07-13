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
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.1.0/contracts/SHRINCS.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsUtils} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsUtils.sol";
import {IShrincsWallet} from "./interfaces/IShrincsWallet.sol";
import {IQuipFactory} from "../interfaces/IQuipFactory.sol";
import {ShrincsWalletCodec as Codec} from "./ShrincsWalletCodec.sol";
import {ShrincsWalletStorage as Storage} from "./ShrincsWalletStorage.sol";

/// @title ShrincsWallet
/// @notice A post-quantum ERC-4337 smart-account wallet authorized by SHRINCS hash-based
///         signatures. Normal operations use the cheap stateful path (leaf-indexed,
///         MonotonicIndex anti-replay, bounded by `maxSignatures`). Routine key rotation
///         (`rotateKey`) is stateful; the main key's stateless half is reserved as break-glass
///         recovery authority (`recoverWallet`). ERC-1271 uses a separate dedicated stateless
///         verifier key plus a classical `owner()` ECDSA AND-gate.
contract ShrincsWallet is IShrincsWallet, ERC4337, Initializable {
    /// @dev The immutable QuipFactory that deploys and registers this wallet.
    address payable public immutable FACTORY;

    /// @dev Transient storage slot gating `migrate` to the `upgradeToAndCall` context.
    /// @notice REQUIRES EIP-1153 (TSTORE/TLOAD).
    uint256 private constant _UPGRADE_GUARD_SLOT =
        uint256(keccak256("quip.shrincs.wallet.upgrade.guard")) - 1;

    /// @dev EIP-712 type hash nesting the ERC-1271 `hash` before ECDSA recovery, binding the
    ///      classical signature to this wallet's domain (mirrors Safe's `SafeMessage`).
    bytes32 private constant _QUIP_SIGNED_HASH_TYPEHASH =
        keccak256("QuipSignedHash(bytes32 hash)");

    /// @dev SHRINCS storage base slots, duplicated from `ShrincsWalletStorage` as numeric
    ///      literals because inline assembly cannot reference cross-library constants or `base+N`.
    ///      Kept in lock-step with `Layout` field order (pinned by the storage-layout fixture).
    bytes32 private constant _PQ_FACTORY_SLOT =
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

    constructor(address payable factory_) {
        if (factory_ == address(0)) revert ZeroAddressFactory();
        FACTORY = factory_;
        _disableInitializers();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   INTERNAL OVERRIDES                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev EIP-712 domain name/version for the ERC-1271 ECDSA half. Distinct from the WOTS+
    ///      wallet's "QuipWallet" so a classical owner signature cannot cross wallet families.
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "QuipShrincsWallet";
        version = "1";
    }

    /// @dev Hybrid authority: every PQ-authorized owner entry point is gated by BOTH the
    ///      classical `owner()` (`onlyOwner`) AND a SHRINCS signature. Upgrades keep the
    ///      classical `onlyOwner` gate here in addition to the stateful signature verified in
    ///      `upgradeToAndCall`.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev ERC-4337 stateful validation with MonotonicIndex leaf advance. State is advanced
    ///      during validation (the revealed stateful leaf is consumed regardless of whether the
    ///      execution phase later succeeds). Never reverts on signature failure — returns 1 so
    ///      the EntryPoint's refund accounting stays clean.
    ///
    ///      By convention `userOp.signature` carries *both* SHRINCS structs — it is the ABI
    ///      encoding of `(PublicKey publicKey, StatefulSignature signature)` — so the decode
    ///      below hands back a public key alongside the signature.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256) {
        // two reasons for check:
        // 1. call would fail on decode (checks first 2 x bytes32 = 64 bytes)
        //    if length check didn't exist
        // 2. solidity encodes offset as one word per dynamic type at the `head` of
        //    the encoded data; two bytes32 words means two dynamic types at the `tail`
        //    of the encded data - namely ShrincsTypes.PublicKey and ShrincsType.StatefulSiganture
        //    so this validation is an indication that two dyanmic types exist and the two bytes32
        //    words contain their offset
        if (userOp.signature.length < 0x40) {
            emit UserOpValidationRejected(
                UserOpValidationFailure.BadSignatureLength
            );
            return 1;
        }
        (
            ShrincsTypes.PublicKey calldata pk,
            ShrincsTypes.StatefulSignature calldata sig
        ) = Codec.decodeUserOpSignature(userOp.signature);

        Storage.Layout storage $ = Storage.layout();
        uint256 epoch = $.keyVersion;
        uint32 leaf = uint32(sig.authPath.length);
        if (leaf == 0 || leaf > $.maxSignatures) {
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
        ShrincsTypes.ActionContext memory ctx = Codec.buildActionContext(
            _shrincsDomainSeparator(),
            $.nonce,
            epoch,
            Codec.ACTION_ERC4337_EXECUTE,
            Codec.erc4337PayloadHash(userOpHash, getExecuteFee())
        );
        if (
            !SHRINCS.verifyStateful($.shrincsPublicKeyCommitment, pk, ctx, sig)
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

    /// @inheritdoc ERC4337
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) public payable override onlyEntryPoint returns (bytes memory result) {
        _collectExecuteFee();
        result = super.execute(target, value, data);
    }

    /// @inheritdoc ERC4337
    function executeBatch(
        Call[] calldata calls
    ) public payable override onlyEntryPoint returns (bytes[] memory results) {
        _collectExecuteFee();
        results = super.executeBatch(calls);
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
            ,
            ShrincsTypes.PublicKey calldata pk,
            uint32 hashSuite,
            bytes32 erc1271Commitment,
            uint32 erc1271HashSuite
        ) = Codec.decodeInit(payload);

        if (erc1271Commitment == bytes32(0)) revert ZeroErc1271Commitment();

        // The SHRINCS library hardcodes HASH_SUITE_KECCAK_256 into every canonical message
        // hash, so the declared suites are a client-agreement check, not a dispatch choice.
        if (
            hashSuite != ShrincsTypes.HASH_SUITE_KECCAK_256 ||
            erc1271HashSuite != ShrincsTypes.HASH_SUITE_KECCAK_256
        ) revert UnsupportedHashSuite();

        // Validate the supplied main bundle's fixed shape and the declared commitment
        // (validPublicKey already checks the embedded commitment recomputes).
        if (!ShrincsUtils.validPublicKey(pk)) revert CommitmentMismatch();
        if (ShrincsUtils.publicKeyCommitment(pk) != commitment)
            revert CommitmentMismatch();

        (ShrincsTypes.StatefulPublicKey memory decoded, bool ok) = ShrincsUtils
            .decodeStatefulPublicKey(pk.statefulPublicKey);
        if (!ok || decoded.maxSignatures == 0) revert ZeroMaxSignatures();

        _initializeOwner(newOwner);
        Storage.Layout storage $ = Storage.layout();
        $.quipFactory = FACTORY;
        $.shrincsPublicKeyCommitment = commitment;
        $.erc1271StatelessCommitment = erc1271Commitment;
        $.maxSignatures = decoded.maxSignatures;
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
            ,
            ShrincsTypes.PublicKey calldata pk,
            uint32 hashSuite,
            bytes32 erc1271Commitment,
            uint32 erc1271HashSuite
        ) = Codec.decodeInit(payload);

        if (erc1271Commitment == bytes32(0)) revert ZeroErc1271Commitment();

        if (
            hashSuite != ShrincsTypes.HASH_SUITE_KECCAK_256 ||
            erc1271HashSuite != ShrincsTypes.HASH_SUITE_KECCAK_256
        ) revert UnsupportedHashSuite();

        if (!ShrincsUtils.validPublicKey(pk)) revert CommitmentMismatch();
        if (ShrincsUtils.publicKeyCommitment(pk) != commitment)
            revert CommitmentMismatch();

        (ShrincsTypes.StatefulPublicKey memory decoded, bool ok) = ShrincsUtils
            .decodeStatefulPublicKey(pk.statefulPublicKey);
        if (!ok || decoded.maxSignatures == 0) revert ZeroMaxSignatures();

        Storage.Layout storage $ = Storage.layout();
        $.shrincsPublicKeyCommitment = commitment;
        $.erc1271StatelessCommitment = erc1271Commitment;
        $.maxSignatures = decoded.maxSignatures;
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
        IQuipFactory factory = IQuipFactory(FACTORY);
        if (factory.getVettedCodeIndex(implCodehash) == type(uint256).max) {
            revert ImplementationNotVetted();
        }
        if (factory.deprecatedImpls(implCodehash))
            revert ImplementationDeprecated();

        (
            ShrincsTypes.PublicKey calldata pk,
            ShrincsTypes.StatefulSignature calldata sig,
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
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatefulSignature calldata signature,
        address target,
        uint256 value,
        bytes calldata data
    ) external payable onlyOwner {
        uint256 fee = getExecuteFee();
        bytes32 dataHash = EfficientHashLib.hashCalldata(data);
        bytes32 payloadHash = Codec.executePayloadHash(
            target,
            value,
            dataHash,
            fee
        );

        // SECURITY — CEI. The leaf advance is the Effect that blocks replay; every line below is
        // an Interaction.
        uint32 leaf = _verifyStatefulAndAdvance(
            publicKey,
            signature,
            Codec.ACTION_EXECUTE,
            payloadHash
        );
        _collectExecuteFee();

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
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatefulSignature calldata signature,
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
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatefulSignature calldata ownerBindingSignature,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey,
        address newOwner
    ) external payable onlyOwner {
        if (newOwner == address(0)) revert ZeroAddressOwner();

        Storage.Layout storage $ = Storage.layout();

        // A genuine handover must hand the NEW owner an entirely fresh bundle (new stateless
        // recovery root).
        // this rotation context MUST be built and verified BEFORE
        // `_verifyStatefulAndAdvance` below, which advances `$.nonce` — both client signatures
        // bind the pre-call nonce N, and the call nets +2 (core +1, install block +1).
        ShrincsTypes.RotationContext memory rctx = Codec.buildRotationContext(
            Codec.rotationDomainSeparator(
                _shrincsDomainSeparator(),
                Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP
            ),
            $.nonce,
            $.keyVersion
        );
        bytes32 nextCommitment = SHRINCS.statelessRotate(
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
        (ShrincsTypes.StatefulPublicKey memory decoded, ) = ShrincsUtils
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
        IQuipFactory(FACTORY).updateWalletOwner(newOwner);
        emit KeyRotated(prev, nextCommitment, $.keyVersion);
    }

    /// @inheritdoc IShrincsWallet
    function setErc1271Key(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatefulSignature calldata signature,
        bytes32 newErc1271Commitment,
        uint32 newErc1271HashSuite
    ) external payable onlyOwner {
        if (newErc1271Commitment == bytes32(0)) revert ZeroErc1271Commitment();
        if (newErc1271HashSuite != ShrincsTypes.HASH_SUITE_KECCAK_256)
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
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatefulSignature calldata signature,
        ShrincsTypes.StatefulRotationTarget calldata nextStatefulKey
    ) external payable onlyOwner {
        if (
            nextStatefulKey.statefulPublicKey.length !=
            ShrincsTypes.STATEFUL_PUBLIC_KEY_BYTES
        ) {
            revert CommitmentMismatch();
        }
        (ShrincsTypes.StatefulPublicKey memory decoded, bool ok) = ShrincsUtils
            .decodeStatefulPublicKey(nextStatefulKey.statefulPublicKey);
        if (!ok || decoded.maxSignatures == 0) revert ZeroMaxSignatures();

        // Recompute the next bundle commitment, reusing the current (verified) stateless root.
        // `currentPublicKey` is validated against the installed commitment inside
        // `_verifyStatefulAndAdvance`, so its pkSeed/hypertreeRoot are trustworthy.
        bytes32 nextCommitment = ShrincsUtils.publicKeyCommitmentFromParts(
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
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external payable onlyOwner {
        Storage.Layout storage $ = Storage.layout();

        // Recovery-tagged rotation domain: a signature over this context is valid ONLY here,
        // never as the recovery half of a `transferOwnership` bundle (and vice versa).
        ShrincsTypes.RotationContext memory ctx = Codec.buildRotationContext(
            Codec.rotationDomainSeparator(
                _shrincsDomainSeparator(),
                Codec.ROTATION_DOMAIN_RECOVER_WALLET
            ),
            $.nonce,
            $.keyVersion
        );

        bytes32 nextCommitment = SHRINCS.statelessRotate(
            $.shrincsPublicKeyCommitment,
            currentPublicKey,
            ctx,
            recoverySignature,
            nextKey
        );
        if (nextCommitment == bytes32(0)) revert InvalidSignature();

        // statelessRotate already validated the next bundle (length + maxSignatures != 0 +
        // declared==computed commitment); decode here only to cache the leaf budget.
        (ShrincsTypes.StatefulPublicKey memory decoded, ) = ShrincsUtils
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
            ShrincsTypes.PublicKey calldata pk,
            ShrincsTypes.StatefulSignature calldata sig,
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
        ShrincsTypes.ActionContext memory ctx = Codec.buildActionContext(
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
        if (
            !SHRINCS.verifyStateful($.shrincsPublicKeyCommitment, pk, ctx, sig)
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
        return IQuipFactory(FACTORY).getVettedCodeIndex(impl.codehash);
    }

    /// @inheritdoc IShrincsWallet
    function getExecuteFee() public view returns (uint256) {
        return IQuipFactory(Storage.layout().quipFactory).executeFee();
    }

    /// @inheritdoc IShrincsWallet
    function quipFactory() external view returns (address payable) {
        return Storage.layout().quipFactory;
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
        return ShrincsTypes.HASH_SUITE_KECCAK_256;
    }

    /// @inheritdoc IShrincsWallet
    function getErc1271HashSuite() external pure returns (uint32) {
        // Not stored: install/rotate paths reject anything but this suite.
        return ShrincsTypes.HASH_SUITE_KECCAK_256;
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

    /// @dev Core stateful verify + bitmap leaf consume shared by every stateful path. Reverts on
    ///      a zero/over-budget/already-consumed leaf or invalid signature; on success marks the
    ///      leaf used in the current epoch's bitmap and advances the action nonce (both Effects),
    ///      returning the consumed leaf.
    function _verifyStatefulAndAdvance(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatefulSignature calldata signature,
        bytes32 actionType,
        bytes32 payloadHash
    ) internal returns (uint32 leaf) {
        Storage.Layout storage $ = Storage.layout();
        uint256 epoch = $.keyVersion;
        leaf = uint32(signature.authPath.length);
        if (leaf == 0 || leaf > $.maxSignatures)
            revert StatefulBudgetExhausted();
        if (_isStatefulLeafUsed($, epoch, leaf)) revert StaleStatefulLeaf();

        ShrincsTypes.ActionContext memory ctx = Codec.buildActionContext(
            _shrincsDomainSeparator(),
            $.nonce,
            epoch,
            actionType,
            payloadHash
        );
        if (
            !SHRINCS.verifyStateful(
                $.shrincsPublicKeyCommitment,
                publicKey,
                ctx,
                signature
            )
        ) revert InvalidSignature();

        _markStatefulLeafUsed($, epoch, leaf);
        unchecked {
            $.statefulLeavesUsed += 1;
            $.nonce += 1;
        }
        emit StatefulSignatureVerified(leaf, epoch);
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
            ShrincsTypes.PublicKey calldata pk,
            ShrincsTypes.StatelessSignature calldata sig,
            bytes calldata ecdsaSig
        ) = Codec.decodeErc1271Signature(signature);

        address recovered = ECDSA.tryRecoverCalldata(
            quipSignedHashEcdsaTarget(hash),
            ecdsaSig
        );
        if (recovered == address(0) || recovered != owner()) {
            return Erc1271ValidationResult.InvalidEcdsaSignature;
        }

        Storage.Layout storage $ = Storage.layout();
        // Binds the LIVE action nonce: every consumed wallet signature invalidates all
        // outstanding ERC-1271 blobs (intended supersession — integrators re-sign after actions).
        ShrincsTypes.ActionContext memory ctx = Codec.buildActionContext(
            _shrincsDomainSeparator(),
            $.nonce,
            $.keyVersion,
            Codec.ACTION_ERC1271,
            hash
        );
        if (
            !SHRINCS.verifyStateless(
                $.erc1271StatelessCommitment,
                pk,
                ctx,
                sig
            )
        ) return Erc1271ValidationResult.InvalidShrincsSignature;

        return Erc1271ValidationResult.Ok;
    }

    /// @dev Sends the per-op execute fee to the factory, if any.
    function _collectExecuteFee() internal {
        uint256 fee = getExecuteFee();
        if (fee > 0) {
            SafeTransferLib.safeTransferETH(Storage.layout().quipFactory, fee);
        }
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
            mstore(add(snapshot, 0x40), sload(_PQ_FACTORY_SLOT))
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
            if iszero(eq(mload(add(snapshot, 0x40)), sload(_PQ_FACTORY_SLOT))) {
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
