// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.1.0/contracts/SHRINCS.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsUtils} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsUtils.sol";
import {ShrincsTestSigner} from "@quip.network/hashsigs-solidity-0.1.0/test/helpers/ShrincsTestSigner.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

/// @title ShrincsE2E signing assembler
/// @dev Fork-independent helpers shared by the e2e suite: generates the wallet + paymaster SHRINCS
///      keys in Solidity (via the dependency's test-only signer) and builds fully co-signed
///      sponsored `PackedUserOperation`s. Signing order mirrors production: the paymaster signs its
///      binding hash (which excludes the signature blob), the blob is embedded, the canonical v0.7
///      userOpHash is computed over the now-complete `paymasterAndData`, and the wallet signs that.
///      Kept separate from the forking base so the encoding cross-check (mirrored hashes vs the
///      harnesses) can run with no RPC. Holds NO fork/etch logic.
abstract contract ShrincsE2EAssembler is Test {
    // Fixed addresses (arbitrary but stable).
    address internal constant WALLET = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    address internal constant PAYMASTER = 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2;
    address internal constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address internal constant RECIPIENT = 0x000000000000000000000000000000000000b0b0;
    address internal constant CALL_TARGET = 0x000000000000000000000000000000000000cA11;
    uint256 internal constant CHAIN_ID = 31337;
    uint32 internal constant MAX_SIG = 8;

    bytes4 internal constant EXECUTE_SELECTOR = bytes4(keccak256("execute(address,uint256,bytes)"));

    // Wallet/paymaster canonical tags (mirror the contracts' constants).
    bytes32 internal constant WALLET_DOMAIN_TAG = keccak256("quip-shrincs-wallet-v1");
    bytes32 internal constant PM_DOMAIN_TAG = keccak256("quip-shrincs-paymaster-v1");
    bytes32 internal constant ACTION_ERC4337_EXECUTE = keccak256("quip.shrincs.action.erc4337Execute");
    bytes32 internal constant ACTION_PAYMASTER_APPROVE = keccak256("quip.shrincs.action.paymasterApprove");

    // Shared gas block (generous verification gas — SPHINCS verify is heavy).
    uint128 internal constant VERIFICATION_GAS = 30_000_000;
    uint128 internal constant CALL_GAS = 1_000_000;
    uint128 internal constant PM_VERIFICATION_GAS = 30_000_000;
    uint128 internal constant PM_POSTOP_GAS = 1_000_000;
    uint256 internal constant PRE_VERIFICATION_GAS = 100_000;

    // Keys: wallet main key, plus two paymaster verifier keys (the second for rotation cases).
    ShrincsTypes.SigningKey internal walletKey;
    ShrincsTypes.PublicKey internal walletPk;
    bytes32 internal walletCommitment;
    ShrincsTypes.SigningKey internal verifierKey;
    ShrincsTypes.PublicKey internal verifierPk;
    bytes32 internal verifierCommitment;
    ShrincsTypes.SigningKey internal verifierKey2;
    ShrincsTypes.PublicKey internal verifierPk2;
    bytes32 internal verifierCommitment2;

    function setUp() public virtual {
        bool ok;
        (walletKey, walletPk, ok) = ShrincsTestSigner.keygen("shrincs-e2e-wallet-key", MAX_SIG);
        assertTrue(ok, "wallet keygen");
        walletCommitment = _toBytes32(walletPk.publicKeyCommitment);
        (verifierKey, verifierPk, ok) = ShrincsTestSigner.keygen("shrincs-e2e-verifier-key", MAX_SIG);
        assertTrue(ok, "verifier keygen");
        verifierCommitment = _toBytes32(verifierPk.publicKeyCommitment);
        (verifierKey2, verifierPk2, ok) = ShrincsTestSigner.keygen("shrincs-e2e-verifier-key-2", MAX_SIG);
        assertTrue(ok, "verifier2 keygen");
        verifierCommitment2 = _toBytes32(verifierPk2.publicKeyCommitment);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    OP ASSEMBLY                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Full builder for a co-signed sponsored op. `useVerifier2`/`pmKeyVersion` select the
    ///      paymaster key + epoch to sign under; `corruptPmBinding` makes the paymaster sign a
    ///      flipped binding hash (its signature then fails on-chain while the wallet's stays valid).
    function _buildSponsoredOp(
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint32 walletLeaf,
        uint32 pmLeaf,
        uint48 validUntil,
        uint48 validAfter,
        bool useVerifier2,
        uint256 pmKeyVersion,
        uint256 walletKeyVersion,
        bool corruptPmBinding
    ) internal view returns (PackedUserOperation memory op) {
        op.sender = WALLET;
        op.nonce = nonce;
        op.initCode = "";
        op.callData = abi.encodeWithSelector(EXECUTE_SELECTOR, target, value, data);
        op.accountGasLimits = bytes32((uint256(VERIFICATION_GAS) << 128) | uint256(CALL_GAS));
        op.preVerificationGas = PRE_VERIFICATION_GAS;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | uint256(10 gwei));
        // Prefix-only paymasterAndData (exactly the 64 bytes the binding hash covers).
        op.paymasterAndData =
            abi.encodePacked(PAYMASTER, PM_VERIFICATION_GAS, PM_POSTOP_GAS, validUntil, validAfter);

        // 1. Paymaster signs its binding hash over the blob-less op.
        bytes32 binding = _pmBindingHash(op);
        if (corruptPmBinding) binding = binding ^ bytes32(uint256(1));
        ShrincsTypes.StatefulSignature memory pmSig =
            _signPaymasterApproval(binding, pmLeaf, pmKeyVersion, useVerifier2);

        // 2. Embed the (pk, sig) blob to complete paymasterAndData.
        op.paymasterAndData = abi.encodePacked(
            op.paymasterAndData, abi.encode(useVerifier2 ? verifierPk2 : verifierPk, pmSig)
        );

        // 3. The canonical v0.7 userOpHash now commits to the complete paymasterAndData.
        bytes32 userOpHash = _computeUserOpHash(op);

        // 4. The wallet signs its erc4337 action context over that hash (fee 0 in e2e).
        ShrincsTypes.StatefulSignature memory walletSig =
            _signWalletErc4337(userOpHash, walletLeaf, walletKeyVersion);
        op.signature = abi.encode(walletPk, walletSig);
    }

    /// @dev Convenience: default sponsored op (epoch 0 both sides, same leaf, no window).
    function _sponsoredOp(address target, uint256 value, bytes memory data, uint256 nonce, uint32 leaf)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return _buildSponsoredOp(target, value, data, nonce, leaf, leaf, 0, 0, false, 0, 0, false);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    SIGNING HELPERS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Signs the wallet's ERC-4337 action context (payload = hash(userOpHash, fee 0)).
    function _signWalletErc4337(bytes32 userOpHash, uint32 leaf, uint256 keyVersion)
        internal
        view
        returns (ShrincsTypes.StatefulSignature memory)
    {
        bytes32 payloadHash = keccak256(abi.encodePacked(userOpHash, bytes32(0)));
        return _signWalletAction(ACTION_ERC4337_EXECUTE, payloadHash, leaf, keyVersion);
    }

    /// @dev Signs an arbitrary wallet action context with the wallet main key.
    function _signWalletAction(bytes32 actionType, bytes32 payloadHash, uint32 leaf, uint256 keyVersion)
        internal
        view
        returns (ShrincsTypes.StatefulSignature memory sig)
    {
        ShrincsTypes.ActionContext memory ctx = ShrincsTypes.ActionContext({
            domainSeparator: _walletDomainSeparator(),
            nonce: 0,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });
        bytes memory message = abi.encodePacked(SHRINCS.statefulActionMessageHash(walletCommitment, ctx));
        bool ok;
        (sig, ok) = ShrincsTestSigner.signStatefulRawAtLeaf(walletKey, leaf, message);
        require(ok, "wallet sign failed");
    }

    /// @dev Signs the paymaster's sponsorship approval context with the selected verifier key.
    function _signPaymasterApproval(bytes32 bindingHash, uint32 leaf, uint256 keyVersion, bool useVerifier2)
        internal
        view
        returns (ShrincsTypes.StatefulSignature memory sig)
    {
        ShrincsTypes.ActionContext memory ctx = ShrincsTypes.ActionContext({
            domainSeparator: _pmDomainSeparator(),
            nonce: 0,
            keyVersion: keyVersion,
            actionType: ACTION_PAYMASTER_APPROVE,
            payloadHash: bindingHash
        });
        bytes32 commitment = useVerifier2 ? verifierCommitment2 : verifierCommitment;
        bytes memory message = abi.encodePacked(SHRINCS.statefulActionMessageHash(commitment, ctx));
        bool ok;
        (sig, ok) =
            ShrincsTestSigner.signStatefulRawAtLeaf(useVerifier2 ? verifierKey2 : verifierKey, leaf, message);
        require(ok, "paymaster sign failed");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    HASH MIRRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Mirrors `ShrincsWallet._shrincsDomainSeparator()`.
    function _walletDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encodePacked(WALLET_DOMAIN_TAG, block.chainid, uint256(uint160(WALLET))));
    }

    /// @dev Mirrors `ShrincsPaymaster._domainSeparator()`.
    function _pmDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encodePacked(PM_DOMAIN_TAG, block.chainid, uint256(uint160(PAYMASTER))));
    }

    /// @dev Mirrors `ShrincsPaymaster._userOpBindingHash` (paymasterAndData truncated to 64 bytes).
    function _pmBindingHash(PackedUserOperation memory op) internal pure returns (bytes32) {
        bytes memory prefix = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            prefix[i] = op.paymasterAndData[i];
        }
        return keccak256(
            abi.encodePacked(
                bytes32(uint256(uint160(op.sender))),
                bytes32(op.nonce),
                keccak256(op.initCode),
                keccak256(op.callData),
                op.accountGasLimits,
                bytes32(op.preVerificationGas),
                op.gasFees,
                keccak256(prefix)
            )
        );
    }

    /// @dev The canonical ERC-4337 v0.7 userOpHash (pure; mirrors `EntryPoint.getUserOpHash`).
    function _computeUserOpHash(PackedUserOperation memory op) internal view returns (bytes32) {
        bytes32 inner = keccak256(
            abi.encode(
                op.sender,
                op.nonce,
                keccak256(op.initCode),
                keccak256(op.callData),
                op.accountGasLimits,
                op.preVerificationGas,
                op.gasFees,
                keccak256(op.paymasterAndData)
            )
        );
        return keccak256(abi.encode(inner, ENTRY_POINT, block.chainid));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    MISC HELPERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _toBytes32(bytes memory bts) internal pure returns (bytes32 out) {
        require(bts.length == 32, "not 32 bytes");
        assembly {
            out := mload(add(bts, 32))
        }
    }

    /// @dev A fresh stateful-only rotation target for the wallet, reusing its stateless root.
    function _walletStatefulRotationTarget(bytes memory seed)
        internal
        view
        returns (ShrincsTypes.StatefulRotationTarget memory target, bytes32 nextCommitment)
    {
        (, ShrincsTypes.PublicKey memory pk, bool ok) = ShrincsTestSigner.keygen(seed, MAX_SIG);
        require(ok, "rotation keygen");
        nextCommitment =
            ShrincsUtils.publicKeyCommitmentFromParts(pk.statefulPublicKey, walletPk.pkSeed, walletPk.hypertreeRoot);
        target = ShrincsTypes.StatefulRotationTarget({
            statefulPublicKey: pk.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(nextCommitment)
        });
    }
}
