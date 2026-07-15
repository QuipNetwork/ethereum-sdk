// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
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

    /// @dev The fee-capped 4337 execution selector: `maxFee` (the signer's fee ceiling) is an
    ///      execution-calldata parameter, bound by the SHRINCS signature via userOpHash → callData.
    bytes4 internal constant EXECUTE_SELECTOR = bytes4(keccak256("execute(address,uint256,bytes,uint256)"));

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

    // The wallet's classical owner: co-signs every userOp (hybrid gate) and submits direct calls.
    address internal WALLET_OWNER;
    uint256 internal WALLET_OWNER_PK;

    // Keys: wallet main key, plus two paymaster verifier keys (the second for rotation cases).
    SHRINCS.SigningKey internal walletKey;
    SHRINCS.PublicKey internal walletPk;
    bytes32 internal walletCommitment;
    SHRINCS.SigningKey internal verifierKey;
    SHRINCS.PublicKey internal verifierPk;
    bytes32 internal verifierCommitment;
    SHRINCS.SigningKey internal verifierKey2;
    SHRINCS.PublicKey internal verifierPk2;
    bytes32 internal verifierCommitment2;

    function setUp() public virtual {
        (WALLET_OWNER, WALLET_OWNER_PK) = makeAddrAndKey("walletOwner");
        bool ok;
        (walletKey, walletPk, ok) = SHRINCSTestSigner.keygen("shrincs-e2e-wallet-key", MAX_SIG);
        assertTrue(ok, "wallet keygen");
        walletCommitment = _toBytes32(walletPk.publicKeyCommitment);
        (verifierKey, verifierPk, ok) = SHRINCSTestSigner.keygen("shrincs-e2e-verifier-key", MAX_SIG);
        assertTrue(ok, "verifier keygen");
        verifierCommitment = _toBytes32(verifierPk.publicKeyCommitment);
        (verifierKey2, verifierPk2, ok) = SHRINCSTestSigner.keygen("shrincs-e2e-verifier-key-2", MAX_SIG);
        assertTrue(ok, "verifier2 keygen");
        // Bundle 2 is the ROTATED bundle `rotateStatefulKey` installs: verifier2's fresh stateful
        // subkey carried over bundle 1's stateless half (the paymaster never rotates it). Only the
        // stateful signing secrets of `verifierKey2` are exercised, so the mismatch between its
        // (discarded) stateless secrets and bundle 1's stateless public parts is irrelevant.
        verifierCommitment2 = SHRINCS.publicKeyCommitmentFromParts(
            verifierPk2.statefulPublicKey, verifierPk.pkSeed, verifierPk.hypertreeRoot
        );
        verifierPk2.publicKeyCommitment = abi.encodePacked(verifierCommitment2);
        verifierPk2.pkSeed = verifierPk.pkSeed;
        verifierPk2.hypertreeRoot = verifierPk.hypertreeRoot;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    OP ASSEMBLY                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Named-field parameters for `_buildSponsoredOp`. Build the common case with
    ///      `_defaultOpParams(...)` and override only the knobs a test exercises.
    struct SponsoredOpParams {
        address target;
        uint256 value;
        bytes data;
        uint256 nonce; // EntryPoint nonce
        uint32 walletLeaf;
        uint32 pmLeaf;
        uint48 validUntil;
        uint48 validAfter;
        bool useVerifier2;
        uint256 pmKeyVersion;
        uint256 walletKeyVersion;
        uint256 walletNonce; // the wallet's live actionNonce() the signature must bind
        bool corruptPmBinding; // paymaster signs a flipped binding hash (its sig fails, wallet's stays valid)
        uint256 maxFee; // the signed execution fee ceiling, carried in callData
    }

    /// @dev The common-case params: same leaf both sides, epoch 0 both sides, no time window,
    ///      wallet action nonce 0, honest paymaster binding, maxFee 0 (the e2e factory default).
    function _defaultOpParams(address target, uint256 value, bytes memory data, uint256 nonce, uint32 leaf)
        internal
        pure
        returns (SponsoredOpParams memory p)
    {
        p.target = target;
        p.value = value;
        p.data = data;
        p.nonce = nonce;
        p.walletLeaf = leaf;
        p.pmLeaf = leaf;
        // Remaining fields deliberately zero/false.
    }

    /// @dev Full builder for a co-signed sponsored op.
    function _buildSponsoredOp(SponsoredOpParams memory p)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = WALLET;
        op.nonce = p.nonce;
        op.initCode = "";
        op.callData = abi.encodeWithSelector(EXECUTE_SELECTOR, p.target, p.value, p.data, p.maxFee);
        op.accountGasLimits = bytes32((uint256(VERIFICATION_GAS) << 128) | uint256(CALL_GAS));
        op.preVerificationGas = PRE_VERIFICATION_GAS;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | uint256(10 gwei));
        // Prefix-only paymasterAndData (exactly the 64 bytes the binding hash covers).
        op.paymasterAndData =
            abi.encodePacked(PAYMASTER, PM_VERIFICATION_GAS, PM_POSTOP_GAS, p.validUntil, p.validAfter);

        // 1. Paymaster signs its binding hash over the blob-less op.
        bytes32 binding = _pmBindingHash(op);
        if (p.corruptPmBinding) binding = binding ^ bytes32(uint256(1));
        SHRINCS.Signature memory pmSig =
            _signPaymasterApproval(binding, p.pmLeaf, p.pmKeyVersion, p.useVerifier2);

        // 2. Embed the (pk, sig) blob to complete paymasterAndData.
        op.paymasterAndData = abi.encodePacked(
            op.paymasterAndData, abi.encode(p.useVerifier2 ? verifierPk2 : verifierPk, pmSig)
        );

        // 3. The canonical v0.7 userOpHash now commits to the complete paymasterAndData.
        bytes32 userOpHash = _computeUserOpHash(op);

        // 4. The wallet signs its erc4337 action context over that hash (maxFee is already
        //    inside it via callData — the digest itself carries no fee word).
        SHRINCS.Signature memory walletSig =
            _signWalletErc4337(userOpHash, p.walletLeaf, p.walletKeyVersion, p.walletNonce);
        // 5. The classical owner co-signs the same hash under the wallet's dedicated userOp
        //    EIP-712 domain — the hybrid blob is (pk, sig, ecdsaSig).
        op.signature = abi.encode(walletPk, walletSig, _ownerCoSign(userOpHash));
    }

    /// @dev Convenience: default sponsored op (see `_defaultOpParams`; wallet nonce 0 is only
    ///      correct for a wallet that has consumed no signature yet).
    function _sponsoredOp(address target, uint256 value, bytes memory data, uint256 nonce, uint32 leaf)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return _sponsoredOp(target, value, data, nonce, leaf, 0);
    }

    /// @dev Default sponsored op at an explicit wallet action nonce (each consumed wallet
    ///      signature advances it, so op N in a sequence binds walletNonce N).
    function _sponsoredOp(
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint32 leaf,
        uint256 walletNonce
    ) internal view returns (PackedUserOperation memory) {
        SponsoredOpParams memory p = _defaultOpParams(target, value, data, nonce, leaf);
        p.walletNonce = walletNonce;
        return _buildSponsoredOp(p);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    SIGNING HELPERS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Signs the wallet's ERC-4337 action context (payload = hash(userOpHash) — ONE word;
    ///      mirrors `Codec.erc4337PayloadHash`, which binds no fee: the signer's maxFee ceiling
    ///      is covered via callData inside userOpHash).
    function _signWalletErc4337(bytes32 userOpHash, uint32 leaf, uint256 keyVersion, uint256 walletNonce)
        internal
        view
        returns (SHRINCS.Signature memory)
    {
        bytes32 payloadHash = keccak256(abi.encodePacked(userOpHash));
        return _signWalletAction(ACTION_ERC4337_EXECUTE, payloadHash, leaf, keyVersion, walletNonce);
    }

    /// @dev Signs an arbitrary wallet action context with the wallet main key. `nonce` must be the
    ///      wallet's live `actionNonce()` at validation time — every consumed signature advances it.
    function _signWalletAction(
        bytes32 actionType,
        bytes32 payloadHash,
        uint32 leaf,
        uint256 keyVersion,
        uint256 nonce
    ) internal view returns (SHRINCS.Signature memory sig) {
        SHRINCS.ActionContext memory ctx = SHRINCS.ActionContext({
            domainSeparator: _walletDomainSeparator(),
            nonce: nonce,
            keyVersion: keyVersion,
            actionType: actionType,
            payloadHash: payloadHash
        });
        bytes memory message = abi.encodePacked(SHRINCS.statefulActionMessageHash(walletCommitment, ctx));
        bool ok;
        (sig, ok) = SHRINCSTestSigner.signStatefulRawAtLeaf(walletKey, leaf, message);
        require(ok, "wallet sign failed");
    }

    /// @dev Signs the paymaster's sponsorship approval context with the selected verifier key.
    function _signPaymasterApproval(bytes32 bindingHash, uint32 leaf, uint256 keyVersion, bool useVerifier2)
        internal
        view
        returns (SHRINCS.Signature memory sig)
    {
        // The paymaster binds NO wrapper nonce (out of scope of the wallet's nonce scheme): its
        // sponsorship freshness is the validUntil/validAfter window + its own one-time leaf.
        SHRINCS.ActionContext memory ctx = SHRINCS.ActionContext({
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
            SHRINCSTestSigner.signStatefulRawAtLeaf(useVerifier2 ? verifierKey2 : verifierKey, leaf, message);
        require(ok, "paymaster sign failed");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    HASH MIRRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Mirrors `ShrincsWallet._shrincsDomainSeparator()`.
    function _walletDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encodePacked(WALLET_DOMAIN_TAG, block.chainid, uint256(uint160(WALLET))));
    }

    /// @dev Mirrors `ShrincsWallet.quipUserOpHashEcdsaTarget` (solady EIP-712: standard domain
    ///      fields, name embeds the SHRINCS profile). Cross-checked against the live getter in
    ///      `encodingCrossCheck.t.sol`.
    function _userOpEcdsaTargetMirror(bytes32 userOpHash) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(
                    bytes(string.concat("QuipShrincsWallet/", SHRINCSParams.PROFILE_NAME, "/v1"))
                ),
                keccak256("1"),
                block.chainid,
                WALLET
            )
        );
        return keccak256(
            abi.encodePacked(
                hex"1901",
                domainSeparator,
                keccak256(abi.encode(keccak256("QuipUserOpHash(bytes32 userOpHash)"), userOpHash))
            )
        );
    }

    /// @dev The owner's userOp co-signature over the mirrored typed-data target.
    function _ownerCoSign(bytes32 userOpHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(WALLET_OWNER_PK, _userOpEcdsaTargetMirror(userOpHash));
        return abi.encodePacked(r, s, v);
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
        returns (SHRINCS.StatefulRotationTarget memory target, bytes32 nextCommitment)
    {
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen(seed, MAX_SIG);
        require(ok, "rotation keygen");
        nextCommitment =
            SHRINCS.publicKeyCommitmentFromParts(pk.statefulPublicKey, walletPk.pkSeed, walletPk.hypertreeRoot);
        target = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: pk.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(nextCommitment)
        });
    }
}
