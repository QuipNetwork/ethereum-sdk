// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {SHRINCSStatelessVectorSigner} from
    "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSStatelessVectorSigner.sol";
import {SHRINCSStatelessVectorSigningFacade} from
    "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSStatelessVectorSigningFacade.sol";
import {SHRINCS256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS256sKeccak.sol";
import {SPHINCSPlusC256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC256sKeccak.sol";
import {ShrincsWalletCodec as Codec} from "../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../harness/ShrincsWalletHarness.sol";
import {MockShrincsFactory} from "../mocks/MockShrincsFactory.sol";

/// @title ShrincsWallet Base Test
/// @dev Generates SHRINCS keys and signatures entirely in Solidity via the dependency's
///      test-only signer helpers (`SHRINCSTestSigner` for keygen + the stateful path, the staged
///      `SHRINCSStatelessVectorSigner` for the stateless path), so no external vectors are needed.
///      The harness is installed with the generated commitments; every test signs the wallet's
///      canonical contexts live against the wallet's current state.
contract ShrincsWalletTest is Test {
    uint256 internal constant CHAIN_ID = 31337;
    uint32 internal constant MAX_SIG = 8;

    // Fixed harness address (kept stable so tests may hardcode `op.sender` etc.).
    address internal constant WALLET = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;

    // Solady ERC4337's canonical EntryPoint (`onlyEntryPoint` overloads).
    address internal constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    // CREATE3 address SHRINCS256sKeccak compile-time pins for its SPHINCSPlusC stateless
    // sibling (`SHRINCS256sKeccak.SPHINCS_PLUS_C_VERIFIER`); the sibling's code must live
    // there or every stateless verification reverts on empty code.
    address internal constant SPHINCS_SIBLING = 0xf1Bd3aE9d3907bA59FB22A77eAcCbd278b51f88A;

    ShrincsWalletHarness internal wallet;
    MockShrincsFactory internal factory;
    SHRINCS256sKeccak internal shrincsVerifier;
    SHRINCSStatelessVectorSigner internal statelessSigner;

    // Main key: stateful path authorizes every normal action; its stateless half is the
    // break-glass recovery authority.
    SHRINCS.SigningKey internal mainKey;
    SHRINCS.PublicKey internal mainPk;
    bytes32 internal mainCommitment;

    // Dedicated ERC-1271 verifier key (only its stateless path is ever used).
    SHRINCS.SigningKey internal erc1271Key;
    SHRINCS.PublicKey internal erc1271Pk;
    bytes32 internal erc1271Commitment;

    address internal OWNER;
    uint256 internal OWNER_PK;

    function setUp() public virtual {
        vm.chainId(CHAIN_ID);
        (OWNER, OWNER_PK) = makeAddrAndKey("owner");

        bool ok;
        (mainKey, mainPk, ok) = SHRINCSTestSigner.keygen("shrincs-wallet-test-main-key", MAX_SIG);
        assertTrue(ok, "main keygen");
        mainCommitment = _commitment32(mainPk);
        (erc1271Key, erc1271Pk, ok) = SHRINCSTestSigner.keygen("shrincs-wallet-test-erc1271-key", MAX_SIG);
        assertTrue(ok, "erc1271 keygen");
        erc1271Commitment = _commitment32(erc1271Pk);

        factory = new MockShrincsFactory();
        // External verifier: deploy the real SHRINCS256sKeccak and place its SPHINCSPlusC
        // sibling's code at the compile-time-pinned CREATE3 address (both are storage-free
        // and constructor-free, so etching runtime code is exact).
        shrincsVerifier = new SHRINCS256sKeccak();
        vm.etch(SPHINCS_SIBLING, address(new SPHINCSPlusC256sKeccak()).code);
        ShrincsWalletHarness impl =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        vm.etch(WALLET, address(impl).code);
        wallet = ShrincsWalletHarness(payable(WALLET));

        wallet.harness_install(OWNER, mainCommitment, erc1271Commitment, MAX_SIG);

        statelessSigner = new SHRINCSStatelessVectorSigner();
    }

    function test_setUp() public view virtual {
        assertEq(wallet.owner(), OWNER);
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment);
        assertEq(wallet.getErc1271Commitment(), erc1271Commitment);
        assertEq(wallet.statefulLeavesUsed(), 0);
        assertFalse(wallet.isStatefulLeafUsed(1));
        assertEq(wallet.maxSignatures(), MAX_SIG);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    KEY / STRUCT HELPERS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Memory copy of the main public-key bundle (calldata-bound wallet params).
    function _mainPk() internal view returns (SHRINCS.PublicKey memory) {
        return mainPk;
    }

    /// @dev Extracts the 32-byte commitment from a bundle's encoded commitment field.
    function _commitment32(SHRINCS.PublicKey memory pk) internal pure returns (bytes32 out) {
        bytes memory c = pk.publicKeyCommitment;
        require(c.length == 32, "commitment not 32 bytes");
        assembly {
            out := mload(add(c, 32))
        }
    }

    /// @dev Generates a fresh full replacement bundle (for `recoverWallet` / `transferOwnership`).
    function _makeRotationTarget(bytes memory seed)
        internal
        view
        returns (SHRINCS.RotationTarget memory target, SHRINCS.SigningKey memory key)
    {
        SHRINCS.PublicKey memory pk;
        bool ok;
        (key, pk, ok) = SHRINCSTestSigner.keygen(seed, MAX_SIG);
        require(ok, "rotation keygen");
        target = SHRINCS.RotationTarget({
            statefulPublicKey: pk.statefulPublicKey,
            publicKeyCommitment: pk.publicKeyCommitment,
            pkSeed: pk.pkSeed,
            hypertreeRoot: pk.hypertreeRoot
        });
    }

    /// @dev Generates a fresh stateful-only subkey target for `rotateKey`, reusing the CURRENT
    ///      main key's stateless seed/root in the recomputed next-bundle commitment.
    function _makeStatefulRotationTarget(bytes memory seed)
        internal
        view
        returns (SHRINCS.StatefulRotationTarget memory target, bytes32 nextCommitment)
    {
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen(seed, MAX_SIG);
        require(ok, "stateful rotation keygen");
        nextCommitment =
            SHRINCS.publicKeyCommitmentFromParts(pk.statefulPublicKey, mainPk.pkSeed, mainPk.hypertreeRoot);
        target = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: pk.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(nextCommitment)
        });
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CONTEXT BUILDERS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The wallet's canonical SHRINCS signing domain (mirrors `_shrincsDomainSeparator`).
    function _walletDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encodePacked(Codec.DOMAIN_TAG, block.chainid, uint256(uint160(WALLET))));
    }

    /// @dev Builds the wallet's canonical action context against its LIVE nonce and key epoch.
    ///      Signing immediately before submission keeps the bound nonce fresh; a signature
    ///      produced here goes stale as soon as any other wallet signature is consumed.
    function _actionContext(bytes32 actionType, bytes32 payloadHash)
        internal
        view
        returns (SHRINCS.ActionContext memory)
    {
        return Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            wallet.actionNonce(),
            wallet.keyVersion(),
            actionType,
            payloadHash
        );
    }

    /// @dev Builds the wallet's canonical rotation context against its LIVE nonce/epoch, under
    ///      the per-path tagged rotation domain (`Codec.ROTATION_DOMAIN_*`).
    function _rotationContext(bytes32 rotationTag) internal view returns (SHRINCS.RotationContext memory) {
        return Codec.buildRotationContext(
            Codec.rotationDomainSeparator(wallet.exposed_shrincsDomainSeparator(), rotationTag),
            wallet.actionNonce(),
            wallet.keyVersion()
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    SIGNING HELPERS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Signs the wallet's canonical STATEFUL action message with the main key at `leaf`.
    function _signStatefulAction(bytes32 actionType, bytes32 payloadHash, uint32 leaf)
        internal
        view
        returns (SHRINCS.Signature memory sig)
    {
        SHRINCS.ActionContext memory ctx = _actionContext(actionType, payloadHash);
        bytes memory message =
            abi.encodePacked(SHRINCS.statefulActionMessageHash(wallet.getShrincsPublicKeyCommitment(), ctx));
        bool ok;
        (sig, ok) = SHRINCSTestSigner.signStatefulRawAtLeaf(mainKey, leaf, message);
        require(ok, "stateful sign failed");
    }

    /// @dev Signs an arbitrary raw stateless message with the given key via the staged signer.
    function _signStatelessRaw(
        SHRINCS.SigningKey memory key,
        SHRINCS.PublicKey memory pk,
        bytes memory message
    ) internal returns (SPHINCSPlusC.Signature memory sig) {
        (bytes32 sessionId, bool ok) = statelessSigner.beginSession(key, pk, message);
        require(ok, "stateless session begin failed");
        (, sig, ok) = SHRINCSStatelessVectorSigningFacade.completeSession(statelessSigner, sessionId);
        require(ok, "stateless sign failed");
    }

    /// @dev Signs the wallet's canonical ERC-1271 STATELESS action message (dedicated verifier key).
    function _signErc1271(bytes32 hash) internal returns (SPHINCSPlusC.Signature memory) {
        SHRINCS.ActionContext memory ctx = _actionContext(Codec.ACTION_ERC1271, hash);
        bytes memory message =
            abi.encodePacked(SHRINCS.statelessActionMessageHash(wallet.getErc1271Commitment(), ctx));
        return _signStatelessRaw(erc1271Key, erc1271Pk, message);
    }

    /// @dev Signs the canonical FULL-rotation recovery message with the main key's stateless half,
    ///      under the given path's tagged rotation domain.
    function _signFullRotation(SHRINCS.RotationTarget memory nextKey, bytes32 rotationTag)
        internal
        returns (SPHINCSPlusC.Signature memory)
    {
        SHRINCS.PublicKey memory pk = mainPk;
        bytes memory message = abi.encodePacked(
            _fullRotationMessageHash(wallet.getShrincsPublicKeyCommitment(), pk, _rotationContext(rotationTag), nextKey)
        );
        return _signStatelessRaw(mainKey, pk, message);
    }

    /// @dev Mirrors `SHRINCS.fullRotationMessageHash` (which requires calldata structs) in memory.
    function _fullRotationMessageHash(
        bytes32 expectedCommitment,
        SHRINCS.PublicKey memory currentPk,
        SHRINCS.RotationContext memory ctx,
        SHRINCS.RotationTarget memory nextKey
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                SHRINCS.OP_ROTATE_FULL,
                HashSuite.HASH_SUITE_ID,
                expectedCommitment,
                ctx.domainSeparator,
                ctx.nonce,
                ctx.keyVersion,
                currentPk.publicKeyCommitment,
                nextKey.publicKeyCommitment
            )
        );
    }

    /// @dev The ECDSA half of an ERC-1271 signature: OWNER signs the wallet's typed-data target.
    function _ownerEcdsa(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, wallet.quipSignedHashEcdsaTarget(hash));
        return abi.encodePacked(r, s, v);
    }

    /// @dev The owner's userOp co-signature: OWNER signs the wallet's dedicated userOp
    ///      typed-data target (distinct domain from the ERC-1271 one).
    function _ownerUserOpEcdsa(bytes32 userOpHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(OWNER_PK, wallet.quipUserOpHashEcdsaTarget(userOpHash));
        return abi.encodePacked(r, s, v);
    }

    /// @dev The canonical hybrid `userOp.signature` blob: SHRINCS structs plus the owner's
    ///      co-signature over `userOpHash`.
    function _userOpBlob(SHRINCS.Signature memory sig, bytes32 userOpHash)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(_mainPk(), sig, _ownerUserOpEcdsa(userOpHash));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PAYLOAD BUILDERS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Builds the factory-supplied `initialize`/`migrate` payload exactly as
    ///      `ShrincsWalletCodec.decodeInit` expects: `abi.encode(commitment, pkSeed, PublicKey,
    ///      hashSuite, erc1271Commitment, erc1271HashSuite)`.
    function _buildInitPayload(
        bytes32 commitment,
        bytes32 pkSeed,
        SHRINCS.PublicKey memory pk,
        uint32 hashSuite,
        bytes32 erc1271Commitment_,
        uint32 erc1271HashSuite
    ) internal pure returns (bytes memory) {
        return abi.encode(commitment, pkSeed, pk, hashSuite, erc1271Commitment_, erc1271HashSuite);
    }

    /// @dev Builds a valid `initialize` payload from the generated main/erc1271 keys. Since
    ///      `initialize` verifies NO signature (only deterministic shape/commitment validation),
    ///      this drives the real success path.
    function _validInitPayload() internal view returns (bytes memory) {
        SHRINCS.PublicKey memory pk = _mainPk();
        return _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );
    }

    function _toBytes32(bytes memory b) internal pure returns (bytes32 out) {
        require(b.length == 32, "not 32 bytes");
        assembly {
            out := mload(add(b, 32))
        }
    }

    /// @dev A `StatefulSignature` whose only meaningful field is `authPath.length` (= the leaf
    ///      index). Used to drive the pre-verify leaf guards (`StatefulBudgetExhausted`) without
    ///      a real signature.
    function _statefulSigWithLeaf(uint256 leaf) internal pure returns (SHRINCS.Signature memory sig) {
        sig.authPath = new bytes32[](leaf);
    }

    /// @dev A structurally-valid leaf-1 stateful signature bound to the ERC-4337 action context
    ///      over a throwaway userOpHash. Its leaf is in-budget and initially unused, so it REACHES
    ///      `SHRINCS.verifyStateful` — but against any other action it fails verification,
    ///      exercising the `InvalidSignature` branch.
    function _wrongContextStatefulSig() internal view returns (SHRINCS.Signature memory) {
        return _signStatefulAction(
            Codec.ACTION_ERC4337_EXECUTE,
            Codec.erc4337PayloadHash(keccak256("throwaway-userop")),
            1
        );
    }

    /// @dev Signs the ERC-4337 validation context for `userOpHash` at `leaf`. No fee word: the
    ///      signer's `maxFee` ceiling rides in `callData` (covered by userOpHash itself).
    function _signErc4337(bytes32 userOpHash, uint32 leaf)
        internal
        view
        returns (SHRINCS.Signature memory)
    {
        return _signStatefulAction(
            Codec.ACTION_ERC4337_EXECUTE, Codec.erc4337PayloadHash(userOpHash), leaf
        );
    }

    /// @dev Builds a minimal PackedUserOperation carrying the abi-encoded (pk, sig) blob.
    function _makeUserOp(bytes memory signature) internal pure returns (ERC4337.PackedUserOperation memory op) {
        op.sender = WALLET;
        op.signature = signature;
    }
}
