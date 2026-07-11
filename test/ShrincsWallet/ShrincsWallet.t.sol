// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.1.0/contracts/SHRINCS.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsUtils} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsUtils.sol";
import {ShrincsTestSigner} from "@quip.network/hashsigs-solidity-0.1.0/test/helpers/ShrincsTestSigner.sol";
import {ShrincsStatelessVectorSigner} from
    "@quip.network/hashsigs-solidity-0.1.0/test/helpers/ShrincsStatelessVectorSigner.sol";
import {ShrincsStatelessVectorSigningFacade} from
    "@quip.network/hashsigs-solidity-0.1.0/test/helpers/ShrincsStatelessVectorSigningFacade.sol";
import {ShrincsWalletCodec as Codec} from "../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../harness/ShrincsWalletHarness.sol";
import {MockShrincsFactory} from "../mocks/MockShrincsFactory.sol";

/// @title ShrincsWallet Base Test
/// @dev Generates SHRINCS keys and signatures entirely in Solidity via the dependency's
///      test-only signer helpers (`ShrincsTestSigner` for keygen + the stateful path, the staged
///      `ShrincsStatelessVectorSigner` for the stateless path), so no external vectors are needed.
///      The harness is installed with the generated commitments; every test signs the wallet's
///      canonical contexts live against the wallet's current state.
contract ShrincsWalletTest is Test {
    uint256 internal constant CHAIN_ID = 31337;
    uint32 internal constant MAX_SIG = 8;

    // Fixed harness address (kept stable so tests may hardcode `op.sender` etc.).
    address internal constant WALLET = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;

    // Solady ERC4337's canonical EntryPoint (`onlyEntryPoint` overloads).
    address internal constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    ShrincsWalletHarness internal wallet;
    MockShrincsFactory internal factory;
    ShrincsStatelessVectorSigner internal statelessSigner;

    // Main key: stateful path authorizes every normal action; its stateless half is the
    // break-glass recovery authority.
    ShrincsTypes.SigningKey internal mainKey;
    ShrincsTypes.PublicKey internal mainPk;
    bytes32 internal mainCommitment;

    // Dedicated ERC-1271 verifier key (only its stateless path is ever used).
    ShrincsTypes.SigningKey internal erc1271Key;
    ShrincsTypes.PublicKey internal erc1271Pk;
    bytes32 internal erc1271Commitment;

    address internal OWNER;
    uint256 internal OWNER_PK;

    function setUp() public virtual {
        vm.chainId(CHAIN_ID);
        (OWNER, OWNER_PK) = makeAddrAndKey("owner");

        bool ok;
        (mainKey, mainPk, ok) = ShrincsTestSigner.keygen("shrincs-wallet-test-main-key", MAX_SIG);
        assertTrue(ok, "main keygen");
        mainCommitment = _commitment32(mainPk);
        (erc1271Key, erc1271Pk, ok) = ShrincsTestSigner.keygen("shrincs-wallet-test-erc1271-key", MAX_SIG);
        assertTrue(ok, "erc1271 keygen");
        erc1271Commitment = _commitment32(erc1271Pk);

        factory = new MockShrincsFactory();
        ShrincsWalletHarness impl = new ShrincsWalletHarness(payable(address(factory)));
        vm.etch(WALLET, address(impl).code);
        wallet = ShrincsWalletHarness(payable(WALLET));

        wallet.harness_install(OWNER, mainCommitment, erc1271Commitment, MAX_SIG);

        statelessSigner = new ShrincsStatelessVectorSigner();
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
    function _mainPk() internal view returns (ShrincsTypes.PublicKey memory) {
        return mainPk;
    }

    /// @dev Extracts the 32-byte commitment from a bundle's encoded commitment field.
    function _commitment32(ShrincsTypes.PublicKey memory pk) internal pure returns (bytes32 out) {
        bytes memory c = pk.publicKeyCommitment;
        require(c.length == 32, "commitment not 32 bytes");
        assembly {
            out := mload(add(c, 32))
        }
    }

    /// @dev Generates a fresh full replacement bundle (for `recoverWallet` / `transferOwnership`).
    function _makeRotationTarget(bytes memory seed)
        internal
        pure
        returns (ShrincsTypes.RotationTarget memory target, ShrincsTypes.SigningKey memory key)
    {
        ShrincsTypes.PublicKey memory pk;
        bool ok;
        (key, pk, ok) = ShrincsTestSigner.keygen(seed, MAX_SIG);
        require(ok, "rotation keygen");
        target = ShrincsTypes.RotationTarget({
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
        returns (ShrincsTypes.StatefulRotationTarget memory target, bytes32 nextCommitment)
    {
        (, ShrincsTypes.PublicKey memory pk, bool ok) = ShrincsTestSigner.keygen(seed, MAX_SIG);
        require(ok, "stateful rotation keygen");
        nextCommitment =
            ShrincsUtils.publicKeyCommitmentFromParts(pk.statefulPublicKey, mainPk.pkSeed, mainPk.hypertreeRoot);
        target = ShrincsTypes.StatefulRotationTarget({
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

    /// @dev Builds the wallet's canonical no-nonce action context against its LIVE key epoch.
    function _actionContext(bytes32 actionType, bytes32 payloadHash)
        internal
        view
        returns (ShrincsTypes.ActionContext memory)
    {
        return Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(), 0, wallet.keyVersion(), actionType, payloadHash
        );
    }

    /// @dev Builds the wallet's canonical rotation context against its LIVE nonce/epoch, under
    ///      the per-path tagged rotation domain (`Codec.ROTATION_DOMAIN_*`).
    function _rotationContext(bytes32 rotationTag) internal view returns (ShrincsTypes.RotationContext memory) {
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
        returns (ShrincsTypes.StatefulSignature memory sig)
    {
        ShrincsTypes.ActionContext memory ctx = _actionContext(actionType, payloadHash);
        bytes memory message =
            abi.encodePacked(SHRINCS.statefulActionMessageHash(wallet.getShrincsPublicKeyCommitment(), ctx));
        bool ok;
        (sig, ok) = ShrincsTestSigner.signStatefulRawAtLeaf(mainKey, leaf, message);
        require(ok, "stateful sign failed");
    }

    /// @dev Signs an arbitrary raw stateless message with the given key via the staged signer.
    function _signStatelessRaw(
        ShrincsTypes.SigningKey memory key,
        ShrincsTypes.PublicKey memory pk,
        bytes memory message
    ) internal returns (ShrincsTypes.StatelessSignature memory sig) {
        (bytes32 sessionId, bool ok) = statelessSigner.beginSession(key, pk, message);
        require(ok, "stateless session begin failed");
        (, sig, ok) = ShrincsStatelessVectorSigningFacade.completeSession(statelessSigner, sessionId);
        require(ok, "stateless sign failed");
    }

    /// @dev Signs the wallet's canonical ERC-1271 STATELESS action message (dedicated verifier key).
    function _signErc1271(bytes32 hash) internal returns (ShrincsTypes.StatelessSignature memory) {
        ShrincsTypes.ActionContext memory ctx = _actionContext(Codec.ACTION_ERC1271, hash);
        bytes memory message =
            abi.encodePacked(SHRINCS.statelessActionMessageHash(wallet.getErc1271Commitment(), ctx));
        return _signStatelessRaw(erc1271Key, erc1271Pk, message);
    }

    /// @dev Signs the canonical FULL-rotation recovery message with the main key's stateless half,
    ///      under the given path's tagged rotation domain.
    function _signFullRotation(ShrincsTypes.RotationTarget memory nextKey, bytes32 rotationTag)
        internal
        returns (ShrincsTypes.StatelessSignature memory)
    {
        ShrincsTypes.PublicKey memory pk = mainPk;
        bytes memory message = abi.encodePacked(
            _fullRotationMessageHash(wallet.getShrincsPublicKeyCommitment(), pk, _rotationContext(rotationTag), nextKey)
        );
        return _signStatelessRaw(mainKey, pk, message);
    }

    /// @dev Mirrors `SHRINCS.fullRotationMessageHash` (which requires calldata structs) in memory.
    function _fullRotationMessageHash(
        bytes32 expectedCommitment,
        ShrincsTypes.PublicKey memory currentPk,
        ShrincsTypes.RotationContext memory ctx,
        ShrincsTypes.RotationTarget memory nextKey
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                ShrincsTypes.OP_ROTATE_FULL,
                ShrincsTypes.HASH_SUITE_KECCAK_256,
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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PAYLOAD BUILDERS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Builds the factory-supplied `initialize`/`migrate` payload exactly as
    ///      `ShrincsWalletCodec.decodeInit` expects: `abi.encode(commitment, pkSeed, PublicKey,
    ///      hashSuite, erc1271Commitment, erc1271HashSuite)`.
    function _buildInitPayload(
        bytes32 commitment,
        bytes32 pkSeed,
        ShrincsTypes.PublicKey memory pk,
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
        ShrincsTypes.PublicKey memory pk = _mainPk();
        return _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            ShrincsTypes.HASH_SUITE_KECCAK_256,
            erc1271Commitment,
            ShrincsTypes.HASH_SUITE_KECCAK_256
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
    function _statefulSigWithLeaf(uint256 leaf) internal pure returns (ShrincsTypes.StatefulSignature memory sig) {
        sig.authPath = new bytes32[](leaf);
    }

    /// @dev A structurally-valid leaf-1 stateful signature bound to the ERC-4337 action context
    ///      over a throwaway userOpHash. Its leaf is in-budget and initially unused, so it REACHES
    ///      `SHRINCS.verifyStateful` — but against any other action it fails verification,
    ///      exercising the `InvalidSignature` branch.
    function _wrongContextStatefulSig() internal view returns (ShrincsTypes.StatefulSignature memory) {
        return _signStatefulAction(
            Codec.ACTION_ERC4337_EXECUTE,
            Codec.erc4337PayloadHash(keccak256("throwaway-userop"), wallet.getExecuteFee()),
            1
        );
    }

    /// @dev Signs the ERC-4337 validation context for `userOpHash` at `leaf` (fee read live).
    function _signErc4337(bytes32 userOpHash, uint32 leaf)
        internal
        view
        returns (ShrincsTypes.StatefulSignature memory)
    {
        return _signStatefulAction(
            Codec.ACTION_ERC4337_EXECUTE, Codec.erc4337PayloadHash(userOpHash, wallet.getExecuteFee()), leaf
        );
    }

    /// @dev Builds a minimal PackedUserOperation carrying the abi-encoded (pk, sig) blob.
    function _makeUserOp(bytes memory signature) internal pure returns (ERC4337.PackedUserOperation memory op) {
        op.sender = WALLET;
        op.signature = signature;
    }
}
