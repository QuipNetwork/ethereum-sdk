// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletHarness} from "../harness/ShrincsWalletHarness.sol";
import {MockShrincsFactory} from "../mocks/MockShrincsFactory.sol";

/// @title ShrincsWallet Base Test
/// @dev Loads the Rust-generated, wallet-bound SHRINCS vectors and places the harness at the
///      vectors' fixed address (via `vm.etch` + `vm.chainId`) so the wallet's
///      `_shrincsDomainSeparator()` reproduces the domain the signatures were bound to.
contract ShrincsWalletTest is Test {
    string internal constant VECTORS = "test/test_vectors/shrincs_wallet_sphincs_256s_keccak.json";

    // Must match the generator's WALLET / CHAIN_ID constants.
    address internal constant WALLET = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    uint256 internal constant CHAIN_ID = 31337;
    uint32 internal constant MAX_SIG = 8;

    // Solady ERC4337's canonical EntryPoint (`onlyEntryPoint` overloads).
    address internal constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    ShrincsWalletHarness internal wallet;
    MockShrincsFactory internal factory;
    string internal vectors;

    address internal OWNER;
    uint256 internal OWNER_PK;

    function setUp() public virtual {
        vm.chainId(CHAIN_ID);
        vectors = vm.readFile(VECTORS);
        (OWNER, OWNER_PK) = makeAddrAndKey("owner");

        factory = new MockShrincsFactory();
        ShrincsWalletHarness impl = new ShrincsWalletHarness(payable(address(factory)));
        // Place the wallet code at the vectors' fixed address so address(this) matches.
        vm.etch(WALLET, address(impl).code);
        wallet = ShrincsWalletHarness(payable(WALLET));

        wallet.harness_install(
            OWNER,
            _bytes32(".mainKey.publicKeyCommitment"),
            uint8(vm.parseJsonUint(vectors, ".mainKey.parameterSetId")),
            _bytes32(".erc1271Key.publicKeyCommitment"),
            uint8(vm.parseJsonUint(vectors, ".erc1271Key.parameterSetId")),
            MAX_SIG
        );
    }

    function test_setUp() public view virtual {
        assertEq(wallet.owner(), OWNER);
        assertEq(wallet.getShrincsPublicKeyCommitment(), _bytes32(".mainKey.publicKeyCommitment"));
        assertEq(wallet.getErc1271Commitment(), _bytes32(".erc1271Key.publicKeyCommitment"));
        assertEq(wallet.statefulLeavesUsed(), 0);
        assertFalse(wallet.isStatefulLeafUsed(1));
        assertEq(wallet.maxSignatures(), MAX_SIG);
        // The wallet's domain separator must equal the one the vectors were bound to.
        assertEq(wallet.exposed_shrincsDomainSeparator(), _bytes32(".domainSeparator"));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PARSING HELPERS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _bytes32(string memory key) internal view returns (bytes32) {
        return _toBytes32(vm.parseJsonBytes(vectors, key));
    }

    function _toBytes32(bytes memory b) internal pure returns (bytes32 out) {
        require(b.length == 32, "not 32 bytes");
        assembly {
            out := mload(add(b, 32))
        }
    }

    /// @dev Parses a `ShrincsTypes.PublicKey` bundle from a JSON object path.
    function _parsePublicKey(string memory base) internal view returns (ShrincsTypes.PublicKey memory pk) {
        pk.parameterSetId =
            ShrincsTypes.ParameterSetId(vm.parseJsonUint(vectors, string.concat(base, ".parameterSetId")));
        pk.statefulPublicKey = vm.parseJsonBytes(vectors, string.concat(base, ".statefulPublicKey"));
        pk.publicKeyCommitment = vm.parseJsonBytes(vectors, string.concat(base, ".publicKeyCommitment"));
        pk.pkSeed = vm.parseJsonBytes(vectors, string.concat(base, ".pkSeed"));
        pk.hypertreeRoot = vm.parseJsonBytes(vectors, string.concat(base, ".hypertreeRoot"));
    }

    /// @dev Parses a `ShrincsTypes.StatefulSignature` from a JSON object path.
    function _parseStatefulSignature(string memory base)
        internal
        view
        returns (ShrincsTypes.StatefulSignature memory sig)
    {
        sig.randomizer = _bytes32(string.concat(base, ".randomizer"));
        sig.counter = uint32(vm.parseJsonUint(vectors, string.concat(base, ".counter")));
        sig.chains = vm.parseJsonBytes32Array(vectors, string.concat(base, ".chains"));
        sig.authPath = vm.parseJsonBytes32Array(vectors, string.concat(base, ".authPath"));
    }

    /// @dev Parses a `ShrincsTypes.RotationTarget` (full next-key bundle) from a JSON object path.
    function _parseRotationTarget(string memory base) internal view returns (ShrincsTypes.RotationTarget memory t) {
        t.parameterSetId =
            ShrincsTypes.ParameterSetId(vm.parseJsonUint(vectors, string.concat(base, ".parameterSetId")));
        t.statefulPublicKey = vm.parseJsonBytes(vectors, string.concat(base, ".statefulPublicKey"));
        t.publicKeyCommitment = vm.parseJsonBytes(vectors, string.concat(base, ".publicKeyCommitment"));
        t.pkSeed = vm.parseJsonBytes(vectors, string.concat(base, ".pkSeed"));
        t.hypertreeRoot = vm.parseJsonBytes(vectors, string.concat(base, ".hypertreeRoot"));
    }

    /// @dev Parses a `ShrincsTypes.StatefulRotationTarget` (stateful-only subkey) from a JSON path.
    function _parseStatefulRotationTarget(string memory base)
        internal
        view
        returns (ShrincsTypes.StatefulRotationTarget memory t)
    {
        t.parameterSetId =
            ShrincsTypes.ParameterSetId(vm.parseJsonUint(vectors, string.concat(base, ".parameterSetId")));
        t.statefulPublicKey = vm.parseJsonBytes(vectors, string.concat(base, ".statefulPublicKey"));
        t.publicKeyCommitment = vm.parseJsonBytes(vectors, string.concat(base, ".publicKeyCommitment"));
    }

    // Sphincs256sKeccakQ20 fixed dimensions: a stateless signature reveals 21 FORS-C entries and
    // 8 hypertree layers (matching the dependency's own known-good `shrincs_sphincs_256s_keccak`
    // vectors). Inner `bytes[]` paths (each entry's / layer's `authPath`, and a layer's
    // `wotsCSignature.chains`) are parsed wholesale via `vm.parseJsonBytesArray`.
    uint256 internal constant FORS_TREES = 21;
    uint256 internal constant HYPERTREE_LAYERS = 8;

    /// @dev Parses a `ShrincsTypes.StatelessSignature` (`fors` + `hypertree`) from a JSON object
    ///      path. An empty `base` returns the zero struct — the ERC-1271 failure-branch tests pass
    ///      a structurally-empty signature that is expected to fail SHRINCS verification.
    function _parseStatelessSignature(string memory base)
        internal
        view
        returns (ShrincsTypes.StatelessSignature memory sig)
    {
        if (bytes(base).length == 0) {
            return sig;
        }

        string memory forsBase = string.concat(base, ".fors");
        sig.fors.randomizer = vm.parseJsonBytes(vectors, string.concat(forsBase, ".randomizer"));
        sig.fors.counter = uint32(vm.parseJsonUint(vectors, string.concat(forsBase, ".counter")));
        sig.fors.entries = new ShrincsTypes.ForsEntry[](FORS_TREES);
        for (uint256 i = 0; i < FORS_TREES; i++) {
            string memory entryBase = string.concat(forsBase, ".entries[", vm.toString(i), "]");
            sig.fors.entries[i].secretLeaf = vm.parseJsonBytes(vectors, string.concat(entryBase, ".secretLeaf"));
            sig.fors.entries[i].authPath = vm.parseJsonBytesArray(vectors, string.concat(entryBase, ".authPath"));
        }

        sig.hypertree = new ShrincsTypes.HypertreeLayerSignature[](HYPERTREE_LAYERS);
        for (uint256 i = 0; i < HYPERTREE_LAYERS; i++) {
            string memory layerBase = string.concat(base, ".hypertree[", vm.toString(i), "]");
            sig.hypertree[i].treeIndex = uint64(vm.parseJsonUint(vectors, string.concat(layerBase, ".treeIndex")));
            sig.hypertree[i].leafIndex = uint32(vm.parseJsonUint(vectors, string.concat(layerBase, ".leafIndex")));
            sig.hypertree[i].wotsCPkHash = vm.parseJsonBytes(vectors, string.concat(layerBase, ".wotsCPkHash"));
            string memory wcBase = string.concat(layerBase, ".wotsCSignature");
            sig.hypertree[i].wotsCSignature.randomizer =
                vm.parseJsonBytes(vectors, string.concat(wcBase, ".randomizer"));
            sig.hypertree[i].wotsCSignature.counter =
                uint32(vm.parseJsonUint(vectors, string.concat(wcBase, ".counter")));
            sig.hypertree[i].wotsCSignature.chains = vm.parseJsonBytesArray(vectors, string.concat(wcBase, ".chains"));
            sig.hypertree[i].authPath = vm.parseJsonBytesArray(vectors, string.concat(layerBase, ".authPath"));
        }
    }

    /// @dev Builds the factory-supplied `initialize`/`migrate` payload exactly as
    ///      `ShrincsWalletCodec.decodeInit` expects: `abi.encode(commitment, pkSeed, PublicKey,
    ///      parameterSetId, erc1271Commitment, erc1271ParameterSetId)`.
    function _buildInitPayload(
        bytes32 commitment,
        bytes32 pkSeed,
        ShrincsTypes.PublicKey memory pk,
        uint8 parameterSetId,
        bytes32 erc1271Commitment,
        uint8 erc1271ParameterSetId
    ) internal pure returns (bytes memory) {
        return abi.encode(commitment, pkSeed, pk, parameterSetId, erc1271Commitment, erc1271ParameterSetId);
    }

    /// @dev Builds a valid `initialize` payload from the main/erc1271 key vectors. Since `initialize`
    ///      verifies NO signature (only deterministic param/commitment validation), this drives the
    ///      real success path.
    function _validInitPayload() internal view returns (bytes memory) {
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        return _buildInitPayload(
            _bytes32(".mainKey.publicKeyCommitment"),
            _bytes32(".mainKey.pkSeed"),
            pk,
            uint8(vm.parseJsonUint(vectors, ".mainKey.parameterSetId")),
            _bytes32(".erc1271Key.publicKeyCommitment"),
            uint8(vm.parseJsonUint(vectors, ".erc1271Key.parameterSetId"))
        );
    }

    /// @dev A `StatefulSignature` whose only meaningful field is `authPath.length` (= the leaf
    ///      index). Used to drive the pre-verify leaf guards (`StatefulBudgetExhausted`) without
    ///      a real signature.
    function _statefulSigWithLeaf(uint256 leaf) internal pure returns (ShrincsTypes.StatefulSignature memory sig) {
        sig.authPath = new bytes32[](leaf);
    }

    /// @dev A structurally-valid leaf-1 stateful signature (the `erc4337[0]` vector). Its leaf is
    ///      in-budget and initially unused, so it REACHES `SHRINCS.verifyStateful` — but it is bound
    ///      to the ERC-4337 action context, so against any other action it fails verification,
    ///      exercising the `InvalidSignature` branch.
    function _wrongContextStatefulSig() internal view returns (ShrincsTypes.StatefulSignature memory) {
        return _parseStatefulSignature(".cases.erc4337[0].signature");
    }

    /// @dev Builds a minimal PackedUserOperation carrying the abi-encoded (pk, sig) blob.
    function _makeUserOp(bytes memory signature) internal pure returns (ERC4337.PackedUserOperation memory op) {
        op.sender = WALLET;
        op.signature = signature;
    }
}
