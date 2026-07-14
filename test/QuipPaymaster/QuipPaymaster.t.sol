// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {QuipPaymaster} from "../../contracts/QuipPaymaster.sol";
import {QuipPaymasterHarness} from "../harness/QuipPaymasterHarness.sol";
import {IQuipPaymaster} from "../../contracts/interfaces/IQuipPaymaster.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

/// @title QuipPaymaster Base Test
/// @dev Base contract for testing QuipPaymaster. Deploys an ERC-1967 proxy
///      pointing to the implementation and initializes with owner. Registers
///      a per-wallet WOTS+ verifier key for the default sender.
contract QuipPaymasterTest is Test {
    QuipPaymaster public implementation;
    QuipPaymaster public paymaster;
    QuipPaymasterHarness public harnessImpl;
    QuipPaymasterHarness public harness;

    address public ADMIN = makeAddr("admin");
    address public ALICE = makeAddr("alice");
    address public BOB = makeAddr("bob");
    address public WALLET = address(0xdead);

    address public constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    /// @dev Domain tag for paymaster approval digests (must match QuipPaymaster._PAYMASTER_APPROVE_TAG).
    bytes32 internal constant _PAYMASTER_APPROVE_TAG = keccak256("quip.digest.paymasterApprove");

    /// @dev Offset into `paymasterAndData` where the WOTS+ signature begins
    ///      (must match QuipPaymaster._PAYMASTER_SIG_OFFSET). Everything up to
    ///      this offset is bound into the userOp binding hash.
    uint256 internal constant _PAYMASTER_SIG_OFFSET = 128;

    /// @dev Default paymaster gas limits used by the test helpers. Tests that
    ///      mutate these to exercise binding must reconstruct the binding hash
    ///      from the mutated values.
    uint128 internal constant _DEFAULT_PM_VERIFICATION_GAS = 100_000;
    uint128 internal constant _DEFAULT_PM_POSTOP_GAS = 50_000;

    /// @dev WOTS+ verifier key state for the default WALLET sender.
    WOTSPlus.WinternitzAddress public verifierPubkey;
    bytes32 public verifierPrivateKey;

    function setUp() public virtual {
        vm.deal(ADMIN, 100 ether);
        vm.deal(ALICE, 100 ether);

        // Generate initial WOTS+ verifier keypair
        (verifierPubkey, verifierPrivateKey) = _generateKeyPair("verifier-seed-0");

        // Deploy implementation
        implementation = new QuipPaymaster();
        harnessImpl = new QuipPaymasterHarness();

        // Deploy proxies via CREATE3
        paymaster = QuipPaymaster(payable(_deployProxy(address(implementation), keccak256("paymaster"))));
        harness = QuipPaymasterHarness(payable(_deployProxy(address(harnessImpl), keccak256("harness"))));

        // Initialize
        paymaster.initialize(ADMIN);
        harness.initialize(ADMIN);

        // Register a verifier for the default wallet sender
        vm.startPrank(ADMIN);
        paymaster.setPqVerifier(WALLET, verifierPubkey);
        harness.setPqVerifier(WALLET, verifierPubkey);
        vm.stopPrank();

        // Fund EntryPoint deposit
        vm.deal(address(paymaster), 10 ether);
    }

    function test_setUp() public view virtual {
        assertEq(paymaster.owner(), ADMIN);
        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, verifierPubkey.publicSeed);
        assertEq(v.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    // --- Helpers ---

    /// @dev Deploy a minimal ERC-1967 proxy via CREATE3 (same bytecode as QuipFactory).
    function _deployProxy(address impl, bytes32 salt) internal returns (address) {
        bytes memory proxyInitcode = abi.encodePacked(
            hex"603d3d8160223d3973",
            impl,
            hex"6009",
            hex"5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076",
            hex"cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3"
        );
        return CREATE3.deployDeterministic(proxyInitcode, salt);
    }

    /// @dev Generate a WOTS+ keypair from a deterministic seed.
    function _generateKeyPair(bytes32 seed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey)
    {
        return WOTSPlus.generateKeyPair(seed);
    }

    /// @dev Sign a message with a WOTS+ private key.
    function _sign(bytes32 privateKey, bytes32 messageHash) internal pure returns (WOTSPlus.WinternitzElements memory) {
        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({messageHash: messageHash});
        bytes32[67] memory elements = WOTSPlus.sign(privateKey, message);
        return WOTSPlus.WinternitzElements({elements: elements});
    }

    /// @dev Build the 128-byte bindable prefix of paymasterAndData (everything
    ///      that the userOpBindingHash commits to, i.e. up to but not including
    ///      the WOTS+ signature region). Layout:
    ///      [0:20)   paymaster address
    ///      [20:36)  paymasterVerificationGasLimit
    ///      [36:52)  paymasterPostOpGasLimit
    ///      [52:58)  validUntil
    ///      [58:64)  validAfter
    ///      [64:128) nextVerifier (publicSeed || publicKeyHash)
    function _paymasterAndDataPrefix(
        address paymasterAddr,
        uint128 pmVerificationGas,
        uint128 pmPostOpGas,
        uint48 validUntil,
        uint48 validAfter,
        WOTSPlus.WinternitzAddress memory nextPubkey
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            paymasterAddr,
            pmVerificationGas,
            pmPostOpGas,
            validUntil,
            validAfter,
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash
        );
    }

    /// @dev Recompute the contract's `userOpBindingHash`. Must stay in lockstep
    ///      with `QuipPaymaster._verifyAndRotate`. Tests that need to sign a
    ///      digest manually (e.g. with the wrong key) use this to build the
    ///      preimage; tests that mutate a field post-signing use the contract's
    ///      computation directly via the WOTS+ verify failure path.
    function _userOpBindingHash(PackedUserOperation memory userOp) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            bytes32(uint256(uint160(userOp.sender))),
            bytes32(userOp.nonce),
            EfficientHashLib.hash(userOp.initCode),
            EfficientHashLib.hash(userOp.callData),
            userOp.accountGasLimits,
            bytes32(userOp.preVerificationGas),
            userOp.gasFees,
            EfficientHashLib.hash(_slice(userOp.paymasterAndData, 0, _PAYMASTER_SIG_OFFSET))
        );
    }

    /// @dev Build the outer digest the paymaster's WOTS+ verifier signs.
    function _paymasterApprovalDigest(
        address paymasterAddr,
        WOTSPlus.WinternitzAddress memory currentPubkey,
        bytes32 userOpBindingHash_
    ) internal view returns (bytes32) {
        return EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(paymasterAddr))),
            currentPubkey.publicSeed,
            currentPubkey.publicKeyHash,
            userOpBindingHash_
        );
    }

    /// @dev Sign a paymaster approval for `userOp` and patch the full
    ///      `paymasterAndData` (header + validity + nextVerifier + sig) into it.
    ///      The userOp passed in must already have all other fields finalized,
    ///      since they go into the binding hash.
    function _signPaymasterApproval(
        PackedUserOperation memory userOp,
        address paymasterAddr,
        uint128 pmVerificationGas,
        uint128 pmPostOpGas,
        uint48 validUntil,
        uint48 validAfter,
        WOTSPlus.WinternitzAddress memory currentPubkey,
        bytes32 currentPrivateKey,
        WOTSPlus.WinternitzAddress memory nextPubkey
    ) internal view returns (PackedUserOperation memory) {
        bytes memory prefix = _paymasterAndDataPrefix(
            paymasterAddr, pmVerificationGas, pmPostOpGas, validUntil, validAfter, nextPubkey
        );

        // Patch the prefix into userOp.paymasterAndData so the binding hash
        // hashes the correct [:128] bytes. Append a 2144-byte zero placeholder
        // for the sig region; that placeholder is excluded from the hash.
        userOp.paymasterAndData = abi.encodePacked(prefix, new bytes(2144));

        bytes32 digest = _paymasterApprovalDigest(paymasterAddr, currentPubkey, _userOpBindingHash(userOp));

        WOTSPlus.WinternitzElements memory sig = _sign(currentPrivateKey, digest);

        userOp.paymasterAndData = abi.encodePacked(prefix, sig.elements);
        return userOp;
    }

    /// @dev Build paymasterAndData with a valid WOTS+ signature for the given wallet.
    ///      Convenience overload mirroring the original test API: constructs a
    ///      default mock userOp from (sender, nonce, callData) and signs it.
    ///      Tests that need to bind non-default gas fields should use
    ///      `_signPaymasterApproval` directly.
    function _buildPaymasterAndData(
        address sender_,
        uint256 nonce_,
        bytes memory callData_,
        uint48 validUntil,
        uint48 validAfter,
        WOTSPlus.WinternitzAddress memory currentPubkey,
        bytes32 currentPrivateKey,
        WOTSPlus.WinternitzAddress memory nextPubkey
    ) internal view returns (bytes memory) {
        PackedUserOperation memory userOp = _mockUserOp("", sender_);
        userOp.nonce = nonce_;
        userOp.callData = callData_;
        userOp = _signPaymasterApproval(
            userOp,
            address(paymaster),
            _DEFAULT_PM_VERIFICATION_GAS,
            _DEFAULT_PM_POSTOP_GAS,
            validUntil,
            validAfter,
            currentPubkey,
            currentPrivateKey,
            nextPubkey
        );
        return userOp.paymasterAndData;
    }

    /// @dev Build a mock PackedUserOperation with the given paymasterAndData and sender.
    function _mockUserOp(bytes memory paymasterData_, address sender_)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender_,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32((uint256(100_000) << 128) | uint256(100_000)),
            preVerificationGas: 21_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(10 gwei)),
            paymasterAndData: paymasterData_,
            signature: ""
        });
    }

    /// @dev Build a mock PackedUserOperation with the default WALLET sender.
    function _mockUserOp(bytes memory paymasterData_) internal view returns (PackedUserOperation memory) {
        return _mockUserOp(paymasterData_, WALLET);
    }

    /// @dev Take a bytes slice. EfficientHashLib.hash requires bytes memory,
    ///      not a slice expression, so this exists to bridge.
    function _slice(bytes memory data, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[start + i];
        }
    }
}
