// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
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

    address public constant ENTRY_POINT =
        0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    /// @dev Domain tag for paymaster approval digests (must match QuipPaymaster._PAYMASTER_APPROVE_TAG).
    bytes32 private constant _PAYMASTER_APPROVE_TAG =
        keccak256("quip.digest.paymasterApprove");

    /// @dev WOTS+ verifier key state for the default WALLET sender.
    WOTSPlus.WinternitzAddress public verifierPubkey;
    bytes32 public verifierPrivateKey;

    function setUp() public virtual {
        vm.deal(ADMIN, 100 ether);
        vm.deal(ALICE, 100 ether);

        // Generate initial WOTS+ verifier keypair
        (verifierPubkey, verifierPrivateKey) = _generateKeyPair(
            "verifier-seed-0"
        );

        // Deploy implementation
        implementation = new QuipPaymaster();
        harnessImpl = new QuipPaymasterHarness();

        // Deploy proxies via CREATE3
        paymaster = QuipPaymaster(
            payable(
                _deployProxy(address(implementation), keccak256("paymaster"))
            )
        );
        harness = QuipPaymasterHarness(
            payable(_deployProxy(address(harnessImpl), keccak256("harness")))
        );

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
    function _deployProxy(
        address impl,
        bytes32 salt
    ) internal returns (address) {
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
    function _generateKeyPair(
        bytes32 seed
    )
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey)
    {
        return WOTSPlus.generateKeyPair(seed);
    }

    /// @dev Sign a message with a WOTS+ private key.
    function _sign(
        bytes32 privateKey,
        bytes32 messageHash
    ) internal pure returns (WOTSPlus.WinternitzElements memory) {
        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: messageHash
        });
        bytes32[67] memory elements = WOTSPlus.sign(privateKey, message);
        return WOTSPlus.WinternitzElements({elements: elements});
    }

    /// @dev Build paymasterAndData with a valid WOTS+ signature for the given wallet.
    ///      Uses the current verifier key and rotates to nextPubkey.
    ///      Digest is built from UserOp fields (not userOpHash) to avoid circular dependency.
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
        // Build domain-tagged digest matching the paymaster's validation logic.
        bytes32 opCommitment = EfficientHashLib.hash(
            bytes32(uint256(uint160(sender_))),
            bytes32(nonce_),
            EfficientHashLib.hash(callData_)
        );

        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(paymaster)))),
            currentPubkey.publicSeed,
            currentPubkey.publicKeyHash,
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            opCommitment
        );

        WOTSPlus.WinternitzElements memory sig = _sign(
            currentPrivateKey,
            digest
        );

        // Pack: [0:20) paymaster, [20:36) verificationGasLimit, [36:52) postOpGasLimit,
        //        [52:58) validUntil, [58:64) validAfter,
        //        [64:128) nextVerifierKey (publicSeed + publicKeyHash),
        //        [128:2272) WOTS+ signature (67 × 32)
        return
            abi.encodePacked(
                address(paymaster),
                uint128(100_000), // paymasterVerificationGasLimit
                uint128(50_000), // paymasterPostOpGasLimit
                validUntil,
                validAfter,
                nextPubkey.publicSeed,
                nextPubkey.publicKeyHash,
                sig.elements
            );
    }

    /// @dev Build a mock PackedUserOperation with the given paymasterAndData and sender.
    function _mockUserOp(
        bytes memory paymasterData_,
        address sender_
    ) internal pure returns (PackedUserOperation memory) {
        return
            PackedUserOperation({
                sender: sender_,
                nonce: 0,
                initCode: "",
                callData: "",
                accountGasLimits: bytes32(
                    (uint256(100_000) << 128) | uint256(100_000)
                ),
                preVerificationGas: 21_000,
                gasFees: bytes32((uint256(1 gwei) << 128) | uint256(10 gwei)),
                paymasterAndData: paymasterData_,
                signature: ""
            });
    }

    /// @dev Build a mock PackedUserOperation with the default WALLET sender.
    function _mockUserOp(
        bytes memory paymasterData_
    ) internal view returns (PackedUserOperation memory) {
        return _mockUserOp(paymasterData_, WALLET);
    }
}
