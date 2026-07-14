// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {Deployer} from "../../contracts/Deployer.sol";
import {QuipFactory} from "../../contracts/QuipFactory.sol";
import {WOTSPlusImplementation} from "../../contracts/wots/WOTSPlusImplementation.sol";
import {QuipPaymaster} from "../../contracts/QuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/wots/WOTSPlusCodec.sol";
import {
    IEntryPoint,
    IEntryPointStake,
    PackedUserOperation
} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

/// @dev Minimal extension of IEntryPoint to expose getUserOpHash on the fork.
interface IEntryPointExt is IEntryPoint {
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);
}

/// @title Integration Test Base
/// @dev Shared fork setup, deployment helpers, and WOTS+ utilities for all
///      integration tests running against the real EntryPoint v0.7 on Base Sepolia.
contract IntegrationBase is Test {
    string constant BASE_SEPOLIA_RPC_ENV = "API_URL_BASE_SEPOLIA";

    address public constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address public ADMIN = makeAddr("admin");
    address public ALICE = makeAddr("alice");
    address public BOB = makeAddr("bob");
    address payable public BENEFICIARY = payable(makeAddr("beneficiary"));

    Deployer public deployer;
    QuipFactory public factory;
    WOTSPlusImplementation public walletImpl;
    WOTSPlusImplementation public wallet;
    QuipPaymaster public paymaster;

    WOTSPlus.WinternitzAddress public alicePubkey;
    bytes32 public alicePrivateKey;

    WOTSPlus.WinternitzAddress[] public recoveryPubkeys;

    /// @dev Fork Base Sepolia in setUp so all tests run against it.
    function setUp() public virtual {
        string memory rpcUrl = vm.envString(BASE_SEPOLIA_RPC_ENV);
        vm.createSelectFork(rpcUrl);
        vm.deal(ADMIN, 100 ether);
        vm.deal(ALICE, 100 ether);
        // Clear any code at deterministic addresses that may collide with
        // deployed contracts on the fork, so they behave as plain EOAs.
        vm.etch(BOB, "");
        vm.etch(BENEFICIARY, "");
    }

    // ── WOTS+ helpers ───────────────────────────────────────────────

    function _generateKeyPair(bytes32 seed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey)
    {
        return WOTSPlus.generateKeyPair(seed);
    }

    function _sign(bytes32 privateKey, bytes32 messageHash) internal pure returns (WOTSPlus.WinternitzElements memory) {
        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({messageHash: messageHash});
        bytes32[67] memory elements = WOTSPlus.sign(privateKey, message);
        return WOTSPlus.WinternitzElements({elements: elements});
    }

    function _generateRecoveryKeys(bytes32 privateKey, uint256 count)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[] memory pubkeys)
    {
        pubkeys = new WOTSPlus.WinternitzAddress[](count);
        for (uint256 i = 0; i < count; i++) {
            bytes32 seed = keccak256(abi.encodePacked(privateKey, "recovery", i));
            (pubkeys[i],) = WOTSPlus.generateKeyPair(seed);
        }
    }

    function _encodeInitPayload(
        WOTSPlus.WinternitzAddress memory pqOwner,
        WOTSPlus.WinternitzAddress[] memory recoveryKeys
    ) internal pure returns (bytes memory) {
        require(recoveryKeys.length == 10, "recoveryKeys length must be 10");
        // Init layout (2048 bytes):
        //   [0:64)      disasterRecoveryKey (deterministic filler)
        //   [64:128)    ownershipKey         (deterministic filler)
        //   [128:768)   transactionKeys[10]  (pqOwner at slot 0 + 9 fillers)
        //   [768:1408)  recoveryKeys[10]
        //   [1408:2048) verificationKeys[10] (deterministic fillers)
        // pqOwner is the primary transaction key so tests can sign with
        // alicePrivateKey against the first transaction-keyset slot.
        (WOTSPlus.WinternitzAddress memory disaster,) = WOTSPlus.generateKeyPair(
            keccak256(abi.encodePacked(pqOwner.publicSeed, pqOwner.publicKeyHash, "disaster-fill"))
        );
        (WOTSPlus.WinternitzAddress memory ownership,) = WOTSPlus.generateKeyPair(
            keccak256(abi.encodePacked(pqOwner.publicSeed, pqOwner.publicKeyHash, "ownership-fill"))
        );
        bytes memory payload = abi.encodePacked(
            disaster.publicSeed,
            disaster.publicKeyHash,
            ownership.publicSeed,
            ownership.publicKeyHash,
            pqOwner.publicSeed,
            pqOwner.publicKeyHash
        );
        for (uint256 i = 1; i < 10; i++) {
            bytes32 seed = keccak256(abi.encodePacked(pqOwner.publicSeed, pqOwner.publicKeyHash, "txn-fill", i));
            (WOTSPlus.WinternitzAddress memory filler,) = WOTSPlus.generateKeyPair(seed);
            payload = abi.encodePacked(payload, filler.publicSeed, filler.publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, recoveryKeys[i].publicSeed, recoveryKeys[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            bytes32 seed = keccak256(abi.encodePacked(pqOwner.publicSeed, pqOwner.publicKeyHash, "verify-fill", i));
            (WOTSPlus.WinternitzAddress memory filler,) = WOTSPlus.generateKeyPair(seed);
            payload = abi.encodePacked(payload, filler.publicSeed, filler.publicKeyHash);
        }
        return payload;
    }

    // ── Deployment helpers ──────────────────────────────────────────

    /// @dev Deploy factory + wallet implementation + ALICE's wallet.
    function _deployWalletStack() internal {
        deployer = new Deployer();

        QuipFactory factoryImpl = new QuipFactory(0.1 ether);
        bytes memory proxyInitcode = LibClone.initCodeERC1967(address(factoryImpl));
        address factoryAddr = deployer.deploy(proxyInitcode, keccak256("QuipFactory-integration"));
        factory = QuipFactory(payable(factoryAddr));
        factory.initialize(payable(ADMIN));

        walletImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(walletImpl));

        (alicePubkey, alicePrivateKey) = _generateKeyPair("alice-integration-vault");
        WOTSPlus.WinternitzAddress[] memory recoveryKeys = _generateRecoveryKeys(alicePrivateKey, 10);
        for (uint256 i = 0; i < recoveryKeys.length; i++) {
            recoveryPubkeys.push(recoveryKeys[i]);
        }
        bytes memory initPayload = _encodeInitPayload(alicePubkey, recoveryKeys);

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy{value: 1 ether}(
            keccak256("integration-vault"), payable(ALICE), initPayload
        );
        wallet = WOTSPlusImplementation(payable(walletAddr));

        IEntryPointStake(ENTRY_POINT).depositTo{value: 5 ether}(address(wallet));
    }

    /// @dev Deploy paymaster proxy and initialize.
    function _deployPaymaster() internal {
        QuipPaymaster impl = new QuipPaymaster();

        bytes memory proxyInitcode = abi.encodePacked(
            hex"603d3d8160223d3973",
            address(impl),
            hex"6009",
            hex"5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076",
            hex"cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3"
        );
        paymaster =
            QuipPaymaster(payable(CREATE3.deployDeterministic(proxyInitcode, keccak256("integration-paymaster"))));

        paymaster.initialize(ADMIN);
    }

    // ── UserOp helpers ──────────────────────────────────────────────

    /// @dev Build a PackedUserOperation for execute(address,uint256,bytes).
    function _buildUserOp(address target, uint256 value, bytes memory data)
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = PackedUserOperation({
            sender: address(wallet),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(bytes4(keccak256("execute(address,uint256,bytes)")), target, value, data),
            accountGasLimits: bytes32((uint256(5_000_000) << 128) | uint256(500_000)),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(10 gwei)),
            paymasterAndData: "",
            signature: ""
        });
    }

    /// @dev Sign a UserOp with WOTS+ keys and set the signature field.
    function _signUserOp(
        PackedUserOperation memory userOp,
        bytes32 privateKey,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq
    ) internal view {
        bytes32 userOpHash = IEntryPointExt(ENTRY_POINT).getUserOpHash(userOp);

        uint256 fee = wallet.getExecuteFee();
        bytes32 digest = Codec.erc4337ExecuteDigest(
            address(wallet),
            block.chainid,
            currentPq.publicSeed,
            currentPq.publicKeyHash,
            nextPq.publicSeed,
            nextPq.publicKeyHash,
            userOpHash,
            fee
        );

        WOTSPlus.WinternitzElements memory sig = _sign(privateKey, digest);
        userOp.signature = Codec.encodeUserOpSignature(currentPq, nextPq, sig);
    }
}
