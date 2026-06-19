// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {Deployer} from "../../contracts/Deployer.sol";
import {QuipFactory} from "../../contracts/QuipFactory.sol";
import {WOTSPlusImplementation} from "../../contracts/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/wots/WOTSPlusCodec.sol";

/// @title QuipFactory Base Test
/// @dev Base contract for testing QuipFactory. Deploys full stack via CREATE3
///      and vets an initial WOTSPlusImplementation implementation for proxy deployment.
contract QuipFactoryTest is Test {
    Deployer public deployer;
    QuipFactory public factory;
    WOTSPlusImplementation public walletImplementation;

    address public ADMIN = makeAddr("admin");
    address public BOB = makeAddr("bob");

    /// @dev ALICE is materialized with her ECDSA private key so tests that exercise
    ///      ERC-1271 (which requires ECDSA from the classical owner) can sign on her behalf.
    address public ALICE;
    uint256 public ALICE_KEY;

    // Standard test amounts
    uint256 public constant INITIAL_DEPOSIT = 1 ether;
    uint256 public constant CREATION_FEE = 0.01 ether;
    uint256 public constant EXECUTE_FEE = 0.002 ether;

    function setUp() public virtual {
        (ALICE, ALICE_KEY) = makeAddrAndKey("alice");
        // Fund test accounts
        vm.deal(ADMIN, 100 ether);
        vm.deal(ALICE, 100 ether);
        vm.deal(BOB, 100 ether);

        // Deploy Deployer
        deployer = new Deployer();

        // Deploy QuipFactory via CREATE3
        bytes memory factoryBytecode = abi.encodePacked(type(QuipFactory).creationCode, abi.encode(ADMIN, 0.1 ether));
        bytes32 factorySalt = keccak256("QuipFactory");
        address factoryAddr = deployer.deploy(factoryBytecode, factorySalt);
        factory = QuipFactory(payable(factoryAddr));

        // Deploy and vet a WOTSPlusImplementation implementation
        walletImplementation = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(walletImplementation));
    }

    function test_setUp() public view virtual {
        assertEq(factory.owner(), ADMIN);
        assertEq(factory.creationFee(), 0);
        assertEq(factory.executeFee(), 0);
        assertEq(factory.MAX_FEE(), 0.1 ether);
        assertEq(factory.getVettedCodeCount(), 1);
    }

    // --- Helpers ---

    /// @dev Generate a WOTS+ keypair from a deterministic seed
    function _generateKeyPair(bytes32 seed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey)
    {
        return WOTSPlus.generateKeyPair(seed);
    }

    /// @dev Sign a message with a WOTS+ private key
    function _sign(bytes32 privateKey, bytes32 messageHash) internal pure returns (WOTSPlus.WinternitzElements memory) {
        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({messageHash: messageHash});
        bytes32[67] memory elements = WOTSPlus.sign(privateKey, message);
        return WOTSPlus.WinternitzElements({elements: elements});
    }

    /// @dev Generate recovery key public keys from a private key
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

    /// @dev Derive the signing key for a recovery key at a given index
    function _recoverySigningKey(bytes32 privateKey, uint256 index) internal pure returns (bytes32) {
        bytes32 seed = keccak256(abi.encodePacked(privateKey, "recovery", index));
        (, bytes32 signingKey) = WOTSPlus.generateKeyPair(seed);
        return signingKey;
    }

    /// @dev Derive the disaster recovery keypair deterministically from a vault seed.
    ///      Tests that exercise `saveWallet` can re-derive the same keypair by feeding
    ///      the vault seed back in.
    function _generateDisasterRecoveryKey(bytes32 vaultSeed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey)
    {
        bytes32 seed = keccak256(abi.encodePacked(vaultSeed, "disaster"));
        (pubkey, privateKey) = WOTSPlus.generateKeyPair(seed);
    }

    /// @dev Derive the ownership keypair deterministically from a vault seed.
    ///      Tests that exercise `transferOwnership` can re-derive the same
    ///      keypair by feeding the vault seed back in.
    function _generateOwnershipKey(bytes32 vaultSeed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey)
    {
        bytes32 seed = keccak256(abi.encodePacked(vaultSeed, "ownership"));
        (pubkey, privateKey) = WOTSPlus.generateKeyPair(seed);
    }

    /// @dev Generate the 10 initial transaction keys deterministically from a vault seed.
    function _generateTransactionKeys(bytes32 vaultSeed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[10] memory pubkeys, bytes32[10] memory privateKeys)
    {
        for (uint256 i = 0; i < 10; i++) {
            bytes32 seed = keccak256(abi.encodePacked(vaultSeed, "txn", i));
            (pubkeys[i], privateKeys[i]) = WOTSPlus.generateKeyPair(seed);
        }
    }

    /// @dev Generate the 10 initial verification keys deterministically from a vault seed.
    function _generateVerificationKeys(bytes32 vaultSeed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[10] memory pubkeys, bytes32[10] memory privateKeys)
    {
        for (uint256 i = 0; i < 10; i++) {
            bytes32 seed = keccak256(abi.encodePacked(vaultSeed, "verify", i));
            (pubkeys[i], privateKeys[i]) = WOTSPlus.generateKeyPair(seed);
        }
    }

    /// @dev Deploy a WOTSPlusImplementation proxy through the factory and return its address.
    ///      Returns the FIRST (index 0) transaction key as the "primary" signing key for
    ///      convenience. Other 9 transaction keys are returned in `txnPubkeys`/`txnPrivkeys`.
    function _createWallet(address owner, bytes32 vaultSeed, uint256 deposit)
        internal
        returns (
            address walletAddr,
            WOTSPlus.WinternitzAddress memory pubkey,
            bytes32 privateKey,
            WOTSPlus.WinternitzAddress[] memory recoveryPubkeys
        )
    {
        WOTSPlus.WinternitzAddress[10] memory txnPubkeys;
        bytes32[10] memory txnPrivkeys;
        (walletAddr, txnPubkeys, txnPrivkeys, recoveryPubkeys) = _createWalletFull(owner, vaultSeed, deposit);
        pubkey = txnPubkeys[0];
        privateKey = txnPrivkeys[0];
    }

    /// @dev Full-form _createWallet that exposes all 10 transaction keys.
    function _createWalletFull(address owner, bytes32 vaultSeed, uint256 deposit)
        internal
        returns (
            address walletAddr,
            WOTSPlus.WinternitzAddress[10] memory txnPubkeys,
            bytes32[10] memory txnPrivkeys,
            WOTSPlus.WinternitzAddress[] memory recoveryPubkeys
        )
    {
        (txnPubkeys, txnPrivkeys) = _generateTransactionKeys(vaultSeed);
        recoveryPubkeys = _generateRecoveryKeys(txnPrivkeys[0], 10);
        bytes memory payload = _buildInitPayloadForCreate(vaultSeed, txnPubkeys, recoveryPubkeys);
        walletAddr = _deployProxyAs(owner, keccak256(abi.encodePacked(vaultSeed)), payload, deposit);
    }

    /// @dev Builds the encoded init payload for `_createWalletFull` without
    ///      holding all stack slots in the parent (stack-too-deep avoidance
    ///      after the always-10 growth bumped the encoded layout).
    function _buildInitPayloadForCreate(
        bytes32 vaultSeed,
        WOTSPlus.WinternitzAddress[10] memory txnPubkeys,
        WOTSPlus.WinternitzAddress[] memory recoveryPubkeys
    ) internal pure returns (bytes memory) {
        (WOTSPlus.WinternitzAddress memory disasterKey,) = _generateDisasterRecoveryKey(vaultSeed);
        (WOTSPlus.WinternitzAddress memory ownershipKey,) = _generateOwnershipKey(vaultSeed);
        WOTSPlus.WinternitzAddress[10] memory recFixed;
        for (uint256 i = 0; i < 10; i++) {
            recFixed[i] = recoveryPubkeys[i];
        }
        (WOTSPlus.WinternitzAddress[10] memory verifPubkeys,) = _generateVerificationKeys(vaultSeed);
        return Codec.encodeInit(disasterKey, ownershipKey, txnPubkeys, recFixed, verifPubkeys);
    }

    function _deployProxyAs(address owner, bytes32 vaultId, bytes memory payload, uint256 deposit)
        internal
        returns (address)
    {
        vm.prank(owner);
        return factory.deployLatestWalletProxy{value: deposit}(vaultId, payable(owner), payload);
    }

    /// @dev Encode init payload from a single "pqOwner" key (legacy shim).
    ///      The single `pqOwner` becomes txn key 0; the other 9 are derived
    ///      deterministically from its public seed/hash; the 10 verification
    ///      keys are derived in parallel. Use only where callers do not
    ///      already have a full batch.
    function _encodeInitPayload(
        WOTSPlus.WinternitzAddress memory pqOwner,
        WOTSPlus.WinternitzAddress[] memory recoveryKeys
    ) internal pure returns (bytes memory) {
        require(recoveryKeys.length == 10, "recoveryKeys length must be 10");
        WOTSPlus.WinternitzAddress[10] memory txnFixed;
        txnFixed[0] = pqOwner;
        for (uint256 i = 1; i < 10; i++) {
            bytes32 seed = keccak256(abi.encodePacked(pqOwner.publicSeed, pqOwner.publicKeyHash, "txn-fill", i));
            (txnFixed[i],) = WOTSPlus.generateKeyPair(seed);
        }
        WOTSPlus.WinternitzAddress[10] memory recFixed;
        for (uint256 i = 0; i < 10; i++) {
            recFixed[i] = recoveryKeys[i];
        }
        WOTSPlus.WinternitzAddress[10] memory verifFixed;
        for (uint256 i = 0; i < 10; i++) {
            bytes32 seed = keccak256(abi.encodePacked(pqOwner.publicSeed, pqOwner.publicKeyHash, "verify-fill", i));
            (verifFixed[i],) = WOTSPlus.generateKeyPair(seed);
        }
        // Derive a stable disaster recovery key from pqOwner for legacy single-key helper.
        bytes32 disasterSeedBytes =
            keccak256(abi.encodePacked(pqOwner.publicSeed, pqOwner.publicKeyHash, "disaster-legacy"));
        (WOTSPlus.WinternitzAddress memory disasterKey,) = WOTSPlus.generateKeyPair(disasterSeedBytes);
        // Likewise derive a stable ownership key from pqOwner for legacy single-key helper.
        bytes32 ownershipSeedBytes =
            keccak256(abi.encodePacked(pqOwner.publicSeed, pqOwner.publicKeyHash, "ownership-legacy"));
        (WOTSPlus.WinternitzAddress memory ownershipKey,) = WOTSPlus.generateKeyPair(ownershipSeedBytes);
        return Codec.encodeInit(disasterKey, ownershipKey, txnFixed, recFixed, verifFixed);
    }

    /// @dev Compute the expected CREATE3 address for a WOTSPlusImplementation
    function _computeWalletAddress(bytes32 vaultId, address) internal view returns (address) {
        return CREATE3.predictDeterministicAddress(vaultId, address(factory));
    }

    /// @dev Deploy a fresh uninitialized WOTSPlusImplementation proxy via CREATE3.
    function _deployFreshProxy(bytes32 salt) internal returns (WOTSPlusImplementation) {
        bytes memory proxyInitcode = abi.encodePacked(
            hex"603d3d8160223d3973",
            address(walletImplementation),
            hex"6009",
            hex"5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076",
            hex"cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3"
        );
        address proxyAddr = CREATE3.deployDeterministic(proxyInitcode, salt);
        return WOTSPlusImplementation(payable(proxyAddr));
    }
}
