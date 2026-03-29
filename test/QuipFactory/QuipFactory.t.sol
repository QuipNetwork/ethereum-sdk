// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {Deployer} from "../../contracts/Deployer.sol";
import {QuipFactory} from "../../contracts/QuipFactory.sol";
import {QuipWallet} from "../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/WOTSPlusCodec.sol";

/// @title QuipFactory Base Test
/// @dev Base contract for testing QuipFactory. Deploys full stack via CREATE3
///      and vets an initial QuipWallet implementation for proxy deployment.
contract QuipFactoryTest is Test {
    Deployer public deployer;
    QuipFactory public factory;
    address public wotsLibrary;
    QuipWallet public walletImplementation;

    address public ADMIN = makeAddr("admin");
    address public ALICE = makeAddr("alice");
    address public BOB = makeAddr("bob");

    // Standard test amounts
    uint256 public constant INITIAL_DEPOSIT = 1 ether;
    uint256 public constant CREATION_FEE = 0.01 ether;
    uint256 public constant TRANSFER_FEE = 0.005 ether;
    uint256 public constant EXECUTE_FEE = 0.002 ether;

    function setUp() public virtual {
        // Fund test accounts
        vm.deal(ADMIN, 100 ether);
        vm.deal(ALICE, 100 ether);
        vm.deal(BOB, 100 ether);

        // Deploy Deployer
        deployer = new Deployer();

        // Deploy WOTSPlus library via CREATE3
        bytes memory wotsBytecode = _getWOTSPlusBytecode();
        bytes32 wotsSalt = keccak256("WOTSPlus");
        wotsLibrary = deployer.deploy(wotsBytecode, wotsSalt);

        // Deploy QuipFactory via CREATE3
        bytes memory factoryBytecode = abi.encodePacked(
            type(QuipFactory).creationCode,
            abi.encode(ADMIN, wotsLibrary, 0.1 ether)
        );
        bytes32 factorySalt = keccak256("QuipFactory");
        address factoryAddr = deployer.deploy(factoryBytecode, factorySalt);
        factory = QuipFactory(payable(factoryAddr));

        // Deploy and vet a QuipWallet implementation
        walletImplementation = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(walletImplementation));
    }

    function test_setUp() public view virtual {
        assertEq(factory.owner(), ADMIN);
        assertEq(factory.WOTS_LIBRARY(), wotsLibrary);
        assertEq(factory.creationFee(), 0);
        assertEq(factory.transferFee(), 0);
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
    function _sign(bytes32 privateKey, bytes32 messageHash)
        internal
        pure
        returns (WOTSPlus.WinternitzElements memory)
    {
        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: messageHash
        });
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
    function _recoverySigningKey(bytes32 privateKey, uint256 index)
        internal
        pure
        returns (bytes32)
    {
        bytes32 seed = keccak256(abi.encodePacked(privateKey, "recovery", index));
        (, bytes32 signingKey) = WOTSPlus.generateKeyPair(seed);
        return signingKey;
    }

    /// @dev Deploy a QuipWallet proxy through the factory and return its address
    function _createWallet(
        address owner,
        bytes32 vaultSeed,
        uint256 deposit
    )
        internal
        returns (
            address walletAddr,
            WOTSPlus.WinternitzAddress memory pubkey,
            bytes32 privateKey,
            WOTSPlus.WinternitzAddress[] memory recoveryPubkeys
        )
    {
        bytes32 vaultId = keccak256(abi.encodePacked(vaultSeed));
        (pubkey, privateKey) = _generateKeyPair(vaultSeed);
        recoveryPubkeys = _generateRecoveryKeys(privateKey, 10);

        bytes memory payload = _encodeInitPayload(pubkey, recoveryPubkeys);

        vm.prank(owner);
        walletAddr = factory.deployLatestWalletProxy{value: deposit}(
            vaultId,
            payable(owner),
            payload
        );
    }

    /// @dev Encode init payload: [0:64) pqOwner + [64:704) recoveryKeys
    function _encodeInitPayload(
        WOTSPlus.WinternitzAddress memory pqOwner,
        WOTSPlus.WinternitzAddress[] memory recoveryKeys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(pqOwner.publicSeed, pqOwner.publicKeyHash);
        for (uint256 i = 0; i < recoveryKeys.length; i++) {
            payload = abi.encodePacked(
                payload,
                recoveryKeys[i].publicSeed,
                recoveryKeys[i].publicKeyHash
            );
        }
        return payload;
    }

    /// @dev Compute the expected CREATE3 address for a QuipWallet
    function _computeWalletAddress(bytes32 vaultId, address)
        internal
        view
        returns (address)
    {
        return CREATE3.predictDeterministicAddress(vaultId, address(factory));
    }

    /// @dev Deploy a fresh uninitialized QuipWallet proxy via CREATE3.
    function _deployFreshProxy(bytes32 salt) internal returns (QuipWallet) {
        bytes memory proxyInitcode = abi.encodePacked(
            hex"603d3d8160223d3973",
            address(walletImplementation),
            hex"6009",
            hex"5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076",
            hex"cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3"
        );
        address proxyAddr = CREATE3.deployDeterministic(proxyInitcode, salt);
        return QuipWallet(payable(proxyAddr));
    }

    /// @dev Get WOTSPlus library creation bytecode.
    ///      Uses vm.getCode to get the artifact bytecode.
    function _getWOTSPlusBytecode() internal view returns (bytes memory) {
        return vm.getCode(
            "WOTSPlus.sol:WOTSPlus"
        );
    }
}
