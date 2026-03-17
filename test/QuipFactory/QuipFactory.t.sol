// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "forge-std-1.14.0/Test.sol";
import {Deployer} from "../../contracts/Deployer.sol";
import {QuipFactory} from "../../contracts/QuipFactory.sol";
import {QuipWallet} from "../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title QuipFactory Base Test
/// @dev Base contract for testing QuipFactory. Deploys full stack via CREATE2.
contract QuipFactoryTest is Test {
    Deployer public deployer;
    QuipFactory public factory;
    address public wotsLibrary;

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

        // Deploy WOTSPlus library via CREATE2
        bytes memory wotsBytecode = _getWOTSPlusBytecode();
        uint256 wotsSalt = uint256(keccak256("WOTSPlus"));
        wotsLibrary = deployer.deploy(wotsBytecode, wotsSalt);

        // Deploy QuipFactory via CREATE2
        bytes memory factoryBytecode = abi.encodePacked(
            type(QuipFactory).creationCode,
            abi.encode(ADMIN, wotsLibrary)
        );
        uint256 factorySalt = uint256(keccak256("QuipFactory"));
        address factoryAddr = deployer.deploy(factoryBytecode, factorySalt);
        factory = QuipFactory(payable(factoryAddr));
    }

    function test_setUp() public view virtual {
        assertEq(factory.admin(), ADMIN);
        assertEq(factory.wotsLibrary(), wotsLibrary);
        assertEq(factory.creationFee(), 0);
        assertEq(factory.transferFee(), 0);
        assertEq(factory.executeFee(), 0);
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

    /// @dev Deploy a QuipWallet through the factory and return its address
    function _createWallet(
        address owner,
        bytes32 vaultSeed,
        uint256 deposit
    )
        internal
        returns (
            address walletAddr,
            WOTSPlus.WinternitzAddress memory pubkey,
            bytes32 privateKey
        )
    {
        bytes32 vaultId = keccak256(abi.encodePacked(vaultSeed));
        (pubkey, privateKey) = _generateKeyPair(vaultSeed);

        vm.prank(owner);
        walletAddr = factory.depositToWinternitz{value: deposit}(
            vaultId,
            payable(owner),
            pubkey
        );
    }

    /// @dev Compute the expected CREATE2 address for a QuipWallet
    function _computeWalletAddress(bytes32 vaultId, address owner)
        internal
        view
        returns (address)
    {
        bytes memory creationCode = abi.encodePacked(
            type(QuipWallet).creationCode,
            abi.encode(address(factory), owner)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(factory),
                vaultId,
                keccak256(creationCode)
            )
        );
        return address(uint160(uint256(hash)));
    }

    /// @dev Get WOTSPlus library creation bytecode.
    ///      Uses vm.getCode to get the artifact bytecode.
    function _getWOTSPlusBytecode() internal returns (bytes memory) {
        return vm.getCode(
            "WOTSPlus.sol:WOTSPlus"
        );
    }
}
