// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactoryHarness} from "../../harness/WalletFactoryHarness.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {PreQSalt1Wallets} from "../../../contracts/PreQSalt1Wallets.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";

/// @dev Minimal wallet impl with a distinct codehash from WOTSPlusImplementation.
contract MockInitWallet {
    function initialize(address payable, bytes calldata) external payable {}

    receive() external payable {}
}

contract WalletFactory_deploy_policy is WalletFactoryTest {
    WalletFactoryHarness public harness;
    PreQSalt1Wallets public registry;
    MockInitWallet public mockImpl;
    WOTSPlusImplementation public wotsImpl;
    uint256 public mockIndex;
    uint256 public wotsIndex;

    function setUp() public override {
        super.setUp();
        WalletFactoryHarness harnessImpl = new WalletFactoryHarness(0.1 ether);
        harness = WalletFactoryHarness(
            payable(LibClone.deployERC1967(address(harnessImpl)))
        );
        harness.initialize(payable(ADMIN));

        vm.startPrank(ADMIN);
        registry = new PreQSalt1Wallets(ADMIN);
        harness.setPreQSalt1Wallets(address(registry));

        mockImpl = new MockInitWallet();
        harness.vetImplementationWithPolicy(address(mockImpl), true);

        wotsImpl = new WOTSPlusImplementation(payable(address(harness)));
        harness.vetImplementation(address(wotsImpl));
        vm.stopPrank();

        mockIndex = harness.getVettedCodeIndex(address(mockImpl).codehash);
        wotsIndex = harness.getVettedCodeIndex(address(wotsImpl).codehash);
    }

    function _buildPayload() internal pure returns (bytes memory) {
        // disaster recovery key (64 bytes): seed 500, hash 501.
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(500)),
            bytes32(uint256(501))
        );
        // ownership key (64 bytes): seed 600, hash 601.
        payload = abi.encodePacked(
            payload,
            bytes32(uint256(600)),
            bytes32(uint256(601))
        );
        // 10 transaction keys (640 bytes): seeds 1,3,5,...,19 / hashes 2,4,6,...,20.
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(uint256(2 * i + 1)),
                bytes32(uint256(2 * i + 2))
            );
        }
        // 10 recovery keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(i + 100),
                bytes32(i + 200)
            );
        }
        // 10 verification keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(i + 300),
                bytes32(i + 400)
            );
        }
        return payload;
    }

    function test_deploySpecificWalletProxy_qsalt1VaultIdSucceeds() public {
        address to = makeAddr("to-qsalt1");
        bytes32 vaultId = Codec.qsalt1VaultId(
            bytes32(uint256(0x11)),
            bytes32(uint256(0x22)),
            to
        );

        address wallet = harness.deploySpecificWalletProxy{
            value: harness.creationFee()
        }(vaultId, bytes32(uint256(1)), mockIndex, payable(to), "");

        assertTrue(wallet != address(0));
        assertEq(harness.wallets(vaultId), wallet);
        assertEq(harness.vaultIdOf(wallet), vaultId);
    }

    function test_deploySpecificWalletProxy_whitelistedLegacySucceeds() public {
        address to = makeAddr("to-whitelisted");
        bytes32 vaultId = bytes32(uint256(1));

        vm.prank(ADMIN);
        registry.add(
            vaultId,
            to,
            bytes32(uint256(0x11)),
            bytes32(uint256(0x22))
        );

        address wallet = harness.deploySpecificWalletProxy{
            value: harness.creationFee()
        }(vaultId, bytes32(uint256(1)), mockIndex, payable(to), "");

        assertTrue(wallet != address(0));
        assertEq(harness.wallets(vaultId), wallet);
        assertEq(harness.vaultIdOf(wallet), vaultId);
    }

    function test_deploySpecificWalletProxy_wotsNonQSalt1Succeeds() public {
        address to = makeAddr("to-wots");
        bytes32 vaultId = bytes32(uint256(2));

        address wallet = harness.deploySpecificWalletProxy{
            value: harness.creationFee()
        }(
            vaultId,
            bytes32(uint256(1)),
            wotsIndex,
            payable(to),
            _buildPayload()
        );

        assertTrue(wallet != address(0));
        assertEq(harness.wallets(vaultId), wallet);
        assertEq(harness.vaultIdOf(wallet), vaultId);
    }

    function test_deploySpecificWalletProxy_revertsWhen_legacyNotWhitelisted()
        public
    {
        address to = makeAddr("to-legacy");
        bytes32 vaultId = bytes32(uint256(1));
        uint256 fee = harness.creationFee();

        vm.expectRevert(IWalletFactory.LegacyNotWhitelisted.selector);
        harness.deploySpecificWalletProxy{value: fee}(
            vaultId,
            bytes32(uint256(1)),
            mockIndex,
            payable(to),
            ""
        );
    }
}
