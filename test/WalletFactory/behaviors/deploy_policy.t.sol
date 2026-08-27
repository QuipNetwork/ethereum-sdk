// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactoryHarness} from "../../harness/WalletFactoryHarness.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";

/// @dev Minimal wallet impl with a distinct codehash from WOTSPlusImplementation.
contract MockInitWallet {
    function initialize(address payable, bytes calldata) external payable {}

    receive() external payable {}
}

contract WalletFactory_deploy_policy is WalletFactoryTest {
    WalletFactoryHarness public harness;
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

        mockImpl = new MockInitWallet();
        harness.vetImplementation(address(mockImpl));
        harness.setV1Compatibility(address(mockImpl), true);

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

    function test_deploySpecificWalletProxy_v1CommitmentSucceeds() public {
        address to = makeAddr("to-v1");
        bytes32 commitment = Codec.v1Commitment(
            bytes32(uint256(0x11)),
            bytes32(uint256(0x22)),
            to
        );

        address wallet = harness.deploySpecificWalletProxy{
            value: harness.creationFee()
        }(commitment, mockIndex, payable(to), "");

        assertTrue(wallet != address(0));
        assertEq(harness.wallets(commitment), wallet);
        assertEq(harness.commitmentOf(wallet), commitment);
    }

    function test_deploySpecificWalletProxy_crossImplementationFrontRunCannotOccupyPrefundedAddress()
        public
    {
        address to = makeAddr("front-run-victim");
        bytes32 commitment = Codec.v1Commitment(
            bytes32(uint256(0x33)),
            bytes32(uint256(0x44)),
            to
        );
        address predicted = CREATE3.predictDeterministicAddress(
            commitment,
            address(harness)
        );
        vm.deal(predicted, 1 ether);

        vm.expectRevert(
            abi.encodeWithSelector(
                IWalletFactory.ImplementationNotV1Compatible.selector,
                address(wotsImpl).codehash
            )
        );
        harness.deploySpecificWalletProxy(
            commitment,
            wotsIndex,
            payable(makeAddr("attacker")),
            _buildPayload()
        );

        assertEq(predicted.code.length, 0);
        assertEq(predicted.balance, 1 ether);

        address wallet = harness.deploySpecificWalletProxy(
            commitment,
            mockIndex,
            payable(to),
            ""
        );
        assertEq(wallet, predicted);
        assertEq(wallet.balance, 1 ether);
    }

    function test_deploySpecificWalletProxy_revertsWhen_implIsNotV1Compatible()
        public
    {
        address to = makeAddr("to-wots");
        bytes32 commitment = bytes32(uint256(2));
        uint256 fee = harness.creationFee();

        vm.expectRevert(
            abi.encodeWithSelector(
                IWalletFactory.ImplementationNotV1Compatible.selector,
                address(wotsImpl).codehash
            )
        );
        harness.deploySpecificWalletProxy{value: fee}(
            commitment,
            wotsIndex,
            payable(to),
            _buildPayload()
        );
    }

    function test_deploySpecificWalletProxy_revertsWhen_compatibilityRevoked()
        public
    {
        address to = makeAddr("to-nonv1");
        bytes32 commitment = bytes32(uint256(1));
        uint256 fee = harness.creationFee();

        vm.prank(ADMIN);
        harness.setV1Compatibility(address(mockImpl), false);
        vm.expectRevert(
            abi.encodeWithSelector(
                IWalletFactory.ImplementationNotV1Compatible.selector,
                address(mockImpl).codehash
            )
        );
        harness.deploySpecificWalletProxy{value: fee}(
            commitment,
            mockIndex,
            payable(to),
            ""
        );
    }
}
