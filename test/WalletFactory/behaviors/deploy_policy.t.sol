// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactoryHarness} from "../../harness/WalletFactoryHarness.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";

/// @dev Minimal wallet impl with a distinct codehash from WOTSPlusImplementation.
contract MockInitWallet {
    function initialize(address payable, bytes calldata) external payable {}

    receive() external payable {}
}

contract WalletFactory_deploy_policy is WalletFactoryTest {
    WalletFactoryHarness public harness;
    MockInitWallet public mockImpl;
    uint256 public mockIndex;

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

        vm.stopPrank();

        mockIndex = harness.getVettedCodeIndex(address(mockImpl).codehash);
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
}
