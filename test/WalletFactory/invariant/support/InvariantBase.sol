// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../../WalletFactory.t.sol";
import {WalletFactoryInvariantHandler, FactoryImplStub} from "./Handler.sol";

abstract contract WalletFactoryInvariantBase is WalletFactoryTest {
    WalletFactoryInvariantHandler public handler;

    uint256 internal constant IMPLEMENTATION_PAIR_COUNT = 8;

    function setUp() public virtual override {
        super.setUp();

        handler = new WalletFactoryInvariantHandler();

        vm.prank(ADMIN);
        factory.transferOwnership(address(handler));

        address[] memory originals = new address[](IMPLEMENTATION_PAIR_COUNT);
        address[] memory twins = new address[](IMPLEMENTATION_PAIR_COUNT);
        for (uint256 i = 0; i < IMPLEMENTATION_PAIR_COUNT; i++) {
            originals[i] = address(new FactoryImplStub(i + 1));
            twins[i] = address(new FactoryImplStub(i + 1));
            require(
                originals[i].codehash == twins[i].codehash,
                "pool twin codehash mismatch"
            );
            require(originals[i] != twins[i], "pool address collision");
        }

        handler.initialize(
            factory,
            address(walletImplementation),
            originals,
            twins
        );
    }

    function test_setUp() public view override {
        assertEq(factory.owner(), address(handler));
        assertEq(factory.creationFee(), 0);
        assertEq(factory.executeFee(), 0);
        assertEq(factory.MAX_FEE(), 0.1 ether);
        assertEq(factory.getVettedCodeCount(), 1);
    }
}
