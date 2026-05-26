// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipOwned} from "../../contracts/dummy_contracts/DummyQuipOwned.sol";
import {
    DummyQuipERC1155, IDummyQuipERC1155Receiver
} from "../../contracts/dummy_contracts/DummyQuipERC1155.sol";

contract GoodERC1155Holder is IDummyQuipERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IDummyQuipERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure returns (bytes4) {
        return IDummyQuipERC1155Receiver.onERC1155BatchReceived.selector;
    }
}

contract BadERC1155Holder {
// no callbacks → safe variants should revert
}

contract DummyQuipERC1155Test is Test {
    DummyQuipERC1155 internal token;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        token = new DummyQuipERC1155("ipfs://x/{id}.json", address(this), true, 100);
    }

    function testUriAndInterface() public view {
        assertEq(token.uri(), "ipfs://x/{id}.json");
        assertTrue(token.supportsInterface(0xd9b67a26)); // ERC-1155
        assertTrue(token.supportsInterface(0x0e89341c)); // ERC-1155 MetadataURI
        assertTrue(token.supportsInterface(0x01ffc9a7)); // ERC-165
        assertFalse(token.supportsInterface(0xdeadbeef));
    }

    function testFaucetCapsPerId() public {
        token.faucet(alice, 1, 50);
        token.faucet(alice, 2, 100);
        assertEq(token.balanceOf(1, alice), 50);
        assertEq(token.balanceOf(2, alice), 100);

        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipERC1155.DummyQuipFaucetCapExceeded.selector, 101, 100)
        );
        token.faucet(alice, 3, 101);
    }

    function testUngatedMintAnyAmount() public {
        vm.prank(alice);
        token.mint(bob, 7, 10_000);
        assertEq(token.balanceOf(7, bob), 10_000);
    }

    function testSafeTransferToCompliantReceiver() public {
        token.mint(alice, 1, 10);
        GoodERC1155Holder holder = new GoodERC1155Holder();

        vm.prank(alice);
        token.safeTransferFrom(alice, address(holder), 1, 4, "");

        assertEq(token.balanceOf(1, alice), 6);
        assertEq(token.balanceOf(1, address(holder)), 4);
    }

    function testSafeTransferToNonCompliantReverts() public {
        token.mint(alice, 1, 10);
        BadERC1155Holder bad = new BadERC1155Holder();

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipERC1155.DummyQuipUnsafeRecipient.selector, address(bad))
        );
        token.safeTransferFrom(alice, address(bad), 1, 1, "");
    }

    function testSafeBatchTransfer() public {
        token.mint(alice, 1, 10);
        token.mint(alice, 2, 20);
        GoodERC1155Holder holder = new GoodERC1155Holder();

        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 3;
        amounts[1] = 5;

        vm.prank(alice);
        token.safeBatchTransferFrom(alice, address(holder), ids, amounts, "");

        assertEq(token.balanceOf(1, address(holder)), 3);
        assertEq(token.balanceOf(2, address(holder)), 5);
        assertEq(token.balanceOf(1, alice), 7);
        assertEq(token.balanceOf(2, alice), 15);
    }

    function testBatchLengthMismatchReverts() public {
        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1;

        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipERC1155.DummyQuipLengthMismatch.selector, 2, 1)
        );
        token.safeBatchTransferFrom(alice, bob, ids, amounts, "");
    }

    function testApprovalAndOperatorTransfer() public {
        token.mint(alice, 1, 10);

        vm.prank(alice);
        token.setApprovalForAll(bob, true);
        assertTrue(token.isApprovedForAll(alice, bob));

        vm.prank(bob);
        token.safeTransferFrom(alice, bob, 1, 4, "");
        assertEq(token.balanceOf(1, bob), 4);
    }

    function testTransferWithoutApprovalReverts() public {
        token.mint(alice, 1, 5);
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipERC1155.DummyQuipNotOwnerOrApproved.selector, bob, alice)
        );
        token.safeTransferFrom(alice, bob, 1, 1, "");
    }

    function testBalanceOfBatch() public {
        token.mint(alice, 1, 10);
        token.mint(bob, 2, 20);

        address[] memory accounts = new address[](2);
        accounts[0] = alice;
        accounts[1] = bob;
        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;

        uint256[] memory bals = token.balanceOfBatch(accounts, ids);
        assertEq(bals[0], 10);
        assertEq(bals[1], 20);
    }

    function testBurnAndInsufficientBalance() public {
        token.mint(alice, 1, 5);

        vm.prank(alice);
        token.burn(alice, 1, 2);
        assertEq(token.balanceOf(1, alice), 3);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                DummyQuipERC1155.DummyQuipInsufficientBalance.selector, alice, uint256(1), uint256(3), uint256(10)
            )
        );
        token.burn(alice, 1, 10);
    }

    function testOwnerOnlySettersAndPrivateMint() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(DummyQuipOwned.DummyQuipNotOwner.selector, alice));
        token.setURI("new");

        token.setURI("new");
        assertEq(token.uri(), "new");

        token.setFaucetConfig(false, 0);
        vm.expectRevert(DummyQuipERC1155.DummyQuipFaucetDisabled.selector);
        token.faucet(alice, 1, 1);

        token.ownerMint(alice, 1, 99);
        assertEq(token.balanceOf(1, alice), 99);
    }
}
