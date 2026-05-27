// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipERC1155} from "../../contracts/dummy_contracts/DummyQuipERC1155.sol";
import {IERC1155Errors} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC6093.sol";
import {IERC1155Receiver} from
    "@openzeppelin-contracts-5.6.0-rc.1/token/ERC1155/IERC1155Receiver.sol";
import {IERC1155} from "@openzeppelin-contracts-5.6.0-rc.1/token/ERC1155/IERC1155.sol";
import {IERC165} from
    "@openzeppelin-contracts-5.6.0-rc.1/utils/introspection/IERC165.sol";

contract GoodReceiver1155 is IERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }
}

contract DummyQuipERC1155Test is Test {
    DummyQuipERC1155 internal token;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);

    string internal constant URI = "ipfs://dummy/{id}.json";

    function setUp() public {
        token = new DummyQuipERC1155(URI);
    }

    function testMetadata() public view {
        assertEq(token.uri(0), URI);
        assertEq(token.totalSupply(), 0);
    }

    function testSupportsERC1155AndERC165() public view {
        assertTrue(token.supportsInterface(type(IERC1155).interfaceId));
        assertTrue(token.supportsInterface(type(IERC165).interfaceId));
    }

    function testMintArbitraryAmounts() public {
        vm.prank(alice);
        token.mint(bob, 42, 250);
        assertEq(token.balanceOf(bob, 42), 250);
        assertEq(token.totalSupply(42), 250);
        assertEq(token.totalSupply(), 250);
    }

    function testMintIsUngated() public {
        vm.prank(alice);
        token.mint(alice, 1, 5);
        vm.prank(bob);
        token.mint(bob, 1, 7);
        assertEq(token.balanceOf(alice, 1), 5);
        assertEq(token.balanceOf(bob, 1), 7);
        assertEq(token.totalSupply(1), 12);
    }

    function testSafeTransferAndApprove() public {
        vm.prank(alice);
        token.mint(alice, 1, 50);

        vm.prank(alice);
        token.setApprovalForAll(bob, true);
        assertTrue(token.isApprovedForAll(alice, bob));

        vm.prank(bob);
        token.safeTransferFrom(alice, bob, 1, 30, "");

        assertEq(token.balanceOf(alice, 1), 20);
        assertEq(token.balanceOf(bob, 1), 30);
    }

    function testTransferToContractRequiresReceiver() public {
        vm.prank(alice);
        token.mint(alice, 1, 5);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC1155Errors.ERC1155InvalidReceiver.selector, address(this)
            )
        );
        token.safeTransferFrom(alice, address(this), 1, 1, "");
    }

    function testSafeTransferToCompliantReceiver() public {
        GoodReceiver1155 receiver = new GoodReceiver1155();
        vm.prank(alice);
        token.mint(alice, 1, 5);

        vm.prank(alice);
        token.safeTransferFrom(alice, address(receiver), 1, 5, "");

        assertEq(token.balanceOf(address(receiver), 1), 5);
    }

    function testBatchTransfer() public {
        vm.prank(alice);
        token.mint(alice, 1, 10);
        vm.prank(alice);
        token.mint(alice, 2, 20);

        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;
        uint256[] memory values = new uint256[](2);
        values[0] = 4;
        values[1] = 8;

        GoodReceiver1155 receiver = new GoodReceiver1155();

        vm.prank(alice);
        token.safeBatchTransferFrom(alice, address(receiver), ids, values, "");

        assertEq(token.balanceOf(address(receiver), 1), 4);
        assertEq(token.balanceOf(address(receiver), 2), 8);
    }

    function testInsufficientBalanceUsesOZError() public {
        vm.prank(alice);
        token.mint(alice, 1, 3);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC1155Errors.ERC1155InsufficientBalance.selector, alice, 3, 10, 1
            )
        );
        token.safeTransferFrom(alice, bob, 1, 10, "");
    }

    function testMissingApprovalForAllUsesOZError() public {
        vm.prank(alice);
        token.mint(alice, 1, 5);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC1155Errors.ERC1155MissingApprovalForAll.selector, bob, alice
            )
        );
        token.safeTransferFrom(alice, bob, 1, 1, "");
    }

    function testBurn() public {
        vm.prank(alice);
        token.mint(alice, 1, 10);

        vm.prank(alice);
        token.burn(alice, 1, 4);

        assertEq(token.balanceOf(alice, 1), 6);
        assertEq(token.totalSupply(1), 6);
    }
}
