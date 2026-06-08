// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipERC721} from "../../contracts/dummy_contracts/DummyQuipERC721.sol";
import {IERC721Errors} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC6093.sol";
import {IERC721Receiver} from
    "@openzeppelin-contracts-5.6.0-rc.1/token/ERC721/IERC721Receiver.sol";
import {IERC721} from "@openzeppelin-contracts-5.6.0-rc.1/token/ERC721/IERC721.sol";
import {IERC165} from
    "@openzeppelin-contracts-5.6.0-rc.1/utils/introspection/IERC165.sol";

contract GoodReceiver721 is IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC721Receiver.onERC721Received.selector;
    }
}

contract BadReceiver721 {
// no onERC721Received => safeTransferFrom should revert with ERC721InvalidReceiver
}

contract DummyQuipERC721Test is Test {
    DummyQuipERC721 internal nft;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);

    function setUp() public {
        nft = new DummyQuipERC721("DummyQuip NFT", "tQNFT");
    }

    function testMetadata() public view {
        assertEq(nft.name(), "DummyQuip NFT");
        assertEq(nft.symbol(), "tQNFT");
        assertEq(nft.nextTokenId(), 0);
        assertEq(nft.totalSupply(), 0);
    }

    function testSupportsERC721AndERC165() public view {
        assertTrue(nft.supportsInterface(type(IERC721).interfaceId));
        assertTrue(nft.supportsInterface(type(IERC165).interfaceId));
    }

    function testMintReturnsAssignedIdAndIncrementsCounter() public {
        vm.prank(alice);
        uint256 firstId = nft.mint(alice);
        assertEq(firstId, 0);
        assertEq(nft.nextTokenId(), 1);
        assertEq(nft.ownerOf(0), alice);

        vm.prank(alice);
        uint256 secondId = nft.mint(alice);
        assertEq(secondId, 1);
        assertEq(nft.nextTokenId(), 2);
        assertEq(nft.ownerOf(1), alice);

        assertEq(nft.totalSupply(), 2);
        assertEq(nft.balanceOf(alice), 2);
    }

    function testMintIsUngated() public {
        // Anyone (alice) can mint to anyone else (bob); no Ownable / faucet.
        vm.prank(alice);
        nft.mint(bob);
        vm.prank(alice);
        nft.mint(bob);

        assertEq(nft.balanceOf(bob), 2);
        assertEq(nft.totalSupply(), 2);
        assertEq(nft.ownerOf(0), bob);
        assertEq(nft.ownerOf(1), bob);
    }

    function testTransferAndApprove() public {
        vm.prank(alice);
        nft.mint(alice);
        vm.prank(alice);
        nft.mint(alice);

        vm.prank(alice);
        nft.approve(bob, 0);
        assertEq(nft.getApproved(0), bob);

        vm.prank(bob);
        nft.transferFrom(alice, bob, 0);
        assertEq(nft.ownerOf(0), bob);
        assertEq(nft.balanceOf(alice), 1);
        assertEq(nft.balanceOf(bob), 1);
    }

    function testTransferFromInsufficientApprovalUsesOZError() public {
        vm.prank(alice);
        nft.mint(alice);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(IERC721Errors.ERC721InsufficientApproval.selector, bob, 0)
        );
        nft.transferFrom(alice, bob, 0);
    }

    function testSafeTransferToReceiver() public {
        GoodReceiver721 receiver = new GoodReceiver721();
        vm.prank(alice);
        nft.mint(alice);

        vm.prank(alice);
        nft.safeTransferFrom(alice, address(receiver), 0);

        assertEq(nft.ownerOf(0), address(receiver));
    }

    function testSafeTransferToNonReceiverReverts() public {
        BadReceiver721 receiver = new BadReceiver721();
        vm.prank(alice);
        nft.mint(alice);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC721Errors.ERC721InvalidReceiver.selector, address(receiver)
            )
        );
        nft.safeTransferFrom(alice, address(receiver), 0);
    }

    function testBurnDecrementsTotalSupply() public {
        vm.prank(alice);
        nft.mint(alice);
        vm.prank(alice);
        nft.mint(alice);

        assertEq(nft.totalSupply(), 2);

        vm.prank(alice);
        nft.burn(0);

        assertEq(nft.totalSupply(), 1);
        vm.expectRevert(
            abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, 0)
        );
        nft.ownerOf(0);
    }
}
