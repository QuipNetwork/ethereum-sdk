// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipOwned} from "../../contracts/dummy_contracts/DummyQuipOwned.sol";
import {
    DummyQuipERC721, IDummyQuipERC721Receiver
} from "../../contracts/dummy_contracts/DummyQuipERC721.sol";

contract GoodERC721Holder is IDummyQuipERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IDummyQuipERC721Receiver.onERC721Received.selector;
    }
}

contract BadERC721Holder {
// no onERC721Received → safeTransferFrom should revert
}

contract DummyQuipERC721Test is Test {
    DummyQuipERC721 internal nft;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        nft = new DummyQuipERC721("DummyQuip NFT", "tQNFT", address(this), true, 10);
    }

    function testNameSymbolAndInterface() public view {
        assertEq(nft.name(), "DummyQuip NFT");
        assertEq(nft.symbol(), "tQNFT");
        assertTrue(nft.supportsInterface(0x80ac58cd)); // ERC-721
        assertTrue(nft.supportsInterface(0x01ffc9a7)); // ERC-165
        assertFalse(nft.supportsInterface(0xdeadbeef));
    }

    function testPublicFaucetMintsSequential() public {
        nft.faucet(alice, 3);
        assertEq(nft.balanceOf(alice), 3);
        assertEq(nft.totalSupply(), 3);
        assertEq(nft.ownerOf(0), alice);
        assertEq(nft.ownerOf(2), alice);
        assertEq(nft.nextTokenId(), 3);
    }

    function testFaucetCapExceededReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipERC721.DummyQuipFaucetCapExceeded.selector, 11, 10)
        );
        nft.faucet(alice, 11);
    }

    function testUngatedMintAnyAmount() public {
        vm.prank(alice);
        nft.mint(bob, 25);
        assertEq(nft.balanceOf(bob), 25);
        assertEq(nft.totalSupply(), 25);
    }

    function testZeroAmountReverts() public {
        vm.expectRevert(DummyQuipERC721.DummyQuipZeroAmount.selector);
        nft.mint(alice, 0);
    }

    function testTransferFromAndApprovalFlow() public {
        nft.mint(alice, 1);
        uint256 tokenId = 0;

        vm.prank(alice);
        nft.approve(bob, tokenId);
        assertEq(nft.getApproved(tokenId), bob);

        vm.prank(bob);
        nft.transferFrom(alice, bob, tokenId);

        assertEq(nft.ownerOf(tokenId), bob);
        assertEq(nft.balanceOf(alice), 0);
        assertEq(nft.balanceOf(bob), 1);
        // approval should clear on transfer
        assertEq(nft.getApproved(tokenId), address(0));
    }

    function testSafeTransferToCompliantReceiver() public {
        GoodERC721Holder holder = new GoodERC721Holder();
        nft.mint(alice, 1);

        vm.prank(alice);
        nft.safeTransferFrom(alice, address(holder), 0);
        assertEq(nft.ownerOf(0), address(holder));
    }

    function testSafeTransferToNonCompliantReverts() public {
        BadERC721Holder holder = new BadERC721Holder();
        nft.mint(alice, 1);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipERC721.DummyQuipUnsafeRecipient.selector, address(holder))
        );
        nft.safeTransferFrom(alice, address(holder), 0);
    }

    function testTransferWithoutApprovalReverts() public {
        nft.mint(alice, 1);
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipERC721.DummyQuipNotOwnerOrApproved.selector, bob, 0)
        );
        nft.transferFrom(alice, bob, 0);
    }

    function testBurnByOwnerAndApproved() public {
        nft.mint(alice, 2);

        vm.prank(alice);
        nft.burn(0);
        assertEq(nft.balanceOf(alice), 1);
        assertEq(nft.totalSupply(), 1);

        vm.prank(alice);
        nft.setApprovalForAll(bob, true);
        vm.prank(bob);
        nft.burn(1);
        assertEq(nft.balanceOf(alice), 0);
    }

    function testBurnNonexistentReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipERC721.DummyQuipNonexistentToken.selector, 42)
        );
        nft.burn(42);
    }

    function testOwnerOnlyFaucetConfig() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(DummyQuipOwned.DummyQuipNotOwner.selector, alice));
        nft.setFaucetConfig(false, 0);

        nft.setFaucetConfig(false, 0);
        vm.expectRevert(DummyQuipERC721.DummyQuipFaucetDisabled.selector);
        nft.faucet(alice, 1);

        nft.ownerMint(alice, 1);
        assertEq(nft.balanceOf(alice), 1);
    }
}
