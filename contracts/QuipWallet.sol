// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol";
import "./QuipFactory.sol";

// Uncomment this line to use console.log

contract QuipWallet {
    address payable public quipFactory;
    address payable public owner;
    WOTSPlus.WinternitzAddress public pqOwner;

    receive() external payable {}
    
    fallback() external payable {}

    event pqTransfer(
        uint256 amount,
        uint256 when,
        WOTSPlus.WinternitzAddress pqFrom,
        WOTSPlus.WinternitzAddress pqNext,
        address to
    );

    constructor(address payable creator, address payable newOwner) payable {
        quipFactory = creator;
        owner = payable(newOwner);
    }

    function initialize(WOTSPlus.WinternitzAddress calldata newPqOwner) public {
        require(msg.sender == owner || msg.sender == quipFactory, "You aren't the owner or creator");
        require(pqOwner.publicSeed == bytes32(0) && pqOwner.publicKeyHash == bytes32(0), "Already initialized");
        pqOwner = newPqOwner;
    }

    function changePqOwner(WOTSPlus.WinternitzAddress calldata newPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig) public {
        require(msg.sender == owner, "You aren't the owner");

        bytes memory msgData = abi.encodePacked(
                pqOwner.publicSeed, pqOwner.publicKeyHash,
                newPqOwner.publicSeed, newPqOwner.publicKeyHash);

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: keccak256(msgData)
        });

        require(WOTSPlus.verify(pqOwner, message, pqSig), "Invalid signature");
        pqOwner = newPqOwner;
    }

    function transferWithWinternitz(WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable to,
        uint256 value) public payable {

        WOTSPlus.WinternitzAddress memory curPqOwner = pqOwner;

        require(msg.value >= getTransferFee(), "Insufficient fee");
        require(msg.sender == owner, "You aren't the owner");
        require(address(this).balance >= value, "Insufficient balance");

        bytes memory msgData = abi.encodePacked(
                pqOwner.publicSeed, pqOwner.publicKeyHash,
                nextPqOwner.publicSeed, nextPqOwner.publicKeyHash,
                to, value);
   
        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: keccak256(msgData)
        });

        require(WOTSPlus.verify(pqOwner, message, pqSig), "Invalid signature");
        pqOwner = nextPqOwner;

        to.transfer(value);
        quipFactory.transfer(msg.value);

        emit pqTransfer(value, block.timestamp, curPqOwner, nextPqOwner, to);
    }

    function executeWithWinternitz(WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable target,
        bytes calldata opdata) payable public returns (bool, bytes memory) {


        require(msg.value >= getExecuteFee(), "Insufficient fee");
        require(msg.sender == owner, "You aren't the owner");

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: keccak256(abi.encodePacked(
                pqOwner.publicSeed, pqOwner.publicKeyHash,
                target, opdata))
        });

        require(WOTSPlus.verify(pqOwner, message, pqSig), "Invalid signature");
        pqOwner = nextPqOwner;
        quipFactory.transfer(msg.value);

        return target.call{value: msg.value}(opdata);
    }

    function getTransferFee() public view returns (uint256) {
        return QuipFactory(quipFactory).transferFee();
    }

    function getExecuteFee() public view returns (uint256) {
        return QuipFactory(quipFactory).executeFee();
    }
}
