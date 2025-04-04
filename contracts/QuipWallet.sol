// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
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

        uint256 fee = getTransferFee();

        require(msg.value >= fee, "Insufficient fee");
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
        quipFactory.transfer(fee);

        emit pqTransfer(value, block.timestamp, curPqOwner, nextPqOwner, to);
    }

    function executeWithWinternitz(WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable target,
        bytes calldata opdata) payable public returns (bool, bytes memory) {

        uint256 fee = getExecuteFee();
        require(msg.value >= fee, "Insufficient fee");

        uint256 forwardValue = msg.value - fee;

        require(msg.sender == owner, "You aren't the owner");

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: keccak256(abi.encodePacked(
                pqOwner.publicSeed, pqOwner.publicKeyHash,
                nextPqOwner.publicSeed, nextPqOwner.publicKeyHash,
                target, opdata))
        });

        require(WOTSPlus.verify(pqOwner, message, pqSig), "Invalid signature");
        pqOwner = nextPqOwner;
        quipFactory.transfer(fee);

        (bool success, bytes memory returnData) = target.call{value: forwardValue}(opdata);
        require(success, string(returnData));
        return (success, returnData);
    }

    function getTransferFee() public view returns (uint256) {
        return QuipFactory(quipFactory).transferFee();
    }

    function getExecuteFee() public view returns (uint256) {
        return QuipFactory(quipFactory).executeFee();
    }
}
