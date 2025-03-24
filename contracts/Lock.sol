// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol";

// Uncomment this line to use console.log
// import "hardhat/console.sol";

contract Lock {
    uint public unlockTime;
    address payable public owner;

    // eth address -> WinternitzAddress.publicKey -> balance
    mapping(address => mapping(bytes32 => uint256)) public balances;


    event Withdrawal(uint amount, uint when);

    constructor(uint _unlockTime) payable {
        require(
            block.timestamp < _unlockTime,
            "Unlock time should be in the future"
        );

        unlockTime = _unlockTime;
        owner = payable(msg.sender);
    }

    function depositToWinternitz(WOTSPlus.WinternitzAddress calldata quipAddress) public payable {
        balances[msg.sender][quipAddress.publicKeyHash] += msg.value;
    }

    function withdrawWithWinternitz(WOTSPlus.WinternitzAddress calldata quipAddress,
        WOTSPlus.WinternitzMessage calldata message,
        WOTSPlus.WinternitzElements calldata signature) public {

        require(WOTSPlus.verify(quipAddress, message, signature), "Invalid signature");
        uint256 balanceToSend = balances[msg.sender][quipAddress.publicKeyHash];
        balances[msg.sender][quipAddress.publicKeyHash] = 0;

        emit Withdrawal(balanceToSend, block.timestamp);

        owner.transfer(balanceToSend);
    }

    function withdraw() public {
        // Uncomment this line, and the import of "hardhat/console.sol", to print a log in your terminal
        // console.log("Unlock time is %o and block timestamp is %o", unlockTime, block.timestamp);

        require(block.timestamp >= unlockTime, "You can't withdraw yet");
        require(msg.sender == owner, "You aren't the owner");

        emit Withdrawal(address(this).balance, block.timestamp);

        owner.transfer(address(this).balance);
    }
}
