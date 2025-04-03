// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

contract DummyContract {
    uint256 public value;
    
    function setValue(uint256 _value) external payable {
        require(msg.value >= 0.01 ether, "Need at least 0.01 ETH");
        value = _value;
    }
    
    function setValueNoFee(uint256 _value) external {
        value = _value;
    }
    
    function failingFunction() external pure {
        require(false, "Function always fails");
    }
}
