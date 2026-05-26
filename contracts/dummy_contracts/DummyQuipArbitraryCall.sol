// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

/// @notice Records arbitrary calls made to it and can forward arbitrary calls to other contracts.
/// @dev Test-only sink + relay for SDK/wallet QA. Anyone can call `execute` and there is no
///      withdraw — any native value sent here either gets forwarded by `execute` or stays put.
contract DummyQuipArbitraryCall {
    struct Call {
        address caller;
        uint256 value;
        bytes data;
    }

    Call[] internal _calls;

    event DummyQuipCallReceived(address indexed caller, uint256 value, bytes data);
    event DummyQuipCallForwarded(
        address indexed caller,
        address indexed target,
        uint256 value,
        bytes data,
        bytes returnData
    );

    error DummyQuipCallReverted(address target, bytes returnData);

    receive() external payable {
        _calls.push(Call({caller: msg.sender, value: msg.value, data: ""}));
        emit DummyQuipCallReceived(msg.sender, msg.value, "");
    }

    // solhint-disable-next-line no-complex-fallback
    fallback() external payable {
        _calls.push(Call({caller: msg.sender, value: msg.value, data: msg.data}));
        emit DummyQuipCallReceived(msg.sender, msg.value, msg.data);
    }

    /// @notice Forwards `data` to `target`, attaching the full `msg.value`.
    function execute(address target, bytes calldata data)
        external
        payable
        returns (bytes memory result)
    {
        (bool ok, bytes memory ret) = target.call{value: msg.value}(data);
        if (!ok) revert DummyQuipCallReverted(target, ret);
        emit DummyQuipCallForwarded(msg.sender, target, msg.value, data, ret);
        return ret;
    }

    function callsCount() external view returns (uint256) {
        return _calls.length;
    }

    function getCall(uint256 index)
        external
        view
        returns (address caller, uint256 value, bytes memory data)
    {
        Call storage c = _calls[index];
        return (c.caller, c.value, c.data);
    }

    function lastCall()
        external
        view
        returns (address caller, uint256 value, bytes memory data)
    {
        Call storage c = _calls[_calls.length - 1];
        return (c.caller, c.value, c.data);
    }
}
