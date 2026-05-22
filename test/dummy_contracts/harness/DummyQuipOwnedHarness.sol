// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {DummyQuipOwned} from "../../../contracts/dummy_contracts/DummyQuipOwned.sol";

/// @dev Exposes DummyQuipOwned for unit tests.
contract DummyQuipOwnedHarness is DummyQuipOwned {
    constructor(address initialOwner) DummyQuipOwned(initialOwner) {}

    function guarded() external onlyOwner {}
}
