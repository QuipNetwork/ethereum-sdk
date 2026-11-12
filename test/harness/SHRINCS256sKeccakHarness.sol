// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS256sKeccak} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS256sKeccak.sol";

/// @title SHRINCS256sKeccakHarness
/// @dev Exposes the address the verifier pins at compile time for its SPHINCSPlusC sibling, so
///      test fixtures read it from the dependency instead of restating the literal.
contract SHRINCS256sKeccakHarness is SHRINCS256sKeccak {
    function exposed_pinnedSphincsPlusC() external pure returns (address) {
        return _pinnedSphincsPlusC();
    }
}
