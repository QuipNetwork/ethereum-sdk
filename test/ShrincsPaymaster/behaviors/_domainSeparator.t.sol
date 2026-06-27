// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {ShrincsPaymasterHarness} from "../../harness/ShrincsPaymasterHarness.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the PURE-ish `_domainSeparator` (binds the domain tag + chainId + the
///      paymaster address). Fully testable now.
contract ShrincsPaymaster__domainSeparator is ShrincsPaymasterTest {
    bytes32 internal constant DOMAIN_TAG =
        keccak256("quip-shrincs-paymaster-v1");

    function test_domainSeparator_matchesDefinition() public view {
        bytes32 expected = EfficientHashLib.hash(
            DOMAIN_TAG,
            bytes32(uint256(CHAIN_ID)),
            bytes32(uint256(uint160(PAYMASTER)))
        );
        assertEq(paymaster.exposed_domainSeparator(), expected);
    }

    function test_domainSeparator_bindsChainId() public {
        bytes32 before = paymaster.exposed_domainSeparator();
        vm.chainId(CHAIN_ID + 1);
        assertTrue(
            paymaster.exposed_domainSeparator() != before,
            "chainId is bound"
        );
    }

    /// @dev The separator binds `address(this)` — the anti-cross-paymaster-replay component. A second
    ///      paymaster at a different address (same chain) must produce a different separator, and it
    ///      must match the canonical definition for THAT address.
    function test_domainSeparator_bindsPaymasterAddress() public {
        ShrincsPaymasterHarness other = new ShrincsPaymasterHarness();
        assertTrue(
            address(other) != PAYMASTER,
            "distinct address precondition"
        );

        bytes32 otherSep = other.exposed_domainSeparator();
        assertTrue(
            otherSep != paymaster.exposed_domainSeparator(),
            "address(this) is bound"
        );
        assertEq(
            otherSep,
            EfficientHashLib.hash(
                DOMAIN_TAG,
                bytes32(uint256(CHAIN_ID)),
                bytes32(uint256(uint160(address(other))))
            ),
            "matches definition for the other address"
        );
    }
}
