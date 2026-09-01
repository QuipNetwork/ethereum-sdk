// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Unit tests for `_shrincsDomainSeparator` (via `exposed_shrincsDomainSeparator`). Every
///      signing helper in this suite BUILDS its contexts from the exposed value, so those tests
///      are circular with respect to the formula — a drifted separator would move signer and
///      verifier together. This file is the independent pin: the separator must equal
///      `keccak256(DOMAIN_TAG ‖ chainid ‖ wallet address)` recomputed from first principles,
///      and must move with both the chain id and the wallet address.
contract ShrincsWallet__shrincsDomainSeparator is ShrincsWalletTest {
    /// @dev The canonical formula, recomputed independently of the wallet.
    function _canonical(uint256 chainId, address wallet_) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(Codec.DOMAIN_TAG, chainId, uint256(uint160(wallet_)))
        );
    }

    function test_exposed_shrincsDomainSeparator_matchesCanonicalFormula() public view {
        assertEq(
            wallet.exposed_shrincsDomainSeparator(),
            _canonical(block.chainid, WALLET),
            "separator == keccak256(DOMAIN_TAG || chainid || wallet)"
        );
    }

    function test_exposed_shrincsDomainSeparator_bindsWalletAddress() public {
        ShrincsWalletHarness other =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        assertEq(
            other.exposed_shrincsDomainSeparator(),
            _canonical(block.chainid, address(other)),
            "each address gets its own domain"
        );
        assertTrue(
            other.exposed_shrincsDomainSeparator() != wallet.exposed_shrincsDomainSeparator(),
            "no cross-wallet signature reuse"
        );
    }

    function test_exposed_shrincsDomainSeparator_bindsChainId() public {
        bytes32 before = wallet.exposed_shrincsDomainSeparator();
        vm.chainId(CHAIN_ID + 1);
        assertEq(
            wallet.exposed_shrincsDomainSeparator(),
            _canonical(CHAIN_ID + 1, WALLET),
            "separator follows the live chain id"
        );
        assertTrue(
            wallet.exposed_shrincsDomainSeparator() != before,
            "no cross-chain signature reuse"
        );
    }
}
