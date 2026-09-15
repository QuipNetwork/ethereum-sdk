// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Identity-binding checks in `initialize`: V1 recompute-and-match, driven end to end
///      through the real factory — the CREATE3 salt IS the identity commitment, published in
///      `commitmentOf` before `initialize` recomputes and matches it.
contract ShrincsWallet_initialize_v1 is ShrincsWalletTest {
    /// @dev Deploys through the real factory with an explicit identity commitment.
    function _deployVia(bytes32 commitment, address owner, bytes memory payload)
        internal
        returns (address)
    {
        vm.prank(owner);
        return factory.deployLatestWalletProxy(commitment, payable(owner), payload);
    }

    function test_initialize_v1MatchingIdentitySucceeds() public {
        (bytes memory payload, bytes32 mainC) = _freshInitPayload("v1-match");
        bytes32 e1271C = _commitment32(_freshErc1271Pk("v1-match"));

        address addr = _deployVia(Codec.v1Commitment(mainC, e1271C, OWNER), OWNER, payload);
        ShrincsWalletHarness w = ShrincsWalletHarness(payable(addr));

        assertEq(w.owner(), OWNER, "owner installed");
        assertEq(w.getShrincsPublicKeyCommitment(), mainC, "main commitment");
        assertEq(w.getErc1271PublicKeyCommitment(), e1271C, "erc1271 commitment");
    }

    function test_initialize_revertsWhen_v1OwnerMismatch() public {
        (bytes memory payload, bytes32 mainC) = _freshInitPayload("v1-owner-mismatch");
        bytes32 e1271C = _commitment32(_freshErc1271Pk("v1-owner-mismatch"));
        address other = makeAddr("otherOwner");
        vm.deal(other, 1 ether);

        // The commitment binds OWNER, but the deploy hands ownership to `other`.
        vm.prank(other);
        vm.expectRevert(IShrincsWallet.IdentityMismatch.selector);
        factory.deployLatestWalletProxy(
            Codec.v1Commitment(mainC, e1271C, OWNER), payable(other), payload
        );
    }

    function test_initialize_revertsWhen_v1StatelessMismatch() public {
        (bytes memory payload, bytes32 mainC) = _freshInitPayload("v1-stateless-mismatch");

        // The commitment binds a bogus ERC-1271 commitment, not the payload's real one.
        vm.expectRevert(IShrincsWallet.IdentityMismatch.selector);
        _deployVia(
            Codec.v1Commitment(mainC, bytes32(uint256(0xdead)), OWNER), OWNER, payload
        );
    }
}
