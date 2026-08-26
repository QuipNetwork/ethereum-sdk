// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Identity-binding checks in `initialize`: V1 recompute-and-match, and
///      revert on a non-V1 salt.
contract ShrincsWallet_initialize_v1 is ShrincsWalletTest {
    /// @dev Runtime code of a harness whose immutable FACTORY is the mock factory.
    bytes internal _implCode;
    uint256 internal _bareNonce;

    function setUp() public override {
        super.setUp();
        ShrincsWalletHarness impl = new ShrincsWalletHarness(
            payable(address(factory)),
            address(shrincsVerifier)
        );
        _implCode = address(impl).code;
    }

    function _freshBare()
        internal
        returns (ShrincsWalletHarness w, address addr)
    {
        addr = address(
            uint160(uint256(keccak256(abi.encode("bare-v1", ++_bareNonce))))
        );
        vm.etch(addr, _implCode);
        w = ShrincsWalletHarness(payable(addr));
    }

    function test_initialize_v1MatchingIdentitySucceeds() public {
        (ShrincsWalletHarness bare, address bareAddr) = _freshBare();
        factory.setCommitment(
            bareAddr,
            Codec.v1Commitment(mainCommitment, erc1271Commitment, OWNER)
        );

        vm.prank(address(factory));
        bare.initialize(payable(OWNER), _validInitPayload());

        assertEq(bare.owner(), OWNER, "owner installed");
        assertEq(
            bare.getShrincsPublicKeyCommitment(),
            mainCommitment,
            "main commitment"
        );
        assertEq(
            bare.getErc1271Commitment(),
            erc1271Commitment,
            "erc1271 commitment"
        );
    }

    function test_initialize_revertsWhen_v1OwnerMismatch() public {
        (ShrincsWalletHarness bare, address bareAddr) = _freshBare();
        factory.setCommitment(
            bareAddr,
            Codec.v1Commitment(mainCommitment, erc1271Commitment, OWNER)
        );
        address other = makeAddr("otherOwner");

        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.IdentityMismatch.selector);
        bare.initialize(payable(other), _validInitPayload());
    }

    function test_initialize_revertsWhen_v1StatelessMismatch() public {
        (ShrincsWalletHarness bare, address bareAddr) = _freshBare();
        factory.setCommitment(
            bareAddr,
            Codec.v1Commitment(mainCommitment, bytes32(uint256(0xdead)), OWNER)
        );

        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.IdentityMismatch.selector);
        bare.initialize(payable(OWNER), _validInitPayload());
    }

    function test_initialize_revertsWhen_nonV1Salt() public {
        (ShrincsWalletHarness bare, address bareAddr) = _freshBare();
        factory.setCommitment(bareAddr, bytes32(uint256(1)));

        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.NotV1Commitment.selector);
        bare.initialize(payable(OWNER), _validInitPayload());
    }
}
