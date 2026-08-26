// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {PreQSalt1Wallets} from "../../../contracts/PreQSalt1Wallets.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Identity-binding checks in `initialize`: QSalt1 recompute-and-match, and the
///      legacy whitelist cross-check for non-QSalt1 vault ids.
contract ShrincsWallet_initialize_qsalt1 is ShrincsWalletTest {
    /// @dev Runtime code of a harness whose immutable FACTORY is the mock factory.
    bytes internal _implCode;
    uint256 internal _bareNonce;
    PreQSalt1Wallets internal registry;

    function setUp() public override {
        super.setUp();
        ShrincsWalletHarness impl = new ShrincsWalletHarness(
            payable(address(factory)),
            address(shrincsVerifier)
        );
        _implCode = address(impl).code;
        registry = new PreQSalt1Wallets(address(this));
        factory.setPreQSalt1Wallets(address(registry));
    }

    function _freshBare()
        internal
        returns (ShrincsWalletHarness w, address addr)
    {
        addr = address(
            uint160(uint256(keccak256(abi.encode("bare-qsalt1", ++_bareNonce))))
        );
        vm.etch(addr, _implCode);
        w = ShrincsWalletHarness(payable(addr));
    }

    function test_initialize_qsalt1MatchingIdentitySucceeds() public {
        (ShrincsWalletHarness bare, address bareAddr) = _freshBare();
        factory.setVaultId(
            bareAddr,
            Codec.qsalt1VaultId(mainCommitment, erc1271Commitment, OWNER)
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

    function test_initialize_revertsWhen_qsalt1OwnerMismatch() public {
        (ShrincsWalletHarness bare, address bareAddr) = _freshBare();
        factory.setVaultId(
            bareAddr,
            Codec.qsalt1VaultId(mainCommitment, erc1271Commitment, OWNER)
        );
        address other = makeAddr("otherOwner");

        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.IdentityMismatch.selector);
        bare.initialize(payable(other), _validInitPayload());
    }

    function test_initialize_revertsWhen_qsalt1StatelessMismatch() public {
        (ShrincsWalletHarness bare, address bareAddr) = _freshBare();
        factory.setVaultId(
            bareAddr,
            Codec.qsalt1VaultId(mainCommitment, bytes32(uint256(0xdead)), OWNER)
        );

        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.IdentityMismatch.selector);
        bare.initialize(payable(OWNER), _validInitPayload());
    }

    function test_initialize_legacyMatchingIdentitySucceeds() public {
        (ShrincsWalletHarness bare, address bareAddr) = _freshBare();
        bytes32 legacyId = bytes32(uint256(1));
        registry.add(legacyId, OWNER, mainCommitment, erc1271Commitment);
        factory.setVaultId(bareAddr, legacyId);

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

    function test_initialize_revertsWhen_legacyIdentityMismatch() public {
        (ShrincsWalletHarness bare, address bareAddr) = _freshBare();
        factory.setVaultId(bareAddr, bytes32(uint256(2)));

        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.LegacyIdentityMismatch.selector);
        bare.initialize(payable(OWNER), _validInitPayload());
    }
}
