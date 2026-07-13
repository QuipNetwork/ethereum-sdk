// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

/// @dev Pins every payload-hash builder to its explicit `EfficientHashLib.hash(...)` definition and
///      the domain/action tags to their `keccak256` source strings.
contract ShrincsWalletCodec_payloadHashes is ShrincsWalletCodecTest {
    function test_erc4337PayloadHash() public view {
        // One word only — no fee: the signer's maxFee ceiling rides in `callData`, which
        // userOpHash already commits to (ERC-7562: validation must not read the live fee).
        bytes32 userOpHash = keccak256("userOp");
        assertEq(codec.exposed_erc4337PayloadHash(userOpHash), EfficientHashLib.hash(userOpHash));
    }

    function test_executePayloadHash_bindsMaxFee() public view {
        address target = address(0xABCD);
        uint256 value = 7 ether;
        bytes32 dataHash = keccak256("data");
        assertEq(
            codec.exposed_executePayloadHash(target, value, dataHash, 1),
            EfficientHashLib.hash(bytes32(uint256(uint160(target))), bytes32(value), dataHash, bytes32(uint256(1)))
        );
        // A different maxFee ceiling must change the bound payload hash (a relayer cannot raise
        // the signer's cap).
        assertTrue(
            codec.exposed_executePayloadHash(target, value, dataHash, 1)
                != codec.exposed_executePayloadHash(target, value, dataHash, 2),
            "maxFee is bound"
        );
    }

    function test_withdrawPayloadHash() public view {
        address to = address(0x1234);
        uint256 amount = 9;
        assertEq(
            codec.exposed_withdrawPayloadHash(to, amount),
            EfficientHashLib.hash(bytes32(uint256(uint160(to))), bytes32(amount))
        );
    }

    function test_upgradePayloadHash_bindsImplAndMigrate() public view {
        address impl = address(0x5678);
        bytes32 migratorHash = keccak256("migrator");
        assertEq(
            codec.exposed_upgradePayloadHash(impl, true, migratorHash),
            EfficientHashLib.hash(bytes32(uint256(uint160(impl))), bytes32(uint256(1)), migratorHash)
        );
        assertEq(
            codec.exposed_upgradePayloadHash(impl, false, migratorHash),
            EfficientHashLib.hash(bytes32(uint256(uint160(impl))), bytes32(uint256(0)), migratorHash)
        );
        assertTrue(
            codec.exposed_upgradePayloadHash(impl, true, migratorHash)
                != codec.exposed_upgradePayloadHash(impl, false, migratorHash),
            "shouldMigrate is bound"
        );
    }

    function test_transferOwnershipPayloadHash_bindsOwnerAndCommitment() public view {
        address newOwner = address(0x9ABC);
        bytes32 nextCommitment = keccak256("next");
        assertEq(
            codec.exposed_transferOwnershipPayloadHash(newOwner, nextCommitment),
            EfficientHashLib.hash(bytes32(uint256(uint160(newOwner))), nextCommitment)
        );
    }

    function test_setErc1271KeyPayloadHash() public view {
        bytes32 newCommitment = keccak256("erc1271-new");
        assertEq(
            codec.exposed_setErc1271KeyPayloadHash(newCommitment, 1),
            EfficientHashLib.hash(newCommitment, bytes32(uint256(1)))
        );
    }

    function test_rotateKeyPayloadHash() public view {
        bytes32 nextCommitment = keccak256("rotate-next");
        assertEq(codec.exposed_rotateKeyPayloadHash(nextCommitment), EfficientHashLib.hash(nextCommitment));
    }

    function test_domainAndActionTags() public pure {
        assertEq(Codec.DOMAIN_TAG, keccak256("quip-shrincs-wallet-v1"));
        assertEq(Codec.ACTION_ERC4337_EXECUTE, keccak256("quip.shrincs.action.erc4337Execute"));
        assertEq(Codec.ACTION_EXECUTE, keccak256("quip.shrincs.action.execute"));
        assertEq(Codec.ACTION_WITHDRAW, keccak256("quip.shrincs.action.withdrawDeposit"));
        assertEq(Codec.ACTION_UPGRADE, keccak256("quip.shrincs.action.upgrade"));
        assertEq(Codec.ACTION_TRANSFER_OWNERSHIP, keccak256("quip.shrincs.action.transferOwnership"));
        assertEq(Codec.ACTION_SET_ERC1271_KEY, keccak256("quip.shrincs.action.setErc1271Key"));
        assertEq(Codec.ACTION_ROTATE_KEY, keccak256("quip.shrincs.action.rotateKey"));
        assertEq(Codec.ACTION_ERC1271, keccak256("quip.shrincs.action.erc1271"));
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */
    // Each builder is pinned to its `EfficientHashLib.hash(...)` definition across the full input
    // domain. Because the recomputation includes every field, a builder that silently dropped or
    // reordered a field would diverge for some fuzzed input — so these double as field-binding tests.

    function testFuzz_erc4337PayloadHash(bytes32 userOpHash) public view {
        assertEq(codec.exposed_erc4337PayloadHash(userOpHash), EfficientHashLib.hash(userOpHash));
    }

    function testFuzz_executePayloadHash(address target, uint256 value, bytes32 dataHash, uint256 maxFee)
        public
        view
    {
        assertEq(
            codec.exposed_executePayloadHash(target, value, dataHash, maxFee),
            EfficientHashLib.hash(bytes32(uint256(uint160(target))), bytes32(value), dataHash, bytes32(maxFee))
        );
    }

    function testFuzz_withdrawPayloadHash(address to, uint256 amount) public view {
        assertEq(
            codec.exposed_withdrawPayloadHash(to, amount),
            EfficientHashLib.hash(bytes32(uint256(uint160(to))), bytes32(amount))
        );
    }

    function testFuzz_upgradePayloadHash(address impl, bool shouldMigrate, bytes32 migratorHash) public view {
        assertEq(
            codec.exposed_upgradePayloadHash(impl, shouldMigrate, migratorHash),
            EfficientHashLib.hash(
                bytes32(uint256(uint160(impl))), bytes32(uint256(shouldMigrate ? 1 : 0)), migratorHash
            )
        );
    }

    function testFuzz_transferOwnershipPayloadHash(address newOwner, bytes32 nextCommitment) public view {
        assertEq(
            codec.exposed_transferOwnershipPayloadHash(newOwner, nextCommitment),
            EfficientHashLib.hash(bytes32(uint256(uint160(newOwner))), nextCommitment)
        );
    }

    function testFuzz_setErc1271KeyPayloadHash(bytes32 newCommitment, uint32 hashSuite) public view {
        assertEq(
            codec.exposed_setErc1271KeyPayloadHash(newCommitment, hashSuite),
            EfficientHashLib.hash(newCommitment, bytes32(uint256(hashSuite)))
        );
    }

    function testFuzz_rotateKeyPayloadHash(bytes32 nextCommitment) public view {
        assertEq(codec.exposed_rotateKeyPayloadHash(nextCommitment), EfficientHashLib.hash(nextCommitment));
    }

    /// @dev Distinct maxFee ⇒ distinct execute payload hash (the ceiling field is genuinely
    ///      bound, not dropped). A complement to the equality-to-definition fuzz above.
    function testFuzz_executePayloadHash_maxFeeIsBound(
        address target,
        uint256 value,
        bytes32 dataHash,
        uint256 maxFeeA,
        uint256 maxFeeB
    ) public view {
        vm.assume(maxFeeA != maxFeeB);
        assertTrue(
            codec.exposed_executePayloadHash(target, value, dataHash, maxFeeA)
                != codec.exposed_executePayloadHash(target, value, dataHash, maxFeeB),
            "distinct maxFee yields distinct payload hash"
        );
    }
}
