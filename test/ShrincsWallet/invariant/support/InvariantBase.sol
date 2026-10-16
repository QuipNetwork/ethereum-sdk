// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../../ShrincsWallet.t.sol";
import {ShrincsWalletInvariantHandler} from "./Handler.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";

abstract contract ShrincsWalletInvariantBase is ShrincsWalletTest {
    ShrincsWalletInvariantHandler public handler;

    /// @dev `_signStatefulAction` maps an auth slot `s` to leaf `SIGN_BASE + s`; targets are leaves.
    uint32 internal constant SEED_AUTH_SLOT = 1;
    uint32 internal constant SEED_TARGET_LEAF = SIGN_BASE + 2;
    uint32 internal constant POOL_AUTH_SLOT_A = 3;
    uint32 internal constant POOL_AUTH_SLOT_B = 4;
    uint32 internal constant POOL_AUTH_SLOT_C = 5;
    uint32 internal constant POOL_TARGET_LEAF_A = SIGN_BASE + 6;
    uint32 internal constant POOL_TARGET_LEAF_B = SIGN_BASE + 7;
    /// @dev The seed revocation consumes its auth leaf plus one target.
    uint32 internal constant SEED_LEAVES_CONSUMED = 2;
    uint256 internal constant POOL_SIZE = 3;

    uint256 internal initialNonce;
    uint256 internal initialKeyVersion;
    uint32 internal initialUsed;
    bytes32 internal initialMainCommitment;
    bytes32 internal initialErc1271Commitment;

    function _targetsHash(
        uint32[] memory targets
    ) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i = 0; i < targets.length; i++) {
            packed = abi.encodePacked(packed, bytes32(uint256(targets[i])));
        }
        return keccak256(packed);
    }

    function _signedMarkTargets(
        uint32[] memory targets,
        uint32 authSlot
    ) internal view returns (SHRINCS.Signature memory sig) {
        bytes32 payloadHash = Codec.markLeavesUsedPayloadHash(
            _targetsHash(targets)
        );
        sig = _signStatefulAction(
            Codec.ACTION_MARK_LEAVES_USED,
            payloadHash,
            authSlot
        );
    }

    function _pushPoolEntry(uint32[] memory targets, uint32 authSlot) internal {
        handler.pushValidMark(
            _mainPk(),
            _signedMarkTargets(targets, authSlot),
            targets
        );
    }

    function _single(uint32 a) internal pure returns (uint32[] memory targets) {
        targets = new uint32[](1);
        targets[0] = a;
    }

    function _pair(
        uint32 a,
        uint32 b
    ) internal pure returns (uint32[] memory targets) {
        targets = new uint32[](2);
        targets[0] = a;
        targets[1] = b;
    }

    function setUp() public virtual override {
        super.setUp();

        handler = new ShrincsWalletInvariantHandler();
        handler.initialize(wallet, OWNER);

        uint32[] memory seedTargets = _single(SEED_TARGET_LEAF);
        SHRINCS.Signature memory seedSig = _signedMarkTargets(
            seedTargets,
            SEED_AUTH_SLOT
        );
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), seedSig, seedTargets);
        handler.recordSeedMark(uint32(seedSig.authPath.length), seedTargets);

        _pushPoolEntry(_single(POOL_TARGET_LEAF_A), POOL_AUTH_SLOT_A);
        _pushPoolEntry(
            _pair(POOL_TARGET_LEAF_A, POOL_TARGET_LEAF_B),
            POOL_AUTH_SLOT_B
        );
        _pushPoolEntry(
            _pair(POOL_TARGET_LEAF_B, POOL_TARGET_LEAF_B),
            POOL_AUTH_SLOT_C
        );

        initialNonce = wallet.actionNonce();
        initialKeyVersion = wallet.keyVersion();
        initialUsed = wallet.statefulLeavesUsed();
        initialMainCommitment = wallet.getShrincsPublicKeyCommitment();
        initialErc1271Commitment = wallet.getErc1271PublicKeyCommitment();
    }

    function test_setUp() public view override {
        assertEq(wallet.owner(), OWNER);
        assertEq(wallet.actionNonce(), initialNonce);
        assertEq(wallet.keyVersion(), initialKeyVersion);
        assertEq(wallet.statefulLeavesUsed(), initialUsed);
        assertEq(
            initialUsed,
            SEED_LEAVES_CONSUMED,
            "seed revocation consumed auth + target"
        );
        assertEq(handler.validPoolLength(), POOL_SIZE, "replay pool seeded");
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment);
        assertEq(wallet.getErc1271PublicKeyCommitment(), erc1271Commitment);
    }
}
