// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../../ShrincsWallet.t.sol";
import {ShrincsWalletInvariantHandler} from "./Handler.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";

abstract contract ShrincsWalletInvariantBase is ShrincsWalletTest {
    ShrincsWalletInvariantHandler public handler;

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

        uint32[] memory seedTargets = _single(SIGN_BASE + 2);
        SHRINCS.Signature memory seedSig = _signedMarkTargets(seedTargets, 1);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), seedSig, seedTargets);
        handler.recordSeedMark(uint32(seedSig.authPath.length), seedTargets);

        _pushPoolEntry(_single(SIGN_BASE + 6), 3);
        _pushPoolEntry(_pair(SIGN_BASE + 6, SIGN_BASE + 7), 4);
        _pushPoolEntry(_pair(SIGN_BASE + 7, SIGN_BASE + 7), 5);

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
        assertEq(initialUsed, 2, "seed revocation consumed auth + target");
        assertEq(handler.validPoolLength(), 3, "replay pool seeded");
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment);
        assertEq(wallet.getErc1271PublicKeyCommitment(), erc1271Commitment);
    }
}
