// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_contextBuilders is ShrincsWalletCodecTest {
    function test_buildActionContext_fields() public view {
        bytes32 dom = keccak256("dom");
        bytes32 action = keccak256("action");
        bytes32 payload = keccak256("payload");
        ShrincsTypes.ActionContext memory ctx = codec.exposed_buildActionContext(dom, 5, 9, action, payload);

        assertEq(ctx.domainSeparator, dom);
        assertEq(ctx.nonce, 5);
        assertEq(ctx.keyVersion, 9);
        assertEq(ctx.actionType, action);
        assertEq(ctx.payloadHash, payload);
    }

    function test_buildRotationContext_fields() public view {
        bytes32 dom = keccak256("dom");
        ShrincsTypes.RotationContext memory ctx = codec.exposed_buildRotationContext(dom, 3, 4);

        assertEq(ctx.domainSeparator, dom);
        assertEq(ctx.nonce, 3);
        assertEq(ctx.keyVersion, 4);
    }

    function test_rotationDomainSeparator_foldsTagIntoBase() public view {
        bytes32 base = keccak256("base");
        bytes32 tag = keccak256("tag");
        assertEq(codec.exposed_rotationDomainSeparator(base, tag), keccak256(abi.encodePacked(base, tag)));
    }

    function test_rotationDomainTags_distinctPerPath() public pure {
        assertEq(Codec.ROTATION_DOMAIN_RECOVER_WALLET, keccak256("quip.shrincs.rotation.recoverWallet"));
        assertEq(Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP, keccak256("quip.shrincs.rotation.transferOwnership"));
        assertTrue(Codec.ROTATION_DOMAIN_RECOVER_WALLET != Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
    }
}
