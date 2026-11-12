// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `erc1271Version`, the SDK capability probe for the fixed-layout
///      ERC-1271 envelope (implementations predating it lack the selector).
contract ShrincsWallet_erc1271Version is ShrincsWalletTest {
    function test_erc1271Version_returnsCodecVersion() public view {
        assertEq(wallet.erc1271Version(), Codec.ERC1271_VERSION);
        assertEq(wallet.erc1271Version(), 1);
    }

    /// @dev The version byte the wallet reports is the one its header check accepts.
    function test_erc1271Version_matchesAcceptedHeaderVersion() public view {
        bytes memory blob = abi.encodePacked(
            Codec.ERC1271_MAGIC,
            wallet.erc1271Version(),
            SHRINCSParams.PROFILE_ID,
            new bytes(Codec.ERC1271_ECDSA_LEN + StatelessLayout.PAYLOAD_LEN)
        );
        // Header accepted; the zero ECDSA half is what fails.
        assertEq(
            uint8(wallet.debugIsValidSignature(keccak256("m"), blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }

    function test_erc1271Version_callableByAnyone() public {
        vm.prank(makeAddr("anyone"));
        assertEq(wallet.erc1271Version(), Codec.ERC1271_VERSION);
    }

    /// @dev Pure: answered by the implementation itself, independent of proxy storage.
    function test_erc1271Version_onImplementation() public view {
        assertEq(walletImplementation.erc1271Version(), Codec.ERC1271_VERSION);
    }
}
