// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {CallContextChecker} from "solady-0.1.26/src/utils/CallContextChecker.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactory} from "../../../contracts/WalletFactory.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @dev Minimal V2: same layout discipline (all state in the ERC-7201
///      namespace), one new function — the smallest observable upgrade.
contract WalletFactoryV2Mock is WalletFactory {
    constructor(uint256 maxFee_) payable WalletFactory(maxFee_) {}

    function version2() external pure returns (bool) {
        return true;
    }
}

/// @dev UUPS upgrade behaviors: authorization, initializer locking, storage
///      continuity, and the load-bearing CREATE3 property — wallet addresses
///      derive from the PROXY address, so they are stable across upgrades.
contract WalletFactory_upgradeToAndCall is WalletFactoryTest {
    function _upgradeToV2(uint256 maxFee) internal returns (WalletFactoryV2Mock v2) {
        WalletFactoryV2Mock v2Impl = new WalletFactoryV2Mock(maxFee);
        vm.prank(ADMIN);
        factory.upgradeToAndCall(address(v2Impl), "");
        v2 = WalletFactoryV2Mock(payable(address(factory)));
    }

    function test_upgradeToAndCall_ownerCanUpgrade() public {
        WalletFactoryV2Mock v2 = _upgradeToV2(0.1 ether);
        assertTrue(v2.version2());
    }

    function test_upgradeToAndCall_revertsWhen_notOwner() public {
        WalletFactoryV2Mock v2Impl = new WalletFactoryV2Mock(0.1 ether);
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.upgradeToAndCall(address(v2Impl), "");
    }

    function test_upgradeToAndCall_revertsWhen_calledOnImplementation() public {
        // Solady UUPS `onlyProxy`: the implementation itself refuses upgrades.
        WalletFactory impl = new WalletFactory(0.1 ether);
        WalletFactoryV2Mock v2Impl = new WalletFactoryV2Mock(0.1 ether);
        vm.expectRevert(CallContextChecker.UnauthorizedCallContext.selector);
        impl.upgradeToAndCall(address(v2Impl), "");
    }

    function test_initialize_revertsWhen_calledTwice() public {
        vm.expectRevert();
        factory.initialize(payable(ALICE));
        assertEq(factory.owner(), ADMIN);
    }

    function test_initialize_revertsWhen_calledOnImplementation() public {
        // `_disableInitializers` in the constructor locks the raw impl.
        WalletFactory impl = new WalletFactory(0.1 ether);
        vm.expectRevert();
        impl.initialize(payable(ALICE));
    }

    function test_upgrade_preservesRegistryAndVettedState() public {
        // Populate every state family pre-upgrade.
        (address walletAddr,,,) = _createWallet(ALICE, "upgrade-continuity", 1 ether);
        bytes32 vaultId = keccak256(abi.encodePacked(bytes32("upgrade-continuity")));
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);
        uint256 vettedCount = factory.getVettedCodeCount();
        uint256 balanceBefore = address(factory).balance;

        _upgradeToV2(0.1 ether);

        // ERC-7201 namespaced state reads back identically through V2.
        assertEq(factory.owner(), ADMIN);
        assertEq(factory.wallets(_salt(vaultId)), walletAddr);
        assertEq(factory.vaultIdOf(walletAddr), vaultId);
        assertEq(factory.walletOwner(walletAddr), ALICE);
        assertNotEq(factory.getVaultIdIndex(ALICE, _salt(vaultId)), type(uint256).max);
        assertEq(factory.creationFee(), CREATION_FEE);
        assertEq(factory.executeFee(), EXECUTE_FEE);
        assertEq(factory.getVettedCodeCount(), vettedCount);
        assertEq(factory.latestWalletImpl(), address(walletImplementation));
        assertEq(address(factory).balance, balanceBefore);
    }

    function test_upgrade_maxFeeIsPerImplementation() public {
        // MAX_FEE lives in implementation code — an upgrade CAN change it.
        // (Documented trust delta: the wallet-side signed maxFee is the floor
        // of protection, not this cap.)
        assertEq(factory.MAX_FEE(), 0.1 ether);
        _upgradeToV2(0.2 ether);
        assertEq(factory.MAX_FEE(), 0.2 ether);
    }

    function test_upgrade_walletAddressesStableAcrossUpgrade() public {
        // CREATE3 derives from address(this) == the proxy, ignoring initcode:
        // counterfactual wallet addresses survive the upgrade.
        bytes32 vaultId = keccak256("stable-across-upgrade");
        // e3r: the CREATE3 salt binds the main-key commitment.
        address predicted = CREATE3.predictDeterministicAddress(_salt(vaultId), address(factory));

        _upgradeToV2(0.1 ether);

        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("stable-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        vm.prank(ALICE);
        address walletAddr =
            factory.deployLatestWalletProxy(vaultId, COMMITMENT, payable(ALICE), _encodeInitPayload(pubkey, rKeys));
        assertEq(walletAddr, predicted);
    }

    function test_upgrade_preUpgradeWalletKeepsWorking() public {
        // A wallet deployed pre-upgrade still resolves factory-side reads
        // (fee gauge + vetted-code gating) against the upgraded logic.
        (address walletAddr,,,) = _createWallet(ALICE, "pre-upgrade-wallet", 1 ether);
        _upgradeToV2(0.1 ether);

        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);
        // The wallet reads the live fee through its immutable factory pointer
        // (now serving V2 logic at the same address).
        (, bytes memory feeData) = walletAddr.staticcall(abi.encodeWithSignature("getExecuteFee()"));
        assertEq(abi.decode(feeData, (uint256)), EXECUTE_FEE);
        assertEq(factory.walletOwner(walletAddr), ALICE);
    }
}
