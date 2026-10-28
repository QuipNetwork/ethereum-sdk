/*
 * CVL rules for WalletFactory — wave 1.
 *
 * Mirrors the Foundry suite (test/WalletFactory/invariant/Local.t.sol):
 *   - invariant_feesBoundedByMaxFee            -> invariant feesBoundedByMaxFee
 *   - invariant_factoryOwnerStable             -> rule ownerStableOutsideOwnershipTransfer
 *   - handler vet/deprecate/undeprecate/setFees -> lifecycle + fee rules per method
 *   - invariant_deprecatedNeverSelectedLatest  -> not mirrored, see end of file
 * Plus access-control and registry write-once rules from
 * test/WalletFactory/behaviors. Both registries are written only by
 * _deployProxy, which is out of scope for wave 1.
 */

using WalletFactoryHarness as factory;

methods {
    // updateWalletOwner calls IWallet(msg.sender).owner(); model it nondeterministically.
    function _.owner() external => NONDET;

    // Rerouting summaries: inlining Solady's Bytes32Set crashes the prover's
    // TAC typechecker — `not(_rootSlot(...))` becomes `BWNot(<skey>)`
    // (bug 1714349382). The six set operations are rerouted to
    // EnumerableSetHarness: same set semantics, no `not()`.
    // `at` is a CVL keyword and cannot be listed, but its inlined body has
    // no `not()` and the harness writes the same element slots (layout
    // `root + i`, like Solady), so it stays crash-free.
    function EnumerableSetLib.length(EnumerableSetLib.Bytes32Set storage set)
        internal
        returns (uint256)
        => EnumerableSetHarness.length(set);
    function EnumerableSetLib.contains(EnumerableSetLib.Bytes32Set storage set, bytes32 value)
        internal
        returns (bool)
        => EnumerableSetHarness.contains(set, value);
    function EnumerableSetLib.indexOf(EnumerableSetLib.Bytes32Set storage set, bytes32 value)
        internal
        returns (uint256)
        => EnumerableSetHarness.indexOf(set, value);
    function EnumerableSetLib.add(EnumerableSetLib.Bytes32Set storage set, bytes32 value)
        internal
        returns (bool)
        => EnumerableSetHarness.add(set, value);
    function EnumerableSetLib.remove(EnumerableSetLib.Bytes32Set storage set, bytes32 value)
        internal
        returns (bool)
        => EnumerableSetHarness.remove(set, value);
    function EnumerableSetLib.values(EnumerableSetLib.Bytes32Set storage set)
        internal
        returns (bytes32[] memory)
        => EnumerableSetHarness.values(set);

    function owner() external returns (address) envfree;
    function creationFee() external returns (uint256) envfree;
    function executeFee() external returns (uint256) envfree;
    function MAX_FEE() external returns (uint256) envfree;
    function latestWalletImpl() external returns (address) envfree;
    function deprecatedImpls(bytes32) external returns (bool) envfree;
    function vettedWalletImpls(bytes32) external returns (address) envfree;
    function codehashOf(address) external returns (bytes32) envfree;
    function getVettedCodeIndex(bytes32) external returns (uint256) envfree;
    function getVettedCodeCount() external returns (uint256) envfree;
    function commitmentOf(address) external returns (bytes32) envfree;
    function walletOwner(address) external returns (address) envfree;
    function wallets(bytes32) external returns (address) envfree;
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                     INVARIANTS                         */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Mirror of invariant_feesBoundedByMaxFee: fees never exceed MAX_FEE.
///      `upgradeToAndCall` excluded: an upgrade delegates to arbitrary code
///      that may write any storage. `renounceOwnership` excluded: it always
///      reverts, so its step would be vacuous (see renounceOwnership_alwaysReverts).
invariant feesBoundedByMaxFee()
    factory.creationFee() <= factory.MAX_FEE()
    && factory.executeFee() <= factory.MAX_FEE()
    filtered {
        f -> f.selector != sig:upgradeToAndCall(address, bytes).selector
        // Always reverts -> no final state -> vacuity flag; covered by
        // renounceOwnership_alwaysReverts.
        && f.selector != sig:renounceOwnership().selector
    }

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                       FEES                             */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Owner sets creationFee; the value is stored as-is when <= MAX_FEE.
rule setCreationFee_success(env e, uint256 newFee) {
    require e.msg.sender == factory.owner();
    require e.msg.value == 0;
    require newFee <= factory.MAX_FEE();
    factory.setCreationFee(e, newFee);
    assert factory.creationFee() == newFee;
}

/// @dev A fee above the immutable MAX_FEE cap is rejected.
rule setCreationFee_revertsWhen_exceedsMaxFee(env e, uint256 newFee) {
    require e.msg.sender == factory.owner();
    require e.msg.value == 0;
    require newFee > factory.MAX_FEE();
    factory.setCreationFee@withrevert(e, newFee);
    assert lastReverted;
}

/// @dev Setting the creation fee is owner-only.
rule setCreationFee_revertsWhen_notOwner(env e, uint256 newFee) {
    require e.msg.sender != factory.owner();
    factory.setCreationFee@withrevert(e, newFee);
    assert lastReverted;
}

/// @dev Owner sets executeFee; the value is stored as-is when <= MAX_FEE.
rule setExecuteFee_success(env e, uint256 newFee) {
    require e.msg.sender == factory.owner();
    require e.msg.value == 0;
    require newFee <= factory.MAX_FEE();
    factory.setExecuteFee(e, newFee);
    assert factory.executeFee() == newFee;
}

/// @dev A fee above the immutable MAX_FEE cap is rejected.
rule setExecuteFee_revertsWhen_exceedsMaxFee(env e, uint256 newFee) {
    require e.msg.sender == factory.owner();
    require e.msg.value == 0;
    require newFee > factory.MAX_FEE();
    factory.setExecuteFee@withrevert(e, newFee);
    assert lastReverted;
}

/// @dev Setting the execute fee is owner-only.
rule setExecuteFee_revertsWhen_notOwner(env e, uint256 newFee) {
    require e.msg.sender != factory.owner();
    factory.setExecuteFee@withrevert(e, newFee);
    assert lastReverted;
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                 IMPL LIFECYCLE                         */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Owner vettes a deployed impl: it becomes latestWalletImpl and is
///      appended to the vetted list (index = previous count).
rule vetImplementation_success(env e, address impl) {
    require e.msg.sender == factory.owner();
    require e.msg.value == 0;
    require nativeCodesize[impl] > 0;
    bytes32 codehash = factory.codehashOf(impl);
    require factory.getVettedCodeIndex(codehash) == max_uint256;
    // Reachable-state premise: the vetted list is append-only and deprecating
    // requires membership, so an unvetted codehash is never deprecated.
    // Without it, the rule trips on the unreachable "deprecated yet
    // unvetted" state that arbitrary initial storage allows.
    require !factory.deprecatedImpls(codehash);
    uint256 countBefore = factory.getVettedCodeCount();
    factory.vetImplementation(e, impl);
    assert factory.latestWalletImpl() == impl;
    assert factory.vettedWalletImpls(codehash) == impl;
    assert !factory.deprecatedImpls(codehash);
    assert factory.getVettedCodeCount() == countBefore + 1;
    assert factory.getVettedCodeIndex(codehash) == countBefore;
}

/// @dev Vetting is owner-only.
rule vetImplementation_revertsWhen_notOwner(env e, address impl) {
    require e.msg.sender != factory.owner();
    factory.vetImplementation@withrevert(e, impl);
    assert lastReverted;
}

/// @dev Owner flags a vetted codehash as deprecated.
rule deprecateImplementation_success(env e, address impl) {
    require e.msg.sender == factory.owner();
    require e.msg.value == 0;
    bytes32 codehash = factory.codehashOf(impl);
    require factory.getVettedCodeIndex(codehash) != max_uint256;
    factory.deprecateImplementation(e, impl);
    assert factory.deprecatedImpls(codehash);
}

/// @dev Deprecating is owner-only.
rule deprecateImplementation_revertsWhen_notOwner(env e, address impl) {
    require e.msg.sender != factory.owner();
    factory.deprecateImplementation@withrevert(e, impl);
    assert lastReverted;
}

/// @dev Owner clears the deprecated flag of a vetted codehash; the vetted
///      entry is kept.
rule undeprecateImplementation_success(env e, address impl) {
    require e.msg.sender == factory.owner();
    require e.msg.value == 0;
    bytes32 codehash = factory.codehashOf(impl);
    require factory.getVettedCodeIndex(codehash) != max_uint256;
    require factory.deprecatedImpls(codehash);
    factory.undeprecateImplementation(e, impl);
    assert !factory.deprecatedImpls(codehash);
    assert factory.vettedWalletImpls(codehash) == impl;
}

/// @dev Undeprecating is owner-only.
rule undeprecateImplementation_revertsWhen_notOwner(env e, address impl) {
    require e.msg.sender != factory.owner();
    factory.undeprecateImplementation@withrevert(e, impl);
    assert lastReverted;
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*              WITHDRAW / RENOUNCE                       */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Owner must be an EOA here; the contract-recipient case (force
///      transfer via CREATE fallback when receive() reverts) is deferred.
rule withdraw_transfersToOwner(env e, uint256 amount) {
    address o = factory.owner();
    require e.msg.sender == o;
    require e.msg.value == 0;
    require o != currentContract;
    require nativeCodesize[o] == 0;
    require to_mathint(amount) <= nativeBalances[currentContract];
    // Real ETH balances cannot overflow uint256. Without this premise the
    // model's CALL overflows, Solady's CREATE-fallback path runs, and the
    // credited recipient is no longer `o`.
    require to_mathint(nativeBalances[o]) + to_mathint(amount) <= max_uint256;
    mathint ownerBefore = nativeBalances[o];
    mathint factoryBefore = nativeBalances[currentContract];
    factory.withdraw(e, amount);
    assert nativeBalances[o] == ownerBefore + to_mathint(amount);
    assert nativeBalances[currentContract] == factoryBefore - to_mathint(amount);
}

/// @dev Withdraws above the factory balance are rejected.
rule withdraw_revertsWhen_insufficientBalance(env e, uint256 amount) {
    require e.msg.sender == factory.owner();
    require e.msg.value == 0;
    require to_mathint(amount) > nativeBalances[currentContract];
    factory.withdraw@withrevert(e, amount);
    assert lastReverted;
}

/// @dev Withdrawing is owner-only.
rule withdraw_revertsWhen_notOwner(env e, uint256 amount) {
    require e.msg.sender != factory.owner();
    factory.withdraw@withrevert(e, amount);
    assert lastReverted;
}

/// @dev renounceOwnership is disabled: every call reverts, owner or not
///      (RenounceDisabled vs Unauthorized).
rule renounceOwnership_alwaysReverts(env e) {
    factory.renounceOwnership@withrevert(e);
    assert lastReverted;
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*               WALLET OWNER CALLBACK                    */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Only a registered wallet (commitmentOf != 0) may update its owner.
rule updateWalletOwner_revertsWhen_notWallet(env e, address newOwner) {
    require factory.commitmentOf(e.msg.sender) == to_bytes32(0);
    factory.updateWalletOwner@withrevert(e, newOwner);
    assert lastReverted;
}

/// @dev The new wallet owner may not be the zero address.
rule updateWalletOwner_revertsWhen_zeroAddressOwner(env e, address newOwner) {
    require factory.commitmentOf(e.msg.sender) != to_bytes32(0);
    require newOwner == 0;
    factory.updateWalletOwner@withrevert(e, newOwner);
    assert lastReverted;
}

/// @dev The new wallet owner must differ from the current one.
rule updateWalletOwner_revertsWhen_sameOwner(env e, address newOwner) {
    require factory.commitmentOf(e.msg.sender) != to_bytes32(0);
    require newOwner != 0;
    require factory.walletOwner(e.msg.sender) == newOwner;
    factory.updateWalletOwner@withrevert(e, newOwner);
    assert lastReverted;
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*              PARAMETRIC / REGISTRIES                   */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Mirror of invariant_factoryOwnerStable: only the two-step ownership
///      transfer may change the owner. Excluded: `upgradeToAndCall` (upgrade
///      to arbitrary code), `initialize` (sets the owner by design),
///      `renounceOwnership` (always reverts -> vacuous step, see
///      renounceOwnership_alwaysReverts).
rule ownerStableOutsideOwnershipTransfer(method f, env e, calldataarg args)
filtered {
    f -> !f.isView
        && f.selector != sig:transferOwnership(address).selector
        && f.selector != sig:completeOwnershipHandover(address).selector
        && f.selector != sig:upgradeToAndCall(address, bytes).selector
        && f.selector != sig:initialize(address).selector
        && f.selector != sig:renounceOwnership().selector
} {
    address ownerBefore = factory.owner();
    f(e, args);
    assert factory.owner() == ownerBefore;
}

/// @dev The `wallets` registry is written only by `_deployProxy` (out of
///      scope); none of the listed methods touch it. `renounceOwnership`
///      omitted: always reverts -> vacuous (see renounceOwnership_alwaysReverts).
rule walletsRegistryWriteOnce(env e, method f, bytes32 salt)
filtered {
    f -> f.selector == sig:vetImplementation(address).selector
        || f.selector == sig:deprecateImplementation(address).selector
        || f.selector == sig:undeprecateImplementation(address).selector
        || f.selector == sig:setCreationFee(uint256).selector
        || f.selector == sig:setExecuteFee(uint256).selector
        || f.selector == sig:withdraw(uint256).selector
        || f.selector == sig:updateWalletOwner(address).selector
        || f.selector == sig:transferOwnership(address).selector
        || f.selector == sig:completeOwnershipHandover(address).selector
} {
    address walletBefore = factory.wallets(salt);
    calldataarg args;
    f(e, args);
    assert factory.wallets(salt) == walletBefore;
}

/// @dev The `commitmentOf` registry is written only by `_deployProxy`;
///      `updateWalletOwner` reads it but never writes it. `renounceOwnership`
///      omitted: always reverts -> vacuous (see renounceOwnership_alwaysReverts).
rule commitmentOfWriteOnce(env e, method f, address wallet)
filtered {
    f -> f.selector == sig:vetImplementation(address).selector
        || f.selector == sig:deprecateImplementation(address).selector
        || f.selector == sig:undeprecateImplementation(address).selector
        || f.selector == sig:setCreationFee(uint256).selector
        || f.selector == sig:setExecuteFee(uint256).selector
        || f.selector == sig:withdraw(uint256).selector
        || f.selector == sig:updateWalletOwner(address).selector
        || f.selector == sig:transferOwnership(address).selector
        || f.selector == sig:completeOwnershipHandover(address).selector
} {
    bytes32 commitmentBefore = factory.commitmentOf(wallet);
    calldataarg args;
    f(e, args);
    assert factory.commitmentOf(wallet) == commitmentBefore;
}
