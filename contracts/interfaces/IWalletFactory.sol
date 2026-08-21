// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

/// @title IWalletFactory
/// @notice Factory for creating and managing Quip wallet proxies. Agnostic to the
///         signature scheme securing each wallet: implementations are vetted by
///         codehash and driven exclusively through the minimal `IWallet`
///         surface (see its natspec for the behavioral vetting contract).
///         Supports multiple vetted implementation versions with index-based selection.
///         UUPS-upgradeable behind an ERC-1967 proxy: the proxy address is the
///         permanent factory identity (wallet immutables and CREATE3 wallet
///         addressing both derive from it and survive logic upgrades).
interface IWalletFactory {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          TYPES                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Deploy-authorization mode a factory requires (e3r). Declared at factory setup
    ///         via `setDeployConfig`; the wallet's `initialize` reads it and enforces exactly
    ///         that form for the deploy signature.
    ///           - `Stateful`: a main-key stateful signature at the reserved deploy leaf
    ///             `quipDeployChainIndex`. One-time, distinct leaf per chain.
    ///           - `Stateless`: a main-key stateless signature bound to the chainId. No leaf
    ///             consumed; the chainId binding is what prevents cross-chain reuse.
    enum DeployMode {
        Stateful,
        Stateless
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ERRORS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when the factory balance is insufficient for the requested withdrawal.
    /// @param requested The amount requested.
    /// @param available The current balance.
    error InsufficientBalance(uint256 requested, uint256 available);
    /// @notice Thrown when a fee exceeds the maximum allowed.
    /// @param fee The fee that was set.
    /// @param maxFee The maximum allowed fee.
    error FeeExceedsMax(uint256 fee, uint256 maxFee);

    /// @notice Thrown when the implementation address has no deployed code.
    error EmptyCode();
    /// @notice Thrown when the implementation's codehash is not in the vetted set.
    error ImplementationNotVetted();
    /// @notice Thrown when attempting to deploy with a deprecated implementation.
    error ImplementationDeprecated();
    /// @notice Thrown when `vetImplementation` is called with a codehash already in
    ///         the vetted set (whether currently active or deprecated). Reactivating
    ///         a deprecated codehash MUST go through `undeprecateImplementation`.
    error AlreadyVetted();
    /// @notice Thrown when `undeprecateImplementation` is called on a vetted codehash
    ///         that is not currently deprecated.
    error NotDeprecated();
    /// @notice Thrown when no active (non-deprecated) implementation exists.
    error NoActiveImplementation();
    /// @notice Thrown when msg.value is less than the creation fee.
    /// @param sent The ETH value sent.
    /// @param required The required creation fee.
    error InsufficientCreationFee(uint256 sent, uint256 required);
    /// @notice Thrown when `renounceOwnership` is called (always reverts).
    error RenounceDisabled();
    /// @notice Thrown when the max fee is zero.
    error ZeroMaxFee();
    /// @notice Thrown when the wallet owner address is zero.
    error ZeroAddressOwner();
    /// @notice Thrown when `_deployProxy` is called with `vaultId == 0`. The zero
    ///         vaultId is reserved as a sentinel for "not deployed by this factory"
    ///         in the `vaultIdOf` reverse mapping; allowing it would collapse the
    ///         "is this caller one of my wallets?" check in `updateWalletOwner`.
    error ZeroVaultId();
    /// @notice Thrown when `updateWalletOwner` is called by an address that is
    ///         not a wallet deployed by this factory (i.e. `vaultIdOf[msg.sender]`
    ///         is zero).
    error OnlyWallet();
    /// @notice Thrown when `updateWalletOwner` is called with `newOwner != owner()`
    ///         on the calling wallet. Pins the callback to the tail of
    ///         `transferOwnership(bytes)` where Solady's `_setOwner(newOwner)` has
    ///         already committed.
    error OwnerStateMismatch();
    /// @notice Thrown when `updateWalletOwner` is called with `newOwner` equal
    ///         to the wallet's currently-registered owner. The wallet has no
    ///         business notifying a no-op transfer.
    error SameOwner();
    /// @notice Thrown when an EnumerableSet mutation inside `updateWalletOwner`
    ///         returns `false` (i.e. `_vaultIds[oldOwner].remove(vaultId)` or
    ///         `_vaultIds[newOwner].add(vaultId)`). Indicates the per-owner
    ///         set has diverged from the factory's `walletOwner` source of
    ///         truth — a "this should never happen" defense-in-depth revert.
    error RegistryDesync();
    /// @notice Thrown when `setDeployConfig` is given a `quipDeployChainIndex` outside the
    ///         reserved deploy-leaf range `[1..MAX_DEPLOY_CHAINS]` (e3r). Index 0 is reserved
    ///         (leaf 0 is never a valid signature); an index above the range would overlap the
    ///         signing budget.
    /// @param quipDeployChainIndex The rejected index.
    error InvalidDeployChainIndex(uint16 quipDeployChainIndex);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         EVENTS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a fresh implementation codehash is added to the vetted
    ///         set. Reactivation of a deprecated codehash is signaled by
    ///         `ImplementationUndeprecated`, not by re-emitting this event.
    /// @param impl The implementation contract address.
    /// @param codehash The codehash of the implementation.
    event ImplementationVetted(address indexed impl, bytes32 indexed codehash);

    /// @notice Emitted when an implementation is deprecated.
    /// @param impl The implementation contract address.
    /// @param codehash The codehash of the implementation.
    event ImplementationSunset(address indexed impl, bytes32 indexed codehash);

    /// @notice Emitted when a previously deprecated implementation codehash is
    ///         reactivated via `undeprecateImplementation`.
    /// @param impl The implementation contract address (may differ from the
    ///        address originally vetted, since `vettedWalletImpls[codehash]` is
    ///        re-bound on undeprecate).
    /// @param codehash The codehash of the implementation.
    event ImplementationUndeprecated(
        address indexed impl,
        bytes32 indexed codehash
    );

    /// @notice Emitted when the creation fee is updated.
    /// @param oldFee The previous creation fee.
    /// @param newFee The new creation fee.
    event CreationFeeUpdated(uint256 oldFee, uint256 newFee);

    /// @notice Emitted when the execute fee is updated.
    /// @param oldFee The previous execute fee.
    /// @param newFee The new execute fee.
    event ExecuteFeeUpdated(uint256 oldFee, uint256 newFee);

    /// @notice Emitted when the factory's deploy authorization config is set (e3r).
    /// @param quipDeployChainIndex The reserved per-chain deploy leaf index.
    /// @param deployMode The required deploy-signature mode.
    event DeployConfigSet(uint16 quipDeployChainIndex, DeployMode deployMode);

    /// @notice Emitted when a new wallet proxy is created.
    /// @param amount The ETH value sent with the creation transaction.
    /// @param when The block timestamp at which the wallet was created.
    /// @param vaultId The salt used to derive the wallet's deterministic address.
    /// @param creator The classical address that owns the new wallet.
    /// @param implementation The vetted implementation the proxy was deployed with —
    ///        tells an off-chain indexer which wallet family/version this is. The
    ///        wallet's key material is NOT echoed here: the init payload is opaque
    ///        to the factory, and each family emits its own `WalletInitialized`
    ///        event (indexed by factory and owner) with its typed key handles.
    /// @param quip The address of the newly deployed wallet proxy.
    event WalletDeployed(
        uint256 amount,
        uint256 when,
        bytes32 indexed vaultId,
        address indexed creator,
        address implementation,
        address indexed quip
    );

    /// @notice Emitted when ETH is withdrawn from the factory.
    /// @param to The address that received the withdrawal.
    /// @param amount The amount of ETH withdrawn.
    event Withdrawn(address indexed to, uint256 amount);

    /// @notice Emitted when a wallet's classical owner changes via the
    ///         wallet's PQ-authenticated ownership-transfer path. The wallet
    ///         calls back into the factory at the tail of that flow to keep
    ///         the per-owner vaultIds set consistent with the wallet's `owner()`.
    /// @param vaultId The wallet's vaultId (derived via `vaultIdOf[msg.sender]`).
    /// @param oldOwner The owner before the transfer.
    /// @param newOwner The owner after the transfer.
    event WalletOwnerChanged(
        bytes32 indexed vaultId,
        address indexed oldOwner,
        address indexed newOwner
    );

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Initializes the factory proxy with its initial owner.
    /// @dev Callable exactly once (Solady `initializer`); the implementation
    ///      itself is locked via `_disableInitializers` in its constructor.
    ///      `MAX_FEE` is NOT set here — it is a per-implementation immutable
    ///      supplied to the implementation's constructor.
    /// @param initialOwner The initial factory owner (expected to be a
    ///        post-quantum wallet; controls vetting, fees, and upgrades).
    function initialize(address payable initialOwner) external;

    /// @notice Approves a fresh implementation's codehash for proxy deployment.
    /// @dev Only callable by the admin. Computes `extcodehash` of `impl` and adds it
    ///      to the vetted set as a new entry. Reverts with `AlreadyVetted` if the
    ///      codehash is already present (whether active or deprecated) — reactivation
    ///      flows through `undeprecateImplementation` so the lifecycle stays
    ///      reconstructable from events alone. Sets `latestWalletImpl` to the new impl.
    /// @param impl The deployed implementation contract address.
    function vetImplementation(address impl) external;

    /// @notice Marks an implementation's codehash as deprecated.
    /// @dev Only callable by the admin. The codehash remains in the set (preserving indices)
    ///      but cannot be used for new proxy deployments until reactivated via
    ///      `undeprecateImplementation`.
    /// @param impl The deployed implementation contract address.
    function deprecateImplementation(address impl) external;

    /// @notice Reactivates a previously deprecated implementation codehash.
    /// @dev Only callable by the admin. The codehash MUST already be in the vetted
    ///      set and currently flagged as deprecated; otherwise reverts with
    ///      `ImplementationNotVetted` or `NotDeprecated`. Re-binds
    ///      `vettedWalletImpls[codehash]` to the supplied address (so a redeploy of
    ///      identical bytecode at a different address can replace the original
    ///      pointer) and recomputes `latestWalletImpl` via the insertion-order
    ///      backward scan, so reactivating the highest-index entry restores it as
    ///      the latest active implementation. Emits `ImplementationUndeprecated`.
    /// @param impl The deployed implementation contract address.
    function undeprecateImplementation(address impl) external;

    /// @notice Deploys a new wallet proxy using the latest active implementation,
    ///         initializes it, and forwards deposited ETH (minus creation fee) to the wallet.
    /// @dev Iterates backwards through the vetted set to find the most recently added
    ///      non-deprecated implementation. Uses CREATE3 for deterministic addressing.
    /// @param vaultId The vault identifier; combined with `commitment` into the CREATE3 salt.
    /// @param commitment The main-key commitment the address is bound to (e3r). Used only to
    ///                derive the salt `keccak256(abi.encode(vaultId, commitment))`; the wallet's
    ///                `initialize` reverts unless it equals the main commitment inside `payload`,
    ///                so it cannot disagree with the installed key.
    /// @param to The classical address that will own the new wallet.
    /// @param payload Implementation-defined init data, passed to the wallet's
    ///                `initialize` verbatim. Opaque to the factory: layout and
    ///                length are documented and validated by each wallet
    ///                family's own codec.
    /// @return The address of the newly deployed wallet proxy.
    function deployLatestWalletProxy(
        bytes32 vaultId,
        bytes32 commitment,
        address payable to,
        bytes calldata payload
    ) external payable returns (address);

    /// @notice Deploys a new wallet proxy using the implementation at a
    ///         specific index, initializes it, and forwards deposited ETH (minus creation
    ///         fee) to the wallet.
    /// @dev The index corresponds to insertion order in the vetted set. Reverts if the
    ///      implementation at the given index is deprecated.
    /// @param vaultId The vault identifier; combined with `commitment` into the CREATE3 salt.
    /// @param commitment The main-key commitment the address is bound to (e3r); see
    ///                `deployLatestWalletProxy`.
    /// @param index The index into the vetted implementation set.
    /// @param to The classical address that will own the new wallet.
    /// @param payload Implementation-defined init data, passed to the wallet's
    ///                `initialize` verbatim. Opaque to the factory: layout and
    ///                length are documented and validated by each wallet
    ///                family's own codec.
    /// @return The address of the newly deployed wallet proxy.
    function deploySpecificWalletProxy(
        bytes32 vaultId,
        bytes32 commitment,
        uint256 index,
        address payable to,
        bytes calldata payload
    ) external payable returns (address);

    /// @notice Callback used by deployed wallets to keep the per-owner
    ///         vaultIds set consistent with `owner()` during the wallet's
    ///         PQ-authenticated ownership-transfer flow.
    /// @dev NOT callable outside that flow. The factory looks up `oldOwner`
    ///      internally via `walletOwner[msg.sender]` — its own source of
    ///      truth — so the wallet cannot pass a wrong value. Gates, in order:
    ///        - `vaultIdOf[msg.sender] != 0` — caller must be a wallet
    ///          deployed by THIS factory. Reverts `OnlyWallet` otherwise.
    ///        - `newOwner != address(0)` — reverts `ZeroAddressOwner`.
    ///        - `newOwner != walletOwner[msg.sender]` — reverts `SameOwner`.
    ///        - `IWallet(msg.sender).owner() == newOwner` — pins the
    ///          callback to a moment when the wallet has ALREADY committed
    ///          its new owner. Per the vetting contract (`IWallet`
    ///          natspec, rule 2), the only path producing that state is the
    ///          wallet's ownership-transfer flow. Reverts `OwnerStateMismatch`.
    ///      On success, moves the vaultId from `walletOwner[msg.sender]`'s
    ///      set to `newOwner`'s set, updates `walletOwner[msg.sender]`,
    ///      and emits `WalletOwnerChanged`. The set mutations are guarded
    ///      against `false` return values from `EnumerableSetLib.add`/
    ///      `remove` and revert `RegistryDesync` if the set is unexpectedly
    ///      out of sync (defense-in-depth; should be unreachable while
    ///      invariant 16 holds).
    /// @param newOwner The owner after the transfer (wallet `owner()` state check).
    function updateWalletOwner(address newOwner) external;

    /// @notice Sets the fee charged when creating a new wallet proxy.
    /// @dev Only callable by the current admin.
    /// @param newFee The new creation fee in wei.
    function setCreationFee(uint256 newFee) external;

    /// @notice Sets the fee charged on PQ-authenticated wallet operations.
    /// @dev Only callable by the current admin.
    /// @param newFee The new execute fee in wei.
    function setExecuteFee(uint256 newFee) external;

    /// @notice Sets the factory's deploy authorization config (e3r). Factory setup, owner-only.
    /// @dev The wallet's `initialize` reads both values from the factory (`msg.sender`) to
    ///      rebuild and verify the deploy authorization. `quipDeployChainIndex` MUST be this
    ///      chain's committed 1-based deploy-list position and MUST stay in
    ///      `[1..MAX_DEPLOY_CHAINS]` (else `InvalidDeployChainIndex`).
    /// @param quipDeployChainIndex The reserved per-chain deploy leaf index.
    /// @param deployMode The deploy-signature mode required at `initialize`.
    function setDeployConfig(
        uint16 quipDeployChainIndex,
        DeployMode deployMode
    ) external;

    /// @notice Withdraws accumulated fees from the factory to the admin.
    /// @dev Only callable by the current admin. Reverts if the factory balance is insufficient.
    /// @param amount The amount of ETH in wei to withdraw.
    function withdraw(uint256 amount) external;

    // NOTE: `renounceOwnership()` is deliberately NOT declared here. The
    // implementation overrides Solady Ownable's payable `renounceOwnership`
    // to always revert `RenounceDisabled` (same pattern as the wallets'
    // interfaces, which declare only the error).

    /// @notice Returns the current fee charged for wallet creation.
    /// @return The creation fee in wei.
    function creationFee() external view returns (uint256);

    /// @notice Returns the current fee charged for PQ-authenticated wallet operations.
    /// @return The execute fee in wei.
    function executeFee() external view returns (uint256);

    /// @notice Returns the maximum fee that can be set.
    /// @return The maximum fee in wei.
    function MAX_FEE() external view returns (uint256);

    /// @notice Returns the factory's reserved per-chain deploy leaf index (e3r).
    /// @dev Read by the wallet's `initialize` to rebuild the deploy context. Zero until
    ///      `setDeployConfig` runs.
    function quipDeployChainIndex() external view returns (uint16);

    /// @notice Returns the factory's required deploy-signature mode (e3r).
    /// @dev Read by the wallet's `initialize`. Defaults to `Stateful` (0) until configured.
    function deployMode() external view returns (DeployMode);

    /// @notice Returns the main-key commitment the in-flight deploy salted its address with
    ///         (e3r). Backed by transient storage: meaningful ONLY while a `_deployProxy` call
    ///         is on the stack (the wallet reads it during `initialize`), and `bytes32(0)`
    ///         otherwise. The wallet reverts unless it equals the commitment inside `payload`.
    function pendingDeployCommitment() external view returns (bytes32);

    /// @notice Returns the wallet address registered under a CREATE3 salt on this factory.
    /// @dev Keyed by the derived salt `keccak256(abi.encode(vaultId, commitment))` (e3r), NOT by
    ///      the raw `vaultId`: with the main-key commitment folded into the salt, two commitments
    ///      under one `vaultId` resolve to two distinct addresses and no longer collide in this
    ///      registry. Same salt on every chain resolves to the same deterministic address.
    /// @param salt The CREATE3 salt `keccak256(abi.encode(vaultId, commitment))`.
    /// @return The wallet address, or `address(0)` if none registered here.
    function wallets(bytes32 salt) external view returns (address);

    /// @notice Returns the vaultId of a wallet deployed by this factory.
    /// @dev Used by `updateWalletOwner` to authenticate the calling wallet
    ///      and derive its vaultId implicitly without trusting an argument.
    ///      Returns `bytes32(0)` if `wallet` was not deployed by this factory.
    /// @param wallet The wallet contract address.
    /// @return The vaultId, or `bytes32(0)` if unknown.
    function vaultIdOf(address wallet) external view returns (bytes32);

    /// @notice Returns the current classical owner of a wallet deployed by
    ///         this factory. Source of truth for the per-owner `vaultIds`
    ///         registry — updated atomically in `updateWalletOwner` so the
    ///         wallet cannot supply a wrong `oldOwner`.
    /// @dev Initialized to `to` in `_deployProxy`. Tracks the wallet's
    ///      classical `owner()` across `transferOwnership(bytes)` rotations.
    ///      Returns `address(0)` if `wallet` was not deployed by this factory.
    /// @param wallet The wallet contract address.
    /// @return The current owner, or `address(0)` if unknown.
    function walletOwner(address wallet) external view returns (address);

    /// @notice Returns the number of wallets currently owned by `owner` in
    ///         this factory's registry.
    /// @dev The set tracks CURRENT classical owner (not initial deployer).
    ///      Updated atomically when `transferOwnership(bytes)` runs on a
    ///      wallet via the `updateWalletOwner` callback.
    /// @param owner The classical owner address.
    function getVaultIdCount(address owner) external view returns (uint256);

    /// @notice Returns the vaultId at `index` in `owner`'s set.
    /// @dev Iteration order is not stable across removals (the underlying
    ///      `EnumerableSetLib.Bytes32Set` uses swap-and-pop). Off-chain
    ///      callers should pair `getVaultIdCount` with a contiguous range
    ///      of `getVaultIdAt(0..N-1)` reads in a single block (or use
    ///      `getVaultIds` for a one-shot snapshot).
    /// @param owner The classical owner address.
    /// @param index The index into `owner`'s set.
    function getVaultIdAt(
        address owner,
        uint256 index
    ) external view returns (bytes32);

    /// @notice Returns the index of `vaultId` in `owner`'s set, or
    ///         `type(uint256).max` if `owner` does not currently own a
    ///         wallet at this vaultId. Mirrors `getVettedCodeIndex`.
    /// @param owner The classical owner address.
    /// @param vaultId The vaultId to query.
    function getVaultIdIndex(
        address owner,
        bytes32 vaultId
    ) external view returns (uint256);

    /// @notice Returns the full set of vaultIds currently owned by `owner`
    ///         as a `bytes32[]` snapshot — one read, no pagination.
    /// @dev Off-chain callers should prefer this over `getVaultIdCount` +
    ///      `getVaultIdAt` loops to avoid the `1 + N` round-trip pattern.
    ///      Order is undefined; the set uses swap-and-pop on removal.
    /// @param owner The classical owner address.
    function getVaultIds(
        address owner
    ) external view returns (bytes32[] memory);

    /// @notice Returns the wallet addresses currently owned by `owner` —
    ///         one address per entry in `owner`'s vaultId set, looked up via
    ///         the `wallets[vaultId]` mapping. One read, no pagination.
    /// @dev Parallel-indexed with `getVaultIds(owner)` when called in the
    ///      same block (both iterate the same underlying set in the same
    ///      order). Pair them via multicall to materialize a
    ///      `(vaultId → wallet)` map without `1 + N` round-trips.
    /// @param owner The classical owner address.
    function getWallets(address owner) external view returns (address[] memory);

    /// @notice Returns the number of vetted implementation codehashes.
    /// @return The count of entries in the vetted set.
    function getVettedCodeCount() external view returns (uint256);

    /// @notice Returns the codehash at a given index in the vetted set.
    /// @param index The index into the vetted set (insertion order).
    /// @return The codehash at the specified index.
    function getVettedCodeAt(uint256 index) external view returns (bytes32);

    /// @notice Returns the index of a codehash in the vetted set.
    /// @param codehash The codehash to look up.
    /// @return The index in the vetted set, or `type(uint256).max` if not found.
    function getVettedCodeIndex(
        bytes32 codehash
    ) external view returns (uint256);

    /// @notice Returns the implementation address associated with a vetted codehash.
    /// @param codehash The codehash to look up.
    /// @return walletImplementation The implementation contract address.
    function vettedWalletImpls(
        bytes32 codehash
    ) external view returns (address walletImplementation);

    /// @notice Returns whether a codehash has been deprecated.
    /// @param codehash The codehash to check.
    /// @return isDeprecated True if the codehash is deprecated.
    function deprecatedImpls(
        bytes32 codehash
    ) external view returns (bool isDeprecated);

    /// @notice Returns the most recently vetted active implementation address.
    /// @return The latest active wallet implementation address, or `address(0)` if none.
    function latestWalletImpl() external view returns (address);
}
