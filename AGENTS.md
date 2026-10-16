## Solidity Testing Patterns (Foundry)

This project uses Foundry for Solidity testing. All tests are written in Solidity using forge-std.

### Principles

- Every public/external function has a dedicated test file in `behaviors/`
- Internal functions must be explicitly tested via a harness contract, where they are 'exposed' - eg, `_deployProxy` is tested via `exposed_deployProxy`. The test file is called `_deployProxy.t.sol` in behaviours.
- Every code path tested: success cases, all reverts (`revertsWhen_`), edge cases (zero/max/empty/boundary)
- One behavior per test function; tests must not depend on each other
- Test: state changes, return values, events, access control, pausability, input validation
- Reversion test cases come last in a test file

### Directory Structure

All test files use `.t.sol` extension. Harnesses use `.sol`.

```
test/
├── {ContractName}/
│   ├── {ContractName}.t.sol        # Base test (setUp, helpers, test_setUp)
│   ├── behaviors/
│   │   ├── {fn}.t.sol              # Public function tests
│   │   └── _{fn}.t.sol             # Internal function tests
│   ├── integration/                 # Fork tests
│   ├── scenario/                    # Simulation tests
│   └── invariant/
│       ├── {Context}.t.sol         # Runnable suite, e.g., Local.t.sol
│       └── support/                # Shared bases and fuzz handlers
│           ├── InvariantBase.sol
│           └── Handler.t.sol
└── harness/
    └── {ContractName}Harness.sol   # Exposes internals via exposed_{fn}()
```

### Naming

**Contracts:** `{Contract}Test` (base), `{Contract}_{fn}` (behavior), `{Contract}__{fn}` (internal), `{Contract}Harness`

**Test functions:**
```
test_{fn}_{behavior}()
test_{fn}_revertsWhen_{condition}()
test_exposed_{fn}_{behavior}()
test_simulation_{scenario}()
test_setUp()
invariant_{description}()
```

**Helpers (internal):** `_stakeFor()`, `_timeskip()`, `_deploy{Contract}()`, `_assertEq{Type}()`, `_assertInvariant_{desc}()`

### Base Test Structure

```solidity
/// @title {ContractName} Base Test
/// @dev Base contract for testing {ContractName}
contract {ContractName}Test is Test {
    struct Actor { address account; bytes32[] proof; }

    {ContractName}Harness public pool;
    ERC20Mock public mockToken;

    address public ADMIN = makeAddr("admin");
    address public ALICE = makeAddr("alice");
    uint256 public constant STAKE_AMOUNT = 10 ether;

    Actor alice = Actor({ account: ALICE, proof: aliceProof });

    function setUp() public virtual { /* deploy, configure, mint */ }
    function test_setUp() public view virtual { /* assert setup */ }
    function _stakeFor(Actor memory actor, uint256 amount) internal { ... }
}
```

### setUp Inheritance

| Type | Pattern |
|------|---------|
| Behavior | Inherit as-is |
| Scenario | `super.setUp()` + config overrides |
| Integration | Full override with `vm.createSelectFork()` |
| Invariant | Own setUp + `handler` + `targetContract()` |

### Test Patterns

```solidity
// State change: before/after delta
uint256 before = token.balanceOf(addr);
_action();
assertEq(before - token.balanceOf(addr), expected);

// Revert
vm.expectRevert(Error.selector);
// or: vm.expectRevert(abi.encodeWithSelector(Error.selector, param));
contract.fn();

// Access control
vm.prank(NON_ADMIN);
vm.expectRevert(abi.encodeWithSelector(
    IAccessControl.AccessControlUnauthorizedAccount.selector, NON_ADMIN, ROLE));
pool.adminFn();

// Events
vm.recordLogs();
contract.fn();
Vm.Log[] memory logs = vm.getRecordedLogs();
assertEq(logs[0].topics[0], Event.selector);
```

### Cheatcodes

| Code | Use |
|------|-----|
| `vm.prank(a)` / `vm.startPrank(a)` | Impersonate |
| `vm.expectRevert(sel)` | Assert revert |
| `vm.warp(t)` / `vm.roll(n)` | Set time/block |
| `deal(tok, a, amt)` | Set balance |
| `vm.recordLogs()` | Capture events |
| `vm.createSelectFork(rpc, blk)` | Fork |
| `bound(v, min, max)` | Bound fuzz input |

---

## Solidity Style Guide

### Contract Layout Order

1. License header (AGPL-3.0-or-later, full copyright block)
2. `pragma solidity ^0.8.33;`
3. Imports
4. Contract body: `using` declarations → constants → constructor → `receive`/`fallback` → internal overrides → external functions → public functions → internal functions → private functions

### Function Ordering

Ordering is **section-based**: functions are grouped by role under the ASCII section
banners such as `INTERNAL OVERRIDES`, `EXTERNAL`, and `INTERNALS`. Within each section they
follow the [Solidity style guide](https://docs.soliditylang.org/en/latest/style-guide.html#order-of-functions)
visibility order (state-changing before view/pure). The canonical section sequence is:

1. `constructor`
2. `receive()` / `fallback()`
3. Internal overrides (e.g., `_guardInitializeOwner`, `_authorizeUpgrade`)
4. External functions (state-changing)
5. External view/pure functions
6. Public functions (state-changing)
7. Public view/pure functions
8. Internal functions
9. Private functions

**Deliberate deviations on the large SHRINCS contracts** (`ShrincsWallet`, `ShrincsPaymaster`,
`WalletFactory`): the base-contract override surface (Solady `Ownable`/`ERC4337`/UUPS) stays
together in the overrides section even when an individual override is `public`/`external`. For
example, `ShrincsWallet` groups `execute`, `executeBatch`, `delegateExecute`, and `storageStore`
with `_authorizeUpgrade` and `_validateSignature` rather than in the public section. Private
helpers group by concern within the internals section — `_statelessRotate` is placed with the
verify helpers rather than last. `WalletFactory` keeps `_authorizeUpgrade` with its other
internals near the file end. Rationale: on these security contracts, adjacency of each override and
its helpers keeps the code auditable and preserves git blame. A strict global visibility sort would
fragment both.

### Import Style

- **Named imports** preferred: `import {Foo} from "path";`
- **Aliases** for disambiguation: `import {WOTSPlusCodec as Codec} from "./WOTSPlusCodec.sol";`
- **Wildcard** only for heavy external deps: `import "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";`
- **Order:** external versioned deps → named solady/oz imports → local interfaces → local contracts/libraries

### Naming Conventions

| Element | Style | Example |
|---------|-------|---------|
| Contracts, Structs, Enums | PascalCase | `QuipWallet`, `Layout` |
| Errors | PascalCase, no "Error" suffix | `InvalidPqOwner`, `InsufficientBalance` |
| Events | PascalCase for lifecycle, camelCase for domain operations | `WalletInitialized`, `pqTransfer` |
| Functions, Variables | camelCase | `changePqOwner`, `totalSupply` |
| Constants | UPPER_CASE | `MAX_RECOVERY_KEYS` |
| Private storage slots | _UPPER_CASE | `_WOTSPLUS_STORAGE_SLOT` |
| Internal/private functions | `_leadingUnderscore` | `_addRecoveryKeys` |
| Params shadowing state/reserved | `trailingUnderscore_` | `factory_` |
| Storage layout variable | `$` | `Storage.Layout storage $` |

### Modifier Order on Declarations

`visibility` → `mutability` → `override` → custom modifiers → `returns`

```solidity
function foo() public payable override onlyOwner returns (uint256)
```

### NatSpec

- Interfaces get full NatSpec: `@title`, `@notice`, `@dev`, `@param`, `@return`
- Implementations use `@inheritdoc IContractName` to avoid duplication
- Errors and events documented in the interface, not the implementation
- `@custom:storage-location` annotation on ERC-7201 storage structs

### Section Dividers

Use decorative ASCII banners for major sections within a contract:

```
/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                      SECTION NAME                             */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
```

### Storage Pattern (ERC-7201)

- Namespace storage via a dedicated library (e.g., `WOTSPlusStorage`) with a `Layout` struct
- Access via `Storage.layout()` returning `Layout storage $`
- Storage slot derived from `keccak256(abi.encode(uint256(keccak256("namespace")) - 1)) & ~bytes32(uint256(0xff))`
- Dollar sign `$` is the conventional name for the storage pointer

### Code Layout

- 4-space indentation
- Opening brace on same line as declaration
- Long function signatures: one parameter per line, closing `)` on its own line
- Formatting enforced by Prettier (`prettier-plugin-solidity`); run `make format`
- Custom errors preferred over `require` strings
- Errors defined in interfaces, not implementations

### Interface Structure

- Separate file per interface in `contracts/interfaces/`
- Layout: errors → events → function signatures
- Full NatSpec on every public element
