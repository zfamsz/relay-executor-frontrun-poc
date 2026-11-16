# RelayExecutor front-run PoC — unbound `callResolver`

A proof-of-concept for a bug bounty report to Relay
([support@relay.link](mailto:support@relay.link)).

## The vulnerability

`RelayExecutor.execute()` is permissionless: anyone may submit an
oracle-signed `ExecuteAndWithdrawRequest` and choose **any**
`callResolver` and `callResolverData`. The oracle's EIP-712 signature
commits to the request fields (amounts, chains, receiver, nonce,
deadline) but **not** to the resolver or its calldata, and `execute()`
has no caller authentication and no resolver allowlist.

Because a solver's settlement transaction is public in the mempool,
an unprivileged attacker can read the signed request and signature,
front-run the settlement with a malicious resolver, swap only enough
input to produce exactly `outAmountMinimum`, and keep the rest of the
funded input (the spread) as Hub tokens. The executor finalises with
only the minimum, so the receiver (the solver being reimbursed for
capital it fronted) receives the minimum instead of the full output,
and the solver's legitimate settlement then reverts with
`RequestAlreadyExecuted`. The attacker converts the stolen Hub tokens
into a real withdrawal via the `RelayAllocator`.

The loss per order is bounded to (expected output − `outAmountMinimum`),
but it is repeatable on every settlement that uses a non-committing
resolver — a systematic drain of solver margin.

## Affected contracts / deployment

- Repository: https://github.com/relayprotocol/relay-settlement
  (commit `b2f3e0e5fba9381293f030ef340ffb4872687fcf`, v0.0.7, 11 Sep 2026)
- Chain: Relay Chain mainnet, chain ID `537713`
- `RelayExecutor` (production): `0x6747c7e64b90dccc0d54f865cbd9513156adbc0c`
- `BasicCallResolver` (production): `0xb24ac15b9da6d88e283ffe048befe02e188ea64e`
- `RelayHub` (production): `0xDDD361727C22A01EB137880678A20b0BEaE69318`
- `RelayAllocator` (production): `0x613D3c588F6B8f89302b463F8F19f7241B2857E2`

Production relevance: the generic `BasicCallResolver` is the resolver
deployed in the production configuration
(`smart-contracts/deployments/contracts/prod.json`,
`utils.basicCallResolver`) and no `PoolDrawResolver` is present in that
production configuration. Real production `execute()` calls used it as
the `callResolver` — for example, on 21 Sep 2026 (Relay Chain blocks
4964095–4965238):

- `0xba81d2d735fbc027c16d0a3bca7f90674fc07a03a5c176a250a141071681dc5b`
- `0xd2d51c0224df05fadb8ddfe837585e3c248ddceeab2b8d3989c52802f31fc192`
- `0x5a3462a233df6b05ba8e753abd83530bd881e799c6beac3db8df7547fe887ae8`

## Running the PoC

Prerequisites: [Foundry](https://book.getfoundry.sh/getting-started/installation)
(`forge`, `cast`).

```shell
git clone https://github.com/zfamsz/relay-executor-frontrun-poc.git
cd relay-executor-frontrun-poc
forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts
forge test --match-contract FrontRunPoC -vvv
```

The project vendors exact copies of the Relay contract sources
(`RelayExecutor`, `RelayHub`, `RelayAllocator`, `ERC20View`, `Utils`,
`BasicCallResolver`, `ICallResolver`) in `src/`, plus OpenZeppelin and
forge-std as dependencies (OpenZeppelin pinned to v5.7.0 in
`foundry.lock`).

## Expected result

2/2 tests pass:

- `test_honestSolverReceiverGetsFullOutput` (baseline): the honest
  resolver swaps everything; the receiver's withdrawal is the full
  **1000**.
- `test_frontRunStealsSpread` (attack): the receiver's withdrawal is
  only the minimum **950**; the attacker keeps **50** input Hub tokens;
  the legitimate settlement reverts with `RequestAlreadyExecuted`; the
  attacker converts the 50 into a real Allocator withdrawal payload
  (`allocator.payloads(stealHash).length > 0`, spender alias burned to 0).

## Suggested fix

Bind the resolver and its calldata to the oracle-signed request: add
`callResolver` and `callResolverData` — or their hash — to the
`ExecuteAndWithdrawRequest` struct and the EIP-712 typehash, so a
front-runner cannot substitute a different resolver. Alternatives:
require the resolver to be allowlisted, or require every resolver to
commit its plan via the request nonce (the `PoolDrawResolver` pattern,
which already exists in the codebase) for all resolver types.

## Disclosure

This repository is the runnable PoC accompanying a responsible
disclosure to the Relay team. It targets vendored copies of Relay's
own contracts in a local Foundry environment only; it does not interact
with any live network.
