# sorowatch-contract

Soroban smart contract for SoroWatch — an on-chain risk registry with
role-based agent authorization and persistent flag history.

## What's implemented
- `initialize(admin, default_threshold)` — one-time setup
- `authorize_agent(admin, agent, role)` — assigns Monitor or Responder role
- `get_role(agent)` — reads an agent's assigned role
- `flag_anomaly(agent, subject, score)` — Responder-only; persists the flag
  (capped at 50 per subject, oldest dropped) and emits a `flagged` event
- `get_flags(subject)` — returns the persisted flag history for an address
- `get_threshold()` — reads the configured risk threshold

## Test coverage
8 tests covering: initialization, double-initialize rejection, successful
flagging by a Responder, rejection of flagging by a Monitor, rejection of
flagging by an unauthorized address, multiple flags accumulating correctly,
the history cap dropping the oldest entry, and role lookup for unknown
addresses.

## Build
```
cargo build --target wasm32-unknown-unknown --release
```

## Test
```
cargo test
```
