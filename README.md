# sorowatch-contract

Soroban smart contract for SoroWatch — an on-chain risk registry with
role-based agent authorization and persistent flag history.

## What's implemented
- `initialize(admin, default_threshold)` — one-time setup
- `authorize_agent(admin, agent, role)` — assigns Monitor or Responder role
- `revoke_agent(admin, agent)` — removes an agent's role and emits `revoked`
- `get_role(agent)` — reads an agent's assigned role
- `flag_anomaly(agent, subject, score)` — Responder-only; persists the flag
  (capped at 50 per subject, oldest dropped) and emits a `flagged` event
- `get_flags(subject)` — returns the persisted flag history for an address
- `get_threshold()` — reads the configured risk threshold
- `pause(admin)` / `unpause(admin)` — admin-only switch that blocks
  `flag_anomaly` while paused (emits `paused` / `unpaused`); reads and admin
  actions keep working. `is_paused()` reads the current state
- `propose_admin(admin, new_admin)` / `accept_admin(new_admin)` /
  `cancel_admin_transfer(admin)` — two-step admin handover. Nothing changes
  until the new admin accepts, and the old admin loses the role at that
  moment. `get_admin()` and `get_pending_admin()` read the current state
- `propose_upgrade` / `cancel_upgrade` / `execute_upgrade` — admin-only
  upgrade path with a 17,280-ledger (about 1 day) delay between proposing and
  executing; `get_pending_upgrade()` shows what is queued

## Test coverage
36 tests covering: initialization and double-initialize rejection; flagging
by Responders and rejection for Monitors and unauthorized addresses; flag
history accumulation and the 50-entry cap; role lookup and `revoke_agent`;
the timelocked upgrade flow (propose, cancel, delay not elapsed, admin
checks); the pause switch (default state, blocked flagging, unpause,
admin-only access, admin actions while paused); and the two-step admin
transfer (acceptance required, wrong address rejected, old admin loses
rights, cancel, re-propose, events).

## Build
```
cargo build --target wasm32-unknown-unknown --release
```

## Test
```
cargo test
```
