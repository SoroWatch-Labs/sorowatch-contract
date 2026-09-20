# Contributing to sorowatch-contract

## Setup
```
cargo build --target wasm32-unknown-unknown --release
cargo test
cargo clippy --all-targets
```

## Before opening a PR
- Run the commands above and make sure they pass.
- Add tests for any new entrypoint or behavior change.
- Keep the PR scoped to one issue; reference it with `Closes #N`.

## Related repos
- sorowatch-ai-agent — scores addresses and calls this contract
- sorowatch-backend — API layer coordinating the agent and this contract
- sorowatch-frontend — dashboard reading data derived from this contract
