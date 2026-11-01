# Agent Terrier contributor instructions

Use descriptive variable names and minimal comments. Use jj for version control and isolated, task-owned workspaces. Preserve unrelated edits.

## Source ownership

This repository owns shared product code, contracts, wire types, client libraries, UI components and local development tools. See docs/arch.md for the component inventory and migration status.

Keep firmware, hardware build/flash/OTA assets, full operator consoles, deployment account configuration, production wallets and secrets outside this repository. Do not import another repository's history or internal documentation. Author public docs from reviewed public behavior and synthetic examples.

Every cross-component schema has one owner. Native and browser clients consume the same generated definitions. Keep independent authorization enforcement at each trust boundary.

## Security

The chain is the authority for identity and grants. The broker must not acquire durable authority or sign owner transactions. Keys stay with their actor. No ambient authority over user data. Keep readable personal data off-chain.

Never add a silent local allow-all mode, weaken an isolation test or copy credential material into fixtures. Development identities must be explicitly marked and rejected by production configurations.

Before any public push, review the entire diff, run python3 scripts/check-public.py, and inspect added artifacts. The scanner is a minimum gate, not proof that a payload contains no confidential data. Never print detected secret values.

## Verification

Run focused checks for the changed behavior before publishing. Run cargo fmt --all before committing. For Rust changes use cargo clippy --workspace --all-targets -- -D warnings and the affected tests. Negative security tests need an authorized positive control, a specific denial and proof of no unauthorized side effect.

Do not claim a full local release before real-chain, Docker, real-model and independent clean-install acceptance pass. Each PR reports What landed and What did NOT land. Keep incomplete issues open.

## Documentation

docs/arch.md owns the component inventory. docs/wiki is the sole wiki source; pages have no YAML frontmatter or redundant leading H1. Generate reference material from canonical public code where possible.
