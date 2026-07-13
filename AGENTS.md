# Agent guide

## Scope

This repository provides two deliberately different development-isolation lanes:

- OCI execution for container-friendly web/backend commands.
- Host-native Xcode execution with worktree-isolated artifacts and owned Simulator devices.

Read `README.md` before changing either boundary.

## Safety invariants

- Never mount a developer home directory, SSH agent, credential directory, or package credential file into the OCI lane.
- Keep repository-local `.env*`, `.npmrc`, `.yarnrc`, `.git`, `.codegraph`, dependency folders, and generated caches out of staging copies.
- Never treat the Xcode lane as a security boundary; host-native commands retain the current macOS user's authority.
- Address Simulator devices by exact UDID. Never add host-wide Simulator shutdown or deletion.
- Keep one persistent owned clone and one lease per worktree.
- The `ios build` lane must remain build-only: direct `xcodebuild`, `build-for-testing`, and exactly `generic/platform=iOS Simulator`. It must not boot Simulator.
- Do not weaken a project's existing host-wide simulator/test lock. Separate clones do not namespace CoreSimulator.
- Machine-, company-, and project-specific configuration belongs outside the repository or in ignored `adapters/*.local.toml` files. Public files must not contain personal paths, device UDIDs, project IDs, bundle IDs, signing teams, credentials, or proprietary project names.

## Qualified concurrency policy

- At most two concurrent generic `build-for-testing` lanes, capped at `-jobs 4` per lane, are the measured safe default for a 32 GiB reference host.
- Simulator-backed Xcode execution remains serialized. Concurrent prebuilt test sessions on separate owned clones stalled before test-host launch during qualification.
- Re-qualify on the target host/Xcode version before raising concurrency or enabling Xcode parallel test workers.

## Changes and verification

- Match the standard-library-only Python style already present.
- Add focused `unittest` coverage for policy and command-construction changes.
- Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m compileall -q src tests
git diff --check
```

- For Simulator lifecycle changes, also exercise one disposable or owned device and verify only that exact UDID changed state.
- Do not commit `.venv`, bytecode, local adapters, result bundles, DerivedData, package clones, logs, or machine-local launchers.
