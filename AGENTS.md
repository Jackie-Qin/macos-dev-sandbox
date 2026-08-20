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
- Keep one persistent owned clone and one stable no-follow lease per worktree. The lease belongs under the registry `.locks/` directory, outside the deletable per-worktree root, and must cover create-to-run plus all cleanup mutations.
- Never infer simulator ownership from a `dev-sandbox-` name alone. Present-but-untrusted metadata must block overwrite and cleanup. Automated pruning requires a complete canonical owner inventory beneath component-wise no-follow, current-user-owned registry/sandbox directories; regular current-user-owned single-link metadata and locks; an exact live name/UDID/runtime match; shutdown state; a nonblocking worktree lease; and fresh process/open-file/Apple-lane rechecks. Recheck the complete registry after acquiring the lease.
- Simulator pruning is dry-run by default. Live pruning uses `simctl delete` for one exact UDID at a time, verifies disappearance from the complete device registry, and retires metadata and sandbox roots through identity-bound directory FDs. Restore a retired root if deletion is not verified, preserve canonical replacements, and never recursively delete a substituted retired path.
- If a newly cloned device cannot be registered safely, revalidate and delete only that returned exact UDID, then verify disappearance. Never leave an unregistered clone silently.
- The `ios build` lane must remain build-only: direct `xcodebuild`, `build-for-testing`, and exactly `generic/platform=iOS Simulator`. It must not boot Simulator or accept caller-supplied DerivedData, cloned-package, or result-bundle output paths.
- Package seeding clones only `SourcePackages` between two safe sandbox roots via `clonefileat` with no-follow descriptors: the seed lease is acquired nonblocking, the target must be empty, and a failed clone restores the empty directory. Never seed DerivedData, result bundles, or simulator state, and never weaken the ownership checks to make a seed succeed.
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
uvx ruff check .
uvx ruff format --check .
git diff --check
```

- For Simulator lifecycle changes, also exercise one disposable or owned device and verify only that exact UDID changed state.
- Do not commit `.venv`, bytecode, local adapters, result bundles, DerivedData, package clones, logs, or machine-local launchers.
