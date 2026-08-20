# macos-dev-sandbox

A small, least-authority development sandbox for Apple-silicon Macs.

It deliberately separates two execution models:

- **OCI web/backend workloads** run inside Apple `container` or Docker from a fresh sanitized staging copy. Host environment variables, SSH agents, cloud credentials, home directories, `.env*`, package credentials, and host dependency caches are not inherited.
- **Xcode/iOS workloads** stay host-native because Xcode and Simulator require macOS. The tool gives each worktree isolated DerivedData, result, log, Swift-package clone, and owned cloned-simulator state.

This is not a production deployment tool. Commands containing deployment or production-mutation terms are denied unless `--allow-dangerous-command` is explicitly supplied.

## Requirements

- macOS 26 on Apple silicon for Apple `container`
- Python 3.11+
- Apple `container` 0.9+ or Docker for the OCI lane
- Xcode command-line tools for the iOS lane

## Quick start

```bash
python3 -m macos_dev_sandbox.cli doctor

# Print the exact isolated web command without running it.
python3 -m macos_dev_sandbox.cli web plan \
  --repo /path/to/web-worktree -- sh -lc 'npm ci && npm test'

# Run it through Apple container.
python3 -m macos_dev_sandbox.cli web run \
  --repo /path/to/web-worktree --engine apple -- sh -lc 'npm ci && npm test'

# Prepare isolated host-native Xcode state.
python3 -m macos_dev_sandbox.cli ios prepare --repo /path/to/ios-worktree
source "$(python3 -m macos_dev_sandbox.cli ios env-path --repo /path/to/ios-worktree)"

# Optionally seed the new sandbox's Swift-package checkouts from a warm
# sibling sandbox. The APFS copy-on-write clone is near-instant and shares
# disk blocks until the checkouts diverge, skipping the cold re-checkout.
python3 -m macos_dev_sandbox.cli ios prepare --repo /path/to/new-worktree \
  --seed-packages-from /path/to/warm-worktree

# Create/reuse one worktree-owned clone, lease it, boot it, run a command,
# then shut down only that exact UDID.
python3 -m macos_dev_sandbox.cli ios run \
  --repo /path/to/ios-worktree \
  --source-simulator "iPhone 17 Pro Max" -- \
  sh -lc 'xcodebuild -scheme App -destination "$DEV_SANDBOX_XCODE_DESTINATION" test'

# Build test artifacts without booting Simulator. This lane accepts only raw
# xcodebuild build-for-testing with the generic iOS Simulator destination and
# injects isolated DerivedData, Swift-package clone, and xcresult paths.
python3 -m macos_dev_sandbox.cli ios build \
  --repo /path/to/ios-worktree -- \
  xcodebuild -project App.xcodeproj -scheme App \
  -destination 'generic/platform=iOS Simulator' -jobs 4 build-for-testing

# Inspect stale worktree-owned simulator clones. This is dry-run by default.
python3 -m macos_dev_sandbox.cli ios prune --max-idle-days 7

# Delete only candidates that still pass the exact-UDID, shutdown, lease,
# process-reference, open-file, and host-idle rechecks.
python3 -m macos_dev_sandbox.cli ios prune --max-idle-days 7 --live
```

For editable installation:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Security model

The OCI lane defaults to:

- one writable bind mount: a disposable sanitized copy of the selected worktree
- a named volume over `node_modules`, preventing Linux dependencies from contaminating the macOS worktree
- read-only container root filesystem
- tmpfs for `/tmp` and package-manager cache
- no host environment inheritance
- no `.env` loading
- no SSH-agent forwarding
- bounded CPU and memory
- deployment/production command denial

This protects accidental host access and credential leakage. It is not a defense against kernel or container-runtime vulnerabilities.

Container-side writes are disposable and do not flow back to the Git worktree. Edit source in the worktree; use the OCI lane for dependency installation, tests, builds, and local servers.

The Xcode lane cannot provide the same security boundary. It isolates build and simulator state, uses exact-UDID destinations, leases one persistent clone per worktree, and never performs host-wide simulator shutdown. Host-native processes still retain the permissions of the macOS user, and CoreSimulator remains a per-login shared service. Use a dedicated macOS account or VM for untrusted code or a hard CoreSimulator boundary.

Owned simulator metadata records the canonical worktree path, exact UDID and name, runtime, source UDID, creation time, and last-use time. Registry and per-worktree roots must be current-user-owned, nonsymlinked directories reached component-by-component with no-follow directory descriptors; metadata, locks, environment output, metadata retirement, and sandbox retirement/removal stay relative to those bound descriptors. Existing metadata and lock files must also be regular, current-user-owned, and single-linked. A present but malformed, misplaced, mismatched, hardlinked, or incompletely inventoried owner record blocks live pruning rather than being treated as absent. Each worktree's lease lives under the stable registry `.locks/` directory, outside the deletable sandbox root, and is held continuously across prepare/create/run/build/cleanup or acquired nonblocking by prune. `ios prune` validates the complete registry and rechecks it after lease acquisition. A device must still match its exact record, use the `dev-sandbox-` namespace, be shutdown, be stale for the configured interval (or have a missing owner worktree), and have no Apple build activity, process reference, or open file. Live deletion uses only `xcrun simctl delete <exact-UDID>`, verifies that the UDID disappeared from the complete device registry, and revalidates owner-record identity before FD-relative metadata retirement. Device creation revalidates the returned clone's exact name/runtime and deletes that exact UDID if ownership registration fails. Devices without trustworthy ownership metadata are protected rather than inferred from their names.

Xcode's own parallel-testing workers may create additional transient clones. Per-worktree clones prevent accidental device reuse but do not namespace CoreSimulator itself.

Package seeding clones only the `SourcePackages` directory between two validated sandbox roots, using `clonefileat` behind no-follow descriptors. The seed sandbox's lease is acquired nonblocking (an active lane refuses the seed), the target must hold an empty `SourcePackages`, and a failed clone restores the empty directory. DerivedData is never seeded: Xcode keys intermediates to source paths, so cross-worktree DerivedData reuse mostly misses while silently spending disk.

The build-only lane is intentionally narrower than `ios run`: it does not boot Simulator and rejects commands unless they are raw `xcodebuild build-for-testing` invocations with the exact generic iOS Simulator destination. Caller-supplied `-derivedDataPath`, `-clonedSourcePackagesDirPath`, and `-resultBundlePath` options—including `-option=value` forms—are rejected so artifact writes cannot escape the validated sandbox. This makes bounded concurrent compilation possible without changing a repository's normal test wrapper or lock policy.

### Qualified concurrency policy

On the 32 GiB reference host with Xcode 26.3:

- Two cold, isolated `build-for-testing` sessions completed concurrently when each was capped at `-jobs 4`. Both produced independent xcresults. Treat two concurrent lanes as an explicit resource-intensive mode, not the default; memory remained available but swap approached saturation.
- One serial `test-without-building` session using the generated `.xctestrun`, one exact owned UDID, and `-parallel-testing-enabled NO` completed successfully.
- Two equivalent `test-without-building` sessions on separate owned clones both stalled before launching their test hosts. Therefore simulator-backed Xcode execution remains host-serialized. Do not weaken an existing host-wide simulator/test lock.

Recommended pipeline: bounded generic `build-for-testing` may run concurrently across worktrees; prebuilt `.xctestrun` execution must run serially on one owned clone at a time.

## Public/private adapters

The core contains no company paths, project IDs, secrets, or deployment credentials. Keep machine- or company-specific launchers outside the repository. If a local wrapper needs a small configuration file, `adapters/example.toml` documents a suggested shape and `adapters/*.local.toml` is ignored by Git.

The CLI does not load adapter TOML files directly; they are an integration convention for local wrappers. Publish from Git's tracked file set rather than archiving the raw working directory.

## Agent and team use

`AGENTS.md` is the repository-local contract for coding agents and teammates. It records the security invariants, qualified concurrency limits, and required verification commands. Keep durable team rules there or in ordinary repository docs rather than relying on a private agent skill.

Personal agent setups may add a thin `macos-dev-sandbox` skill that routes to this repository, but `AGENTS.md` and this README remain canonical for every clone.

## Status

Stage B adds a constrained build-only lane and measured concurrency qualification. Publishing a remote repository, CI, release signing, parallel simulator-backed Xcode execution, and stronger macOS-account/VM isolation remain separate decisions.
