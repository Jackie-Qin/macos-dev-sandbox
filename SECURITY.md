# Security policy

## Supported versions

Security fixes are applied to the latest released version and the default branch.

## Reporting a vulnerability

Please use the repository host's private security-advisory channel. Do not open a public issue for credential exposure, sandbox escapes, unsafe host mounts, destructive Simulator behavior, or production-command bypasses.

A useful report includes:

- affected version or commit;
- operating system and runtime versions;
- the exact command or configuration that crosses the documented boundary;
- a minimal reproduction without real credentials or proprietary source;
- expected and observed behavior.

## Security boundaries

### OCI lane

The OCI lane reduces accidental host access by using a sanitized source copy, no inherited host environment, no credential mounts, a read-only container root, and bounded resources. It is not a defense against vulnerabilities in the host kernel, virtualization stack, or container runtime.

### Xcode lane

The Xcode/Simulator lane is state isolation, not a hostile-code sandbox. Xcode must run on macOS and retains the current user's filesystem and Keychain authority. Use a separate macOS account, virtual machine, or dedicated host for untrusted code.

Worktree-owned Simulator clones prevent accidental device reuse; they do not create a separate CoreSimulator service namespace. Simulator-backed test execution should remain host-serialized unless re-qualified on the target host.

### Out of scope

- vulnerabilities in Apple Xcode, CoreSimulator, Apple Container, Docker, or the guest image itself;
- malicious code intentionally granted host-native Xcode execution;
- secrets explicitly placed in source files before staging;
- production actions explicitly allowed through a dangerous-command override.
