from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, TypedDict

DEFAULT_IMAGE = "docker.io/library/node:24-bookworm-slim"
CONTROL_COMMAND_TIMEOUT_SECONDS = 30
TRUSTED_XCODEBUILD = "/usr/bin/xcodebuild"


@dataclass(frozen=True)
class RetiredSandboxRoot:
    path: Path
    device: int
    inode: int
    owner: int
    parent_device: int
    parent_inode: int


RENAME_EXCL = 0x00000004
RENAME_SWAP = 0x00000002
RENAME_NOFOLLOW_ANY = 0x00000010

XCODE_PATH_ENVIRONMENT_KEYS = frozenset(
    {
        "BUILD_DIR",
        "BUILD_PRODUCTS_DIR",
        "BUILD_ROOT",
        "BUILT_PRODUCTS_DIR",
        "CACHE_ROOT",
        "CONFIGURATION_BUILD_DIR",
        "CONFIGURATION_TEMP_DIR",
        "DERIVED_FILES_DIR",
        "DERIVED_FILE_DIR",
        "DERIVED_SOURCES_DIR",
        "DSTROOT",
        "MODULE_CACHE_DIR",
        "OBJECT_FILE_DIR",
        "OBJECT_FILE_DIR_normal",
        "OBJROOT",
        "PROJECT_TEMP_DIR",
        "PROJECT_TEMP_ROOT",
        "PROJECT_DIR",
        "PROJECT_FILE_PATH",
        "SOURCE_ROOT",
        "SRCROOT",
        "SHARED_PRECOMPS_DIR",
        "SYMROOT",
        "TARGET_BUILD_DIR",
        "TARGET_TEMP_DIR",
        "TEMP_DIR",
        "TEMP_FILES_DIR",
        "TEMP_ROOT",
        "WORKSPACE_PATH",
        "XCODE_XCCONFIG_FILE",
    }
)


DANGEROUS_TERMS = (
    "deploy",
    "firebase use prod",
    "firebase use production",
    "firebase deploy",
    "wrangler deploy",
    "cf:deploy",
    "app-store",
    "appstore",
    "asc submit",
    "fastlane deliver",
)


class SandboxError(RuntimeError):
    pass


class PruneResult(TypedDict):
    live: bool
    max_idle_days: int
    candidates: list[dict[str, object]]
    protected: list[dict[str, object]]
    deleted: list[dict[str, object]]


def run_checked(
    argv: list[str], *, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            text=True,
            check=True,
            capture_output=capture,
            timeout=CONTROL_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise SandboxError(
            f"control command timed out after {CONTROL_COMMAND_TIMEOUT_SECONDS} seconds"
        ) from error


def run_quiet_control(argv: list[str], *, operation: str) -> None:
    try:
        subprocess.run(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=CONTROL_COMMAND_TIMEOUT_SECONDS,
            check=True,
        )
    except subprocess.TimeoutExpired as error:
        raise SandboxError(f"{operation} timed out") from error
    except subprocess.CalledProcessError as error:
        raise SandboxError(f"{operation} failed") from error


def git_root(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_dir():
        raise SandboxError(f"repository does not exist: {resolved}")
    try:
        result = run_checked(
            ["git", "-C", str(resolved), "rev-parse", "--show-toplevel"], capture=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise SandboxError(f"not a Git worktree: {resolved}") from exc
    root = Path(result.stdout.strip()).resolve()
    if root != resolved:
        raise SandboxError(f"pass the worktree root, not a subdirectory: {root}")
    return root


def ensure_safe_command(command: list[str], allow_dangerous: bool) -> None:
    if not command:
        raise SandboxError("a command is required after --")
    normalized = " ".join(command).lower()
    match = next((term for term in DANGEROUS_TERMS if term in normalized), None)
    if match and not allow_dangerous:
        raise SandboxError(
            f"refusing command containing '{match}'; use --allow-dangerous-command only in an approved operator lane"
        )


def selected_engine(requested: str) -> str:
    if requested != "auto":
        binary = "container" if requested == "apple" else "docker"
        if shutil.which(binary) is None:
            raise SandboxError(f"{binary} is not installed")
        return requested
    if shutil.which("container"):
        return "apple"
    if shutil.which("docker"):
        return "docker"
    raise SandboxError("neither Apple container nor Docker is installed")


def workspace_id(repo: Path) -> str:
    canonical_repo = repo.resolve(strict=False)
    digest = hashlib.sha256(str(canonical_repo).encode()).hexdigest()[:12]
    return f"dev-sandbox-{canonical_repo.name.lower()}-{digest}"


def dependency_volume(repo: Path) -> str:
    return f"{workspace_id(repo)}-node-modules"


def web_workspace(repo: Path) -> Path:
    web_registry = simulator_registry_root().with_name(
        f"{simulator_registry_root().name}-web"
    )
    return web_registry / workspace_id(repo) / "WebWorkspace"


def web_workspace_lock_path(repo: Path) -> Path:
    web_registry = simulator_registry_root().with_name(
        f"{simulator_registry_root().name}-web"
    )
    return web_registry / ".locks" / f"{workspace_id(repo)}.lock"


def copy_web_directory_at(source_fd: int, destination_fd: int) -> None:
    blocked_exact = {
        ".git",
        ".codegraph",
        "node_modules",
        ".next",
        ".wrangler",
        ".turbo",
        ".npmrc",
        ".yarnrc",
    }
    for name in os.listdir(source_fd):
        if name in blocked_exact or name.startswith(".env"):
            continue
        source_child_fd = -1
        destination_child_fd = -1
        try:
            before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                os.symlink(
                    os.readlink(name, dir_fd=source_fd),
                    name,
                    dir_fd=destination_fd,
                )
                continue
            if stat.S_ISDIR(before.st_mode):
                source_child_fd = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=source_fd,
                )
                opened = os.fstat(source_child_fd)
                if opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
                    raise SandboxError("web source changed during staging")
                os.mkdir(name, mode=0o700, dir_fd=destination_fd)
                destination_child_fd = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=destination_fd,
                )
                copy_web_directory_at(source_child_fd, destination_child_fd)
                continue
            if not stat.S_ISREG(before.st_mode):
                continue
            source_child_fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=source_fd,
            )
            opened = os.fstat(source_child_fd)
            if opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
                raise SandboxError("web source changed during staging")
            destination_child_fd = os.open(
                name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                stat.S_IMODE(before.st_mode) & 0o777,
                dir_fd=destination_fd,
            )
            while chunk := os.read(source_child_fd, 1024 * 1024):
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_child_fd, view)
                    view = view[written:]
            os.fsync(destination_child_fd)
        except OSError as error:
            raise SandboxError("unsafe web workspace staging") from error
        finally:
            if destination_child_fd >= 0:
                os.close(destination_child_fd)
            if source_child_fd >= 0:
                os.close(source_child_fd)


def rename_swap_at(directory_fd: int, first: str, second: str) -> None:
    try:
        renameatx_np = ctypes.CDLL(None, use_errno=True).renameatx_np
    except AttributeError as error:
        raise OSError("renameatx_np is unavailable") from error
    renameatx_np.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx_np.restype = ctypes.c_int
    result = renameatx_np(
        directory_fd,
        os.fsencode(first),
        directory_fd,
        os.fsencode(second),
        RENAME_SWAP | RENAME_NOFOLLOW_ANY,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), second)


def remove_owned_directory_at(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
) -> None:
    child_fd = -1
    try:
        child_fd = os.open(
            name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(child_fd)
        if (
            opened.st_dev != expected.st_dev
            or opened.st_ino != expected.st_ino
            or opened.st_uid != expected.st_uid
            or not stat.S_ISDIR(opened.st_mode)
        ):
            raise SandboxError("unsafe web workspace replacement")
        remove_directory_contents_at(child_fd, expected.st_uid, expected.st_dev)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if current.st_dev != expected.st_dev or current.st_ino != expected.st_ino:
            raise SandboxError("web workspace changed during replacement")
        os.rmdir(name, dir_fd=parent_fd)
    except OSError as error:
        raise SandboxError("unsafe web workspace replacement") from error
    finally:
        if child_fd >= 0:
            os.close(child_fd)


def _prepare_web_workspace_locked(repo: Path) -> Path:
    workspace = web_workspace(repo)
    root = require_safe_sandbox_root(workspace.parent)
    root_fd = open_owned_directory(root, "unsafe web workspace root")
    source_fd = -1
    staging_fd = -1
    staging_name = f".WebWorkspace.staging-{os.getpid()}-{secrets.token_hex(8)}"
    staging_identity: os.stat_result | None = None
    try:
        source_fd = os.open(
            repo,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.mkdir(staging_name, mode=0o700, dir_fd=root_fd)
        staging_fd = os.open(
            staging_name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=root_fd,
        )
        copy_web_directory_at(source_fd, staging_fd)
        staging_identity = os.fstat(staging_fd)
        try:
            existing = os.stat(workspace.name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            rename_exclusive_at(root_fd, staging_name, workspace.name)
            staging_name = ""
        else:
            if not stat.S_ISDIR(existing.st_mode) or existing.st_uid != os.getuid():
                raise SandboxError("unsafe web workspace replacement")
            rename_swap_at(root_fd, staging_name, workspace.name)
            published = os.stat(workspace.name, dir_fd=root_fd, follow_symlinks=False)
            displaced = os.stat(staging_name, dir_fd=root_fd, follow_symlinks=False)
            if (
                published.st_dev != staging_identity.st_dev
                or published.st_ino != staging_identity.st_ino
                or displaced.st_dev != existing.st_dev
                or displaced.st_ino != existing.st_ino
            ):
                raise SandboxError("web workspace changed during replacement")
            remove_owned_directory_at(root_fd, staging_name, existing)
            staging_name = ""
        return workspace
    except OSError as error:
        raise SandboxError("unsafe web workspace staging") from error
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        if source_fd >= 0:
            os.close(source_fd)
        if staging_name and staging_identity is not None:
            try:
                remove_owned_directory_at(root_fd, staging_name, staging_identity)
            except SandboxError:
                pass
        os.close(root_fd)


@contextmanager
def web_workspace_lease(repo: Path):
    with open_ios_lane_lock(web_workspace_lock_path(repo)) as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def prepare_web_workspace(repo: Path) -> Path:
    with web_workspace_lease(repo):
        return _prepare_web_workspace_locked(repo)


def web_command(
    *,
    repo: Path,
    command: list[str],
    engine: str,
    image: str,
    cpus: int,
    memory: str,
    port: str | None,
) -> list[str]:
    name = workspace_id(repo)
    workspace = web_workspace(repo)
    shell_command = shlex.join(command)
    if engine == "apple":
        argv = [
            "container",
            "run",
            "--rm",
            "--name",
            name,
            "--cpus",
            str(cpus),
            "--memory",
            memory,
            "--read-only",
            "--mount",
            f"type=bind,source={workspace},target=/workspace",
            "--mount",
            f"type=volume,source={dependency_volume(repo)},target=/workspace/node_modules",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/root/.npm",
            "--workdir",
            "/workspace",
            "--env",
            "CI=1",
            "--env",
            "HOME=/tmp/home",
            "--env",
            "npm_config_cache=/root/.npm",
        ]
        if port:
            argv += ["--publish", port]
        argv += [image, "/bin/sh", "-lc", shell_command]
        return argv

    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--cpus",
        str(cpus),
        "--memory",
        memory,
        "--read-only",
        "--mount",
        f"type=bind,source={workspace},target=/workspace",
        "--mount",
        f"type=volume,source={dependency_volume(repo)},target=/workspace/node_modules",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/root/.npm",
        "--workdir",
        "/workspace",
        "--env",
        "CI=1",
        "--env",
        "HOME=/tmp/home",
        "--env",
        "npm_config_cache=/root/.npm",
    ]
    if port:
        argv += ["--publish", port]
    argv += [image, "/bin/sh", "-lc", shell_command]
    return argv


def simulator_registry_root() -> Path:
    return Path.home() / "Library" / "Caches" / "macos-dev-sandbox"


def registry_root_is_safe(root: Path) -> bool:
    if not root.is_absolute():
        return False
    home = Path.home()
    candidates = [root]
    try:
        relative = root.relative_to(home)
    except ValueError:
        pass
    else:
        current = home
        candidates = [current]
        for part in relative.parts:
            current /= part
            candidates.append(current)
    for candidate in candidates:
        if candidate.is_symlink():
            return False
    existing = root
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    try:
        return existing.is_dir() and existing.stat().st_uid == os.getuid()
    except OSError:
        return False


def require_safe_registry_root(root: Path) -> Path:
    if not registry_root_is_safe(root):
        raise SandboxError(f"unsafe simulator registry root: {root}")
    return root.resolve(strict=False)


def require_safe_sandbox_root(root: Path) -> Path:
    registry_root = require_safe_registry_root(root.parent)
    if root.parent.resolve(strict=False) != registry_root or root.is_symlink():
        raise SandboxError(f"unsafe simulator sandbox root: {root}")
    if root.exists():
        try:
            if not root.is_dir() or root.stat().st_uid != os.getuid():
                raise SandboxError(f"unsafe simulator sandbox root: {root}")
        except OSError as error:
            raise SandboxError(f"unsafe simulator sandbox root: {root}") from error
    return root


def sandbox_root(repo: Path) -> Path:
    canonical_repo = repo.resolve(strict=False)
    digest = hashlib.sha256(str(canonical_repo).encode()).hexdigest()[:16]
    return simulator_registry_root() / f"{canonical_repo.name}-{digest}"


def ios_lane_lock_path(repo: Path, registry_root: Path | None = None) -> Path:
    root = registry_root or simulator_registry_root()
    name = sandbox_root(repo.resolve(strict=False)).name
    return root / ".locks" / f"{name}.lock"


def simulator_name(repo: Path) -> str:
    return workspace_id(repo)


def ios_environment(
    repo: Path,
    simulator_udid: str | None = None,
    *,
    root: Path | None = None,
) -> dict[str, str]:
    root = root or sandbox_root(repo)
    values = {
        "DEV_SANDBOX_ROOT": str(root),
        "DEV_SANDBOX_REPO": str(repo),
        "DEV_SANDBOX_DERIVED_DATA": str(root / "DerivedData"),
        "DEV_SANDBOX_RESULTS": str(root / "Results"),
        "DEV_SANDBOX_LOGS": str(root / "Logs"),
        "DEV_SANDBOX_HOME": str(root / "Home"),
        "DEV_SANDBOX_SOURCE_PACKAGES": str(root / "SourcePackages"),
    }
    if simulator_udid:
        values["DEV_SANDBOX_SIMULATOR_UDID"] = simulator_udid
        values["DEV_SANDBOX_XCODE_DESTINATION"] = (
            f"platform=iOS Simulator,id={simulator_udid}"
        )
    return values


def command_arg_value(command: list[str], option: str) -> str | None:
    values = command_arg_values(command, option)
    return values[0] if values else None


def command_arg_values(command: list[str], option: str) -> list[str]:
    values: list[str] = []
    for index, argument in enumerate(command):
        if argument == option:
            if index + 1 >= len(command):
                raise SandboxError(f"missing value for {option}")
            values.append(command[index + 1])
        elif argument.startswith(f"{option}="):
            values.append(argument.split("=", 1)[1])
    return values


def validate_ios_build_command(command: list[str]) -> None:
    if not command or command[0] not in {"xcodebuild", TRUSTED_XCODEBUILD}:
        raise SandboxError("iOS build lane requires a direct xcodebuild command")
    options_with_values = {
        "-arch",
        "-configuration",
        "-destination",
        "-destination-timeout",
        "-jobs",
        "-project",
        "-scheme",
        "-sdk",
        "-toolchain",
        "-workspace",
    }
    flag_options = {
        "-allowProvisioningDeviceRegistration",
        "-allowProvisioningUpdates",
        "-parallelizeTargets",
        "-quiet",
        "-showBuildTimingSummary",
        "-skipMacroValidation",
        "-skipPackagePluginValidation",
    }
    artifact_options = (
        "-derivedDataPath",
        "-clonedSourcePackagesDirPath",
        "-resultBundlePath",
        "-resultStreamPath",
        "-xcconfig",
        "-settingsFile",
    )
    if any(
        argument == option or argument.startswith(f"{option}=")
        for argument in command
        for option in artifact_options
    ) or any(
        argument == setting or argument.startswith(f"{setting}=")
        for argument in command
        for setting in XCODE_PATH_ENVIRONMENT_KEYS
    ):
        raise SandboxError("iOS build lane refuses caller-supplied artifact path")
    actions: list[str] = []
    index = 1
    while index < len(command):
        argument = command[index]
        if argument in options_with_values:
            if index + 1 >= len(command):
                raise SandboxError(f"missing value for {argument}")
            index += 2
            continue
        if argument in flag_options:
            index += 1
            continue
        if argument.startswith("-"):
            raise SandboxError(f"iOS build lane refuses unsupported option: {argument}")
        if "=" in argument:
            key, _, value = argument.partition("=")
            if not key or not value:
                raise SandboxError("iOS build lane refuses malformed build setting")
            index += 1
            continue
        actions.append(argument)
        index += 1
    if actions != ["build-for-testing"]:
        raise SandboxError("iOS build lane allows only the build-for-testing action")
    forbidden_actions = {
        "test",
        "test-without-building",
        "build",
        "analyze",
        "archive",
        "install",
        "installhdrs",
        "installsrc",
        "clean",
        "docbuild",
    }
    found = forbidden_actions.intersection(command)
    if found:
        raise SandboxError(f"iOS build lane refuses action: {min(found)}")
    destinations = command_arg_values(command, "-destination")
    if destinations != ["generic/platform=iOS Simulator"]:
        raise SandboxError(
            "iOS build lane requires -destination 'generic/platform=iOS Simulator'"
        )


def validate_ios_source_inputs(repo: Path, command: list[str]) -> None:
    repo_root = repo.expanduser().resolve()
    selectors = [
        (option, value)
        for option in ("-project", "-workspace")
        for value in command_arg_values(command, option)
    ]
    if len(selectors) > 1:
        raise SandboxError("iOS build lane allows at most one project or workspace")
    for option, value in selectors:
        if not value or value.startswith("-"):
            raise SandboxError(f"invalid value for {option}")
        selected = Path(value).expanduser()
        if not selected.is_absolute():
            selected = repo_root / selected
        try:
            selected.resolve().relative_to(repo_root)
        except ValueError as exc:
            raise SandboxError(
                "iOS build lane requires project/workspace inside repository"
            ) from exc


def ios_build_command(repo: Path, command: list[str]) -> list[str]:
    validate_ios_build_command(command)
    validate_ios_source_inputs(repo, command)
    values = ios_environment(repo)
    planned = command.copy()
    planned[0] = TRUSTED_XCODEBUILD
    if command_arg_value(planned, "-derivedDataPath") is None:
        planned += ["-derivedDataPath", values["DEV_SANDBOX_DERIVED_DATA"]]
    if command_arg_value(planned, "-clonedSourcePackagesDirPath") is None:
        planned += [
            "-clonedSourcePackagesDirPath",
            values["DEV_SANDBOX_SOURCE_PACKAGES"],
        ]
    if command_arg_value(planned, "-resultBundlePath") is None:
        result = Path(values["DEV_SANDBOX_RESULTS"]) / (
            f"build-for-testing_{time.strftime('%Y%m%d%H%M%S')}_{os.getpid()}.xcresult"
        )
        planned += ["-resultBundlePath", str(result)]
    return planned


def open_owned_directory(
    path: Path,
    error_message: str,
    *,
    create: bool = True,
) -> int:
    if not path.is_absolute():
        raise SandboxError(f"{error_message}: {path}")
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_fd = -1
    try:
        directory_fd = os.open(path.anchor, flags)
        for part in path.parts[1:]:
            try:
                child_fd = os.open(part, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                if not create or os.fstat(directory_fd).st_uid != os.getuid():
                    raise
                os.mkdir(part, mode=0o700, dir_fd=directory_fd)
                child_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        directory_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.getuid()
        ):
            raise OSError("directory is not owned by the current user")
    except OSError as error:
        if directory_fd >= 0:
            os.close(directory_fd)
        raise SandboxError(f"{error_message}: {path}") from error
    return directory_fd


def ensure_owned_child_directory(directory_fd: int, name: str, path: Path) -> None:
    try:
        try:
            os.mkdir(name, mode=0o700, dir_fd=directory_fd)
        except FileExistsError:
            pass
        child_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except OSError as error:
        raise SandboxError(f"unsafe simulator sandbox directory: {path}") from error
    try:
        child_stat = os.fstat(child_fd)
        if not stat.S_ISDIR(child_stat.st_mode) or child_stat.st_uid != os.getuid():
            raise SandboxError(f"unsafe simulator sandbox directory: {path}")
    finally:
        os.close(child_fd)


def validate_owned_output(directory_fd: int, name: str, error_message: str) -> None:
    try:
        output_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise SandboxError(error_message) from error
    if (
        not stat.S_ISREG(output_stat.st_mode)
        or output_stat.st_uid != os.getuid()
        or output_stat.st_nlink != 1
    ):
        raise SandboxError(error_message)


def read_owned_output_at(
    directory_fd: int, name: str, error_message: str
) -> str | None:
    file_fd = -1
    try:
        try:
            file_fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None
        file_stat = os.fstat(file_fd)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.getuid()
            or file_stat.st_nlink != 1
        ):
            return None
        with os.fdopen(file_fd, "r") as handle:
            file_fd = -1
            return handle.read()
    except OSError:
        return None
    finally:
        if file_fd >= 0:
            os.close(file_fd)


def read_owned_output(path: Path, error_message: str) -> str | None:
    try:
        directory_fd = open_owned_directory(
            path.parent,
            error_message,
            create=False,
        )
    except SandboxError:
        return None
    try:
        return read_owned_output_at(directory_fd, path.name, error_message)
    finally:
        os.close(directory_fd)


def atomic_write_owned_output_at(
    directory_fd: int,
    name: str,
    content: str,
    error_message: str,
    *,
    legacy_names: tuple[str, ...] = (),
) -> None:
    temporary_name = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    temporary_fd = -1
    temporary_stat: os.stat_result | None = None
    try:
        validate_owned_output(directory_fd, name, error_message)
        for legacy_name in legacy_names:
            validate_owned_output(directory_fd, legacy_name, error_message)
        try:
            existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        temporary_fd = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        temporary_stat = os.fstat(temporary_fd)
        if (
            not stat.S_ISREG(temporary_stat.st_mode)
            or temporary_stat.st_uid != os.getuid()
            or temporary_stat.st_nlink != 1
        ):
            raise SandboxError(error_message)
        with os.fdopen(temporary_fd, "w") as handle:
            temporary_fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if existing is None:
            rename_exclusive_at(directory_fd, temporary_name, name)
            temporary_name = ""
        else:
            rename_swap_at(directory_fd, temporary_name, name)
            published = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            displaced = os.stat(
                temporary_name, dir_fd=directory_fd, follow_symlinks=False
            )
            published_matches = (
                published.st_dev == temporary_stat.st_dev
                and published.st_ino == temporary_stat.st_ino
                and published.st_uid == temporary_stat.st_uid
                and stat.S_ISREG(published.st_mode)
            )
            displaced_matches = (
                displaced.st_dev == existing.st_dev
                and displaced.st_ino == existing.st_ino
                and displaced.st_uid == existing.st_uid
                and displaced.st_nlink == existing.st_nlink
                and stat.S_ISREG(displaced.st_mode)
            )
            if not published_matches or not displaced_matches:
                if not published_matches or not stat.S_ISREG(displaced.st_mode):
                    raise SandboxError(error_message)
                displaced_identity = (
                    displaced.st_dev,
                    displaced.st_ino,
                    displaced.st_uid,
                    displaced.st_nlink,
                )
                published_again = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                displaced_again = os.stat(
                    temporary_name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (
                    published_again.st_dev != temporary_stat.st_dev
                    or published_again.st_ino != temporary_stat.st_ino
                    or (
                        displaced_again.st_dev,
                        displaced_again.st_ino,
                        displaced_again.st_uid,
                        displaced_again.st_nlink,
                    )
                    != displaced_identity
                ):
                    raise SandboxError(error_message)
                rename_swap_at(directory_fd, temporary_name, name)
                restored = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                returned = os.stat(
                    temporary_name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (
                    (
                        restored.st_dev,
                        restored.st_ino,
                        restored.st_uid,
                        restored.st_nlink,
                    )
                    != displaced_identity
                    or returned.st_dev != temporary_stat.st_dev
                    or returned.st_ino != temporary_stat.st_ino
                ):
                    raise SandboxError(error_message)
                raise SandboxError(error_message)
            os.unlink(temporary_name, dir_fd=directory_fd)
            temporary_name = ""
    except OSError as error:
        raise SandboxError(error_message) from error
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name and temporary_stat is not None:
            try:
                current = os.stat(
                    temporary_name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (
                    current.st_dev == temporary_stat.st_dev
                    and current.st_ino == temporary_stat.st_ino
                    and current.st_uid == temporary_stat.st_uid
                ):
                    os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass


def atomic_write_owned_output(
    directory: Path,
    name: str,
    content: str,
    error_message: str,
    *,
    legacy_names: tuple[str, ...] = (),
) -> None:
    directory_fd = open_owned_directory(directory, error_message)
    try:
        atomic_write_owned_output_at(
            directory_fd,
            name,
            content,
            error_message,
            legacy_names=legacy_names,
        )
    finally:
        os.close(directory_fd)


def write_ios_environment(
    repo: Path,
    simulator_udid: str | None = None,
    *,
    root: Path | None = None,
) -> Path:
    root = require_safe_sandbox_root(root or sandbox_root(repo))
    values = ios_environment(repo, simulator_udid, root=root)
    root_fd = open_owned_directory(root, "unsafe simulator sandbox root")
    try:
        for key in (
            "DEV_SANDBOX_DERIVED_DATA",
            "DEV_SANDBOX_RESULTS",
            "DEV_SANDBOX_LOGS",
            "DEV_SANDBOX_HOME",
            "DEV_SANDBOX_SOURCE_PACKAGES",
        ):
            path = Path(values[key])
            if path.parent != root:
                raise SandboxError(f"unsafe simulator sandbox directory: {path}")
            ensure_owned_child_directory(root_fd, path.name, path)
        env_path = root / "environment.sh"
        content = (
            "\n".join(
                f"export {key}={shlex.quote(value)}" for key, value in values.items()
            )
            + "\n"
        )
        atomic_write_owned_output_at(
            root_fd,
            env_path.name,
            content,
            f"unsafe simulator sandbox output: {env_path}",
        )
    finally:
        os.close(root_fd)
    return env_path


def resolve_simulator(source: str) -> str:
    result = run_checked(
        ["xcrun", "simctl", "list", "devices", "available", "--json"], capture=True
    )
    devices = json.loads(result.stdout).get("devices", {})
    matches = [
        device
        for runtime in devices.values()
        for device in runtime
        if source in (device.get("udid"), device.get("name"))
    ]
    if len(matches) != 1:
        names = (
            ", ".join(f"{d.get('name')} ({d.get('udid')})" for d in matches) or "none"
        )
        raise SandboxError(
            f"simulator source must match exactly one available device; matches: {names}"
        )
    return str(matches[0]["udid"])


def clone_simulator(repo: Path, source: str) -> str:
    source_udid = resolve_simulator(source)
    name = simulator_name(repo)
    result = run_checked(["xcrun", "simctl", "clone", source_udid, name], capture=True)
    return result.stdout.strip()


def simulator_metadata_path(repo: Path) -> Path:
    return sandbox_root(repo) / "simulator.json"


def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def write_simulator_metadata(
    repo: Path,
    *,
    udid: str,
    source_udid: str,
    runtime: str | None = None,
    created_at: datetime | None = None,
    last_used_at: datetime | None = None,
) -> Path:
    now = utc_now()
    path = simulator_metadata_path(repo)
    registry_root = path.parent.parent
    require_safe_sandbox_root(path.parent)
    if (path.exists() or path.is_symlink()) and prune_metadata(
        path, registry_root
    ) is None:
        raise SandboxError(f"untrusted simulator metadata exists: {path}")

    payload = {
        "version": 1,
        "repo": str(repo.resolve()),
        "udid": udid,
        "source_udid": source_udid,
        "name": simulator_name(repo),
        "runtime": runtime,
        "created_at": (created_at or now).astimezone(UTC).isoformat(),
        "last_used_at": (last_used_at or now).astimezone(UTC).isoformat(),
    }
    atomic_write_owned_output(
        path.parent,
        path.name,
        json.dumps(payload, indent=2) + "\n",
        f"unsafe simulator metadata output: {path}",
        legacy_names=(path.with_suffix(".json.tmp").name,),
    )
    return path


def mark_simulator_used(repo: Path, expected_udid: str | None = None) -> None:
    metadata = trusted_simulator_metadata(repo)
    if metadata is None:
        return
    path = simulator_metadata_path(repo)
    udid = str(metadata.get("udid", ""))
    source_udid = str(metadata.get("source_udid", ""))
    if not udid or not source_udid:
        return
    if expected_udid is not None and udid != expected_udid:
        raise SandboxError("owned simulator metadata changed while lane lease was held")
    created_value = metadata.get("created_at")
    created_at = created_value if isinstance(created_value, datetime) else None
    if created_at is None:
        raise SandboxError(f"untrusted simulator metadata exists: {path}")
    write_simulator_metadata(
        repo,
        udid=udid,
        source_udid=source_udid,
        runtime=str(metadata.get("runtime")) if metadata.get("runtime") else None,
        created_at=created_at,
        last_used_at=utc_now(),
    )


def simulator_inventory(*, available_only: bool) -> dict[str, dict[str, object]]:
    command = ["xcrun", "simctl", "list", "devices"]
    if available_only:
        command.append("available")
    command.append("--json")
    result = run_checked(command, capture=True)
    if result.stderr:
        raise SandboxError("simulator device inventory produced stderr")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict) or not isinstance(payload.get("devices"), dict):
        raise SandboxError("simulator device inventory has an unsupported schema")
    devices = payload["devices"]
    inventory: dict[str, dict[str, object]] = {}
    for runtime, runtime_devices in devices.items():
        if (
            not isinstance(runtime, str)
            or not runtime
            or not isinstance(runtime_devices, list)
        ):
            raise SandboxError("simulator device inventory has a malformed runtime")
        for device in runtime_devices:
            if not isinstance(device, dict):
                raise SandboxError("simulator device inventory has a malformed device")
            device_info = dict(device)
            udid = device_info.get("udid")
            if not isinstance(udid, str) or not udid:
                raise SandboxError("simulator device inventory has a malformed device")
            for field in ("name", "state"):
                if (
                    not isinstance(device_info.get(field), str)
                    or not device_info[field]
                ):
                    raise SandboxError(
                        "simulator device inventory has a malformed device"
                    )
            if udid in inventory:
                raise SandboxError(
                    f"duplicate simulator UDID in device inventory: {udid}"
                )
            device_info["runtime"] = runtime
            inventory[udid] = device_info
    return inventory


def available_simulators() -> dict[str, dict[str, object]]:
    return simulator_inventory(available_only=True)


def all_simulators() -> dict[str, dict[str, object]]:
    return simulator_inventory(available_only=False)


def wait_until_simulator_absent(
    udid: str,
    *,
    attempts: int = 10,
    delay_seconds: float = 0.2,
) -> bool:
    for attempt in range(attempts):
        try:
            if udid not in all_simulators():
                return True
        except (
            OSError,
            subprocess.SubprocessError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
        ):
            return False
        if attempt + 1 < attempts:
            time.sleep(delay_seconds)
    return False


def apple_lane_active() -> bool:
    for name in (
        "xcodebuild",
        "xctest",
        "swift-build",
        "swiftc",
        "swift-frontend",
        "clang",
    ):
        try:
            result = subprocess.run(
                ["pgrep", "-x", name],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return True
        if (result.stderr or "").strip():
            return True
        if result.returncode == 0:
            return True
        if result.returncode != 1:
            return True
    return False


def process_args_reference_any(values: tuple[str, ...]) -> bool:
    for value in values:
        if not value:
            continue
        try:
            result = subprocess.run(
                ["pgrep", "-f", "--", re.escape(value)],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return True
        if result.returncode == 1:
            if (result.stdout or "").strip() or (result.stderr or "").strip():
                return True
            continue
        if result.returncode != 0:
            return True
        if (result.stderr or "").strip():
            return True
        lines = result.stdout.splitlines()
        if not lines or any(not line.strip().isdigit() for line in lines):
            return True
        if any(int(line.strip()) != os.getpid() for line in lines):
            return True
    return False


def simulator_device_root(udid: str) -> Path:
    return Path.home() / "Library" / "Developer" / "CoreSimulator" / "Devices" / udid


def path_has_open_files(path: Path) -> bool:
    if path.is_symlink() or not path.is_dir():
        return True
    try:
        result = subprocess.run(
            ["lsof", "-nP", "-Fn", "+D", str(path)],
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return True
    if (
        result.returncode == 1
        and not (result.stdout or "").strip()
        and not (result.stderr or "").strip()
    ):
        return False
    if result.returncode != 0:
        return True
    if (result.stderr or "").strip():
        return True
    names: list[str] = []
    for line in result.stdout.splitlines():
        if not line.startswith("n"):
            continue
        name = line[1:]
        if not name:
            return True
        names.append(name)
    if not names:
        return True
    return True


def simulator_device_has_open_files(udid: str) -> bool:
    return path_has_open_files(simulator_device_root(udid))


@contextmanager
def open_ios_lane_lock(path: Path):
    registry_root = require_safe_registry_root(path.parent.parent)
    lock_directory = path.parent
    if lock_directory.parent.resolve(strict=False) != registry_root:
        raise SandboxError(f"unsafe simulator lane lock: {path}")
    registry_fd = open_owned_directory(registry_root, "unsafe simulator registry root")
    try:
        try:
            os.mkdir(lock_directory.name, mode=0o700, dir_fd=registry_fd)
        except FileExistsError:
            pass
        directory_fd = os.open(
            lock_directory.name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=registry_fd,
        )
    except OSError as error:
        os.close(registry_fd)
        raise SandboxError(f"unsafe simulator lane lock: {path}") from error
    try:
        directory_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.getuid()
        ):
            raise SandboxError(f"unsafe simulator lane lock: {path}")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
        except OSError as error:
            raise SandboxError(f"unsafe simulator lane lock: {path}") from error
        try:
            lock_stat = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(lock_stat.st_mode)
                or lock_stat.st_uid != os.getuid()
                or lock_stat.st_nlink != 1
            ):
                raise SandboxError(f"unsafe simulator lane lock: {path}")
            with os.fdopen(lock_fd, "r+") as handle:
                lock_fd = -1
                yield handle
        finally:
            if lock_fd >= 0:
                os.close(lock_fd)
    finally:
        os.close(directory_fd)
        os.close(registry_fd)


@contextmanager
def try_ios_lane_lease(path: Path):
    with open_ios_lane_lock(path) as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def legacy_repo_from_environment(root: Path) -> Path | None:
    path = root / "environment.sh"
    if not path.is_file() or path.is_symlink():
        return None
    for line in path.read_text().splitlines():
        if not line.startswith("export DEV_SANDBOX_REPO="):
            continue
        try:
            value = shlex.split(line.removeprefix("export DEV_SANDBOX_REPO="))[0]
        except (ValueError, IndexError):
            return None
        repo = Path(value)
        return repo if repo.is_absolute() else None
    return None


def parse_prune_metadata(
    content: str,
    registry_root: Path,
    *,
    identity_path: Path,
) -> dict[str, object] | None:
    try:
        metadata: object = json.loads(content)
    except json.JSONDecodeError:
        return None
    if not isinstance(metadata, dict) or metadata.get("version") != 1:
        return None
    repo_value = metadata.get("repo")
    repo = Path(repo_value) if isinstance(repo_value, str) and repo_value else None
    if repo is None or not repo.is_absolute() or repo != repo.resolve(strict=False):
        return None
    expected_path = registry_root / sandbox_root(repo).name / "simulator.json"
    if identity_path != expected_path:
        return None
    udid = metadata.get("udid")
    source_udid = metadata.get("source_udid")
    name = metadata.get("name")
    runtime = metadata.get("runtime")
    if not all(
        isinstance(value, str) and value for value in (udid, source_udid, name, runtime)
    ):
        return None
    if name != simulator_name(repo):
        return None
    created_at = parse_timestamp(metadata.get("created_at"))
    last_used_at = parse_timestamp(metadata.get("last_used_at"))
    if created_at is None or last_used_at is None:
        return None
    metadata["repo"] = str(repo)
    metadata["created_at"] = created_at
    metadata["last_used_at"] = last_used_at
    return metadata


def prune_metadata(
    path: Path,
    registry_root: Path,
    *,
    canonical_path: Path | None = None,
) -> dict[str, object] | None:
    if (
        not registry_root_is_safe(registry_root)
        or path.is_symlink()
        or path.parent.is_symlink()
    ):
        return None
    try:
        directory_fd = open_owned_directory(
            path.parent,
            f"unsafe simulator metadata parent: {path.parent}",
            create=False,
        )
    except SandboxError:
        return None
    try:
        try:
            before = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return None
        content = read_owned_output_at(
            directory_fd,
            path.name,
            f"unsafe simulator metadata: {path}",
        )
        if content is None:
            return None
        try:
            after = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return None
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_nlink,
            before.st_mode,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_nlink,
            after.st_mode,
        ):
            return None
        metadata = parse_prune_metadata(
            content,
            registry_root,
            identity_path=canonical_path or path,
        )
        if metadata is not None:
            metadata["_file_identity"] = identity
        return metadata
    finally:
        os.close(directory_fd)


SIMULATOR_METADATA_FIELDS = (
    "version",
    "repo",
    "udid",
    "source_udid",
    "name",
    "runtime",
    "created_at",
    "last_used_at",
)


def simulator_metadata_matches(
    current: dict[str, object] | None, expected: dict[str, object]
) -> bool:
    return current is not None and all(
        current.get(key) == expected.get(key) for key in SIMULATOR_METADATA_FIELDS
    )


def retire_metadata_if_unchanged(
    path: Path,
    registry_root: Path,
    expected: dict[str, object],
) -> Literal["retired", "replaced", "failed"]:
    retired_name = f".{path.name}.retired-{os.getpid()}-{time.time_ns()}"
    try:
        directory_fd = open_owned_directory(
            path.parent,
            f"unsafe simulator metadata parent: {path.parent}",
            create=False,
        )
    except SandboxError:
        return "failed"
    try:
        expected_identity = expected.get("_file_identity")
        if (
            not isinstance(expected_identity, tuple)
            or len(expected_identity) != 5
            or not all(isinstance(value, int) for value in expected_identity)
        ):
            return "failed"
        try:
            before = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return "failed"
        if expected_identity != (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_nlink,
            before.st_mode,
        ):
            return "replaced"
        try:
            rename_exclusive_at(
                directory_fd,
                path.name,
                retired_name,
            )
        except OSError:
            return "failed"
        try:
            retired_stat = os.stat(
                retired_name, dir_fd=directory_fd, follow_symlinks=False
            )
        except OSError:
            return "failed"
        if expected_identity != (
            retired_stat.st_dev,
            retired_stat.st_ino,
            retired_stat.st_uid,
            retired_stat.st_nlink,
            retired_stat.st_mode,
        ):
            return "replaced"
        content = read_owned_output_at(
            directory_fd,
            retired_name,
            f"unsafe retired simulator metadata: {path}",
        )
        try:
            after_read = os.stat(
                retired_name, dir_fd=directory_fd, follow_symlinks=False
            )
        except OSError:
            return "replaced"
        if expected_identity != (
            after_read.st_dev,
            after_read.st_ino,
            after_read.st_uid,
            after_read.st_nlink,
            after_read.st_mode,
        ):
            return "replaced"
        captured = (
            parse_prune_metadata(content, registry_root, identity_path=path)
            if content is not None
            else None
        )
        if simulator_metadata_matches(captured, expected):
            try:
                os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                replacement_exists = False
            except OSError:
                return "failed"
            else:
                replacement_exists = True
            try:
                before_unlink = os.stat(
                    retired_name, dir_fd=directory_fd, follow_symlinks=False
                )
            except OSError:
                return "replaced"
            if expected_identity != (
                before_unlink.st_dev,
                before_unlink.st_ino,
                before_unlink.st_uid,
                before_unlink.st_nlink,
                before_unlink.st_mode,
            ):
                return "replaced"
            try:
                os.unlink(retired_name, dir_fd=directory_fd)
            except OSError:
                if not replacement_exists:
                    try:
                        current = os.stat(
                            retired_name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                    except OSError:
                        return "failed"
                    if expected_identity != (
                        current.st_dev,
                        current.st_ino,
                        current.st_uid,
                        current.st_nlink,
                        current.st_mode,
                    ):
                        return "replaced"
                    try:
                        rename_exclusive_at(directory_fd, retired_name, path.name)
                    except OSError:
                        return "replaced"
                    return "failed"
                return "replaced"
            return "replaced" if replacement_exists else "retired"
        if captured is not None:
            try:
                current = os.stat(
                    retired_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError:
                return "replaced"
            if expected_identity != (
                current.st_dev,
                current.st_ino,
                current.st_uid,
                current.st_nlink,
                current.st_mode,
            ):
                return "replaced"
            try:
                rename_exclusive_at(directory_fd, retired_name, path.name)
            except OSError:
                return "replaced"
        return "replaced"
    finally:
        os.close(directory_fd)


def capture_sandbox_root_identity(root: Path) -> RetiredSandboxRoot | None:
    parent_fd = open_owned_directory(
        root.parent,
        "unsafe iOS sandbox root parent",
        create=False,
    )
    try:
        parent_stat = os.fstat(parent_fd)
        try:
            current = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid():
            raise SandboxError(f"unsafe iOS sandbox root: {root}")
        return RetiredSandboxRoot(
            path=root,
            device=current.st_dev,
            inode=current.st_ino,
            owner=current.st_uid,
            parent_device=parent_stat.st_dev,
            parent_inode=parent_stat.st_ino,
        )
    finally:
        os.close(parent_fd)


def sandbox_retirement_marker_path(root: Path) -> Path:
    return root.parent / ".locks" / f"{root.name}.retirement.json"


def write_sandbox_retirement_marker(
    root: Path,
    retired_name: str,
    identity: RetiredSandboxRoot,
) -> None:
    marker = sandbox_retirement_marker_path(root)
    directory_fd = open_owned_directory(
        marker.parent,
        "unsafe retirement marker directory",
    )
    os.close(directory_fd)
    payload = {
        "version": 1,
        "root_name": root.name,
        "retired_name": retired_name,
        "device": identity.device,
        "inode": identity.inode,
        "owner": identity.owner,
        "parent_device": identity.parent_device,
        "parent_inode": identity.parent_inode,
    }
    atomic_write_owned_output(
        marker.parent,
        marker.name,
        json.dumps(payload, sort_keys=True) + "\n",
        "unsafe iOS sandbox retirement marker",
    )


def remove_sandbox_retirement_marker(root: Path) -> None:
    marker = sandbox_retirement_marker_path(root)
    directory_fd = open_owned_directory(
        marker.parent,
        "unsafe retirement marker directory",
        create=False,
    )
    try:
        try:
            before = os.stat(marker.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
        ):
            raise SandboxError("unsafe iOS sandbox retirement marker")
        retired_name = f".{marker.name}.retired-{os.getpid()}-{time.time_ns()}"
        rename_exclusive_at(directory_fd, marker.name, retired_name)
        after = os.stat(retired_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_uid != before.st_uid
            or after.st_nlink != before.st_nlink
            or after.st_mode != before.st_mode
        ):
            raise SandboxError("iOS sandbox retirement marker changed")
        os.unlink(retired_name, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def retirement_marker_matches(
    root: Path,
    retired_name: str,
    child_stat: os.stat_result,
    parent_stat: os.stat_result,
) -> bool:
    marker = sandbox_retirement_marker_path(root)
    try:
        content = read_owned_output(
            marker,
            "unsafe iOS sandbox retirement marker",
        )
        payload = json.loads(content) if content is not None else None
    except (SandboxError, json.JSONDecodeError):
        return False
    return payload == {
        "version": 1,
        "root_name": root.name,
        "retired_name": retired_name,
        "device": child_stat.st_dev,
        "inode": child_stat.st_ino,
        "owner": child_stat.st_uid,
        "parent_device": parent_stat.st_dev,
        "parent_inode": parent_stat.st_ino,
    }


def retire_sandbox_root(
    root: Path, expected: RetiredSandboxRoot | None = None
) -> RetiredSandboxRoot:
    parent_fd = open_owned_directory(
        root.parent,
        "unsafe iOS sandbox root parent",
        create=False,
    )
    retired_name = f".{root.name}.retired-{os.getpid()}-{time.time_ns()}"
    try:
        parent_stat = os.fstat(parent_fd)
        before = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid():
            raise SandboxError(f"unsafe iOS sandbox root: {root}")
        if expected is not None and (
            expected.path != root
            or parent_stat.st_dev != expected.parent_device
            or parent_stat.st_ino != expected.parent_inode
            or before.st_dev != expected.device
            or before.st_ino != expected.inode
            or before.st_uid != expected.owner
        ):
            raise SandboxError(f"iOS sandbox root changed before retirement: {root}")
        identity = RetiredSandboxRoot(
            path=root,
            device=before.st_dev,
            inode=before.st_ino,
            owner=before.st_uid,
            parent_device=parent_stat.st_dev,
            parent_inode=parent_stat.st_ino,
        )
        write_sandbox_retirement_marker(root, retired_name, identity)
        try:
            rename_exclusive_at(parent_fd, root.name, retired_name)
        except OSError:
            remove_sandbox_retirement_marker(root)
            raise
        after = os.stat(retired_name, dir_fd=parent_fd, follow_symlinks=False)
        if after.st_dev != before.st_dev or after.st_ino != before.st_ino:
            try:
                rename_exclusive_at(parent_fd, retired_name, root.name)
            except OSError as error:
                raise SandboxError(
                    f"iOS sandbox root changed during retirement and could not be restored: {root}"
                ) from error
            remove_sandbox_retirement_marker(root)
            raise SandboxError(f"iOS sandbox root changed during retirement: {root}")
        return RetiredSandboxRoot(
            path=root.with_name(retired_name),
            device=before.st_dev,
            inode=before.st_ino,
            owner=before.st_uid,
            parent_device=parent_stat.st_dev,
            parent_inode=parent_stat.st_ino,
        )
    except OSError as error:
        raise SandboxError(
            f"could not atomically retire iOS sandbox root: {root}"
        ) from error
    finally:
        os.close(parent_fd)


def retired_sandbox_identity_matches(
    retired: RetiredSandboxRoot,
    parent_fd: int,
) -> bool:
    try:
        parent_stat = os.fstat(parent_fd)
        current = os.stat(
            retired.path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except OSError:
        return False
    return (
        parent_stat.st_dev == retired.parent_device
        and parent_stat.st_ino == retired.parent_inode
        and current.st_dev == retired.device
        and current.st_ino == retired.inode
        and current.st_uid == retired.owner
        and stat.S_ISDIR(current.st_mode)
    )


def rename_exclusive_at(directory_fd: int, source: str, destination: str) -> None:
    try:
        renameatx_np = ctypes.CDLL(None, use_errno=True).renameatx_np
    except AttributeError as error:
        raise OSError("renameatx_np is unavailable") from error
    renameatx_np.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx_np.restype = ctypes.c_int
    result = renameatx_np(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        RENAME_EXCL | RENAME_NOFOLLOW_ANY,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination)


def restore_retired_sandbox_root(
    root: Path,
    retired: RetiredSandboxRoot,
) -> bool:
    try:
        parent_fd = open_owned_directory(
            root.parent,
            "unsafe iOS sandbox root parent",
            create=False,
        )
    except SandboxError:
        return False
    try:
        if not retired_sandbox_identity_matches(retired, parent_fd):
            return False
        rename_exclusive_at(parent_fd, retired.path.name, root.name)
        remove_sandbox_retirement_marker(root)
        return True
    except OSError:
        return False
    finally:
        os.close(parent_fd)


def remove_retired_sandbox_root(retired: RetiredSandboxRoot) -> None:
    parent_fd = open_owned_directory(
        retired.path.parent,
        "unsafe retired sandbox parent",
        create=False,
    )
    root_fd = -1
    try:
        if not retired_sandbox_identity_matches(retired, parent_fd):
            raise SandboxError(
                f"retired sandbox changed before removal: {retired.path}"
            )
        try:
            root_fd = os.open(
                retired.path.name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except OSError as error:
            raise SandboxError(
                f"could not open retired sandbox for removal: {retired.path}"
            ) from error
        opened = os.fstat(root_fd)
        if (
            opened.st_dev != retired.device
            or opened.st_ino != retired.inode
            or opened.st_uid != retired.owner
            or not stat.S_ISDIR(opened.st_mode)
        ):
            raise SandboxError(
                f"retired sandbox changed before removal: {retired.path}"
            )
        validate_directory_contents_at(root_fd, retired.owner, retired.device)
        remove_directory_contents_at(root_fd, retired.owner, retired.device)
        if not retired_sandbox_identity_matches(retired, parent_fd):
            raise SandboxError(
                f"retired sandbox changed after content removal: {retired.path}"
            )
        os.rmdir(retired.path.name, dir_fd=parent_fd)
        root_name = retired.path.name[1:].split(".retired-", 1)[0]
        remove_sandbox_retirement_marker(retired.path.with_name(root_name))
    except OSError as error:
        raise SandboxError(
            f"could not remove retired sandbox: {retired.path}"
        ) from error
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        os.close(parent_fd)


def validate_directory_contents_at(
    directory_fd: int, expected_owner: int, expected_device: int
) -> None:
    try:
        names = os.listdir(directory_fd)
    except OSError as error:
        raise SandboxError("could not enumerate retired sandbox") from error
    for name in names:
        child_fd = -1
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if metadata.st_uid != expected_owner:
                raise SandboxError("retired sandbox contains an unowned entry")
            if metadata.st_dev != expected_device:
                raise SandboxError("retired sandbox entry is on a different filesystem")
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            child_fd = os.open(
                name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
            opened = os.fstat(child_fd)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_uid != expected_owner
            ):
                raise SandboxError("retired sandbox entry changed during validation")
            validate_directory_contents_at(child_fd, expected_owner, expected_device)
        except OSError as error:
            raise SandboxError("could not validate retired sandbox entry") from error
        finally:
            if child_fd >= 0:
                os.close(child_fd)


def remove_directory_contents_at(
    directory_fd: int, expected_owner: int, expected_device: int
) -> None:
    try:
        names = os.listdir(directory_fd)
    except OSError as error:
        raise SandboxError("could not enumerate retired sandbox") from error
    for name in names:
        child_fd = -1
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if metadata.st_uid != expected_owner:
                raise SandboxError("retired sandbox contains an unowned entry")
            if metadata.st_dev != expected_device:
                raise SandboxError("retired sandbox entry is on a different filesystem")
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_fd,
                )
                opened = os.fstat(child_fd)
                if (
                    opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or opened.st_uid != expected_owner
                ):
                    raise SandboxError("retired sandbox entry changed during removal")
                remove_directory_contents_at(child_fd, expected_owner, expected_device)
                os.close(child_fd)
                child_fd = -1
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if current.st_dev != opened.st_dev or current.st_ino != opened.st_ino:
                    raise SandboxError("retired sandbox entry changed during removal")
                os.rmdir(name, dir_fd=directory_fd)
            else:
                current = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (
                    current.st_dev != metadata.st_dev
                    or current.st_ino != metadata.st_ino
                    or current.st_uid != expected_owner
                    or current.st_mode != metadata.st_mode
                ):
                    raise SandboxError("retired sandbox entry changed during removal")
                os.unlink(name, dir_fd=directory_fd)
        except OSError as error:
            raise SandboxError("could not remove retired sandbox entry") from error
        finally:
            if child_fd >= 0:
                os.close(child_fd)


def trusted_simulator_metadata(repo: Path) -> dict[str, object] | None:
    path = simulator_metadata_path(repo)
    metadata = prune_metadata(path, path.parent.parent)
    if metadata is None and (path.exists() or path.is_symlink()):
        raise SandboxError(f"untrusted simulator metadata exists: {path}")
    return metadata


def registry_child_is_valid_build_root(
    child_fd: int,
    entry_path: Path,
    *,
    canonical_path: Path | None = None,
    expected_repo: Path | None = None,
) -> bool:
    content = read_owned_output_at(
        child_fd,
        "environment.sh",
        f"unsafe iOS build environment: {entry_path / 'environment.sh'}",
    )
    if content is None:
        return False
    values: dict[str, str] = {}
    try:
        for line in content.splitlines():
            fields = shlex.split(line)
            if len(fields) != 2 or fields[0] != "export" or "=" not in fields[1]:
                return False
            key, value = fields[1].split("=", 1)
            if not key or key in values:
                return False
            values[key] = value
    except ValueError:
        return False
    repo_value = values.get("DEV_SANDBOX_REPO")
    if not repo_value:
        return False
    repo = Path(repo_value)
    canonical_repo = repo.resolve(strict=False)
    if expected_repo is not None and canonical_repo != expected_repo.resolve(
        strict=False
    ):
        return False
    digest = hashlib.sha256(str(canonical_repo).encode()).hexdigest()[:16]
    expected_root = entry_path.parent / f"{canonical_repo.name}-{digest}"
    expected = {
        "DEV_SANDBOX_ROOT": str(expected_root),
        "DEV_SANDBOX_REPO": str(repo),
        "DEV_SANDBOX_DERIVED_DATA": str(expected_root / "DerivedData"),
        "DEV_SANDBOX_RESULTS": str(expected_root / "Results"),
        "DEV_SANDBOX_LOGS": str(expected_root / "Logs"),
        "DEV_SANDBOX_HOME": str(expected_root / "Home"),
        "DEV_SANDBOX_SOURCE_PACKAGES": str(expected_root / "SourcePackages"),
    }
    extra_keys = values.keys() - expected.keys()
    if extra_keys:
        if extra_keys != {
            "DEV_SANDBOX_SIMULATOR_UDID",
            "DEV_SANDBOX_XCODE_DESTINATION",
        }:
            return False
        udid = values["DEV_SANDBOX_SIMULATOR_UDID"]
        if (
            not udid
            or values["DEV_SANDBOX_XCODE_DESTINATION"]
            != f"platform=iOS Simulator,id={udid}"
        ):
            return False
        expected["DEV_SANDBOX_SIMULATOR_UDID"] = udid
        expected["DEV_SANDBOX_XCODE_DESTINATION"] = f"platform=iOS Simulator,id={udid}"
    return (canonical_path or entry_path) == expected_root and values == expected


def build_root_matches_identity(
    root: Path,
    expected: RetiredSandboxRoot,
    repo: Path,
) -> bool:
    child_fd = open_owned_directory(
        root,
        "unsafe iOS build-only sandbox root",
        create=False,
    )
    try:
        current = os.fstat(child_fd)
        if (
            current.st_dev != expected.device
            or current.st_ino != expected.inode
            or current.st_uid != expected.owner
            or not stat.S_ISDIR(current.st_mode)
        ):
            return False
        return registry_child_is_valid_build_root(
            child_fd,
            root,
            canonical_path=root,
            expected_repo=repo,
        )
    finally:
        os.close(child_fd)


def restore_orphaned_retired_sandbox_root(root: Path) -> bool:
    parent_fd = open_owned_directory(
        root.parent,
        "unsafe iOS sandbox root parent",
        create=False,
    )
    child_fd = -1
    try:
        parent_stat = os.fstat(parent_fd)
        prefix = f".{root.name}.retired-"
        candidates = [name for name in os.listdir(parent_fd) if name.startswith(prefix)]
        if not candidates:
            return False
        try:
            os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SandboxError("canonical and retired iOS sandbox roots both exist")
        if len(candidates) != 1:
            raise SandboxError(
                "multiple retired iOS sandbox roots require manual recovery"
            )
        name = candidates[0]
        child_fd = os.open(
            name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        child_stat = os.fstat(child_fd)
        if not stat.S_ISDIR(child_stat.st_mode) or child_stat.st_uid != os.getuid():
            raise SandboxError("unsafe retired iOS sandbox root")
        child_names = os.listdir(child_fd)
        trusted = False
        if "simulator.json" in child_names:
            content = read_owned_output_at(
                child_fd,
                "simulator.json",
                "unsafe retired simulator metadata",
            )
            trusted = (
                content is not None
                and parse_prune_metadata(
                    content,
                    root.parent,
                    identity_path=root / "simulator.json",
                )
                is not None
            )
        elif "environment.sh" in child_names:
            trusted = registry_child_is_valid_build_root(
                child_fd,
                root.with_name(name),
                canonical_path=root,
            )
        else:
            trusted = retirement_marker_matches(
                root,
                name,
                child_stat,
                parent_stat,
            )
        if not trusted:
            raise SandboxError(
                "retired iOS sandbox root has no trusted ownership record"
            )
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            current.st_dev != child_stat.st_dev
            or current.st_ino != child_stat.st_ino
            or current.st_uid != child_stat.st_uid
            or current.st_mode != child_stat.st_mode
        ):
            raise SandboxError("retired iOS sandbox root changed during recovery")
        rename_exclusive_at(parent_fd, name, root.name)
        remove_sandbox_retirement_marker(root)
        return True
    except OSError as error:
        raise SandboxError("could not recover retired iOS sandbox root") from error
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        os.close(parent_fd)


def recover_retired_metadata_at(
    child_fd: int,
    entry_path: Path,
    registry_root: Path,
    retired_names: list[str],
    *,
    expected_repo: Path,
) -> None:
    if len(retired_names) != 1:
        raise SandboxError("multiple retired simulator metadata files require recovery")
    retired_name = retired_names[0]
    before = os.stat(retired_name, dir_fd=child_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
    ):
        raise SandboxError("unsafe retired simulator metadata")
    content = read_owned_output_at(
        child_fd,
        retired_name,
        f"unsafe retired simulator metadata: {entry_path / retired_name}",
    )
    parsed = (
        parse_prune_metadata(
            content,
            registry_root,
            identity_path=entry_path / "simulator.json",
        )
        if content is not None
        else None
    )
    if parsed is None or Path(str(parsed["repo"])) != expected_repo:
        raise SandboxError("retired simulator metadata is not authenticated")
    after = os.stat(retired_name, dir_fd=child_fd, follow_symlinks=False)
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_uid != before.st_uid
        or after.st_nlink != before.st_nlink
        or after.st_mode != before.st_mode
    ):
        raise SandboxError("retired simulator metadata changed during recovery")
    rename_exclusive_at(child_fd, retired_name, "simulator.json")


def recover_registry_retired_metadata(root: Path) -> list[Path]:
    registry_fd = open_owned_directory(
        root, "unsafe simulator registry root", create=False
    )
    candidates: list[tuple[Path, Path]] = []
    unsafe: list[Path] = []
    try:
        for name in sorted(os.listdir(registry_fd)):
            if name == ".locks":
                continue
            entry_path = root / name
            if name.startswith("."):
                continue
            child_fd = -1
            saw_retired_metadata = False
            try:
                child_fd = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=registry_fd,
                )
                child_stat = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(child_stat.st_mode)
                    or child_stat.st_uid != os.getuid()
                ):
                    raise OSError("unsafe registry child")
                child_names = os.listdir(child_fd)
                retired_names = sorted(
                    child_name
                    for child_name in child_names
                    if child_name.startswith(".simulator.json.retired-")
                )
                if not retired_names:
                    continue
                saw_retired_metadata = True
                if "simulator.json" in child_names or len(retired_names) != 1:
                    raise OSError("ambiguous retired simulator metadata")
                content = read_owned_output_at(
                    child_fd,
                    retired_names[0],
                    f"unsafe retired simulator metadata: {entry_path}",
                )
                parsed = (
                    parse_prune_metadata(
                        content,
                        root,
                        identity_path=entry_path / "simulator.json",
                    )
                    if content is not None
                    else None
                )
                if parsed is None:
                    raise OSError("unauthenticated retired simulator metadata")
                candidates.append((entry_path, Path(str(parsed["repo"]))))
            except (OSError, SandboxError):
                if saw_retired_metadata:
                    unsafe.append(entry_path)
            finally:
                if child_fd >= 0:
                    os.close(child_fd)
    finally:
        os.close(registry_fd)
    if unsafe:
        return unsafe
    for entry_path, repo in candidates:
        with try_ios_lane_lease(ios_lane_lock_path(repo, root)) as acquired:
            if not acquired:
                return [entry_path]
            child_fd = open_owned_directory(
                entry_path,
                f"unsafe simulator metadata parent: {entry_path}",
                create=False,
            )
            try:
                child_names = os.listdir(child_fd)
                retired_names = sorted(
                    child_name
                    for child_name in child_names
                    if child_name.startswith(".simulator.json.retired-")
                )
                if "simulator.json" in child_names and not retired_names:
                    continue
                if "simulator.json" in child_names:
                    return [entry_path]
                recover_retired_metadata_at(
                    child_fd,
                    entry_path,
                    root,
                    retired_names,
                    expected_repo=repo,
                )
            except (OSError, SandboxError):
                return [entry_path]
            finally:
                os.close(child_fd)
    return []


def registry_metadata_inventory(root: Path) -> tuple[list[Path], list[Path]]:
    if not root.exists() and not root.is_symlink():
        return [], []
    try:
        registry_fd = open_owned_directory(
            root,
            "unsafe simulator registry root",
            create=False,
        )
    except SandboxError:
        return [], [root]
    metadata_paths: list[Path] = []
    unsafe_paths: list[Path] = []
    try:
        try:
            names = sorted(os.listdir(registry_fd))
        except OSError:
            return [], [root]
        for name in names:
            entry_path = root / name
            child_fd = -1
            try:
                child_fd = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=registry_fd,
                )
                child_stat = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(child_stat.st_mode)
                    or child_stat.st_uid != os.getuid()
                ):
                    raise OSError("unsafe registry child")
                if name == ".locks":
                    continue
                if name.startswith("."):
                    raise OSError("unexpected hidden registry child")
                child_names = os.listdir(child_fd)
                retired_metadata = sorted(
                    child_name
                    for child_name in child_names
                    if child_name.startswith(".simulator.json.retired-")
                )
                if retired_metadata:
                    raise OSError("retired simulator metadata requires live recovery")
                if "simulator.json" not in child_names:
                    if registry_child_is_valid_build_root(child_fd, entry_path):
                        continue
                    raise OSError("registry child has no trusted ownership record")
                metadata_stat = os.stat(
                    "simulator.json",
                    dir_fd=child_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(metadata_stat.st_mode)
                    or metadata_stat.st_uid != os.getuid()
                    or metadata_stat.st_nlink != 1
                ):
                    raise OSError("unsafe simulator metadata")
                metadata_paths.append(entry_path / "simulator.json")
            except (OSError, SandboxError):
                unsafe_paths.append(entry_path)
            finally:
                if child_fd >= 0:
                    os.close(child_fd)
    finally:
        os.close(registry_fd)
    return metadata_paths, unsafe_paths


def prune_owned_simulators(
    *,
    base: Path | None = None,
    max_idle_days: int = 7,
    live: bool = False,
    now: datetime | None = None,
) -> PruneResult:
    if max_idle_days < 1:
        raise SandboxError("max idle days must be at least 1")
    registry_root = base or (Path.home() / "Library" / "Caches" / "macos-dev-sandbox")
    result: PruneResult = {
        "live": live,
        "max_idle_days": max_idle_days,
        "candidates": [],
        "protected": [],
        "deleted": [],
    }
    candidates = result["candidates"]
    protected = result["protected"]
    deleted = result["deleted"]
    if not registry_root_is_safe(registry_root):
        protected.append({"path": str(registry_root), "reason": "unsafe-registry-root"})
        return result
    root = registry_root.resolve(strict=False)
    metadata_records: list[tuple[Path, dict[str, object]]] = []
    if live:
        recovery_unsafe = recover_registry_retired_metadata(root)
        if recovery_unsafe:
            for unsafe_path in recovery_unsafe:
                protected.append(
                    {"path": str(unsafe_path), "reason": "metadata-recovery-failed"}
                )
            return result
    metadata_paths, unsafe_paths = registry_metadata_inventory(root)
    for metadata_path in metadata_paths:
        metadata = prune_metadata(metadata_path, root)
        if metadata is None:
            protected.append(
                {"path": str(metadata_path), "reason": "unsafe-metadata-path"}
            )
        else:
            metadata_records.append((metadata_path, metadata))
    registered_repo_paths = {
        Path(str(metadata["repo"]))
        for _, metadata in metadata_records
        if isinstance(metadata.get("repo"), str)
    }
    unsafe_paths = [
        path
        for path in unsafe_paths
        if path not in registered_repo_paths or path.is_symlink() or not path.is_dir()
    ]
    registry_unsafe = bool(unsafe_paths) or len(metadata_records) != len(metadata_paths)
    for unsafe_path in unsafe_paths:
        protected.append({"path": str(unsafe_path), "reason": "unsafe-metadata-path"})
    if live and registry_unsafe:
        protected.append({"path": str(root), "reason": "registry-validation-failed"})
        return result
    if apple_lane_active():
        protected.append({"reason": "apple-lane-active"})
        return result
    devices = available_simulators()
    cutoff = (now or utc_now()).astimezone(UTC) - timedelta(days=max_idle_days)
    for metadata_path, metadata in metadata_records:
        udid = str(metadata.get("udid", ""))
        name = str(metadata.get("name", ""))
        runtime_value = metadata.get("runtime")
        runtime = runtime_value if isinstance(runtime_value, str) else ""
        repo = Path(str(metadata["repo"]))
        last_used_at = metadata["last_used_at"]
        if (
            not udid
            or not name.startswith("dev-sandbox-")
            or not isinstance(last_used_at, datetime)
        ):
            protected.append(
                {
                    "udid": udid,
                    "path": str(metadata_path),
                    "reason": "metadata-incomplete",
                }
            )
            continue
        device = devices.get(udid)
        device_already_absent = live and device is None and udid not in all_simulators()
        if device is None and not device_already_absent:
            protected.append({"udid": udid, "reason": "device-not-available"})
            continue
        if device is not None and (
            device.get("name") != name
            or device.get("udid") != udid
            or (runtime and device.get("runtime") != runtime)
        ):
            protected.append({"udid": udid, "reason": "metadata-device-mismatch"})
            continue
        if device is not None and device.get("state") != "Shutdown":
            protected.append({"udid": udid, "reason": "device-not-shutdown"})
            continue
        if repo.exists() and last_used_at >= cutoff:
            protected.append({"udid": udid, "reason": "not-stale"})
            continue
        references = (udid, str(metadata_path.parent), str(repo))
        if process_args_reference_any(references):
            protected.append({"udid": udid, "reason": "process-reference"})
            continue
        if not device_already_absent and simulator_device_has_open_files(udid):
            protected.append({"udid": udid, "reason": "open-files"})
            continue
        item: dict[str, object] = {
            "udid": udid,
            "name": name,
            "runtime": runtime or (device.get("runtime") if device else None),
            "repo": str(repo),
            "last_used_at": last_used_at.isoformat(),
        }
        candidates.append(item)
        if not live:
            continue
        with try_ios_lane_lease(ios_lane_lock_path(repo, root)) as acquired:
            if not acquired:
                protected.append({"udid": udid, "reason": "lease-busy"})
                continue
            current_paths, current_unsafe_paths = registry_metadata_inventory(root)
            current_records = [
                current
                for current_path in current_paths
                if (current := prune_metadata(current_path, root)) is not None
            ]
            current_registered_repo_paths = {
                Path(str(current["repo"])) for current in current_records
            }
            current_unsafe_paths = [
                path
                for path in current_unsafe_paths
                if path not in current_registered_repo_paths
                or path.is_symlink()
                or not path.is_dir()
            ]
            if (
                current_unsafe_paths
                or len(current_records) != len(current_paths)
                or set(current_paths) != set(metadata_paths)
            ):
                protected.append(
                    {"udid": udid, "reason": "registry-changed-after-lease"}
                )
                continue
            current_metadata = prune_metadata(metadata_path, root)
            if current_metadata is None or any(
                current_metadata.get(key) != metadata.get(key)
                for key in (
                    "repo",
                    "udid",
                    "source_udid",
                    "name",
                    "runtime",
                    "created_at",
                )
            ):
                protected.append(
                    {"udid": udid, "reason": "metadata-changed-after-lease"}
                )
                continue
            current_last_used = current_metadata.get("last_used_at")
            if not isinstance(current_last_used, datetime):
                protected.append(
                    {"udid": udid, "reason": "metadata-changed-after-lease"}
                )
                continue
            if repo.exists() and current_last_used >= cutoff:
                protected.append({"udid": udid, "reason": "not-stale-after-lease"})
                continue
            if apple_lane_active() or process_args_reference_any(references):
                protected.append({"udid": udid, "reason": "became-active"})
                continue
            if not device_already_absent and simulator_device_has_open_files(udid):
                protected.append({"udid": udid, "reason": "open-files-race"})
                continue
            if device_already_absent:
                if udid in all_simulators():
                    protected.append({"udid": udid, "reason": "device-changed"})
                    continue
            else:
                current = available_simulators().get(udid)
                if (
                    current is None
                    or current.get("name") != name
                    or current.get("udid") != udid
                    or current.get("state") != "Shutdown"
                    or (runtime and current.get("runtime") != runtime)
                ):
                    protected.append({"udid": udid, "reason": "device-changed"})
                    continue
                try:
                    run_checked(["xcrun", "simctl", "delete", udid])
                except (
                    subprocess.CalledProcessError,
                    FileNotFoundError,
                    SandboxError,
                ):
                    protected.append({"udid": udid, "reason": "delete-failed"})
                    continue
                if not wait_until_simulator_absent(udid):
                    protected.append(
                        {"udid": udid, "reason": "delete-verification-failed"}
                    )
                    continue
            if not repo.is_dir():
                try:
                    write_ios_environment(repo, root=metadata_path.parent)
                except SandboxError:
                    protected.append(
                        {"udid": udid, "reason": "build-record-write-failed"}
                    )
                    continue
            retirement = retire_metadata_if_unchanged(
                metadata_path, root, current_metadata
            )
            if retirement != "retired":
                protected.append(
                    {
                        "udid": udid,
                        "reason": (
                            "metadata-replaced-after-delete"
                            if retirement == "replaced"
                            else "metadata-retirement-failed"
                        ),
                    }
                )
                continue
            if repo.is_dir():
                write_ios_environment(repo)
            deleted.append(item)
    return result


def owned_simulator(repo: Path) -> str | None:
    metadata = trusted_simulator_metadata(repo)
    if metadata is None:
        return None
    udid = str(metadata.get("udid", ""))
    expected_name = simulator_name(repo)
    device = available_simulators().get(udid)
    runtime = metadata.get("runtime")
    if (
        metadata.get("name") != expected_name
        or device is None
        or device.get("udid") != udid
        or device.get("name") != expected_name
        or (runtime and device.get("runtime") != runtime)
    ):
        return None
    return udid


def selected_cleanup_udid(repo: Path, requested_udid: str | None) -> str | None:
    metadata = trusted_simulator_metadata(repo)
    owned = owned_simulator(repo)
    if metadata is not None and owned is None:
        metadata_udid = str(metadata.get("udid", ""))
        if not metadata_udid or metadata_udid in all_simulators():
            raise SandboxError(
                "owned simulator metadata does not match an available exact device"
            )
        owned = metadata_udid
    if requested_udid and requested_udid != owned:
        raise SandboxError(
            f"requested simulator {requested_udid} does not match owned simulator {owned or 'none'}"
        )
    return owned


def ensure_owned_simulator(
    repo: Path,
    source: str | None,
    *,
    lease_held: bool = False,
) -> str:
    if not lease_held:
        with ios_lane_lease(repo):
            return ensure_owned_simulator(repo, source, lease_held=True)
    metadata = trusted_simulator_metadata(repo)
    existing = owned_simulator(repo)
    if existing:
        return existing
    if metadata is not None:
        raise SandboxError(
            "owned simulator metadata does not match an available exact device"
        )
    if not source:
        raise SandboxError(
            "no owned simulator exists; pass --source-simulator to create one"
        )
    source_udid = resolve_simulator(source)
    source_device = available_simulators()[source_udid]
    if source_device.get("state") != "Shutdown":
        raise SandboxError(
            f"source simulator must be shutdown before cloning: {source_device.get('name')} ({source_udid})"
        )
    runtime = (
        str(source_device.get("runtime")) if source_device.get("runtime") else None
    )
    devices_before_clone = all_simulators()
    udid = clone_simulator(repo, source_udid)
    try:
        devices_after_clone = all_simulators()
    except BaseException as inventory_error:
        raise SandboxError(
            f"cloned simulator {udid} could not be inventoried; preserve it for inspection "
            f"or recover the exact device with: xcrun simctl delete {udid}"
        ) from inventory_error
    cloned_device = devices_after_clone.get(udid)
    proven_new = (
        udid not in devices_before_clone
        and cloned_device is not None
        and cloned_device.get("udid") == udid
    )
    if not proven_new:
        raise SandboxError("new simulator identity could not be verified")
    assert cloned_device is not None
    if (
        cloned_device.get("name") != simulator_name(repo)
        or cloned_device.get("state") != "Shutdown"
        or (runtime and cloned_device.get("runtime") != runtime)
    ):
        try:
            run_checked(["xcrun", "simctl", "delete", udid])
            if not wait_until_simulator_absent(udid):
                raise SandboxError("new simulator rollback could not be verified")
        except BaseException as rollback_error:
            raise SandboxError(
                f"new simulator identity invalid and rollback failed: {rollback_error}"
            ) from rollback_error
        raise SandboxError("new simulator identity could not be verified")
    try:
        write_simulator_metadata(
            repo,
            udid=udid,
            source_udid=source_udid,
            runtime=runtime,
        )
    except BaseException as registration_error:
        try:
            device = available_simulators().get(udid)
            if (
                device is None
                or device.get("udid") != udid
                or device.get("name") != simulator_name(repo)
                or (runtime and device.get("runtime") != runtime)
            ):
                raise SandboxError(
                    "new simulator identity could not be verified for rollback"
                )
            run_checked(["xcrun", "simctl", "delete", udid])
            if not wait_until_simulator_absent(udid):
                raise SandboxError("new simulator rollback could not be verified")
        # A rollback failure of any kind must surface as a combined error rather
        # than leave an unregistered clone silently.
        except BaseException as rollback_error:  # noqa: BLE001
            raise SandboxError(
                f"simulator registration failed and rollback failed: {rollback_error}"
            ) from registration_error
        raise
    try:
        write_ios_environment(repo, udid)
    except BaseException as environment_error:
        raise SandboxError(
            f"simulator {udid} registration is preserved after environment failed; retry setup: "
            f"{environment_error}"
        ) from environment_error
    return udid


@contextmanager
def ios_lane_lease(repo: Path):
    path = ios_lane_lock_path(repo)
    with open_ios_lane_lock(path) as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def run_ios_lane(
    repo: Path,
    simulator_udid: str,
    command: list[str],
    keep_booted: bool,
    *,
    lease_held: bool = False,
) -> int:
    if not lease_held:
        with ios_lane_lease(repo):
            return run_ios_lane(
                repo, simulator_udid, command, keep_booted, lease_held=True
            )
    environment = os.environ.copy()
    environment.update(ios_environment(repo, simulator_udid))
    write_ios_environment(repo, simulator_udid)
    mark_simulator_used(repo, simulator_udid)
    child: subprocess.Popen[bytes] | None = None
    interrupted_signal: int | None = None
    boot_attempted = False
    previous_handlers = {}

    def interrupt(signum: int, _frame: object) -> None:
        nonlocal interrupted_signal
        interrupted_signal = signum
        if child and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)

    try:
        boot_attempted = True
        run_quiet_control(
            ["xcrun", "simctl", "boot", simulator_udid],
            operation="simulator boot",
        )
        run_checked(["xcrun", "simctl", "bootstatus", simulator_udid, "-b"])
        previous_handlers = {
            signum: signal.signal(signum, interrupt)
            for signum in (signal.SIGINT, signal.SIGTERM)
        }
        child = subprocess.Popen(
            command, cwd=repo, env=environment, start_new_session=True
        )
        return_code = child.wait()
        return 128 + interrupted_signal if interrupted_signal else return_code
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if boot_attempted and not keep_booted:
            run_quiet_control(
                ["xcrun", "simctl", "shutdown", simulator_udid],
                operation="simulator shutdown",
            )
        mark_simulator_used(repo, simulator_udid)


def run_ios_with_owned_simulator(
    repo: Path,
    source: str | None,
    command: list[str],
    keep_booted: bool,
) -> int:
    with ios_lane_lease(repo):
        udid = ensure_owned_simulator(repo, source, lease_held=True)
        return run_ios_lane(repo, udid, command, keep_booted, lease_held=True)


def prepare_ios_sandbox(repo: Path, source: str | None) -> tuple[Path, str | None]:
    with ios_lane_lease(repo):
        udid = ensure_owned_simulator(repo, source, lease_held=True) if source else None
        return write_ios_environment(repo, udid), udid


def run_ios_build_lane(repo: Path, command: list[str]) -> int:
    with ios_lane_lease(repo):
        write_ios_environment(repo)
        planned = ios_build_command(repo, command)
        environment = os.environ.copy()
        for key in XCODE_PATH_ENVIRONMENT_KEYS:
            environment.pop(key, None)
        environment.update(ios_environment(repo))
        child: subprocess.Popen[bytes] | None = None
        interrupted_signal: int | None = None

        def interrupt(signum: int, _frame: object) -> None:
            nonlocal interrupted_signal
            interrupted_signal = signum
            if child and child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)

        previous_handlers = {
            signum: signal.signal(signum, interrupt)
            for signum in (signal.SIGINT, signal.SIGTERM)
        }
        try:
            child = subprocess.Popen(
                planned, cwd=repo, env=environment, start_new_session=True
            )
            return_code = child.wait()
            return 128 + interrupted_signal if interrupted_signal else return_code
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)


def cleanup_ios_sandbox(repo: Path, requested_udid: str | None) -> None:
    with ios_lane_lease(repo):
        root = sandbox_root(repo)
        restore_orphaned_retired_sandbox_root(root)
        root = require_safe_sandbox_root(root)
        expected_metadata = trusted_simulator_metadata(repo)
        simulator_udid = selected_cleanup_udid(repo, requested_udid)
        root_identity = capture_sandbox_root_identity(root)
        root_exists = root_identity is not None
        if (
            root_exists
            and expected_metadata is None
            and not build_root_matches_identity(root, root_identity, repo)
        ):
            raise SandboxError(
                "build-only simulator sandbox root has no trusted ownership record"
            )
        device_already_absent = False
        device_root = simulator_device_root(simulator_udid) if simulator_udid else None
        if simulator_udid:
            initial_device = available_simulators().get(simulator_udid)
            if initial_device is None and simulator_udid not in all_simulators():
                device_already_absent = True
        references = tuple(
            value
            for value in (
                simulator_udid or "",
                str(device_root) if device_root else "",
                str(root),
            )
            if value
        )
        if apple_lane_active():
            raise SandboxError("Apple build or test activity blocks simulator cleanup")
        if process_args_reference_any(references):
            raise SandboxError("simulator process reference blocks cleanup")
        if (root_exists and path_has_open_files(root)) or (
            simulator_udid
            and not device_already_absent
            and simulator_device_has_open_files(simulator_udid)
        ):
            raise SandboxError("simulator open file blocks cleanup")
        if simulator_udid:
            if (
                expected_metadata is None
                or expected_metadata.get("udid") != simulator_udid
            ):
                raise SandboxError("owned simulator metadata changed before cleanup")
            device = available_simulators().get(simulator_udid)
            if device is None:
                if simulator_udid in all_simulators():
                    raise SandboxError("owned simulator changed before cleanup")
                device_already_absent = True
            else:
                if (
                    device.get("udid") != simulator_udid
                    or device.get("name") != simulator_name(repo)
                    or device.get("runtime") != expected_metadata.get("runtime")
                ):
                    raise SandboxError("owned simulator changed before cleanup")
                run_quiet_control(
                    ["xcrun", "simctl", "shutdown", simulator_udid],
                    operation="simulator shutdown",
                )
            if apple_lane_active():
                raise SandboxError("Apple activity appeared before simulator delete")
            if process_args_reference_any(references):
                raise SandboxError("simulator process reference appeared before delete")
            if (
                not device_already_absent
                and simulator_device_has_open_files(simulator_udid)
            ) or path_has_open_files(root):
                raise SandboxError("simulator open file appeared before delete")
            if not simulator_metadata_matches(
                trusted_simulator_metadata(repo), expected_metadata
            ):
                raise SandboxError("owned simulator metadata changed before delete")
            if not device_already_absent and owned_simulator(repo) != simulator_udid:
                raise SandboxError("owned simulator metadata changed before delete")
            if not device_already_absent:
                device = available_simulators().get(simulator_udid)
                if (
                    device is None
                    or device.get("udid") != simulator_udid
                    or device.get("name") != simulator_name(repo)
                    or device.get("state") != "Shutdown"
                    or device.get("runtime") != expected_metadata.get("runtime")
                ):
                    raise SandboxError("owned simulator changed before delete")
        if not root_exists:
            return
        assert root_identity is not None
        retired_root = retire_sandbox_root(root, root_identity)
        canonical_metadata_path = root / "simulator.json"
        retired_metadata_path = retired_root.path / "simulator.json"
        try:
            if expected_metadata is None:
                if retired_metadata_path.exists() or retired_metadata_path.is_symlink():
                    raise SandboxError(
                        "simulator metadata appeared during cleanup; "
                        f"preserved at {retired_root.path}"
                    )
            else:
                retired_metadata = prune_metadata(
                    retired_metadata_path,
                    root.parent,
                    canonical_path=canonical_metadata_path,
                )
                if not simulator_metadata_matches(retired_metadata, expected_metadata):
                    raise SandboxError(
                        "owned simulator metadata changed during cleanup; "
                        f"preserved at {retired_root.path}"
                    )
            retired_references = tuple(
                value
                for value in (simulator_udid or "", str(retired_root.path))
                if value
            )
            if apple_lane_active() or process_args_reference_any(retired_references):
                raise SandboxError(
                    f"activity appeared during cleanup; preserved at {retired_root.path}"
                )
            if path_has_open_files(retired_root.path) or (
                simulator_udid
                and not device_already_absent
                and simulator_device_has_open_files(simulator_udid)
            ):
                raise SandboxError(
                    f"open files appeared during cleanup; preserved at {retired_root.path}"
                )
            if simulator_udid:
                assert expected_metadata is not None
                if not device_already_absent:
                    run_checked(["xcrun", "simctl", "delete", simulator_udid])
                    if not wait_until_simulator_absent(simulator_udid):
                        raise SandboxError(
                            "simulator deletion could not be verified; "
                            f"sandbox preserved at {retired_root.path}"
                        )
                retired_metadata = prune_metadata(
                    retired_metadata_path,
                    root.parent,
                    canonical_path=canonical_metadata_path,
                )
                if not simulator_metadata_matches(retired_metadata, expected_metadata):
                    raise SandboxError(
                        "owned simulator metadata changed after delete; "
                        f"preserved at {retired_root.path}"
                    )
            if process_args_reference_any(
                (str(retired_root.path),)
            ) or path_has_open_files(retired_root.path):
                raise SandboxError(
                    "sandbox became active before removal; "
                    f"preserved at {retired_root.path}"
                )
            remove_retired_sandbox_root(retired_root)
        except BaseException as error:
            if not restore_retired_sandbox_root(root, retired_root):
                raise SandboxError(
                    f"{error}; cleanup failed and sandbox recovery could not be restored; "
                    f"preserved at {retired_root.path}"
                ) from error
            raise


def doctor() -> int:
    checks = {
        "platform": f"{sys.platform}/{os.uname().machine}",
        "git": shutil.which("git"),
        "apple_container": shutil.which("container"),
        "docker": shutil.which("docker"),
        "xcrun": shutil.which("xcrun"),
    }
    print(json.dumps(checks, indent=2))
    required = (
        checks["git"]
        and (checks["apple_container"] or checks["docker"])
        and checks["xcrun"]
    )
    return 0 if required else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="dev-sandbox")
    commands = root.add_subparsers(dest="group", required=True)
    commands.add_parser("doctor")

    web = commands.add_parser("web")
    web_commands = web.add_subparsers(dest="action", required=True)
    for action in ("plan", "run"):
        item = web_commands.add_parser(action)
        item.add_argument("--repo", required=True, type=Path)
        item.add_argument(
            "--engine", choices=("auto", "apple", "docker"), default="auto"
        )
        item.add_argument("--image", default=DEFAULT_IMAGE)
        item.add_argument("--cpus", type=int, default=4)
        item.add_argument("--memory", default="8G")
        item.add_argument("--port")
        item.add_argument("--allow-dangerous-command", action="store_true")
        item.add_argument("command", nargs=argparse.REMAINDER)

    ios = commands.add_parser("ios")
    ios_commands = ios.add_subparsers(dest="action", required=True)
    prepare = ios_commands.add_parser("prepare")
    prepare.add_argument("--repo", required=True, type=Path)
    prepare.add_argument("--clone-simulator")
    run = ios_commands.add_parser("run")
    run.add_argument("--repo", required=True, type=Path)
    run.add_argument("--source-simulator")
    run.add_argument("--keep-booted", action="store_true")
    run.add_argument("--allow-dangerous-command", action="store_true")
    run.add_argument("command", nargs=argparse.REMAINDER)
    build = ios_commands.add_parser("build")
    build.add_argument("--repo", required=True, type=Path)
    build.add_argument("command", nargs=argparse.REMAINDER)
    status = ios_commands.add_parser("status")
    status.add_argument("--repo", required=True, type=Path)
    env_path = ios_commands.add_parser("env-path")
    env_path.add_argument("--repo", required=True, type=Path)
    cleanup = ios_commands.add_parser("cleanup")
    cleanup.add_argument("--repo", required=True, type=Path)
    cleanup.add_argument("--simulator-udid")
    prune = ios_commands.add_parser("prune")
    prune.add_argument("--max-idle-days", type=int, default=7)
    prune.add_argument("--live", action="store_true")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.group == "doctor":
            return doctor()
        if args.group == "ios" and args.action == "prune":
            print(
                json.dumps(
                    prune_owned_simulators(
                        max_idle_days=args.max_idle_days, live=args.live
                    ),
                    indent=2,
                )
            )
            return 0
        repo = git_root(args.repo)
        if args.group == "web":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            ensure_safe_command(command, args.allow_dangerous_command)
            engine = selected_engine(args.engine)
            planned = web_command(
                repo=repo,
                command=command,
                engine=engine,
                image=args.image,
                cpus=args.cpus,
                memory=args.memory,
                port=args.port,
            )
            if args.action == "plan":
                print(shlex.join(planned))
                return 0
            prepare_web_workspace(repo)
            if engine == "apple":
                subprocess.run(
                    ["container", "volume", "create", dependency_volume(repo)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            return subprocess.run(planned, check=False).returncode
        if args.action == "prepare":
            env_path, udid = prepare_ios_sandbox(repo, args.clone_simulator)
            print(env_path)
            if udid:
                print(f"DEV_SANDBOX_SIMULATOR_UDID={udid}")
            return 0
        if args.action == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            ensure_safe_command(command, args.allow_dangerous_command)
            return run_ios_with_owned_simulator(
                repo, args.source_simulator, command, args.keep_booted
            )
        if args.action == "build":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            ensure_safe_command(command, False)
            return run_ios_build_lane(repo, command)
        if args.action == "status":
            udid = owned_simulator(repo)
            payload = {
                "repo": str(repo),
                "root": str(sandbox_root(repo)),
                "simulator_udid": udid,
            }
            if udid:
                payload["simulator"] = available_simulators()[udid]
            print(json.dumps(payload, indent=2))
            return 0
        if args.action == "env-path":
            path = sandbox_root(repo) / "environment.sh"
            if not path.exists():
                raise SandboxError("sandbox is not prepared; run ios prepare first")
            print(path)
            return 0
        if args.action == "cleanup":
            cleanup_ios_sandbox(repo, args.simulator_udid)
            return 0
        raise SandboxError("unsupported command")
    except SandboxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
