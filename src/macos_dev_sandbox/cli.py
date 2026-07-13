from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import signal
import shlex
import shutil
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

DEFAULT_IMAGE = "docker.io/library/node:24-bookworm-slim"
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


def run_checked(argv: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, check=True, capture_output=capture)


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
    digest = hashlib.sha256(str(repo).encode()).hexdigest()[:12]
    return f"dev-sandbox-{repo.name.lower()}-{digest}"


def dependency_volume(repo: Path) -> str:
    return f"{workspace_id(repo)}-node-modules"


def web_workspace(repo: Path) -> Path:
    return sandbox_root(repo) / "WebWorkspace"


def prepare_web_workspace(repo: Path) -> Path:
    workspace = web_workspace(repo)
    shutil.rmtree(workspace, ignore_errors=True)

    def ignored(directory: str, names: list[str]) -> set[str]:
        blocked = {".git", ".codegraph", "node_modules", ".next", ".wrangler", ".turbo"}
        blocked.update(name for name in names if name.startswith(".env"))
        blocked.update(name for name in names if name in {".npmrc", ".yarnrc"})
        for name in names:
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                blocked.add(name)
        return blocked.intersection(names)

    shutil.copytree(repo, workspace, symlinks=True, ignore=ignored)
    return workspace


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
            "container", "run", "--rm", "--name", name,
            "--cpus", str(cpus), "--memory", memory,
            "--read-only",
            "--mount", f"type=bind,source={workspace},target=/workspace",
            "--mount", f"type=volume,source={dependency_volume(repo)},target=/workspace/node_modules",
            "--tmpfs", "/tmp", "--tmpfs", "/root/.npm",
            "--workdir", "/workspace",
            "--env", "CI=1", "--env", "HOME=/tmp/home", "--env", "npm_config_cache=/root/.npm",
        ]
        if port:
            argv += ["--publish", port]
        argv += [image, "/bin/sh", "-lc", shell_command]
        return argv

    argv = [
        "docker", "run", "--rm", "--name", name,
        "--cpus", str(cpus), "--memory", memory,
        "--read-only",
        "--mount", f"type=bind,source={workspace},target=/workspace",
        "--mount", f"type=volume,source={dependency_volume(repo)},target=/workspace/node_modules",
        "--tmpfs", "/tmp", "--tmpfs", "/root/.npm",
        "--workdir", "/workspace",
        "--env", "CI=1", "--env", "HOME=/tmp/home", "--env", "npm_config_cache=/root/.npm",
    ]
    if port:
        argv += ["--publish", port]
    argv += [image, "/bin/sh", "-lc", shell_command]
    return argv


def sandbox_root(repo: Path) -> Path:
    digest = hashlib.sha256(str(repo).encode()).hexdigest()[:16]
    return Path.home() / "Library" / "Caches" / "macos-dev-sandbox" / f"{repo.name}-{digest}"


def simulator_name(repo: Path) -> str:
    return workspace_id(repo)


def ios_environment(repo: Path, simulator_udid: str | None = None) -> dict[str, str]:
    root = sandbox_root(repo)
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
        values["DEV_SANDBOX_XCODE_DESTINATION"] = f"platform=iOS Simulator,id={simulator_udid}"
    return values


def command_arg_value(command: list[str], option: str) -> str | None:
    for index, argument in enumerate(command):
        if argument == option and index + 1 < len(command):
            return command[index + 1]
        if argument.startswith(f"{option}="):
            return argument.split("=", 1)[1]
    return None


def validate_ios_build_command(command: list[str]) -> None:
    if not command or Path(command[0]).name != "xcodebuild":
        raise SandboxError("iOS build lane requires a direct xcodebuild command")
    if command.count("build-for-testing") != 1:
        raise SandboxError("iOS build lane allows only the build-for-testing action")
    forbidden_actions = {"test", "test-without-building", "build", "archive", "install", "clean"}
    found = forbidden_actions.intersection(command)
    if found:
        raise SandboxError(f"iOS build lane refuses action: {sorted(found)[0]}")
    destination = command_arg_value(command, "-destination")
    if destination != "generic/platform=iOS Simulator":
        raise SandboxError(
            "iOS build lane requires -destination 'generic/platform=iOS Simulator'"
        )


def ios_build_command(repo: Path, command: list[str]) -> list[str]:
    validate_ios_build_command(command)
    values = ios_environment(repo)
    planned = command.copy()
    if command_arg_value(planned, "-derivedDataPath") is None:
        planned += ["-derivedDataPath", values["DEV_SANDBOX_DERIVED_DATA"]]
    if command_arg_value(planned, "-clonedSourcePackagesDirPath") is None:
        planned += ["-clonedSourcePackagesDirPath", values["DEV_SANDBOX_SOURCE_PACKAGES"]]
    if command_arg_value(planned, "-resultBundlePath") is None:
        result = Path(values["DEV_SANDBOX_RESULTS"]) / (
            f"build-for-testing_{time.strftime('%Y%m%d%H%M%S')}_{os.getpid()}.xcresult"
        )
        planned += ["-resultBundlePath", str(result)]
    return planned


def write_ios_environment(repo: Path, simulator_udid: str | None = None) -> Path:
    root = sandbox_root(repo)
    values = ios_environment(repo, simulator_udid)
    for key in (
        "DEV_SANDBOX_DERIVED_DATA", "DEV_SANDBOX_RESULTS", "DEV_SANDBOX_LOGS",
        "DEV_SANDBOX_HOME", "DEV_SANDBOX_SOURCE_PACKAGES",
    ):
        path = Path(values[key])
        path.mkdir(parents=True, exist_ok=True)
    env_path = root / "environment.sh"
    content = "\n".join(f"export {key}={shlex.quote(value)}" for key, value in values.items()) + "\n"
    env_path.write_text(content)
    return env_path


def resolve_simulator(source: str) -> str:
    result = run_checked(["xcrun", "simctl", "list", "devices", "available", "--json"], capture=True)
    devices = json.loads(result.stdout).get("devices", {})
    matches = [device for runtime in devices.values() for device in runtime if source in (device.get("udid"), device.get("name"))]
    if len(matches) != 1:
        names = ", ".join(f"{d.get('name')} ({d.get('udid')})" for d in matches) or "none"
        raise SandboxError(f"simulator source must match exactly one available device; matches: {names}")
    return str(matches[0]["udid"])


def clone_simulator(repo: Path, source: str) -> str:
    source_udid = resolve_simulator(source)
    name = simulator_name(repo)
    result = run_checked(["xcrun", "simctl", "clone", source_udid, name], capture=True)
    return result.stdout.strip()


def simulator_metadata_path(repo: Path) -> Path:
    return sandbox_root(repo) / "simulator.json"


def available_simulators() -> dict[str, dict[str, object]]:
    result = run_checked(["xcrun", "simctl", "list", "devices", "available", "--json"], capture=True)
    devices = json.loads(result.stdout).get("devices", {})
    return {str(device["udid"]): device for runtime in devices.values() for device in runtime}


def owned_simulator(repo: Path) -> str | None:
    path = simulator_metadata_path(repo)
    if not path.exists():
        return None
    metadata = json.loads(path.read_text())
    udid = str(metadata.get("udid", ""))
    return udid if udid in available_simulators() else None


def ensure_owned_simulator(repo: Path, source: str | None) -> str:
    existing = owned_simulator(repo)
    if existing:
        return existing
    if not source:
        raise SandboxError("no owned simulator exists; pass --source-simulator to create one")
    source_udid = resolve_simulator(source)
    source_device = available_simulators()[source_udid]
    if source_device.get("state") != "Shutdown":
        raise SandboxError(
            f"source simulator must be shutdown before cloning: {source_device.get('name')} ({source_udid})"
        )
    udid = clone_simulator(repo, source_udid)
    path = simulator_metadata_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"udid": udid, "source_udid": source_udid, "name": simulator_name(repo)}, indent=2) + "\n")
    write_ios_environment(repo, udid)
    return udid


@contextmanager
def ios_lane_lease(repo: Path):
    path = sandbox_root(repo) / "lane.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def run_ios_lane(repo: Path, simulator_udid: str, command: list[str], keep_booted: bool) -> int:
    environment = os.environ.copy()
    environment.update(ios_environment(repo, simulator_udid))
    write_ios_environment(repo, simulator_udid)
    with ios_lane_lease(repo):
        subprocess.run(["xcrun", "simctl", "boot", simulator_udid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run_checked(["xcrun", "simctl", "bootstatus", simulator_udid, "-b"])
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
            child = subprocess.Popen(command, cwd=repo, env=environment, start_new_session=True)
            return_code = child.wait()
            return 128 + interrupted_signal if interrupted_signal else return_code
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
            if not keep_booted:
                subprocess.run(
                    ["xcrun", "simctl", "shutdown", simulator_udid],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )


def run_ios_build_lane(repo: Path, command: list[str]) -> int:
    write_ios_environment(repo)
    planned = ios_build_command(repo, command)
    environment = os.environ.copy()
    environment.update(ios_environment(repo))
    with ios_lane_lease(repo):
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
            child = subprocess.Popen(planned, cwd=repo, env=environment, start_new_session=True)
            return_code = child.wait()
            return 128 + interrupted_signal if interrupted_signal else return_code
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)


def doctor() -> int:
    checks = {
        "platform": f"{sys.platform}/{os.uname().machine}",
        "git": shutil.which("git"),
        "apple_container": shutil.which("container"),
        "docker": shutil.which("docker"),
        "xcrun": shutil.which("xcrun"),
    }
    print(json.dumps(checks, indent=2))
    required = checks["git"] and (checks["apple_container"] or checks["docker"]) and checks["xcrun"]
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
        item.add_argument("--engine", choices=("auto", "apple", "docker"), default="auto")
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
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.group == "doctor":
            return doctor()
        repo = git_root(args.repo)
        if args.group == "web":
            prepare_web_workspace(repo)
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            ensure_safe_command(command, args.allow_dangerous_command)
            engine = selected_engine(args.engine)
            planned = web_command(
                repo=repo, command=command, engine=engine, image=args.image,
                cpus=args.cpus, memory=args.memory, port=args.port,
            )
            if args.action == "plan":
                print(shlex.join(planned))
                return 0
            if engine == "apple":
                subprocess.run(
                    ["container", "volume", "create", dependency_volume(repo)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            return subprocess.run(planned).returncode
        if args.action == "prepare":
            udid = None
            if args.clone_simulator:
                udid = ensure_owned_simulator(repo, args.clone_simulator)
            env_path = write_ios_environment(repo, udid)
            print(env_path)
            if udid:
                print(f"DEV_SANDBOX_SIMULATOR_UDID={udid}")
            return 0
        if args.action == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            ensure_safe_command(command, args.allow_dangerous_command)
            udid = ensure_owned_simulator(repo, args.source_simulator)
            return run_ios_lane(repo, udid, command, args.keep_booted)
        if args.action == "build":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            ensure_safe_command(command, False)
            return run_ios_build_lane(repo, command)
        if args.action == "status":
            udid = owned_simulator(repo)
            payload = {"repo": str(repo), "root": str(sandbox_root(repo)), "simulator_udid": udid}
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
            simulator_udid = args.simulator_udid or owned_simulator(repo)
            if simulator_udid:
                subprocess.run(["xcrun", "simctl", "shutdown", simulator_udid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                run_checked(["xcrun", "simctl", "delete", simulator_udid])
            shutil.rmtree(sandbox_root(repo), ignore_errors=True)
            return 0
        raise SandboxError("unsupported command")
    except SandboxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
