from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import time
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from macos_dev_sandbox import cli
from macos_dev_sandbox.cli import (
    SandboxError,
    apple_lane_active,
    ensure_safe_command,
    ios_build_command,
    ios_environment,
    prepare_web_workspace,
    prune_owned_simulators,
    sandbox_root,
    selected_cleanup_udid,
    simulator_name,
    validate_ios_build_command,
    web_command,
    web_workspace,
    workspace_id,
)


class SafetyGateTests(unittest.TestCase):
    def test_denies_deployment_commands(self) -> None:
        with self.assertRaisesRegex(SandboxError, "refusing command"):
            ensure_safe_command(["npm", "run", "cf:deploy:production"], False)

    def test_allows_normal_test_command(self) -> None:
        ensure_safe_command(["npm", "test"], False)


class WebPlanTests(unittest.TestCase):
    def test_web_plan_does_not_prepare_or_mutate_workspace(self) -> None:
        repo = Path("/tmp/example-worktree")
        with (
            patch("macos_dev_sandbox.cli.git_root", return_value=repo),
            patch("macos_dev_sandbox.cli.selected_engine", return_value="docker"),
            patch("macos_dev_sandbox.cli.prepare_web_workspace") as prepare,
            patch("builtins.print"),
        ):
            self.assertEqual(
                cli.main(
                    [
                        "web",
                        "plan",
                        "--repo",
                        str(repo),
                        "--engine",
                        "docker",
                        "--",
                        "npm",
                        "test",
                    ]
                ),
                0,
            )
        prepare.assert_not_called()

    def test_apple_plan_has_one_repo_mount_and_no_secret_inheritance(self) -> None:
        repo = Path("/tmp/example-worktree")
        command = web_command(
            repo=repo,
            command=["npm", "test"],
            engine="apple",
            image="node:24",
            cpus=2,
            memory="4G",
            port=None,
        )
        rendered = " ".join(command)
        self.assertIn(
            f"type=bind,source={web_workspace(repo)},target=/workspace", rendered
        )
        self.assertIn("--read-only", command)
        self.assertNotIn("--ssh", command)
        self.assertNotIn("--env-file", command)
        self.assertEqual(rendered.count("type=bind"), 1)
        self.assertIn("type=volume", rendered)

    def test_port_is_opt_in(self) -> None:
        command = web_command(
            repo=Path("/tmp/example"),
            command=["npm", "run", "dev"],
            engine="docker",
            image="node:24",
            cpus=2,
            memory="4G",
            port="127.0.0.1:3000:3000",
        )
        self.assertIn("127.0.0.1:3000:3000", command)

    def test_workspace_id_is_stable_and_path_specific(self) -> None:
        self.assertEqual(workspace_id(Path("/tmp/a")), workspace_id(Path("/tmp/a")))
        self.assertNotEqual(workspace_id(Path("/tmp/a")), workspace_id(Path("/tmp/b")))

    def test_staging_copy_excludes_repository_local_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            (repo / ".env.local").write_text("SECRET=not-visible")
            (repo / ".npmrc").write_text("//registry.example/:_authToken=not-visible")
            (repo / "source.txt").write_text("visible")
            registry = base / "registry"
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root", return_value=registry
            ):
                workspace = prepare_web_workspace(repo)
                (workspace / "stale.txt").write_text("replace me")
                workspace = prepare_web_workspace(repo)
            self.assertFalse((workspace / ".env.local").exists())
            self.assertFalse((workspace / ".npmrc").exists())
            self.assertEqual((workspace / "source.txt").read_text(), "visible")
            self.assertFalse((workspace / "stale.txt").exists())

    def test_staging_holds_workspace_lease_through_publication(self) -> None:
        repo = Path("/tmp/example-worktree")
        workspace = Path("/tmp/example-workspace")
        events: list[str] = []

        @contextmanager
        def lease(_repo: Path):
            events.append("lease-enter")
            try:
                yield
            finally:
                events.append("lease-exit")

        def prepare(_repo: Path) -> Path:
            events.append("publish")
            return workspace

        with (
            patch("macos_dev_sandbox.cli.web_workspace_lease", side_effect=lease),
            patch(
                "macos_dev_sandbox.cli._prepare_web_workspace_locked",
                side_effect=prepare,
            ),
        ):
            self.assertEqual(workspace, prepare_web_workspace(repo))
        self.assertEqual(["lease-enter", "publish", "lease-exit"], events)

    def test_staging_refuses_symlinked_workspace_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            (repo / "source.txt").write_text("visible")
            registry = base / "registry"
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root", return_value=registry
            ):
                root = sandbox_root(repo)
                root.mkdir(parents=True)
                outside = base / "outside"
                outside.mkdir()
                sentinel = outside / "sentinel.txt"
                sentinel.write_text("preserve me\n")
                workspace = web_workspace(repo)
                workspace.parent.mkdir(parents=True)
                workspace.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(SandboxError, "unsafe web workspace"):
                    prepare_web_workspace(repo)
            self.assertEqual("preserve me\n", sentinel.read_text())


class IOSLaneTests(unittest.TestCase):
    def test_simulator_name_is_stable_and_worktree_specific(self) -> None:
        first = simulator_name(Path("/tmp/worktree-a"))
        self.assertEqual(first, simulator_name(Path("/tmp/worktree-a")))
        self.assertNotEqual(first, simulator_name(Path("/tmp/worktree-b")))
        self.assertTrue(first.startswith("dev-sandbox-"))

    def test_ios_environment_uses_exact_udid_and_isolated_paths(self) -> None:
        repo = Path("/tmp/worktree-a")
        environment = ios_environment(repo, "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        self.assertEqual(
            environment["DEV_SANDBOX_XCODE_DESTINATION"],
            "platform=iOS Simulator,id=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        )
        self.assertIn(
            workspace_id(repo).split("-")[-1], environment["DEV_SANDBOX_ROOT"]
        )
        self.assertNotEqual(
            environment["DEV_SANDBOX_DERIVED_DATA"], environment["DEV_SANDBOX_RESULTS"]
        )

    def test_build_lane_requires_generic_simulator_build_for_testing(self) -> None:
        validate_ios_build_command(
            [
                "xcodebuild",
                "-project",
                "ExampleApp.xcodeproj",
                "-scheme",
                "ExampleAppTests",
                "-destination",
                "generic/platform=iOS Simulator",
                "build-for-testing",
            ]
        )
        for command in (
            [
                "xcodebuild",
                "-destination",
                "platform=iOS Simulator,name=iPhone 17",
                "build-for-testing",
            ],
            ["xcodebuild", "-destination", "generic/platform=iOS Simulator", "test"],
            [
                "./scripts/project_xcodebuild.sh",
                "-destination",
                "generic/platform=iOS Simulator",
                "build-for-testing",
            ],
            [
                "/tmp/xcodebuild",
                "-destination",
                "generic/platform=iOS Simulator",
                "build-for-testing",
            ],
            [
                "xcodebuild",
                "-scheme",
                "build-for-testing",
                "-destination",
                "generic/platform=iOS Simulator",
            ],
            [
                "xcodebuild",
                "-configuration",
                "build-for-testing",
                "-destination",
                "generic/platform=iOS Simulator",
            ],
            [
                "xcodebuild",
                "-create-xcframework",
                "-scheme",
                "build-for-testing",
                "-destination",
                "generic/platform=iOS Simulator",
            ],
            [
                "xcodebuild",
                "-destination",
                "generic/platform=iOS Simulator",
                "build-for-testing",
                "analyze",
            ],
            [
                "xcodebuild",
                "-destination",
                "generic/platform=iOS Simulator",
                "build-for-testing",
                "installhdrs",
            ],
            [
                "xcodebuild",
                "-destination",
                "generic/platform=iOS Simulator",
                "docbuild",
                "build-for-testing",
            ],
            [
                "xcodebuild",
                "-destination",
                "generic/platform=iOS Simulator",
                "-destination",
                "platform=iOS Simulator,id=OTHER",
                "build-for-testing",
            ],
        ):
            with (
                self.subTest(command=command),
                self.assertRaises(SandboxError),
            ):
                validate_ios_build_command(command)

    def test_build_lane_confines_explicit_project_and_workspace_to_repo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            outside = base / "Outside.xcworkspace"
            outside.mkdir()
            inside = repo / "Inside.xcodeproj"
            inside.mkdir()
            escaping = repo / "Escaping.xcworkspace"
            escaping.symlink_to(outside, target_is_directory=True)
            common = [
                "-scheme",
                "App",
                "-destination",
                "generic/platform=iOS Simulator",
                "build-for-testing",
            ]

            for selector in (
                ["-workspace", str(outside)],
                ["-workspace", str(escaping)],
                ["-project", "../Outside.xcworkspace"],
                ["SRCROOT=/tmp/outside"],
                ["PROJECT_DIR=/tmp/outside"],
                ["SOURCE_ROOT=/tmp/outside"],
                ["WORKSPACE_PATH=/tmp/outside"],
            ):
                with (
                    self.subTest(selector=selector),
                    self.assertRaises(SandboxError),
                ):
                    ios_build_command(repo, ["xcodebuild", *selector, *common])

            planned = ios_build_command(
                repo,
                ["xcodebuild", "-project", str(inside), *common],
            )
            self.assertIn(str(inside), planned)

    def test_build_lane_injects_isolated_artifact_paths(self) -> None:
        repo = Path("/tmp/worktree-a")
        command = ios_build_command(
            repo,
            [
                "xcodebuild",
                "-project",
                "ExampleApp.xcodeproj",
                "-scheme",
                "ExampleAppTests",
                "-destination",
                "generic/platform=iOS Simulator",
                "build-for-testing",
            ],
        )
        rendered = " ".join(command)
        environment = ios_environment(repo)
        self.assertEqual("/usr/bin/xcodebuild", command[0])
        self.assertIn(
            f"-derivedDataPath {environment['DEV_SANDBOX_DERIVED_DATA']}", rendered
        )
        self.assertIn(
            f"-clonedSourcePackagesDirPath {environment['DEV_SANDBOX_SOURCE_PACKAGES']}",
            rendered,
        )
        self.assertIn("-resultBundlePath", command)
        self.assertIn(environment["DEV_SANDBOX_RESULTS"], rendered)

    def test_build_lane_rejects_custom_artifact_paths_and_equals_forms(self) -> None:
        base = [
            "xcodebuild",
            "-destination",
            "generic/platform=iOS Simulator",
            "build-for-testing",
        ]
        for artifact_arguments in (
            ["-derivedDataPath", "/tmp/outside-derived-data"],
            ["-derivedDataPath=/tmp/outside-derived-data"],
            ["-clonedSourcePackagesDirPath", "/tmp/outside-packages"],
            ["-clonedSourcePackagesDirPath=/tmp/outside-packages"],
            ["-resultBundlePath", "/tmp/outside.xcresult"],
            ["-resultBundlePath=/tmp/outside.xcresult"],
            ["-resultStreamPath", "/tmp/outside-result-stream"],
            ["-resultStreamPath=/tmp/outside-result-stream"],
            ["SYMROOT=/tmp/outside-symroot"],
            ["SYMROOT"],
            ["OBJROOT=/tmp/outside-objroot"],
            ["CONFIGURATION_BUILD_DIR=/tmp/outside-products"],
            ["MODULE_CACHE_DIR=/tmp/outside-modules"],
            ["BUILD_DIR=/tmp/outside-build"],
            ["PROJECT_TEMP_DIR=/tmp/outside-project-temp"],
            ["TARGET_TEMP_DIR=/tmp/outside-target-temp"],
            ["TEMP_ROOT=/tmp/outside-temp"],
            ["SOURCE_ROOT=/tmp/outside-source"],
            ["-xcconfig", "/tmp/outside.xcconfig"],
            ["-settingsFile", "/tmp/outside-settings.json"],
        ):
            with (
                self.subTest(artifact_arguments=artifact_arguments),
                self.assertRaisesRegex(SandboxError, "artifact path"),
            ):
                ios_build_command(Path("/tmp/worktree-a"), base + artifact_arguments)

    def test_build_lane_scrubs_inherited_xcode_output_settings(self) -> None:
        repo = Path("/tmp/worktree-a")
        captured_environment: dict[str, str] = {}

        @contextmanager
        def lease(_repo: Path):
            yield

        class Child:
            pid = 123

            def wait(self) -> int:
                return 0

            def poll(self) -> int:
                return 0

        def launch(*_args, **kwargs):
            captured_environment.update(kwargs["env"])
            return Child()

        inherited = {
            "PATH": "/usr/bin:/bin",
            "BUILD_DIR": "/tmp/outside-build",
            "PROJECT_TEMP_DIR": "/tmp/outside-project-temp",
            "TARGET_TEMP_DIR": "/tmp/outside-target-temp",
            "SYMROOT": "/tmp/outside-symroot",
            "XCODE_XCCONFIG_FILE": "/tmp/outside.xcconfig",
            "SRCROOT": "/tmp/outside-source",
            "PROJECT_DIR": "/tmp/outside-project",
        }
        with (
            patch.dict(os.environ, inherited, clear=True),
            patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
            patch("macos_dev_sandbox.cli.write_ios_environment"),
            patch("macos_dev_sandbox.cli.subprocess.Popen", side_effect=launch),
            patch("macos_dev_sandbox.cli.signal.signal", return_value=signal.SIG_DFL),
        ):
            self.assertEqual(
                cli.run_ios_build_lane(
                    repo,
                    [
                        "xcodebuild",
                        "-destination",
                        "generic/platform=iOS Simulator",
                        "build-for-testing",
                    ],
                ),
                0,
            )
        self.assertEqual(captured_environment["PATH"], inherited["PATH"])
        for key in inherited.keys() - {"PATH"}:
            self.assertNotIn(key, captured_environment)


class IOSPruneTests(unittest.TestCase):
    NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
    RUNTIME = "com.apple.CoreSimulator.SimRuntime.iOS-26-3"

    def test_simulator_inventory_requires_devices_mapping(self) -> None:
        completed = subprocess.CompletedProcess(
            ["xcrun", "simctl", "list"],
            0,
            stdout=json.dumps({"pairs": {}}),
            stderr="",
        )
        with (
            patch("macos_dev_sandbox.cli.run_checked", return_value=completed),
            self.assertRaisesRegex(SandboxError, "device inventory"),
        ):
            cli.simulator_inventory(available_only=False)

    def test_simulator_inventory_rejects_success_with_stderr(self) -> None:
        completed = subprocess.CompletedProcess(
            ["xcrun", "simctl", "list"],
            0,
            stdout=json.dumps({"devices": {}}),
            stderr="simctl warning\n",
        )
        with (
            patch("macos_dev_sandbox.cli.run_checked", return_value=completed),
            self.assertRaisesRegex(SandboxError, "stderr"),
        ):
            cli.simulator_inventory(available_only=False)

    def test_simulator_inventory_rejects_duplicate_udids(self) -> None:
        completed = subprocess.CompletedProcess(
            ["xcrun", "simctl", "list"],
            0,
            stdout=json.dumps(
                {
                    "devices": {
                        "runtime-a": [
                            {"udid": "DUPLICATE", "name": "One", "state": "Shutdown"}
                        ],
                        "runtime-b": [
                            {"udid": "DUPLICATE", "name": "Two", "state": "Shutdown"}
                        ],
                    }
                }
            ),
            stderr="",
        )
        with (
            patch("macos_dev_sandbox.cli.run_checked", return_value=completed),
            self.assertRaisesRegex(SandboxError, "duplicate simulator UDID"),
        ):
            cli.simulator_inventory(available_only=False)

    def write_metadata(
        self,
        base: Path,
        repo: Path,
        udid: str,
        *,
        name: str | None = None,
        last_used_at: datetime | None = None,
    ) -> Path:
        canonical_repo = repo.resolve(strict=False)
        root = base.resolve(strict=False) / sandbox_root(canonical_repo).name
        root.mkdir(parents=True)
        metadata = root / "simulator.json"
        metadata.write_text(
            json.dumps(
                {
                    "version": 1,
                    "repo": str(canonical_repo),
                    "udid": udid,
                    "source_udid": "SOURCE-UDID",
                    "name": name or simulator_name(canonical_repo),
                    "runtime": self.RUNTIME,
                    "created_at": (self.NOW - timedelta(days=30)).isoformat(),
                    "last_used_at": (
                        last_used_at or self.NOW - timedelta(days=10)
                    ).isoformat(),
                }
            )
            + "\n"
        )
        return metadata

    def device(
        self, repo: Path, udid: str, *, state: str = "Shutdown"
    ) -> dict[str, object]:
        canonical_repo = repo.resolve(strict=False)
        return {
            "udid": udid,
            "name": simulator_name(canonical_repo),
            "state": state,
            "runtime": self.RUNTIME,
        }

    def test_prune_plan_selects_only_stale_exact_shutdown_owned_device(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stale_repo = base / "repo-stale"
            stale = self.write_metadata(base, stale_repo, "STALE")
            fresh_repo = base / "repo-fresh"
            fresh_repo.mkdir()
            fresh = self.write_metadata(
                base, fresh_repo, "FRESH", last_used_at=self.NOW - timedelta(days=1)
            )
            booted_repo = base / "repo-booted"
            mismatch_repo = base / "repo-mismatch"
            self.write_metadata(base, booted_repo, "BOOTED")
            self.write_metadata(base, mismatch_repo, "MISMATCH")
            symlink_target = self.write_metadata(
                base, base / "repo-symlink", "SYMLINK-TARGET"
            )
            symlink_root = base / "sandbox-symlink"
            symlink_root.mkdir()
            (symlink_root / "simulator.json").symlink_to(symlink_target)
            devices = {
                "STALE": self.device(stale_repo, "STALE"),
                "FRESH": self.device(fresh_repo, "FRESH"),
                "BOOTED": self.device(booted_repo, "BOOTED", state="Booted"),
                "MISMATCH": {
                    "udid": "MISMATCH",
                    "name": "someone-elses-device",
                    "state": "Shutdown",
                },
            }
            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=devices
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=False, now=self.NOW
                )

            self.assertEqual([item["udid"] for item in result["candidates"]], ["STALE"])
            reasons = {item.get("udid"): item["reason"] for item in result["protected"]}
            self.assertEqual(reasons["FRESH"], "not-stale")
            self.assertEqual(reasons["BOOTED"], "device-not-shutdown")
            self.assertEqual(reasons["MISMATCH"], "metadata-device-mismatch")
            self.assertIn(
                "unsafe-metadata-path", {item["reason"] for item in result["protected"]}
            )
            self.assertTrue(stale.exists())
            self.assertTrue(fresh.exists())

    def test_live_prune_rechecks_and_deletes_only_exact_udid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "repo"
            repo.mkdir()
            metadata = self.write_metadata(base, repo, "EXACT")
            device = {"EXACT": self.device(repo, "EXACT")}

            @contextmanager
            def acquired(_root: Path):
                yield True

            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators",
                    side_effect=[device, device],
                ),
                patch(
                    "macos_dev_sandbox.cli.all_simulators", return_value={}, create=True
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.try_ios_lane_lease", side_effect=acquired),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )

            run.assert_called_once_with(["xcrun", "simctl", "delete", "EXACT"])
            self.assertEqual([item["udid"] for item in result["deleted"]], ["EXACT"])
            self.assertFalse(metadata.exists())

    def test_live_prune_fails_closed_when_apple_lane_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.write_metadata(base, base / "repo", "BLOCKED")
            with (
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=True),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            run.assert_not_called()
            self.assertEqual(result["protected"][0]["reason"], "apple-lane-active")

    def test_live_prune_fails_closed_when_lease_is_busy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "missing-repo"
            self.write_metadata(base, repo, "LEASED")
            device = {"LEASED": self.device(repo, "LEASED")}

            @contextmanager
            def busy(_root: Path):
                yield False

            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=device
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.try_ios_lane_lease", side_effect=busy),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            run.assert_not_called()
            self.assertIn(
                "lease-busy", {item["reason"] for item in result["protected"]}
            )

    def test_prune_protects_process_referenced_device(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "missing-repo"
            metadata = self.write_metadata(base, repo, "REFERENCED")
            device = {"REFERENCED": self.device(repo, "REFERENCED")}
            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=device
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=True,
                ) as process_reference,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=False, now=self.NOW
                )
            self.assertEqual(result["candidates"], [])
            self.assertIn(
                "process-reference", {item["reason"] for item in result["protected"]}
            )
            process_reference.assert_called_once_with(
                ("REFERENCED", str(metadata.parent), str(repo.resolve(strict=False)))
            )

    def test_prune_protects_runtime_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "missing-repo"
            metadata_path = self.write_metadata(base, repo, "RUNTIME")
            metadata = json.loads(metadata_path.read_text())
            metadata["runtime"] = "com.apple.CoreSimulator.SimRuntime.iOS-26-3"
            metadata_path.write_text(json.dumps(metadata) + "\n")
            device = {
                "RUNTIME": {
                    "udid": "RUNTIME",
                    "name": simulator_name(repo),
                    "state": "Shutdown",
                    "runtime": "com.apple.CoreSimulator.SimRuntime.iOS-26-2",
                }
            }
            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=device
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=False, now=self.NOW
                )
            self.assertEqual(result["candidates"], [])
            self.assertIn(
                "metadata-device-mismatch",
                {item["reason"] for item in result["protected"]},
            )

    def test_prune_rejects_metadata_moved_outside_derived_owner_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "repo"
            metadata = self.write_metadata(base, repo, "MOVED")
            wrong_root = base / "wrong-registry-child"
            wrong_root.mkdir()
            moved = wrong_root / "simulator.json"
            metadata.replace(moved)
            device = {"MOVED": self.device(repo, "MOVED")}
            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=device
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=False, now=self.NOW
                )
            self.assertEqual(result["candidates"], [])
            self.assertTrue(moved.exists())
            self.assertIn(
                "unsafe-metadata-path",
                {item["reason"] for item in result["protected"]},
            )

    def test_live_prune_revalidates_freshness_after_acquiring_lease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "repo"
            repo.mkdir()
            metadata = self.write_metadata(base, repo, "FRESHENED")
            device = {"FRESHENED": self.device(repo, "FRESHENED")}

            @contextmanager
            def refresh_then_acquire(_root: Path):
                payload = json.loads(metadata.read_text())
                payload["last_used_at"] = self.NOW.isoformat()
                metadata.write_text(json.dumps(payload) + "\n")
                yield True

            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=device
                ),
                patch(
                    "macos_dev_sandbox.cli.all_simulators", return_value={}, create=True
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.try_ios_lane_lease",
                    side_effect=refresh_then_acquire,
                ),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            run.assert_not_called()
            self.assertTrue(metadata.exists())
            self.assertIn(
                "not-stale-after-lease",
                {item["reason"] for item in result["protected"]},
            )

    def test_prune_rejects_malformed_or_unsupported_metadata_without_crashing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            payloads: list[tuple[Path, object]] = [
                (base / "repo-list", []),
                (
                    base / "repo-version",
                    {
                        "version": 999,
                        "repo": str((base / "repo-version").resolve(strict=False)),
                        "udid": "VERSION",
                        "source_udid": "",
                        "name": simulator_name(base / "repo-version"),
                        "runtime": self.RUNTIME,
                        "created_at": "bad",
                        "last_used_at": "bad",
                    },
                ),
            ]
            for repo, payload in payloads:
                root = base / sandbox_root(repo).name
                root.mkdir()
                (root / "simulator.json").write_text(json.dumps(payload) + "\n")
            with (
                patch("macos_dev_sandbox.cli.available_simulators", return_value={}),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            run.assert_not_called()
            self.assertEqual(result["candidates"], [])
            self.assertEqual(
                [item["reason"] for item in result["protected"]].count(
                    "unsafe-metadata-path"
                ),
                2,
            )

    def test_live_prune_refuses_hardlinked_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            metadata = self.write_metadata(base, repo, "HARDLINKED")
            outside = base / "outside-metadata.json"
            os.link(metadata, outside)
            with (
                patch("macos_dev_sandbox.cli.available_simulators", return_value={}),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            run.assert_not_called()
            self.assertTrue(metadata.exists())
            self.assertIn(
                "unsafe-metadata-path",
                {item["reason"] for item in result["protected"]},
            )

    def test_live_prune_requires_complete_registry_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            metadata = self.write_metadata(base, repo, "EXACT")
            (base / "unexpected-owner-root").mkdir()
            devices = {"EXACT": self.device(repo, "EXACT")}
            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=devices
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            run.assert_not_called()
            self.assertTrue(metadata.exists())
            self.assertIn(
                "registry-validation-failed",
                {item["reason"] for item in result["protected"]},
            )

    def test_live_prune_rechecks_complete_registry_after_lease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            self.write_metadata(base, repo, "STALE")
            device = {"STALE": self.device(repo, "STALE")}

            @contextmanager
            def mutate_registry_after_lease(_root: Path):
                (base / "unexpected-owner-root").mkdir()
                yield True

            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators",
                    return_value=device,
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.try_ios_lane_lease",
                    side_effect=mutate_registry_after_lease,
                ),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base,
                    max_idle_days=7,
                    live=True,
                    now=self.NOW,
                )

            run.assert_not_called()
            self.assertIn(
                "registry-changed-after-lease",
                {item["reason"] for item in result["protected"]},
            )

    def test_live_prune_requires_absence_from_complete_device_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "missing-repo"
            metadata = self.write_metadata(base, repo, "STILL-REGISTERED")
            device = {"STILL-REGISTERED": self.device(repo, "STILL-REGISTERED")}

            @contextmanager
            def acquired(_root: Path):
                yield True

            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators",
                    side_effect=[device, device, {}],
                ),
                patch(
                    "macos_dev_sandbox.cli.all_simulators",
                    return_value=device,
                    create=True,
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.try_ios_lane_lease", side_effect=acquired),
                patch("macos_dev_sandbox.cli.run_checked"),
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            self.assertEqual(result["deleted"], [])
            self.assertTrue(metadata.exists())
            self.assertIn(
                "delete-verification-failed",
                {item["reason"] for item in result["protected"]},
            )

    def test_live_prune_preserves_replacement_metadata_after_old_device_delete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata = self.write_metadata(base, repo, "OLD")
            device = {"OLD": self.device(repo, "OLD")}

            @contextmanager
            def acquired(_root: Path):
                yield True

            def replace_metadata(_udid: str) -> bool:
                payload = json.loads(metadata.read_text())
                payload["udid"] = "NEW"
                payload["created_at"] = self.NOW.isoformat()
                payload["last_used_at"] = self.NOW.isoformat()
                metadata.write_text(json.dumps(payload) + "\n")
                return True

            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators",
                    side_effect=[device, device],
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.try_ios_lane_lease", side_effect=acquired),
                patch(
                    "macos_dev_sandbox.cli.wait_until_simulator_absent",
                    side_effect=replace_metadata,
                ),
                patch("macos_dev_sandbox.cli.run_checked"),
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )

            self.assertTrue(metadata.exists())
            self.assertEqual("NEW", json.loads(metadata.read_text())["udid"])
            self.assertIn(
                "metadata-replaced-after-delete",
                {item["reason"] for item in result["protected"]},
            )

    def test_live_prune_preserves_replacement_created_at_atomic_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata = self.write_metadata(base, repo, "OLD")
            device = {"OLD": self.device(repo, "OLD")}
            real_rename = cli.rename_exclusive_at

            @contextmanager
            def acquired(_root: Path):
                yield True

            def rename_at_capture(directory_fd: int, source: str, destination: str):
                payload = json.loads(metadata.read_text())
                result = real_rename(directory_fd, source, destination)
                if source == metadata.name:
                    payload["udid"] = "NEW"
                    payload["created_at"] = self.NOW.isoformat()
                    payload["last_used_at"] = self.NOW.isoformat()
                    metadata.write_text(json.dumps(payload) + "\n")
                return result

            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators",
                    side_effect=[device, device],
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.try_ios_lane_lease", side_effect=acquired),
                patch(
                    "macos_dev_sandbox.cli.wait_until_simulator_absent",
                    return_value=True,
                ),
                patch(
                    "macos_dev_sandbox.cli.rename_exclusive_at",
                    side_effect=rename_at_capture,
                ),
                patch("macos_dev_sandbox.cli.run_checked"),
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )

            self.assertTrue(metadata.exists())
            self.assertEqual("NEW", json.loads(metadata.read_text())["udid"])
            self.assertIn(
                "metadata-replaced-after-delete",
                {item["reason"] for item in result["protected"]},
            )

    def test_unregistered_namespaced_device_is_never_inferred_as_owned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            device = {
                "UNREGISTERED": {
                    "udid": "UNREGISTERED",
                    "name": "dev-sandbox-unregistered",
                    "state": "Shutdown",
                    "runtime": self.RUNTIME,
                }
            }
            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=device
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            run.assert_not_called()
            self.assertEqual(result["candidates"], [])
            self.assertEqual(result["deleted"], [])

    def test_live_prune_accepts_trusted_build_only_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory).resolve()
            base = temporary_root / "registry"
            base.mkdir()
            build_repo = temporary_root / "build-repo"
            stale_repo = temporary_root / "missing-repo"
            build_repo.mkdir()
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root", return_value=base
            ):
                cli.write_ios_environment(build_repo)
            metadata = self.write_metadata(base, stale_repo, "STALE")
            device = {"STALE": self.device(stale_repo, "STALE")}

            @contextmanager
            def acquired(_root: Path):
                yield True

            with (
                patch(
                    "macos_dev_sandbox.cli.available_simulators",
                    side_effect=[device, device],
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.try_ios_lane_lease", side_effect=acquired),
                patch(
                    "macos_dev_sandbox.cli.wait_until_simulator_absent",
                    return_value=True,
                ),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            run.assert_called_once_with(["xcrun", "simctl", "delete", "STALE"])
            self.assertEqual(["STALE"], [item["udid"] for item in result["deleted"]])
            self.assertFalse(metadata.exists())

    def test_live_prune_retries_metadata_retirement_after_device_is_absent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "missing-repo"
            metadata = self.write_metadata(base, repo, "ALREADY-DELETED")

            @contextmanager
            def acquired(_root: Path):
                yield True

            with (
                patch("macos_dev_sandbox.cli.available_simulators", return_value={}),
                patch(
                    "macos_dev_sandbox.cli.all_simulators",
                    side_effect=[{}, {}],
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.try_ios_lane_lease", side_effect=acquired),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
            run.assert_not_called()
            self.assertEqual(
                ["ALREADY-DELETED"], [item["udid"] for item in result["deleted"]]
            )
            self.assertFalse(metadata.exists())

    def test_live_prune_of_missing_repo_converges_on_second_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "missing-repo"
            metadata = self.write_metadata(base, repo, "ALREADY-DELETED")

            @contextmanager
            def acquired(_root: Path):
                yield True

            with (
                patch("macos_dev_sandbox.cli.available_simulators", return_value={}),
                patch(
                    "macos_dev_sandbox.cli.all_simulators",
                    side_effect=[{}, {}],
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.try_ios_lane_lease", side_effect=acquired),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                first = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )
                second = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )

            run.assert_not_called()
            self.assertEqual(
                ["ALREADY-DELETED"], [item["udid"] for item in first["deleted"]]
            )
            self.assertEqual([], second["deleted"])
            self.assertEqual([], second["protected"])
            self.assertFalse(metadata.exists())
            self.assertTrue((metadata.parent / "environment.sh").is_file())

    def test_live_prune_recovers_orphaned_retired_metadata_after_process_death(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "missing-repo"
            metadata = self.write_metadata(base, repo, "ALREADY-DELETED")
            cli.write_ios_environment(repo, "ALREADY-DELETED")
            retired = metadata.with_name(
                f".{metadata.name}.retired-99999-{time.time_ns()}"
            )
            metadata.rename(retired)
            lease_held = False
            real_recover = cli.recover_retired_metadata_at

            @contextmanager
            def acquired(_root: Path):
                nonlocal lease_held
                lease_held = True
                try:
                    yield True
                finally:
                    lease_held = False

            def recover_under_lease(*args, **kwargs) -> None:
                self.assertTrue(lease_held)
                real_recover(*args, **kwargs)

            with (
                patch("macos_dev_sandbox.cli.available_simulators", return_value={}),
                patch(
                    "macos_dev_sandbox.cli.all_simulators",
                    side_effect=[{}, {}],
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.try_ios_lane_lease", side_effect=acquired),
                patch(
                    "macos_dev_sandbox.cli.recover_retired_metadata_at",
                    side_effect=recover_under_lease,
                ),
                patch("macos_dev_sandbox.cli.run_checked") as run,
            ):
                result = prune_owned_simulators(
                    base=base, max_idle_days=7, live=True, now=self.NOW
                )

            run.assert_not_called()
            self.assertEqual(
                ["ALREADY-DELETED"], [item["udid"] for item in result["deleted"]]
            )
            self.assertFalse(metadata.exists())
            self.assertFalse(retired.exists())

    def test_apple_lane_activity_fails_closed_on_pgrep_error(self) -> None:
        failed = subprocess.CompletedProcess(["pgrep"], 2, stdout="", stderr="")
        with patch("macos_dev_sandbox.cli.subprocess.run", return_value=failed):
            self.assertTrue(apple_lane_active())
        with patch(
            "macos_dev_sandbox.cli.subprocess.run", side_effect=FileNotFoundError
        ):
            self.assertTrue(apple_lane_active())
        with patch(
            "macos_dev_sandbox.cli.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["pgrep"], 5),
        ):
            self.assertTrue(apple_lane_active())
        noisy = subprocess.CompletedProcess(
            ["pgrep"], 0, stdout="123\n", stderr="warning\n"
        )
        with patch("macos_dev_sandbox.cli.subprocess.run", return_value=noisy) as run:
            self.assertTrue(apple_lane_active())
        self.assertEqual(5, run.call_args.kwargs["timeout"])

    def test_checked_control_command_uses_bounded_timeout(self) -> None:
        with (
            patch(
                "macos_dev_sandbox.cli.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["xcrun", "simctl"], 30),
            ) as run,
            self.assertRaisesRegex(SandboxError, "timed out"),
        ):
            cli.run_checked(["xcrun", "simctl", "list"])
        run.assert_called_once_with(
            ["xcrun", "simctl", "list"],
            text=True,
            check=True,
            capture_output=False,
            timeout=30,
        )

    def test_process_reference_uses_checked_targeted_inventory(self) -> None:
        for output in ("", "not-a-pid\n"):
            with (
                self.subTest(output=output),
                patch(
                    "macos_dev_sandbox.cli.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        ["pgrep"], 0, stdout=output, stderr=""
                    ),
                ),
            ):
                self.assertTrue(cli.process_args_reference_any(("EXACT-UDID",)))

        with patch(
            "macos_dev_sandbox.cli.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["pgrep"], 0, stdout=f"{os.getpid()}\n", stderr=""
            ),
        ) as run:
            self.assertFalse(cli.process_args_reference_any(("EXACT-UDID",)))
        self.assertEqual("pgrep", run.call_args.args[0][0])
        self.assertEqual(5, run.call_args.kwargs["timeout"])

        with patch(
            "macos_dev_sandbox.cli.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["pgrep"], 0, stdout="999\n", stderr=""
            ),
        ):
            self.assertTrue(cli.process_args_reference_any(("EXACT-UDID",)))

        with patch(
            "macos_dev_sandbox.cli.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["pgrep"], 0, stdout=f"{os.getpid()}\n", stderr="warning\n"
            ),
        ):
            self.assertTrue(cli.process_args_reference_any(("EXACT-UDID",)))

        with patch(
            "macos_dev_sandbox.cli.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["pgrep"], 1, stdout="", stderr=""
            ),
        ):
            self.assertFalse(cli.process_args_reference_any(("EXACT-UDID",)))

        with patch(
            "macos_dev_sandbox.cli.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["pgrep"], 5),
        ):
            self.assertTrue(cli.process_args_reference_any(("EXACT-UDID",)))

    def test_open_file_inventory_fails_closed_when_root_or_snapshot_is_incomplete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-device"
            self.assertTrue(cli.path_has_open_files(missing))

            device_root = Path(directory) / "device"
            device_root.mkdir()
            for output in ("", "p123\nn\n", "p123\nn/other/path\n"):
                with (
                    self.subTest(output=output),
                    patch(
                        "macos_dev_sandbox.cli.subprocess.run",
                        return_value=subprocess.CompletedProcess(
                            ["lsof"], 0, stdout=output, stderr=""
                        ),
                    ),
                ):
                    self.assertTrue(cli.path_has_open_files(device_root))

            noisy_match = subprocess.CompletedProcess(
                ["lsof"],
                0,
                stdout=f"p123\nn{device_root}/open-file\n",
                stderr="warning\n",
            )
            with patch(
                "macos_dev_sandbox.cli.subprocess.run", return_value=noisy_match
            ):
                self.assertTrue(cli.path_has_open_files(device_root))

            no_match = subprocess.CompletedProcess(["lsof"], 1, stdout="", stderr="")
            with patch(
                "macos_dev_sandbox.cli.subprocess.run", return_value=no_match
            ) as run:
                self.assertFalse(cli.path_has_open_files(device_root))
            self.assertEqual(
                ["lsof", "-nP", "-Fn", "+D", str(device_root)],
                run.call_args.args[0],
            )
            self.assertEqual(15, run.call_args.kwargs["timeout"])

            with patch(
                "macos_dev_sandbox.cli.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["lsof"], 15),
            ):
                self.assertTrue(cli.path_has_open_files(device_root))

    def test_metadata_retirement_restores_canonical_record_on_unlink_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata_path = self.write_metadata(base, repo, "EXACT")
            expected = cli.prune_metadata(metadata_path, base)
            self.assertIsNotNone(expected)
            assert expected is not None
            real_unlink = os.unlink

            def fail_retired_unlink(path, *args, **kwargs):
                if str(path).startswith(".simulator.json.retired-"):
                    raise OSError("simulated unlink failure")
                return real_unlink(path, *args, **kwargs)

            with patch(
                "macos_dev_sandbox.cli.os.unlink", side_effect=fail_retired_unlink
            ):
                retirement = cli.retire_metadata_if_unchanged(
                    metadata_path,
                    base,
                    expected,
                )

            self.assertEqual("failed", retirement)
            self.assertTrue(metadata_path.is_file())
            self.assertEqual("EXACT", json.loads(metadata_path.read_text())["udid"])
            retired_paths = list(metadata_path.parent.glob(".simulator.json.retired-*"))
            self.assertEqual([], retired_paths)

    def test_metadata_unlink_recovery_never_clobbers_concurrent_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata_path = self.write_metadata(base, repo, "OLD")
            expected = cli.prune_metadata(metadata_path, base)
            assert expected is not None
            real_unlink = os.unlink
            replacement_written = False

            def race_unlink(path, *args, **kwargs):
                nonlocal replacement_written
                if (
                    str(path).startswith(".simulator.json.retired-")
                    and not replacement_written
                ):
                    replacement = dict(expected)
                    replacement.update(
                        {
                            "udid": "NEW",
                            "created_at": self.NOW.isoformat(),
                            "last_used_at": self.NOW.isoformat(),
                        }
                    )
                    metadata_path.write_text(
                        json.dumps(
                            {
                                key: (
                                    value.isoformat()
                                    if isinstance(value, datetime)
                                    else value
                                )
                                for key, value in replacement.items()
                            }
                        )
                        + "\n"
                    )
                    replacement_written = True
                    raise OSError("simulated unlink race")
                return real_unlink(path, *args, **kwargs)

            with patch("macos_dev_sandbox.cli.os.unlink", side_effect=race_unlink):
                self.assertEqual(
                    "replaced",
                    cli.retire_metadata_if_unchanged(metadata_path, base, expected),
                )
            self.assertEqual("NEW", json.loads(metadata_path.read_text())["udid"])

    def test_metadata_retirement_never_unlinks_substituted_retired_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata_path = self.write_metadata(base, repo, "OLD")
            expected = cli.prune_metadata(metadata_path, base)
            assert expected is not None
            real_read = cli.read_owned_output_at
            substituted_inode: int | None = None

            def substitute_after_read(
                directory_fd: int, name: str, error_message: str
            ) -> str | None:
                nonlocal substituted_inode
                content = real_read(directory_fd, name, error_message)
                if name.startswith(".simulator.json.retired-"):
                    os.unlink(name, dir_fd=directory_fd)
                    replacement_fd = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=directory_fd,
                    )
                    try:
                        os.write(replacement_fd, (content or "").encode())
                        substituted_inode = os.fstat(replacement_fd).st_ino
                    finally:
                        os.close(replacement_fd)
                return content

            with patch(
                "macos_dev_sandbox.cli.read_owned_output_at",
                side_effect=substitute_after_read,
            ):
                result = cli.retire_metadata_if_unchanged(
                    metadata_path,
                    base,
                    expected,
                )

            retired = list(metadata_path.parent.glob(".simulator.json.retired-*"))
            self.assertNotEqual("retired", result)
            self.assertEqual(1, len(retired))
            self.assertEqual(substituted_inode, retired[0].stat().st_ino)

    def test_metadata_retirement_preserves_pre_rename_replacement_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata_path = self.write_metadata(base, repo, "OLD")
            expected = cli.prune_metadata(metadata_path, base)
            assert expected is not None
            original_content = metadata_path.read_text()
            real_rename = cli.rename_exclusive_at
            replacement_inode: int | None = None

            def replace_before_rename(
                directory_fd: int, source: str, destination: str
            ) -> None:
                nonlocal replacement_inode
                if source == metadata_path.name:
                    os.unlink(source, dir_fd=directory_fd)
                    replacement_fd = os.open(
                        source,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=directory_fd,
                    )
                    try:
                        os.write(replacement_fd, original_content.encode())
                        replacement_inode = os.fstat(replacement_fd).st_ino
                    finally:
                        os.close(replacement_fd)
                real_rename(directory_fd, source, destination)

            with patch(
                "macos_dev_sandbox.cli.rename_exclusive_at",
                side_effect=replace_before_rename,
            ):
                result = cli.retire_metadata_if_unchanged(
                    metadata_path,
                    base,
                    expected,
                )

            retired = list(metadata_path.parent.glob(".simulator.json.retired-*"))
            self.assertEqual("replaced", result)
            self.assertEqual(1, len(retired))
            self.assertEqual(replacement_inode, retired[0].stat().st_ino)

    def test_cleanup_refuses_non_owned_requested_udid(self) -> None:
        with patch("macos_dev_sandbox.cli.owned_simulator", return_value="OWNED"):
            with self.assertRaises(SandboxError):
                selected_cleanup_udid(Path("/tmp/worktree"), "OTHER")
            self.assertEqual(
                selected_cleanup_udid(Path("/tmp/worktree"), "OWNED"), "OWNED"
            )

    def test_clone_is_rolled_back_when_registration_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve()
            source_device = {
                "udid": "SOURCE",
                "name": "Source",
                "state": "Shutdown",
                "runtime": self.RUNTIME,
            }
            cloned_device = self.device(repo, "CLONED")
            with (
                patch(
                    "macos_dev_sandbox.cli.trusted_simulator_metadata",
                    return_value=None,
                ),
                patch("macos_dev_sandbox.cli.owned_simulator", return_value=None),
                patch("macos_dev_sandbox.cli.resolve_simulator", return_value="SOURCE"),
                patch(
                    "macos_dev_sandbox.cli.available_simulators",
                    side_effect=[{"SOURCE": source_device}, {"CLONED": cloned_device}],
                ),
                patch("macos_dev_sandbox.cli.clone_simulator", return_value="CLONED"),
                patch(
                    "macos_dev_sandbox.cli.all_simulators",
                    side_effect=[
                        {"SOURCE": source_device},
                        {"SOURCE": source_device, "CLONED": cloned_device},
                    ],
                ),
                patch(
                    "macos_dev_sandbox.cli.write_simulator_metadata",
                    side_effect=SandboxError("registration failed"),
                ),
                patch(
                    "macos_dev_sandbox.cli.wait_until_simulator_absent",
                    return_value=True,
                ) as wait,
                patch("macos_dev_sandbox.cli.run_checked") as run,
                self.assertRaisesRegex(SandboxError, "registration failed"),
            ):
                cli.ensure_owned_simulator(repo, "SOURCE", lease_held=True)
            run.assert_called_once_with(["xcrun", "simctl", "delete", "CLONED"])
            wait.assert_called_once_with("CLONED")

    def test_clone_inventory_failure_reports_exact_udid_without_deleting(self) -> None:
        repo = Path("/tmp/worktree")
        source_device = {
            "udid": "SOURCE",
            "name": "Source",
            "state": "Shutdown",
            "runtime": self.RUNTIME,
        }
        with (
            patch(
                "macos_dev_sandbox.cli.trusted_simulator_metadata", return_value=None
            ),
            patch("macos_dev_sandbox.cli.owned_simulator", return_value=None),
            patch("macos_dev_sandbox.cli.resolve_simulator", return_value="SOURCE"),
            patch(
                "macos_dev_sandbox.cli.available_simulators",
                return_value={"SOURCE": source_device},
            ),
            patch("macos_dev_sandbox.cli.clone_simulator", return_value="CLONED"),
            patch(
                "macos_dev_sandbox.cli.all_simulators",
                side_effect=[
                    {"SOURCE": source_device},
                    SandboxError("inventory timed out"),
                ],
            ),
            patch("macos_dev_sandbox.cli.write_simulator_metadata") as write,
            patch("macos_dev_sandbox.cli.run_checked") as run,
            self.assertRaisesRegex(SandboxError, r"CLONED.*xcrun simctl delete CLONED"),
        ):
            cli.ensure_owned_simulator(repo, "SOURCE", lease_held=True)
        write.assert_not_called()
        run.assert_not_called()

    def test_environment_failure_preserves_registered_clone_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            registry = base / "registry"
            repo = base / "repo"
            repo.mkdir()
            source_device: dict[str, object] = {
                "udid": "SOURCE",
                "name": "Source",
                "state": "Shutdown",
                "runtime": self.RUNTIME,
            }
            cloned_device = self.device(repo, "CLONED")
            inventory_calls = 0
            deleted = False
            real_write_environment = cli.write_ios_environment
            environment_calls = 0

            def available() -> dict[str, dict[str, object]]:
                nonlocal inventory_calls
                inventory_calls += 1
                if inventory_calls == 1:
                    return {"SOURCE": source_device}
                return {} if deleted else {"CLONED": cloned_device}

            def control(argv: list[str], *, capture: bool = False):
                nonlocal deleted
                self.assertFalse(capture)
                if argv == ["xcrun", "simctl", "delete", "CLONED"]:
                    deleted = True
                return subprocess.CompletedProcess(argv, 0)

            def write_environment(repo_path: Path, udid: str | None = None) -> Path:
                nonlocal environment_calls
                environment_calls += 1
                if environment_calls == 1:
                    raise SandboxError("environment failed")
                return real_write_environment(repo_path, udid)

            with (
                patch(
                    "macos_dev_sandbox.cli.simulator_registry_root",
                    return_value=registry,
                ),
                patch("macos_dev_sandbox.cli.resolve_simulator", return_value="SOURCE"),
                patch(
                    "macos_dev_sandbox.cli.available_simulators", side_effect=available
                ),
                patch("macos_dev_sandbox.cli.clone_simulator", return_value="CLONED"),
                patch(
                    "macos_dev_sandbox.cli.all_simulators",
                    side_effect=[
                        {"SOURCE": source_device},
                        {"SOURCE": source_device, "CLONED": cloned_device},
                    ],
                ),
                patch(
                    "macos_dev_sandbox.cli.write_ios_environment",
                    side_effect=write_environment,
                ),
                patch(
                    "macos_dev_sandbox.cli.wait_until_simulator_absent",
                    return_value=True,
                ),
                patch("macos_dev_sandbox.cli.run_checked", side_effect=control) as run,
            ):
                with self.assertRaisesRegex(SandboxError, "environment failed"):
                    cli.ensure_owned_simulator(repo, "SOURCE", lease_held=True)
                self.assertEqual(
                    "CLONED",
                    cli.ensure_owned_simulator(repo, None, lease_held=True),
                )
                cli.write_ios_environment(repo, "CLONED")
                root = sandbox_root(repo)
            run.assert_not_called()
            self.assertFalse(deleted)
            self.assertTrue((root / "simulator.json").is_file())
            self.assertTrue((root / "environment.sh").is_file())

    def test_clone_identity_is_verified_before_registration(self) -> None:
        repo = Path("/tmp/worktree")
        source_device = {
            "udid": "SOURCE",
            "name": "Source",
            "state": "Shutdown",
            "runtime": self.RUNTIME,
        }
        wrong_clone = {
            "udid": "CLONED",
            "name": "someone-elses-simulator",
            "state": "Shutdown",
            "runtime": self.RUNTIME,
        }
        with (
            patch(
                "macos_dev_sandbox.cli.trusted_simulator_metadata", return_value=None
            ),
            patch("macos_dev_sandbox.cli.owned_simulator", return_value=None),
            patch("macos_dev_sandbox.cli.resolve_simulator", return_value="SOURCE"),
            patch(
                "macos_dev_sandbox.cli.available_simulators",
                return_value={"SOURCE": source_device},
            ),
            patch("macos_dev_sandbox.cli.clone_simulator", return_value="CLONED"),
            patch(
                "macos_dev_sandbox.cli.all_simulators",
                side_effect=[
                    {"SOURCE": source_device},
                    {"SOURCE": source_device, "CLONED": wrong_clone},
                ],
            ),
            patch("macos_dev_sandbox.cli.write_simulator_metadata") as write,
            patch(
                "macos_dev_sandbox.cli.wait_until_simulator_absent",
                return_value=True,
            ) as wait,
            patch("macos_dev_sandbox.cli.run_checked") as run,
            self.assertRaisesRegex(SandboxError, "identity"),
        ):
            cli.ensure_owned_simulator(repo, "SOURCE", lease_held=True)
        write.assert_not_called()
        run.assert_called_once_with(["xcrun", "simctl", "delete", "CLONED"])
        wait.assert_called_once_with("CLONED")

    def test_clone_never_rolls_back_a_preexisting_returned_udid(self) -> None:
        repo = Path("/tmp/worktree")
        source_device = {
            "udid": "SOURCE",
            "name": "Source",
            "state": "Shutdown",
            "runtime": self.RUNTIME,
        }
        existing = self.device(repo, "EXISTING")
        with (
            patch(
                "macos_dev_sandbox.cli.trusted_simulator_metadata", return_value=None
            ),
            patch("macos_dev_sandbox.cli.owned_simulator", return_value=None),
            patch("macos_dev_sandbox.cli.resolve_simulator", return_value="SOURCE"),
            patch(
                "macos_dev_sandbox.cli.available_simulators",
                return_value={"SOURCE": source_device},
            ),
            patch("macos_dev_sandbox.cli.clone_simulator", return_value="EXISTING"),
            patch(
                "macos_dev_sandbox.cli.all_simulators",
                side_effect=[
                    {"SOURCE": source_device, "EXISTING": existing},
                    {"SOURCE": source_device, "EXISTING": existing},
                ],
            ),
            patch("macos_dev_sandbox.cli.write_simulator_metadata") as write,
            patch("macos_dev_sandbox.cli.run_checked") as run,
            self.assertRaisesRegex(SandboxError, "identity"),
        ):
            cli.ensure_owned_simulator(repo, "SOURCE", lease_held=True)
        write.assert_not_called()
        run.assert_not_called()

    def test_cleanup_refuses_process_referenced_owned_device(self) -> None:
        repo = Path("/tmp/worktree")
        device = self.device(repo, "OWNED")

        @contextmanager
        def lease(_repo: Path):
            yield

        with (
            patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
            patch("macos_dev_sandbox.cli.selected_cleanup_udid", return_value="OWNED"),
            patch("macos_dev_sandbox.cli.owned_simulator", return_value="OWNED"),
            patch(
                "macos_dev_sandbox.cli.available_simulators",
                return_value={"OWNED": device},
            ),
            patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
            patch(
                "macos_dev_sandbox.cli.process_args_reference_any", return_value=True
            ),
            patch(
                "macos_dev_sandbox.cli.simulator_device_has_open_files",
                return_value=False,
            ),
            patch("macos_dev_sandbox.cli.run_checked") as run_checked,
            self.assertRaisesRegex(SandboxError, "process reference"),
        ):
            cli.cleanup_ios_sandbox(repo, "OWNED")
        run_checked.assert_not_called()

    def test_cleanup_rechecks_process_reference_after_shutdown(self) -> None:
        repo = Path("/tmp/worktree")
        device = self.device(repo, "OWNED")
        metadata = {"udid": "OWNED", "runtime": self.RUNTIME}

        @contextmanager
        def lease(_repo: Path):
            yield

        with (
            patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
            patch("macos_dev_sandbox.cli.selected_cleanup_udid", return_value="OWNED"),
            patch("macos_dev_sandbox.cli.owned_simulator", return_value="OWNED"),
            patch(
                "macos_dev_sandbox.cli.trusted_simulator_metadata",
                return_value=metadata,
            ),
            patch(
                "macos_dev_sandbox.cli.available_simulators",
                return_value={"OWNED": device},
            ),
            patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
            patch(
                "macos_dev_sandbox.cli.process_args_reference_any",
                side_effect=[False, True],
            ),
            patch(
                "macos_dev_sandbox.cli.simulator_device_has_open_files",
                return_value=False,
            ),
            patch("macos_dev_sandbox.cli.subprocess.run") as shutdown,
            patch("macos_dev_sandbox.cli.run_checked") as run_checked,
            self.assertRaisesRegex(SandboxError, "appeared before delete"),
        ):
            cli.cleanup_ios_sandbox(repo, "OWNED")
        shutdown.assert_called_once_with(
            ["xcrun", "simctl", "shutdown", "OWNED"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=True,
        )
        run_checked.assert_not_called()

    def test_cleanup_preserves_replacement_sandbox_created_after_retirement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata_path = self.write_metadata(base, repo, "OWNED")
            root = metadata_path.parent
            device = {"OWNED": self.device(repo, "OWNED")}
            replacement_payload = json.loads(metadata_path.read_text())
            replacement_payload["udid"] = "NEW"
            replacement_payload["created_at"] = self.NOW.isoformat()
            replacement_payload["last_used_at"] = self.NOW.isoformat()

            @contextmanager
            def lease(_repo: Path):
                yield

            def delete_old_device(_command) -> None:
                root.mkdir()
                (root / "replacement-sentinel").write_text("new sandbox\n")
                (root / "simulator.json").write_text(
                    json.dumps(replacement_payload) + "\n"
                )

            with (
                patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch(
                    "macos_dev_sandbox.cli.selected_cleanup_udid",
                    return_value="OWNED",
                ),
                patch("macos_dev_sandbox.cli.owned_simulator", return_value="OWNED"),
                patch(
                    "macos_dev_sandbox.cli.available_simulators",
                    side_effect=[device, device, device],
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.path_has_open_files", return_value=False),
                patch("macos_dev_sandbox.cli.subprocess.run"),
                patch(
                    "macos_dev_sandbox.cli.wait_until_simulator_absent",
                    return_value=True,
                ),
                patch(
                    "macos_dev_sandbox.cli.run_checked",
                    side_effect=delete_old_device,
                ),
            ):
                cli.cleanup_ios_sandbox(repo, "OWNED")

            self.assertEqual(
                "new sandbox\n", (root / "replacement-sentinel").read_text()
            )
            self.assertEqual(
                "NEW", json.loads((root / "simulator.json").read_text())["udid"]
            )
            self.assertEqual([], list(root.parent.glob(f".{root.name}.retired-*")))

    def test_untrusted_existing_metadata_cannot_be_overwritten_or_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata = self.write_metadata(base, repo, "OLD")
            payload = json.loads(metadata.read_text())
            payload["version"] = 999
            metadata.write_text(json.dumps(payload) + "\n")

            @contextmanager
            def acquired(_repo: Path):
                yield

            with (
                patch(
                    "macos_dev_sandbox.cli.simulator_metadata_path",
                    return_value=metadata,
                ),
                patch(
                    "macos_dev_sandbox.cli.sandbox_root", return_value=metadata.parent
                ),
                patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=acquired),
                patch("macos_dev_sandbox.cli.clone_simulator") as clone,
            ):
                with self.assertRaisesRegex(
                    SandboxError, "untrusted simulator metadata"
                ):
                    cli.ensure_owned_simulator(repo, "SOURCE")
                with self.assertRaisesRegex(
                    SandboxError, "untrusted simulator metadata"
                ):
                    cli.cleanup_ios_sandbox(repo, None)
            clone.assert_not_called()
            self.assertTrue(metadata.exists())
            self.assertEqual(999, json.loads(metadata.read_text())["version"])

    def test_owned_simulator_rejects_symlinked_registry_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            real_registry = base / "real-registry"
            real_registry.mkdir()
            linked_registry = base / "linked-registry"
            linked_registry.symlink_to(real_registry, target_is_directory=True)
            repo = base / "repo"
            repo.mkdir()
            metadata = self.write_metadata(real_registry, repo, "LINKED")
            linked_metadata = linked_registry / metadata.parent.name / metadata.name
            devices = {"LINKED": self.device(repo, "LINKED")}
            with (
                patch(
                    "macos_dev_sandbox.cli.simulator_metadata_path",
                    return_value=linked_metadata,
                ),
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=devices
                ),
                self.assertRaisesRegex(SandboxError, "untrusted simulator metadata"),
            ):
                cli.owned_simulator(repo)

    def test_owned_simulator_requires_exact_device_payload_udid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata = self.write_metadata(base, repo, "EXPECTED")
            mismatched = self.device(repo, "DIFFERENT")
            devices = {"EXPECTED": mismatched}
            with (
                patch(
                    "macos_dev_sandbox.cli.simulator_metadata_path",
                    return_value=metadata,
                ),
                patch(
                    "macos_dev_sandbox.cli.available_simulators", return_value=devices
                ),
            ):
                self.assertIsNone(cli.owned_simulator(repo))

    def test_open_file_detector_matches_device_root_directory_itself(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            udid = "ROOT-OPEN"
            device_root = (
                home / "Library" / "Developer" / "CoreSimulator" / "Devices" / udid
            )
            device_root.mkdir(parents=True)
            lsof = subprocess.CompletedProcess(
                ["lsof"], 0, stdout=f"p1\nn{device_root}\n", stderr=""
            )
            with (
                patch("macos_dev_sandbox.cli.Path.home", return_value=home),
                patch("macos_dev_sandbox.cli.subprocess.run", return_value=lsof),
            ):
                self.assertTrue(cli.simulator_device_has_open_files(udid))

    def test_lane_lock_is_outside_deletable_sandbox_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            repo = home / "repo"
            with patch("macos_dev_sandbox.cli.Path.home", return_value=home):
                root = sandbox_root(repo)
                lock = cli.ios_lane_lock_path(repo)
            self.assertFalse(lock.is_relative_to(root))
            self.assertTrue(lock.is_relative_to(root.parent))

    def test_lane_lease_bootstraps_fresh_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            lock_path = base / "registry" / ".locks" / "lane.lock"
            with (
                patch(
                    "macos_dev_sandbox.cli.ios_lane_lock_path", return_value=lock_path
                ),
                cli.ios_lane_lease(repo),
            ):
                self.assertTrue(lock_path.is_file())

    def test_owned_output_refuses_symlinked_registry_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            outside = base / "outside-registry"
            outside.mkdir()
            linked_registry = base / "linked-registry"
            linked_registry.symlink_to(outside, target_is_directory=True)
            sandbox = linked_registry / "sandbox"
            with self.assertRaisesRegex(SandboxError, "unsafe output"):
                cli.atomic_write_owned_output(
                    sandbox,
                    "sentinel.txt",
                    "unsafe\n",
                    "unsafe output",
                )
            self.assertFalse((outside / "sandbox" / "sentinel.txt").exists())

    def test_open_owned_directory_closes_descriptor_when_fstat_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve()
            real_open = os.open
            opened_descriptors: list[int] = []

            def tracked_open(*args: object, **kwargs: object) -> int:
                descriptor = real_open(*args, **kwargs)  # type: ignore[arg-type]
                opened_descriptors.append(descriptor)
                return descriptor

            with (
                patch("macos_dev_sandbox.cli.os.open", side_effect=tracked_open),
                patch(
                    "macos_dev_sandbox.cli.os.fstat",
                    side_effect=OSError("fstat failed"),
                ),
                self.assertRaisesRegex(SandboxError, "unsafe directory"),
            ):
                cli.open_owned_directory(path, "unsafe directory")
            self.assertTrue(opened_descriptors)
            for descriptor in opened_descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_process_reference_ignores_current_process_only(self) -> None:
        token = "UNIQUE-OWNED-UDID"
        own_inventory = subprocess.CompletedProcess(
            ["pgrep"], 0, stdout=f"{os.getpid()}\n", stderr=""
        )
        other_inventory = subprocess.CompletedProcess(
            ["pgrep"], 0, stdout="99999\n", stderr=""
        )
        with patch(
            "macos_dev_sandbox.cli.subprocess.run",
            side_effect=[own_inventory, other_inventory],
        ):
            self.assertFalse(cli.process_args_reference_any((token,)))
            self.assertTrue(cli.process_args_reference_any((token,)))

    def test_lane_lease_refuses_symlinked_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            lock_directory = base / "registry" / ".locks"
            lock_directory.mkdir(parents=True)
            target = base / "outside.txt"
            target.write_text("sentinel")
            lock_path = lock_directory / "lane.lock"
            lock_path.symlink_to(target)
            with (
                patch(
                    "macos_dev_sandbox.cli.ios_lane_lock_path", return_value=lock_path
                ),
                self.assertRaisesRegex(SandboxError, "unsafe simulator lane lock"),
                cli.ios_lane_lease(repo),
            ):
                self.fail("symlinked lock unexpectedly acquired")
            self.assertEqual("sentinel", target.read_text())

    def test_lane_lease_refuses_hardlinked_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            lock_directory = base / "registry" / ".locks"
            lock_directory.mkdir(parents=True)
            target = base / "outside.txt"
            target.write_text("sentinel")
            lock_path = lock_directory / "lane.lock"
            os.link(target, lock_path)
            with (
                patch(
                    "macos_dev_sandbox.cli.ios_lane_lock_path", return_value=lock_path
                ),
                self.assertRaisesRegex(SandboxError, "unsafe simulator lane lock"),
                cli.ios_lane_lease(repo),
            ):
                self.fail("hardlinked lock unexpectedly acquired")
            self.assertEqual("sentinel", target.read_text())

    def test_environment_writer_refuses_symlinked_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            root = base / "registry" / "sandbox"
            root.mkdir(parents=True)
            target = base / "outside.txt"
            target.write_text("sentinel")
            (root / "environment.sh").symlink_to(target)
            with (
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                self.assertRaisesRegex(SandboxError, "unsafe simulator sandbox output"),
            ):
                cli.write_ios_environment(repo)
            self.assertEqual("sentinel", target.read_text())

    def test_environment_writer_preserves_replacement_created_before_first_publish(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            root = base / "registry" / "sandbox"
            root.mkdir(parents=True)
            real_rename_exclusive = cli.rename_exclusive_at

            def inject_replacement(
                directory_fd: int, source: str, destination: str
            ) -> None:
                replacement_fd = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_fd,
                )
                try:
                    os.write(replacement_fd, b"replacement must survive\n")
                finally:
                    os.close(replacement_fd)
                real_rename_exclusive(directory_fd, source, destination)

            with (
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch(
                    "macos_dev_sandbox.cli.rename_exclusive_at",
                    side_effect=inject_replacement,
                ),
                self.assertRaisesRegex(SandboxError, "unsafe simulator sandbox output"),
            ):
                cli.write_ios_environment(repo)
            self.assertEqual(
                "replacement must survive\n", (root / "environment.sh").read_text()
            )

    def test_environment_writer_restores_existing_replacement_created_at_swap(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            root = base / "registry" / "sandbox"
            root.mkdir(parents=True)
            output = root / "environment.sh"
            output.write_text("original\n")
            real_rename_swap = cli.rename_swap_at
            injected = False

            def inject_replacement(
                directory_fd: int, source: str, destination: str
            ) -> None:
                nonlocal injected
                if not injected:
                    injected = True
                    os.unlink(destination, dir_fd=directory_fd)
                    replacement_fd = os.open(
                        destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=directory_fd,
                    )
                    try:
                        os.write(replacement_fd, b"replacement must survive\n")
                    finally:
                        os.close(replacement_fd)
                real_rename_swap(directory_fd, source, destination)

            with (
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch(
                    "macos_dev_sandbox.cli.rename_swap_at",
                    side_effect=inject_replacement,
                ),
                self.assertRaisesRegex(SandboxError, "unsafe simulator sandbox output"),
            ):
                cli.write_ios_environment(repo)
            self.assertEqual("replacement must survive\n", output.read_text())

    def test_environment_writer_refuses_symlinked_build_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            root = base / "registry" / "sandbox"
            root.mkdir(parents=True)
            outside = base / "outside"
            outside.mkdir()
            (root / "DerivedData").symlink_to(outside, target_is_directory=True)
            with (
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                self.assertRaisesRegex(
                    SandboxError, "unsafe simulator sandbox directory"
                ),
            ):
                cli.write_ios_environment(repo)

    def test_metadata_writer_refuses_symlinked_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            root = base / "registry" / "sandbox"
            root.mkdir(parents=True)
            target = base / "outside.txt"
            target.write_text("sentinel")
            (root / "simulator.json.tmp").symlink_to(target)
            with (
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                self.assertRaisesRegex(
                    SandboxError, "unsafe simulator metadata output"
                ),
            ):
                cli.write_simulator_metadata(repo, udid="OWNED", source_udid="SOURCE")
            self.assertEqual("sentinel", target.read_text())

    def test_environment_writer_rejects_symlinked_sandbox_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            registry = base / "registry"
            target = base / "target"
            registry.mkdir()
            target.mkdir()
            linked_root = registry / "linked-root"
            linked_root.symlink_to(target, target_is_directory=True)
            with (
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=linked_root),
                self.assertRaisesRegex(SandboxError, "unsafe simulator sandbox root"),
            ):
                cli.write_ios_environment(base / "repo")

    def test_cleanup_without_simulator_holds_lease_through_root_removal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            registry = base / "registry"
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root", return_value=registry
            ):
                root = sandbox_root(repo)
                cli.write_ios_environment(repo)
            held = False

            @contextmanager
            def lease(_repo: Path):
                nonlocal held
                held = True
                try:
                    yield
                finally:
                    held = False

            def remove(name: str, *, dir_fd: int) -> None:
                self.assertTrue(held)
                self.assertTrue(name.startswith(f".{root.name}.retired-"))
                os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                os.rmdir(name, dir_fd=dir_fd)

            with (
                patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
                patch("macos_dev_sandbox.cli.selected_cleanup_udid", return_value=None),
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.path_has_open_files", return_value=False),
                patch("macos_dev_sandbox.cli.shutil.rmtree", side_effect=remove),
            ):
                cli.cleanup_ios_sandbox(repo, None)

            self.assertFalse(root.exists())

    def test_cleanup_without_simulator_rejects_unauthenticated_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            root = base / "registry" / "sandbox"
            root.mkdir(parents=True)
            sentinel = root / "unrelated.txt"
            sentinel.write_text("preserve me\n")

            @contextmanager
            def lease(_repo: Path):
                yield

            with (
                patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
                patch("macos_dev_sandbox.cli.selected_cleanup_udid", return_value=None),
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.path_has_open_files", return_value=False),
                self.assertRaisesRegex(SandboxError, "ownership record"),
            ):
                cli.cleanup_ios_sandbox(repo, None)

            self.assertEqual("preserve me\n", sentinel.read_text())

    def test_cleanup_recovers_authenticated_orphaned_retired_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory).resolve()
            registry = temporary_root / "registry"
            repo = temporary_root / "repo"
            repo.mkdir()
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root",
                return_value=registry,
            ):
                cli.write_ios_environment(repo, "ALREADY-DELETED")
                root = cli.sandbox_root(repo)
                identity = cli.capture_sandbox_root_identity(root)
                assert identity is not None
                retired = cli.retire_sandbox_root(root, identity)
                self.assertFalse(root.exists())
                self.assertTrue(retired.path.is_dir())
                with (
                    patch(
                        "macos_dev_sandbox.cli.apple_lane_active", return_value=False
                    ),
                    patch(
                        "macos_dev_sandbox.cli.process_args_reference_any",
                        return_value=False,
                    ),
                    patch(
                        "macos_dev_sandbox.cli.path_has_open_files", return_value=False
                    ),
                ):
                    cli.cleanup_ios_sandbox(repo, None)
            self.assertFalse(root.exists())
            self.assertFalse(retired.path.exists())

    def test_orphan_recovery_restores_pristine_root_from_retirement_marker(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "registry" / "pristine-root"
            root.mkdir(parents=True)
            original = root.stat()
            identity = cli.capture_sandbox_root_identity(root)
            assert identity is not None

            retired = cli.retire_sandbox_root(root, identity)
            marker = cli.sandbox_retirement_marker_path(root)
            self.assertFalse(root.exists())
            self.assertTrue(retired.path.is_dir())
            self.assertTrue(marker.is_file())

            self.assertTrue(cli.restore_orphaned_retired_sandbox_root(root))
            restored = root.stat()
            self.assertEqual(
                (original.st_dev, original.st_ino), (restored.st_dev, restored.st_ino)
            )
            self.assertFalse(retired.path.exists())
            self.assertFalse(marker.exists())

    def test_orphan_recovery_refuses_substitution_after_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory).resolve()
            registry = temporary_root / "registry"
            repo = temporary_root / "repo"
            repo.mkdir()
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root",
                return_value=registry,
            ):
                cli.write_ios_environment(repo)
                root = cli.sandbox_root(repo)
                identity = cli.capture_sandbox_root_identity(root)
                assert identity is not None
                retired = cli.retire_sandbox_root(root, identity)
                captured = retired.path.with_name(f"{retired.path.name}.captured")
                real_validate = cli.registry_child_is_valid_build_root
                replacement_sentinel: Path | None = None

                def substitute_after_authentication(*args, **kwargs) -> bool:
                    nonlocal replacement_sentinel
                    trusted = real_validate(*args, **kwargs)
                    retired.path.rename(captured)
                    retired.path.mkdir()
                    replacement_sentinel = retired.path / "replacement"
                    replacement_sentinel.write_text("preserve me\n")
                    return trusted

                with (
                    patch(
                        "macos_dev_sandbox.cli.registry_child_is_valid_build_root",
                        side_effect=substitute_after_authentication,
                    ),
                    self.assertRaisesRegex(SandboxError, "changed during recovery"),
                ):
                    cli.restore_orphaned_retired_sandbox_root(root)

            self.assertFalse(root.exists())
            assert replacement_sentinel is not None
            self.assertEqual("preserve me\n", replacement_sentinel.read_text())
            self.assertTrue(captured.is_dir())

    def test_cleanup_without_simulator_checks_activity_before_retirement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            registry = base / "registry"
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root", return_value=registry
            ):
                cli.write_ios_environment(repo)
                root = sandbox_root(repo)

            @contextmanager
            def lease(_repo: Path):
                yield

            with (
                patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
                patch("macos_dev_sandbox.cli.selected_cleanup_udid", return_value=None),
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=True,
                ),
                patch("macos_dev_sandbox.cli.path_has_open_files", return_value=False),
                self.assertRaisesRegex(SandboxError, "process reference"),
            ):
                cli.cleanup_ios_sandbox(repo, None)
            self.assertTrue(root.exists())
            self.assertEqual([], list(root.parent.glob(f".{root.name}.retired-*")))

    def test_retired_root_removal_refuses_cross_device_entry_before_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = parent / ".sandbox.retired-test"
            root.mkdir()
            safe = root / "safe-file"
            safe.write_text("must also survive\n")
            child = root / "mounted-file"
            child.write_text("preserve me\n")
            root_stat = root.stat()
            parent_stat = parent.stat()
            retired = cli.RetiredSandboxRoot(
                path=root,
                device=root_stat.st_dev,
                inode=root_stat.st_ino,
                owner=root_stat.st_uid,
                parent_device=parent_stat.st_dev,
                parent_inode=parent_stat.st_ino,
            )
            real_stat = os.stat

            def cross_device_stat(path, *args, **kwargs):
                observed = real_stat(path, *args, **kwargs)
                if path != child.name:
                    return observed
                return os.stat_result(
                    (
                        observed.st_mode,
                        observed.st_ino,
                        observed.st_dev + 1,
                        observed.st_nlink,
                        observed.st_uid,
                        observed.st_gid,
                        observed.st_size,
                        observed.st_atime,
                        observed.st_mtime,
                        observed.st_ctime,
                    )
                )

            with (
                patch(
                    "macos_dev_sandbox.cli.os.listdir",
                    return_value=[safe.name, child.name],
                ),
                patch("macos_dev_sandbox.cli.os.stat", side_effect=cross_device_stat),
                self.assertRaisesRegex(SandboxError, "different filesystem"),
            ):
                cli.remove_retired_sandbox_root(retired)
            self.assertEqual("must also survive\n", safe.read_text())
            self.assertEqual("preserve me\n", child.read_text())

    def test_web_workspace_does_not_poison_simulator_registry_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            registry = base / "registry"
            web_repo = base / "web-repo"
            web_repo.mkdir()
            (web_repo / "package.json").write_text("{}\n")
            ios_repo = base / "ios-repo"
            ios_repo.mkdir()
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root", return_value=registry
            ):
                metadata = self.write_metadata(registry, ios_repo, "STALE")
                workspace = prepare_web_workspace(web_repo)
                metadata_paths, unsafe_paths = cli.registry_metadata_inventory(registry)
            self.assertEqual([metadata], metadata_paths)
            self.assertEqual([], unsafe_paths)
            self.assertTrue(workspace.is_dir())
            self.assertFalse(workspace.is_relative_to(registry))

    def test_cleanup_restores_root_when_simulator_delete_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            metadata_path = self.write_metadata(base, repo, "OWNED")
            root = metadata_path.parent
            metadata = cli.prune_metadata(metadata_path, root.parent)
            assert metadata is not None
            device = {"OWNED": self.device(repo, "OWNED")}

            @contextmanager
            def lease(_repo: Path):
                yield

            with (
                patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch(
                    "macos_dev_sandbox.cli.selected_cleanup_udid", return_value="OWNED"
                ),
                patch(
                    "macos_dev_sandbox.cli.trusted_simulator_metadata",
                    return_value=metadata,
                ),
                patch("macos_dev_sandbox.cli.owned_simulator", return_value="OWNED"),
                patch(
                    "macos_dev_sandbox.cli.available_simulators",
                    side_effect=[device, device, device],
                ),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.simulator_device_has_open_files",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.path_has_open_files", return_value=False),
                patch("macos_dev_sandbox.cli.subprocess.run"),
                patch(
                    "macos_dev_sandbox.cli.run_checked",
                    side_effect=SandboxError("delete failed"),
                ),
                self.assertRaisesRegex(SandboxError, "delete failed"),
            ):
                cli.cleanup_ios_sandbox(repo, "OWNED")
            self.assertTrue(root.exists())
            self.assertEqual([], list(root.parent.glob(f".{root.name}.retired-*")))

    def test_cleanup_refuses_substituted_retired_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            registry = base / "registry"
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root", return_value=registry
            ):
                cli.write_ios_environment(repo)
                root = sandbox_root(repo)
            retired_checks = 0
            replacement_sentinel: Path | None = None

            @contextmanager
            def lease(_repo: Path):
                yield

            def replace_before_final_removal(path: Path) -> bool:
                nonlocal retired_checks, replacement_sentinel
                if path.name.startswith(f".{root.name}.retired-"):
                    retired_checks += 1
                    if retired_checks == 2:
                        captured = path.with_name(f"{path.name}.captured")
                        path.rename(captured)
                        path.mkdir()
                        replacement_sentinel = path / "replacement-sentinel"
                        replacement_sentinel.write_text("preserve me\n")
                return False

            with (
                patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
                patch("macos_dev_sandbox.cli.selected_cleanup_udid", return_value=None),
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch(
                    "macos_dev_sandbox.cli.path_has_open_files",
                    side_effect=replace_before_final_removal,
                ),
                self.assertRaisesRegex(SandboxError, "changed before removal"),
            ):
                cli.cleanup_ios_sandbox(repo, None)
            assert replacement_sentinel is not None
            self.assertEqual("preserve me\n", replacement_sentinel.read_text())

    def test_cleanup_refuses_root_replacement_before_retirement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            registry = base / "registry"
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root", return_value=registry
            ):
                cli.write_ios_environment(repo)
                root = sandbox_root(repo)
            (root / "original").write_text("original\n")
            captured = root.with_name("captured-original")
            real_retire = cli.retire_sandbox_root

            @contextmanager
            def lease(_repo: Path):
                yield

            def replace_then_retire(path: Path, expected):
                path.rename(captured)
                path.mkdir()
                (path / "replacement").write_text("preserve me\n")
                return real_retire(path, expected)

            with (
                patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
                patch("macos_dev_sandbox.cli.selected_cleanup_udid", return_value=None),
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.path_has_open_files", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.retire_sandbox_root",
                    side_effect=replace_then_retire,
                ),
                self.assertRaisesRegex(SandboxError, "changed before retirement"),
            ):
                cli.cleanup_ios_sandbox(repo, None)
            self.assertEqual("preserve me\n", (root / "replacement").read_text())
            self.assertEqual("original\n", (captured / "original").read_text())

    def test_cleanup_preserves_replacement_after_retired_root_is_opened(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / "repo"
            repo.mkdir()
            registry = base / "registry"
            with patch(
                "macos_dev_sandbox.cli.simulator_registry_root", return_value=registry
            ):
                cli.write_ios_environment(repo)
                root = sandbox_root(repo)
            (root / "original").write_text("original\n")
            real_remove_contents = cli.remove_directory_contents_at
            replacement: Path | None = None

            @contextmanager
            def lease(_repo: Path):
                yield

            def substitute_after_open(
                directory_fd: int, owner: int, device: int
            ) -> None:
                nonlocal replacement
                if replacement is None:
                    retired = next(root.parent.glob(f".{root.name}.retired-*"))
                    captured = retired.with_name(f"{retired.name}.captured")
                    retired.rename(captured)
                    retired.mkdir()
                    replacement = retired / "replacement"
                    replacement.write_text("preserve me\n")
                real_remove_contents(directory_fd, owner, device)

            with (
                patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
                patch("macos_dev_sandbox.cli.selected_cleanup_udid", return_value=None),
                patch("macos_dev_sandbox.cli.sandbox_root", return_value=root),
                patch("macos_dev_sandbox.cli.apple_lane_active", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.process_args_reference_any",
                    return_value=False,
                ),
                patch("macos_dev_sandbox.cli.path_has_open_files", return_value=False),
                patch(
                    "macos_dev_sandbox.cli.remove_directory_contents_at",
                    side_effect=substitute_after_open,
                ),
                self.assertRaisesRegex(SandboxError, "changed after content removal"),
            ):
                cli.cleanup_ios_sandbox(repo, None)
            assert replacement is not None
            self.assertEqual("preserve me\n", replacement.read_text())

    def test_root_retirement_restores_replacement_moved_during_rename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = parent / "sandbox"
            root.mkdir()
            (root / "original").write_text("original\n")
            expected = cli.capture_sandbox_root_identity(root)
            assert expected is not None
            captured = parent / "captured-original"
            real_rename = cli.rename_exclusive_at
            injected = False

            def replace_during_rename(
                directory_fd: int, source: str, destination: str
            ) -> None:
                nonlocal injected
                if source == root.name and not injected:
                    root.rename(captured)
                    root.mkdir()
                    (root / "replacement").write_text("preserve me\n")
                    injected = True
                real_rename(directory_fd, source, destination)

            with (
                patch(
                    "macos_dev_sandbox.cli.rename_exclusive_at",
                    side_effect=replace_during_rename,
                ),
                self.assertRaisesRegex(SandboxError, "changed during retirement"),
            ):
                cli.retire_sandbox_root(root, expected)

            self.assertEqual("preserve me\n", (root / "replacement").read_text())
            self.assertEqual("original\n", (captured / "original").read_text())

    def test_recursive_removal_preserves_replaced_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            victim = root / "victim.txt"
            victim.write_text("original\n")
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            real_stat = os.stat
            victim_stats = 0

            def replace_after_first_stat(path, *args, **kwargs):
                nonlocal victim_stats
                result = real_stat(path, *args, **kwargs)
                if path == victim.name:
                    victim_stats += 1
                    if victim_stats == 1:
                        os.unlink(victim.name, dir_fd=directory_fd)
                        replacement_fd = os.open(
                            victim.name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=directory_fd,
                        )
                        try:
                            os.write(replacement_fd, b"preserve me\n")
                        finally:
                            os.close(replacement_fd)
                return result

            try:
                with (
                    patch(
                        "macos_dev_sandbox.cli.os.stat",
                        side_effect=replace_after_first_stat,
                    ),
                    self.assertRaisesRegex(SandboxError, "changed during removal"),
                ):
                    cli.remove_directory_contents_at(
                        directory_fd, os.getuid(), os.fstat(directory_fd).st_dev
                    )
            finally:
                os.close(directory_fd)

            self.assertEqual("preserve me\n", victim.read_text())

    def test_run_ios_lane_bounds_boot_and_shutdown_controls(self) -> None:
        child = MagicMock()
        child.wait.return_value = 0
        with (
            patch("macos_dev_sandbox.cli.write_ios_environment"),
            patch("macos_dev_sandbox.cli.mark_simulator_used"),
            patch("macos_dev_sandbox.cli.subprocess.run") as control,
            patch("macos_dev_sandbox.cli.run_checked"),
            patch("macos_dev_sandbox.cli.subprocess.Popen", return_value=child),
        ):
            self.assertEqual(
                0,
                cli.run_ios_lane(
                    Path("/tmp/worktree"),
                    "OWNED",
                    ["/usr/bin/true"],
                    False,
                    lease_held=True,
                ),
            )
        self.assertEqual(
            [
                call(
                    ["xcrun", "simctl", "boot", "OWNED"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=True,
                ),
                call(
                    ["xcrun", "simctl", "shutdown", "OWNED"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=True,
                ),
            ],
            control.call_args_list,
        )

    def test_quiet_control_rejects_nonzero_exit(self) -> None:
        with (
            patch(
                "macos_dev_sandbox.cli.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, ["xcrun", "simctl"]),
            ),
            self.assertRaisesRegex(SandboxError, "simulator shutdown failed"),
        ):
            cli.run_quiet_control(
                ["xcrun", "simctl", "shutdown", "OWNED"],
                operation="simulator shutdown",
            )

    def test_run_ios_lane_shutdowns_when_bootstatus_fails(self) -> None:
        with (
            patch("macos_dev_sandbox.cli.write_ios_environment"),
            patch("macos_dev_sandbox.cli.mark_simulator_used"),
            patch("macos_dev_sandbox.cli.run_quiet_control") as control,
            patch(
                "macos_dev_sandbox.cli.run_checked",
                side_effect=SandboxError("bootstatus failed"),
            ),
            patch("macos_dev_sandbox.cli.subprocess.Popen") as popen,
            self.assertRaisesRegex(SandboxError, "bootstatus failed"),
        ):
            cli.run_ios_lane(
                Path("/tmp/worktree"),
                "OWNED",
                ["/usr/bin/true"],
                False,
                lease_held=True,
            )
        self.assertEqual(
            [
                call(
                    ["xcrun", "simctl", "boot", "OWNED"],
                    operation="simulator boot",
                ),
                call(
                    ["xcrun", "simctl", "shutdown", "OWNED"],
                    operation="simulator shutdown",
                ),
            ],
            control.call_args_list,
        )
        popen.assert_not_called()

    def test_create_to_run_transition_stays_under_one_lane_lease(self) -> None:
        repo = Path("/tmp/worktree")
        held = False

        @contextmanager
        def lease(_repo: Path):
            nonlocal held
            held = True
            try:
                yield
            finally:
                held = False

        def ensure(
            _repo: Path, _source: str | None, *, lease_held: bool = False
        ) -> str:
            self.assertTrue(held)
            self.assertTrue(lease_held)
            return "OWNED"

        def run(
            _repo: Path,
            _udid: str,
            _command: list[str],
            _keep: bool,
            *,
            lease_held: bool = False,
        ) -> int:
            self.assertTrue(held)
            self.assertTrue(lease_held)
            return 0

        with (
            patch("macos_dev_sandbox.cli.ios_lane_lease", side_effect=lease),
            patch("macos_dev_sandbox.cli.ensure_owned_simulator", side_effect=ensure),
            patch("macos_dev_sandbox.cli.run_ios_lane", side_effect=run),
        ):
            self.assertEqual(
                0,
                cli.run_ios_with_owned_simulator(repo, "SOURCE", ["xcodebuild"], False),
            )


if __name__ == "__main__":
    unittest.main()
