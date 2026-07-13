from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from macos_dev_sandbox.cli import (
    SandboxError,
    ensure_safe_command,
    ios_build_command,
    ios_environment,
    prepare_web_workspace,
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
        self.assertIn(f"type=bind,source={web_workspace(repo)},target=/workspace", rendered)
        self.assertIn("--read-only", command)
        self.assertNotIn("--ssh", command)
        self.assertNotIn("--env-file", command)
        self.assertEqual(rendered.count("type=bind"), 1)
        self.assertIn("type=volume", rendered)

    def test_port_is_opt_in(self) -> None:
        command = web_command(
            repo=Path("/tmp/example"), command=["npm", "run", "dev"],
            engine="docker", image="node:24", cpus=2, memory="4G", port="127.0.0.1:3000:3000",
        )
        self.assertIn("127.0.0.1:3000:3000", command)

    def test_workspace_id_is_stable_and_path_specific(self) -> None:
        self.assertEqual(workspace_id(Path("/tmp/a")), workspace_id(Path("/tmp/a")))
        self.assertNotEqual(workspace_id(Path("/tmp/a")), workspace_id(Path("/tmp/b")))

    def test_staging_copy_excludes_repository_local_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / ".env.local").write_text("SECRET=not-visible")
            (repo / ".npmrc").write_text("//registry.example/:_authToken=not-visible")
            (repo / "source.txt").write_text("visible")
            workspace = prepare_web_workspace(repo)
            self.assertFalse((workspace / ".env.local").exists())
            self.assertFalse((workspace / ".npmrc").exists())
            self.assertEqual((workspace / "source.txt").read_text(), "visible")


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
        self.assertIn(workspace_id(repo).split("-")[-1], environment["DEV_SANDBOX_ROOT"])
        self.assertNotEqual(
            environment["DEV_SANDBOX_DERIVED_DATA"], environment["DEV_SANDBOX_RESULTS"]
        )

    def test_build_lane_requires_generic_simulator_build_for_testing(self) -> None:
        validate_ios_build_command(
            [
                "xcodebuild",
                "-project", "ExampleApp.xcodeproj",
                "-scheme", "ExampleAppTests",
                "-destination", "generic/platform=iOS Simulator",
                "build-for-testing",
            ]
        )
        for command in (
            ["xcodebuild", "-destination", "platform=iOS Simulator,name=iPhone 17", "build-for-testing"],
            ["xcodebuild", "-destination", "generic/platform=iOS Simulator", "test"],
            ["./scripts/project_xcodebuild.sh", "-destination", "generic/platform=iOS Simulator", "build-for-testing"],
        ):
            with self.subTest(command=command):
                with self.assertRaises(SandboxError):
                    validate_ios_build_command(command)

    def test_build_lane_injects_isolated_artifact_paths(self) -> None:
        repo = Path("/tmp/worktree-a")
        command = ios_build_command(
            repo,
            [
                "xcodebuild",
                "-project", "ExampleApp.xcodeproj",
                "-scheme", "ExampleAppTests",
                "-destination", "generic/platform=iOS Simulator",
                "build-for-testing",
            ],
        )
        rendered = " ".join(command)
        environment = ios_environment(repo)
        self.assertIn(f"-derivedDataPath {environment['DEV_SANDBOX_DERIVED_DATA']}", rendered)
        self.assertIn(
            f"-clonedSourcePackagesDirPath {environment['DEV_SANDBOX_SOURCE_PACKAGES']}", rendered
        )
        self.assertIn("-resultBundlePath", command)
        self.assertIn(environment["DEV_SANDBOX_RESULTS"], rendered)


if __name__ == "__main__":
    unittest.main()
