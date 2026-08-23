#!/usr/bin/env python3
"""Regression mutations for the source-install lifecycle structure checker."""

from __future__ import annotations

import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = REPO_ROOT / "test/check-source-install-lifecycle.py"
JUSTFILE = REPO_ROOT / "justfile"
CONTAINERFILE = REPO_ROOT / "test/Containerfile"
SYSTEMD_LIFECYCLE_RUNNER = (
    REPO_ROOT / "test/run-source-install-daemon-lifecycle-systemd.sh"
)
SYSTEMD_LIFECYCLE_HARNESS = (
    REPO_ROOT / "test/source-install-daemon-lifecycle-systemd.sh"
)
SOURCE_LIFECYCLE_TEST = REPO_ROOT / "test/source-install-daemon-lifecycle.sh"
CONTAINER_HELPER_COPY = (
    b"COPY scripts/source-install-daemon-lifecycle.sh "
    b"/build/scripts/source-install-daemon-lifecycle.sh"
)
BOOTED_LIFECYCLE_FIXTURE_COPIES = (
    b"COPY test/source-install-recipe-install-probe.sh "
    b"/source-install-lifecycle/test/source-install-recipe-install-probe.sh",
    b"COPY test/source-install-recipe-fake-systemctl.sh "
    b"/source-install-lifecycle/test/source-install-recipe-fake-systemctl.sh",
    b"COPY test/source-install-recipe-fake-busctl.sh "
    b"/source-install-lifecycle/test/source-install-recipe-fake-busctl.sh",
)
CONTAINER_INSTALL_LINE = "    just install-files"
SOURCE_LINE = "    source scripts/source-install-daemon-lifecycle.sh"
BEGIN_LINE = "    facelock_source_install_begin"
COMPLETE_LINE = "    facelock_source_install_complete"
STATUS_LINE = "    if $NEEDS_SETUP || $NEEDS_ORT; then"
INSTALL_FILES_STRICT_MODE = (
    "\ninstall-files:\n    #!/usr/bin/bash -p\n    set -euo pipefail"
)
POSTLUDE_BLANK_LINES = '    echo ""\n    echo ""'
INSTALL_FILES_SHEBANG = "\ninstall-files:\n    #!/usr/bin/bash -p\n"
RECIPE_CASE_NAME = re.compile(r"\b(recipe-[a-z0-9-]+)\b")


def dispatched_recipe_cases(body: str) -> list[str]:
    cases: list[str] = []
    for line in body.splitlines():
        if not re.match(r"^\s*recipe-[a-z0-9-]+", line):
            continue
        case_pattern = line.split(")", 1)[0]
        cases.extend(RECIPE_CASE_NAME.findall(case_pattern))
    return cases


class SourceInstallLifecycleCheckerTests(unittest.TestCase):
    def install_files_bash(self, justfile: bytes) -> bytes:
        lines = justfile.split(b"\n")
        start = lines.index(b"install-files:") + 1
        recipe: list[bytes] = []
        for line in lines[start:]:
            if line and not line.startswith((b" ", b"\t", b"#")):
                break
            recipe.append(line[4:] if line.startswith(b"    ") else line)
        return b"\n".join(recipe) + b"\n"

    def assert_valid_bash(self, name: str, justfile: str) -> None:
        result = subprocess.run(
            ["bash", "-n"],
            input=self.install_files_bash(justfile.encode()),
            check=False,
            capture_output=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"{name} mutation is not valid Bash:\n{result.stderr.decode()}",
        )

    def run_checker(
        self,
        justfile: pathlib.Path,
        containerfile: pathlib.Path = CONTAINERFILE,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), str(justfile), str(containerfile)],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_mutation_rejected(
        self,
        name: str,
        needle: str,
        replacement: str,
        expected_diagnostic: str | None = None,
    ) -> None:
        original = JUSTFILE.read_bytes().decode()
        self.assertEqual(
            original.count(needle),
            1,
            f"mutation needle count changed for {name}: {needle!r}",
        )
        mutated = original.replace(needle, replacement, 1)
        self.assert_valid_bash(name, mutated)
        with tempfile.TemporaryDirectory(prefix="facelock-lifecycle-checker-") as temp:
            mutated_path = pathlib.Path(temp) / "justfile"
            mutated_path.write_bytes(mutated.encode())
            result = self.run_checker(mutated_path)
        self.assertNotEqual(
            result.returncode,
            0,
            f"checker accepted {name} mutation",
        )
        diagnostic = "source-install lifecycle structure:"
        if expected_diagnostic is not None:
            diagnostic += f" {expected_diagnostic}"
        self.assertIn(diagnostic, result.stderr, f"checker did not diagnose {name} mutation")
        self.assertNotIn("Traceback", result.stderr)

    def assert_control_cannot_create_checker_only_begin(
        self, name: str, control: str, expected_byte: int
    ) -> None:
        original = JUSTFILE.read_bytes().decode()
        mutated = original.replace(
            BEGIN_LINE,
            "    # checker-comment" + control + BEGIN_LINE,
            1,
        )
        self.assert_valid_bash(name, mutated)

        with tempfile.TemporaryDirectory(prefix="facelock-lifecycle-checker-") as temp:
            mutated_path = pathlib.Path(temp) / "justfile"
            mutated_path.write_bytes(mutated.encode())
            dry_run = subprocess.run(
                [
                    "just",
                    "--dry-run",
                    "--justfile",
                    str(mutated_path),
                    "--working-directory",
                    str(REPO_ROOT),
                    "install-files",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
            )
            result = self.run_checker(mutated_path)

        self.assertEqual(dry_run.returncode, 0, dry_run.stderr.decode())
        active_lines = [
            line.strip(b" \t")
            for line in (dry_run.stdout + dry_run.stderr).split(b"\n")
        ]
        self.assertNotIn(BEGIN_LINE.strip(" \t").encode(), active_lines)
        self.assertIn(
            b"install -Dm755 target/release/facelock /usr/bin/facelock",
            active_lines,
        )
        self.assertNotEqual(result.returncode, 0, f"checker accepted {name} mutation")
        self.assertIn(
            "source-install lifecycle structure: "
            f"disallowed control byte 0x{expected_byte:02x}",
            result.stderr,
        )
        self.assertNotIn("Traceback", result.stderr)

    def assert_unicode_whitespace_cannot_normalize_begin(
        self, name: str, whitespace: str
    ) -> None:
        original = JUSTFILE.read_bytes().decode()
        mutated = original.replace(BEGIN_LINE, BEGIN_LINE + whitespace, 1)
        self.assert_valid_bash(name, mutated)

        with tempfile.TemporaryDirectory(prefix="facelock-lifecycle-checker-") as temp:
            mutated_path = pathlib.Path(temp) / "justfile"
            mutated_path.write_bytes(mutated.encode())
            dry_run = subprocess.run(
                [
                    "just",
                    "--dry-run",
                    "--justfile",
                    str(mutated_path),
                    "--working-directory",
                    str(REPO_ROOT),
                    "install-files",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
            )
            result = self.run_checker(mutated_path)

        self.assertEqual(dry_run.returncode, 0, dry_run.stderr.decode())
        active_lines = [
            line.strip(b" \t")
            for line in (dry_run.stdout + dry_run.stderr).split(b"\n")
        ]
        canonical_begin = BEGIN_LINE.encode().strip(b" \t")
        self.assertNotIn(canonical_begin, active_lines)
        self.assertIn(canonical_begin + whitespace.encode(), active_lines)
        self.assertIn(
            b"install -Dm755 target/release/facelock /usr/bin/facelock",
            active_lines,
        )
        self.assertNotEqual(result.returncode, 0, f"checker accepted {name} mutation")
        self.assertIn(
            "source-install lifecycle structure: disallowed Unicode whitespace "
            f"U+{ord(whitespace):04X}",
            result.stderr,
        )
        self.assertNotIn("Traceback", result.stderr)

    def test_canonical_files_are_accepted(self) -> None:
        result = self.run_checker(JUSTFILE)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_justfile_startup_environment_exports_are_rejected(self) -> None:
        original = JUSTFILE.read_bytes().decode()
        for variable in ("BASH_ENV", "ENV"):
            with self.subTest(variable=variable):
                mutated = f'export {variable} := "/tmp/facelock-hook"\n' + original
                with tempfile.TemporaryDirectory(
                    prefix="facelock-lifecycle-checker-"
                ) as temp:
                    mutated_path = pathlib.Path(temp) / "justfile"
                    mutated_path.write_bytes(mutated.encode())
                    dry_run = subprocess.run(
                        [
                            "just",
                            "--dry-run",
                            "--justfile",
                            str(mutated_path),
                            "--working-directory",
                            str(REPO_ROOT),
                            "install-files",
                        ],
                        cwd=REPO_ROOT,
                        check=False,
                        capture_output=True,
                    )
                    result = self.run_checker(mutated_path)
                self.assertEqual(dry_run.returncode, 0, dry_run.stderr.decode())
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "source-install lifecycle structure: shell startup "
                    "environment is forbidden in Justfile",
                    result.stderr,
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_privileged_bash_shebang_ignores_caller_bash_env(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="facelock-lifecycle-bash-env-"
        ) as temp:
            temp_path = pathlib.Path(temp)
            hook = temp_path / "hook.sh"
            marker = temp_path / "hook-ran"
            probe = temp_path / "justfile"
            hook.write_text(f"touch -- {shlex.quote(str(marker))}\n")
            probe.write_text(
                "probe:\n"
                "    #!/usr/bin/bash -p\n"
                "    set -euo pipefail\n"
                f"    test ! -e {shlex.quote(str(marker))}\n"
            )
            result = subprocess.run(
                [
                    "just",
                    "--justfile",
                    str(probe),
                    "--working-directory",
                    str(temp_path),
                    "probe",
                ],
                cwd=REPO_ROOT,
                env={
                    **os.environ,
                    "BASH_ENV": str(hook),
                    "XDG_RUNTIME_DIR": str(temp_path),
                },
                check=False,
                capture_output=True,
                text=True,
            )
            marker_was_created = marker.exists()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker_was_created, "privileged Bash processed caller BASH_ENV")

    def test_lone_cr_cannot_create_a_checker_only_lifecycle_begin(self) -> None:
        self.assert_control_cannot_create_checker_only_begin(
            "lone CR checker-only lifecycle begin", "\r", 0x0D
        )

    def test_vertical_tab_cannot_create_a_checker_only_lifecycle_begin(self) -> None:
        self.assert_control_cannot_create_checker_only_begin(
            "vertical tab checker-only lifecycle begin", "\v", 0x0B
        )

    def test_unicode_whitespace_cannot_create_a_checker_only_begin(self) -> None:
        candidates = {
            "no-break space": "\u00a0",
            "figure space": "\u2007",
            "line separator": "\u2028",
            "paragraph separator": "\u2029",
            "narrow no-break space": "\u202f",
            "ideographic space": "\u3000",
        }
        for name, whitespace in candidates.items():
            with self.subTest(name=name):
                self.assert_unicode_whitespace_cannot_normalize_begin(
                    name, whitespace
                )

    def test_other_disallowed_justfile_controls_are_rejected_before_parsing(
        self,
    ) -> None:
        original = JUSTFILE.read_bytes()
        needle = BEGIN_LINE.encode()
        for byte in (0x00, 0x01, 0x0C, 0x1F, 0x7F):
            with self.subTest(byte=f"0x{byte:02x}"):
                mutated = original.replace(
                    needle,
                    b"    # checker-comment" + bytes((byte,)) + needle,
                    1,
                )
                with tempfile.TemporaryDirectory(
                    prefix="facelock-lifecycle-checker-"
                ) as temp:
                    mutated_path = pathlib.Path(temp) / "justfile"
                    mutated_path.write_bytes(mutated)
                    result = self.run_checker(mutated_path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "source-install lifecycle structure: "
                    f"disallowed control byte 0x{byte:02x}",
                    result.stderr,
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_crlf_is_rejected_by_the_lf_only_input_policy(self) -> None:
        mutated = JUSTFILE.read_bytes().replace(b"\n", b"\r\n", 1)
        with tempfile.TemporaryDirectory(prefix="facelock-lifecycle-checker-") as temp:
            mutated_path = pathlib.Path(temp) / "justfile"
            mutated_path.write_bytes(mutated)
            result = self.run_checker(mutated_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "source-install lifecycle structure: disallowed control byte 0x0d",
            result.stderr,
        )
        self.assertNotIn("Traceback", result.stderr)

    def test_invalid_utf8_has_a_controlled_diagnostic(self) -> None:
        mutated = b"\xff" + JUSTFILE.read_bytes()
        with tempfile.TemporaryDirectory(prefix="facelock-lifecycle-checker-") as temp:
            mutated_path = pathlib.Path(temp) / "justfile"
            mutated_path.write_bytes(mutated)
            result = self.run_checker(mutated_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not valid UTF-8", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_containerfile_control_cannot_create_a_checker_only_copy(self) -> None:
        original = CONTAINERFILE.read_bytes()
        for byte in (0x0B, 0x0D):
            with self.subTest(byte=f"0x{byte:02x}"):
                mutated = original.replace(
                    CONTAINER_HELPER_COPY,
                    b"# checker-comment"
                    + bytes((byte,))
                    + CONTAINER_HELPER_COPY,
                    1,
                )
                with tempfile.TemporaryDirectory(
                    prefix="facelock-lifecycle-checker-"
                ) as temp:
                    mutated_path = pathlib.Path(temp) / "Containerfile"
                    mutated_path.write_bytes(mutated)
                    result = self.run_checker(JUSTFILE, mutated_path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "source-install lifecycle structure: "
                    f"disallowed control byte 0x{byte:02x}",
                    result.stderr,
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_booted_lifecycle_fixture_sources_are_required(self) -> None:
        original = CONTAINERFILE.read_bytes()
        candidate = original + b"\n" + b"\n".join(
            copy_line
            for copy_line in BOOTED_LIFECYCLE_FIXTURE_COPIES
            if copy_line not in original
        ) + b"\n"
        for copy_line in BOOTED_LIFECYCLE_FIXTURE_COPIES:
            with self.subTest(copy_line=copy_line.decode()):
                self.assertEqual(candidate.count(copy_line), 1)
                mutated = candidate.replace(copy_line + b"\n", b"", 1)
                with tempfile.TemporaryDirectory(
                    prefix="facelock-lifecycle-checker-"
                ) as temp:
                    mutated_path = pathlib.Path(temp) / "Containerfile"
                    mutated_path.write_bytes(mutated)
                    result = self.run_checker(JUSTFILE, mutated_path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "source-install lifecycle structure: missing booted systemd "
                    "lifecycle fixture copy",
                    result.stderr,
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_source_lifecycle_runs_booted_recipe_dispatch_contract(self) -> None:
        source = SOURCE_LIFECYCLE_TEST.read_text()
        self.assertIn(
            'python3 "$repo_root/test/check-source-install-lifecycle-test.py"',
            source,
        )

    def test_recipe_dispatch_parser_ignores_comments_and_preserves_duplicates(
        self,
    ) -> None:
        body = """
            recipe-alpha | recipe-beta) # recipe-comment-spoof
            recipe-alpha)
        """
        self.assertEqual(
            dispatched_recipe_cases(body),
            ["recipe-alpha", "recipe-beta", "recipe-alpha"],
        )

    def test_booted_recipe_inventory_reaches_top_level_dispatch(self) -> None:
        runner = SYSTEMD_LIFECYCLE_RUNNER.read_text()
        harness = SYSTEMD_LIFECYCLE_HARNESS.read_text()
        runner_inventory = re.search(
            r"^cases=\(\n(?P<body>.*?)^\)", runner, re.MULTILINE | re.DOTALL
        )
        recipe_dispatch = re.search(
            r"^run_recipe_case\(\) \{.*?^\s+case \"\$case_name\" in\n"
            r"(?P<body>.*?)^\s+esac",
            harness,
            re.MULTILINE | re.DOTALL,
        )
        top_level_dispatch = re.search(
            r"^case \"\$case_name\" in\n(?P<body>.*?)^esac\n\nexpected_success",
            harness,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(runner_inventory)
        self.assertIsNotNone(recipe_dispatch)
        self.assertIsNotNone(top_level_dispatch)

        runner_cases = re.findall(
            r"^\s*(recipe-[a-z0-9-]+)\s*$",
            runner_inventory.group("body"),
            re.MULTILINE,
        )
        recipe_cases = dispatched_recipe_cases(recipe_dispatch.group("body"))
        top_level_cases = dispatched_recipe_cases(top_level_dispatch.group("body"))
        for name, cases in (
            ("runner", runner_cases),
            ("run_recipe_case", recipe_cases),
            ("top-level", top_level_cases),
        ):
            with self.subTest(dispatch=name):
                self.assertEqual(
                    len(cases),
                    len(set(cases)),
                    f"{name} recipe dispatch contains duplicate case labels",
                )
        self.assertEqual(set(runner_cases), set(recipe_cases))
        self.assertEqual(set(runner_cases), set(top_level_cases))

    def test_booted_recipe_dispatch_rejects_comment_and_duplicate_mutations(
        self,
    ) -> None:
        runner = SYSTEMD_LIFECYCLE_RUNNER.read_text()
        harness = SYSTEMD_LIFECYCLE_HARNESS.read_text()
        runner_inventory = re.search(
            r"^cases=\(\n(?P<body>.*?)^\)", runner, re.MULTILINE | re.DOTALL
        )
        top_level_dispatch = re.search(
            r"^case \"\$case_name\" in\n(?P<body>.*?)^esac\n\nexpected_success",
            harness,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(runner_inventory)
        self.assertIsNotNone(top_level_dispatch)
        runner_cases = re.findall(
            r"^\s*(recipe-[a-z0-9-]+)\s*$",
            runner_inventory.group("body"),
            re.MULTILINE,
        )
        route = (
            "recipe-known-legacy-retired | recipe-admin-overrides-preserved | \\\n"
            "        recipe-fake-manager-overrides-preserved)"
        )
        top_level = top_level_dispatch.group("body")
        self.assertEqual(top_level.count(route), 1)

        comment_mutation = top_level.replace(
            route,
            "recipe-admin-overrides-preserved | \\\n"
            "        recipe-fake-manager-overrides-preserved)\n"
            "    # recipe-known-legacy-retired",
            1,
        )
        comment_cases = dispatched_recipe_cases(comment_mutation)
        self.assertNotEqual(set(runner_cases), set(comment_cases))

        duplicate_mutation = top_level.replace(
            "recipe-known-legacy-retired | recipe-admin-overrides-preserved",
            "recipe-known-legacy-retired | recipe-known-legacy-retired | "
            "recipe-admin-overrides-preserved",
            1,
        )
        duplicate_cases = dispatched_recipe_cases(duplicate_mutation)
        self.assertNotEqual(len(duplicate_cases), len(set(duplicate_cases)))

    def test_normalized_extra_container_install_invocations_are_rejected(
        self,
    ) -> None:
        mutations = {
            "quote-concatenated argument": (
                'just install"-files"',
                "sh",
                "expected the offline-image command to be the only active "
                "install-files invocation",
            ),
            "backslash-escaped argument": (
                r"just install\-files",
                "sh",
                "expected the offline-image command to be the only active "
                "install-files invocation",
            ),
            "prefix operator-adjacent invocation": (
                'true&&just install"-files"',
                "sh",
                "expected the offline-image command to be the only active "
                "install-files invocation",
            ),
            "suffix operator-adjacent invocation": (
                'just install"-files"&&true',
                "sh",
                "expected the offline-image command to be the only active "
                "install-files invocation",
            ),
            "or-list operator-adjacent invocation": (
                'false||just install"-files"',
                "sh",
                "expected the offline-image command to be the only active "
                "install-files invocation",
            ),
            "pipeline operator-adjacent invocation": (
                'printf x|just install"-files"',
                "sh",
                "expected the offline-image command to be the only active "
                "install-files invocation",
            ),
            "ANSI-C quoted argument": (
                "just install$'-files'",
                "bash",
                "unsupported shell quote syntax in Containerfile",
            ),
            "localized quoted argument": (
                'just install$"-files"',
                "bash",
                "unsupported shell quote syntax in Containerfile",
            ),
        }
        original = CONTAINERFILE.read_bytes().decode()
        for name, (payload, shell, expected_diagnostic) in mutations.items():
            with self.subTest(name=name):
                shell_result = subprocess.run(
                    [
                        shell,
                        "-c",
                        'just() { printf "%s\\n" "$1"; }\n' + payload,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(shell_result.returncode, 0, shell_result.stderr)
                self.assertEqual(shell_result.stdout, "install-files\n")

                mutated = original.replace(
                    CONTAINER_INSTALL_LINE,
                    CONTAINER_INSTALL_LINE + "\nRUN " + payload,
                    1,
                )
                with tempfile.TemporaryDirectory(
                    prefix="facelock-lifecycle-checker-"
                ) as temp:
                    mutated_path = pathlib.Path(temp) / "Containerfile"
                    mutated_path.write_bytes(mutated.encode())
                    result = self.run_checker(JUSTFILE, mutated_path)
                self.assertNotEqual(result.returncode, 0, f"checker accepted {name}")
                self.assertIn(
                    "source-install lifecycle structure: " + expected_diagnostic,
                    result.stderr,
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_continued_extra_container_install_invocations_are_rejected(
        self,
    ) -> None:
        payloads = {
            "continued command argument": "just \\\n    install-files",
            "continued quote-concatenated command and argument": (
                'ju"st" \\\n    install"-files"'
            ),
            "continued split argument": "just install\\\n-files",
        }
        original = CONTAINERFILE.read_bytes().decode()
        expected_diagnostic = (
            "expected the offline-image command to be the only active "
            "install-files invocation"
        )
        for name, payload in payloads.items():
            with self.subTest(name=name):
                shell_result = subprocess.run(
                    [
                        "sh",
                        "-c",
                        'just() { printf "%s\\n" "$1"; }\n' + payload,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(shell_result.returncode, 0, shell_result.stderr)
                self.assertEqual(shell_result.stdout, "install-files\n")

                mutated = original.replace(
                    CONTAINER_INSTALL_LINE,
                    CONTAINER_INSTALL_LINE + "\nRUN " + payload,
                    1,
                )
                with tempfile.TemporaryDirectory(
                    prefix="facelock-lifecycle-checker-"
                ) as temp:
                    mutated_path = pathlib.Path(temp) / "Containerfile"
                    mutated_path.write_bytes(mutated.encode())
                    result = self.run_checker(JUSTFILE, mutated_path)
                self.assertNotEqual(result.returncode, 0, f"checker accepted {name}")
                self.assertIn(
                    "source-install lifecycle structure: " + expected_diagnostic,
                    result.stderr,
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_nested_shell_container_install_invocations_are_rejected(self) -> None:
        payloads = {
            "bash command string": "bash -c 'just install-files'",
            "sh command string": 'sh -c "just install-files"',
            "combined shell options": (
                "/usr/bin/env bash -lc 'set -e; just install-files'"
            ),
            "nested command string": (
                "bash -c \"sh -c 'just install-files'\""
            ),
        }
        original = CONTAINERFILE.read_bytes().decode()
        expected_diagnostic = (
            "expected the offline-image command to be the only active "
            "install-files invocation"
        )
        for name, payload in payloads.items():
            with self.subTest(name=name):
                mutated = original.replace(
                    CONTAINER_INSTALL_LINE,
                    CONTAINER_INSTALL_LINE + "\nRUN " + payload,
                    1,
                )
                with tempfile.TemporaryDirectory(
                    prefix="facelock-lifecycle-checker-"
                ) as temp:
                    mutated_path = pathlib.Path(temp) / "Containerfile"
                    mutated_path.write_bytes(mutated.encode())
                    result = self.run_checker(JUSTFILE, mutated_path)
                self.assertNotEqual(result.returncode, 0, f"checker accepted {name}")
                self.assertIn(
                    "source-install lifecycle structure: " + expected_diagnostic,
                    result.stderr,
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_shell_startup_environment_injection_is_rejected(self) -> None:
        payloads = {
            "Docker ENV BASH_ENV assignment": "ENV BASH_ENV=/tmp/facelock-hook",
            "Docker legacy ENV assignment": "ENV ENV /tmp/facelock-hook",
            "Docker ARG BASH_ENV assignment": "ARG BASH_ENV=/tmp/facelock-hook",
            "RUN environment assignment": (
                "RUN BASH_ENV=/tmp/facelock-hook just install-files"
            ),
            "shell export": "RUN export ENV=/tmp/facelock-hook",
        }
        original = CONTAINERFILE.read_bytes().decode()
        for name, payload in payloads.items():
            with self.subTest(name=name):
                mutated = original.replace(
                    "RUN FACELOCK_SOURCE_INSTALL_OFFLINE_IMAGE=container-build \\",
                    payload
                    + "\nRUN FACELOCK_SOURCE_INSTALL_OFFLINE_IMAGE=container-build \\",
                    1,
                )
                with tempfile.TemporaryDirectory(
                    prefix="facelock-lifecycle-checker-"
                ) as temp:
                    mutated_path = pathlib.Path(temp) / "Containerfile"
                    mutated_path.write_bytes(mutated.encode())
                    result = self.run_checker(JUSTFILE, mutated_path)
                self.assertNotEqual(result.returncode, 0, f"checker accepted {name}")
                self.assertIn(
                    "source-install lifecycle structure: shell startup "
                    "environment is forbidden",
                    result.stderr,
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_just_options_cannot_hide_extra_container_install_invocations(
        self,
    ) -> None:
        mutations = {
            "Just option terminator": (
                "just -- install-files",
                ["just", "--dry-run", "--", "install-files"],
            ),
            "ordinary Just option": (
                "just --dry-run install-files",
                ["just", "--dry-run", "install-files"],
            ),
        }
        original = CONTAINERFILE.read_bytes().decode()
        expected_diagnostic = (
            "expected the offline-image command to be the only active "
            "install-files invocation"
        )
        for name, (payload, just_command) in mutations.items():
            with self.subTest(name=name):
                dry_run = subprocess.run(
                    just_command,
                    cwd=REPO_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
                expanded_recipe = dry_run.stdout + dry_run.stderr
                self.assertIn("facelock_source_install_begin", expanded_recipe)
                self.assertIn(
                    "install -Dm755 target/release/facelock /usr/bin/facelock",
                    expanded_recipe,
                )

                mutated = original.replace(
                    CONTAINER_INSTALL_LINE,
                    CONTAINER_INSTALL_LINE + "\nRUN " + payload,
                    1,
                )
                with tempfile.TemporaryDirectory(
                    prefix="facelock-lifecycle-checker-"
                ) as temp:
                    mutated_path = pathlib.Path(temp) / "Containerfile"
                    mutated_path.write_bytes(mutated.encode())
                    result = self.run_checker(JUSTFILE, mutated_path)
                self.assertNotEqual(result.returncode, 0, f"checker accepted {name}")
                self.assertIn(
                    "source-install lifecycle structure: " + expected_diagnostic,
                    result.stderr,
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_blank_cannot_precede_install_files_shebang(self) -> None:
        self.assert_mutation_rejected(
            "blank before install-files shebang",
            INSTALL_FILES_SHEBANG,
            "\ninstall-files:\n\n    #!/usr/bin/bash -p\n",
            "install-files recipe must start with the exact Bash shebang",
        )

    def test_comment_cannot_precede_install_files_shebang(self) -> None:
        self.assert_mutation_rejected(
            "comment before install-files shebang",
            INSTALL_FILES_SHEBANG,
            "\ninstall-files:\n"
            "    # unexpected leading comment\n"
            "    #!/usr/bin/bash -p\n",
            "install-files recipe must start with the exact Bash shebang",
        )

    def test_install_files_shebang_is_required(self) -> None:
        self.assert_mutation_rejected(
            "missing install-files shebang",
            INSTALL_FILES_SHEBANG,
            "\ninstall-files:\n",
            "install-files recipe must start with the exact Bash shebang",
        )

    def test_install_files_shebang_cannot_use_sh(self) -> None:
        self.assert_mutation_rejected(
            "replaced install-files shebang",
            INSTALL_FILES_SHEBANG,
            "\ninstall-files:\n    #!/bin/sh\n",
            "install-files recipe must start with the exact Bash shebang",
        )

    def test_ignored_comment_backslash_is_rejected_before_strict_mode(self) -> None:
        self.assert_mutation_rejected(
            "ignored comment has ambiguous trailing backslash before strict mode",
            INSTALL_FILES_STRICT_MODE,
            "\ninstall-files:\n"
            "    #!/usr/bin/bash -p\n"
            "    # ambiguous trailing backslash "
            + "\\"
            + "\n    set -euo pipefail",
            "install-files line has ambiguous comment/backslash syntax",
        )

    def test_ignored_comment_backslash_is_rejected_in_postlude(self) -> None:
        self.assert_mutation_rejected(
            "ignored comment has ambiguous trailing backslash in postlude",
            POSTLUDE_BLANK_LINES,
            '    echo ""\n'
            "    # ambiguous trailing backslash "
            + "\\"
            + '\n    echo ""',
            "install-files line has ambiguous comment/backslash syntax",
        )

    def test_inline_comment_backslash_cannot_hide_heredoc(self) -> None:
        self.assert_mutation_rejected(
            "inline comment backslash hides completion heredoc",
            COMPLETE_LINE,
            "    : # inline comment is terminal in Bash "
            + "\\"
            + "\n    : <<facelock_source_install_complete\n"
            + "        fi\n"
            + COMPLETE_LINE,
            "install-files line has ambiguous comment/backslash syntax",
        )

    def test_normalized_systemctl_literals_are_rejected(self) -> None:
        mutations = {
            "quoted command literal": '    sys"tem"ctl daemon-reload',
            "quoted absolute command literal": '    /usr/bin/sys"tem"ctl daemon-reload',
            "quoted assignment literal": '    lifecycle_manager=sys"tem"ctl',
        }
        for name, command in mutations.items():
            with self.subTest(name=name):
                self.assert_mutation_rejected(
                    name,
                    BEGIN_LINE,
                    BEGIN_LINE + "\n" + command,
                    "systemctl literal is forbidden",
                )

    def test_lifecycle_interval_bypass_mechanisms_are_rejected(self) -> None:
        mutations = {
            "exec replaces install shell": "    exec /bin/true",
            "exit trap cleared": "    trap - EXIT",
            "exit trap replaced": "    trap ':' EXIT",
            "completion function unset": (
                "    unset -f facelock_source_install_complete"
            ),
            "completion function redefined": (
                "    facelock_source_install_complete() { :; }"
            ),
        }
        for name, command in mutations.items():
            with self.subTest(name=name):
                self.assert_mutation_rejected(
                    name,
                    BEGIN_LINE,
                    BEGIN_LINE + "\n" + command,
                    "unexpected active lifecycle install interval command",
                )

    def test_alternative_asset_writers_are_rejected(self) -> None:
        mutations = {
            "rsync legacy unit writer": (
                "    rsync -a systemd/facelock-daemon.service "
                "/etc/systemd/system/facelock-daemon.service"
            ),
            "cp legacy D-Bus writer": (
                "    cp dbus/org.facelock.Daemon.conf "
                "/etc/dbus-1/system.d/org.facelock.Daemon.conf"
            ),
            "shell redirection legacy activation writer": (
                "    printf '%s\\n' '[D-BUS Service]' > "
                "/etc/dbus-1/system-services/org.facelock.Daemon.service"
            ),
        }
        for name, command in mutations.items():
            with self.subTest(name=name):
                self.assert_mutation_rejected(
                    name,
                    BEGIN_LINE,
                    BEGIN_LINE + "\n" + command,
                    "unexpected active lifecycle install interval command",
                )

    def test_unsupported_bash_quotes_cannot_hide_systemctl_literals(self) -> None:
        mutations = {
            "ANSI-C quoted literal": "    sys$'\\x74em'ctl daemon-reload",
            "localized quoted literal": '    sys$"tem"ctl daemon-reload',
        }
        for name, command in mutations.items():
            with self.subTest(name=name):
                self.assert_mutation_rejected(
                    name,
                    BEGIN_LINE,
                    BEGIN_LINE + "\n" + command,
                    "unexpected active lifecycle install interval command",
                )

    def test_pre_boundary_shell_bypasses_are_rejected(self) -> None:
        mutations = {
            "assignment command substitution": (
                SOURCE_LINE,
                "    hidden=$(touch /tmp/facelock-before-boundary)\n" + SOURCE_LINE,
            ),
            "glued control operator": (
                SOURCE_LINE,
                "    true;touch /tmp/facelock-before-boundary\n" + SOURCE_LINE,
            ),
            "unlisted unlink command": (
                SOURCE_LINE,
                "    unlink /tmp/facelock-before-boundary\n" + SOURCE_LINE,
            ),
            "glued redirection": (
                SOURCE_LINE,
                "    printf owned>/tmp/facelock-before-boundary\n" + SOURCE_LINE,
            ),
            "process substitution": (
                SOURCE_LINE,
                "    : < <(touch /tmp/facelock-before-boundary)\n" + SOURCE_LINE,
            ),
            "arbitrary assignment": (
                SOURCE_LINE,
                "    LD_PRELOAD=/tmp/facelock-before-boundary.so\n" + SOURCE_LINE,
            ),
            "extra source command": (
                SOURCE_LINE,
                "    source /tmp/facelock-before-boundary.sh\n" + SOURCE_LINE,
            ),
            "and-list absorbs source": (
                SOURCE_LINE,
                "    false &&\n" + SOURCE_LINE,
            ),
            "or-list absorbs source": (
                SOURCE_LINE,
                "    true ||\n" + SOURCE_LINE,
            ),
            "pipeline subshell absorbs source": (
                SOURCE_LINE,
                "    true |\n" + SOURCE_LINE,
            ),
            "stderr pipeline subshell absorbs source": (
                SOURCE_LINE,
                "    true |&\n" + SOURCE_LINE,
            ),
            "folded and-list absorbs source": (
                SOURCE_LINE,
                "    false &" + "\\" + "\n    &\n" + SOURCE_LINE,
            ),
            "folded or-list absorbs source": (
                SOURCE_LINE,
                "    true |" + "\\" + "\n    |\n" + SOURCE_LINE,
            ),
            "folded pipeline absorbs source": (
                SOURCE_LINE,
                "    true " + "\\" + "\n    |\n" + SOURCE_LINE,
            ),
            "folded stderr pipeline absorbs source": (
                SOURCE_LINE,
                "    true |" + "\\" + "\n    &\n" + SOURCE_LINE,
            ),
            "heredoc absorbs source and begin": (
                SOURCE_LINE,
                "    : <<facelock_source_install_begin\n" + SOURCE_LINE,
            ),
            "folded heredoc absorbs source and begin": (
                SOURCE_LINE,
                "    : <"
                + "\\"
                + "\n    <facelock_source_install_begin\n"
                + SOURCE_LINE,
            ),
            "boundaries wrapped in false branch": (
                SOURCE_LINE + "\n" + BEGIN_LINE,
                "    if false; then\n"
                + SOURCE_LINE
                + "\n"
                + BEGIN_LINE
                + "\n    fi",
            ),
            "dynamic compound command": (
                SOURCE_LINE,
                "    lifecycle_tool=touch\n"
                "    if \"$lifecycle_tool\" /tmp/facelock-before-boundary; then :; fi\n"
                + SOURCE_LINE,
            ),
            "function command": (
                SOURCE_LINE,
                "    lifecycle_hidden() { touch /tmp/facelock-before-boundary; }\n"
                "    lifecycle_hidden\n"
                + SOURCE_LINE,
            ),
            "continued command absorbs begin": (
                BEGIN_LINE,
                "    true "
                + "\\"
                + "\n"
                + BEGIN_LINE
                + "\n    touch /tmp/facelock-before-boundary",
            ),
        }
        for name, (needle, replacement) in mutations.items():
            with self.subTest(name=name):
                self.assert_mutation_rejected(name, needle, replacement)

    def test_post_completion_shell_bypasses_are_rejected(self) -> None:
        mutations = {
            "assignment command substitution": (
                COMPLETE_LINE,
                COMPLETE_LINE
                + "\n    hidden=$(touch /tmp/facelock-after-boundary)",
            ),
            "glued control operator": (
                COMPLETE_LINE,
                COMPLETE_LINE + "\n    true;touch /tmp/facelock-after-boundary",
            ),
            "unlisted unlink command": (
                COMPLETE_LINE,
                COMPLETE_LINE + "\n    unlink /tmp/facelock-after-boundary",
            ),
            "glued redirection": (
                COMPLETE_LINE,
                COMPLETE_LINE
                + "\n    printf owned>/tmp/facelock-after-boundary",
            ),
            "process substitution": (
                COMPLETE_LINE,
                COMPLETE_LINE + "\n    : < <(touch /tmp/facelock-after-boundary)",
            ),
            "arbitrary assignment": (
                COMPLETE_LINE,
                COMPLETE_LINE
                + "\n    LD_PRELOAD=/tmp/facelock-after-boundary.so",
            ),
            "extra source command": (
                COMPLETE_LINE,
                COMPLETE_LINE + "\n    source /tmp/facelock-after-boundary.sh",
            ),
            "dynamic compound command": (
                COMPLETE_LINE,
                COMPLETE_LINE
                + "\n    lifecycle_tool=touch\n"
                "    if \"$lifecycle_tool\" /tmp/facelock-after-boundary; then :; fi",
            ),
            "approved dynamic command reassigned": (
                STATUS_LINE,
                "    NEEDS_SETUP=touch\n" + STATUS_LINE,
            ),
            "function command": (
                COMPLETE_LINE,
                COMPLETE_LINE
                + "\n    lifecycle_hidden() { touch /tmp/facelock-after-boundary; }\n"
                "    lifecycle_hidden",
            ),
            "continued command absorbs completion": (
                COMPLETE_LINE,
                "    true "
                + "\\"
                + "\n"
                + COMPLETE_LINE
                + "\n    touch /tmp/facelock-after-boundary",
            ),
            "and-list continuation absorbs completion": (
                COMPLETE_LINE,
                "    false && " + "\\" + "\n" + COMPLETE_LINE,
            ),
            "or-list continuation absorbs completion": (
                COMPLETE_LINE,
                "    true || " + "\\" + "\n" + COMPLETE_LINE,
            ),
            "pipeline continuation absorbs completion": (
                COMPLETE_LINE,
                "    true | " + "\\" + "\n" + COMPLETE_LINE,
            ),
            "stderr pipeline continuation absorbs completion": (
                COMPLETE_LINE,
                "    true |& " + "\\" + "\n" + COMPLETE_LINE,
            ),
            "and-list absorbs completion": (
                COMPLETE_LINE,
                "    false &&\n" + COMPLETE_LINE,
            ),
            "or-list absorbs completion": (
                COMPLETE_LINE,
                "    true ||\n" + COMPLETE_LINE,
            ),
            "pipeline subshell absorbs completion": (
                COMPLETE_LINE,
                "    true |\n" + COMPLETE_LINE,
            ),
            "stderr pipeline subshell absorbs completion": (
                COMPLETE_LINE,
                "    true |&\n" + COMPLETE_LINE,
            ),
            "folded and-list absorbs completion": (
                COMPLETE_LINE,
                "    false &" + "\\" + "\n    &\n" + COMPLETE_LINE,
            ),
            "folded or-list absorbs completion": (
                COMPLETE_LINE,
                "    true |" + "\\" + "\n    |\n" + COMPLETE_LINE,
            ),
            "folded stderr pipeline absorbs completion": (
                COMPLETE_LINE,
                "    true |" + "\\" + "\n    &\n" + COMPLETE_LINE,
            ),
            "completion wrapped in false branch": (
                COMPLETE_LINE,
                "    if false; then\n" + COMPLETE_LINE + "\n    fi",
            ),
            "folded heredoc absorbs completion through canonical delimiter": (
                COMPLETE_LINE,
                "    : <"
                + "\\"
                + "\n    <fi\n"
                + "        fi\n"
                + COMPLETE_LINE,
            ),
            "heredoc absorbs completion": (
                COMPLETE_LINE,
                "    : <<facelock_source_install_complete\n" + COMPLETE_LINE,
            ),
        }
        for name, (needle, replacement) in mutations.items():
            with self.subTest(name=name):
                self.assert_mutation_rejected(name, needle, replacement)


if __name__ == "__main__":
    unittest.main()
