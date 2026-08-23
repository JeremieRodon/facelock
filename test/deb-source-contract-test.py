#!/usr/bin/env python3
"""Regression mutations for executable Debian lifecycle operations."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_CONTRACT = REPO_ROOT / "test/deb-source-contract.sh"
LIFECYCLE = REPO_ROOT / "test/deb-package-lifecycle.sh"
PACKAGE_VALIDATOR = REPO_ROOT / "test/pkg-validate.sh"


class DebianSourceContractTests(unittest.TestCase):
    def run_contract(
        self,
        lifecycle: pathlib.Path = LIFECYCLE,
        package_validator: pathlib.Path = PACKAGE_VALIDATOR,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["FACELOCK_DEB_LIFECYCLE"] = str(lifecycle)
        environment["FACELOCK_PACKAGE_VALIDATOR"] = str(package_validator)
        return subprocess.run(
            ["bash", str(SOURCE_CONTRACT)],
            cwd=REPO_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_mutation_rejected(
        self,
        name: str,
        needle: str,
        replacement: str,
        expected_diagnostic: str,
    ) -> None:
        original = LIFECYCLE.read_text()
        self.assertEqual(
            original.count(needle),
            1,
            f"mutation needle count changed for {name}: {needle!r}",
        )
        mutated = original.replace(needle, replacement, 1)
        with tempfile.TemporaryDirectory(prefix="facelock-deb-source-contract-") as temp:
            lifecycle = pathlib.Path(temp) / "deb-package-lifecycle.sh"
            lifecycle.write_text(mutated)
            result = self.run_contract(lifecycle)
        self.assertNotEqual(result.returncode, 0, f"contract accepted {name} mutation")
        self.assertIn(
            f"deb source contract: {expected_diagnostic}",
            result.stderr,
            f"contract did not diagnose {name} mutation",
        )

    def test_canonical_lifecycle_is_accepted(self) -> None:
        result = self.run_contract(LIFECYCLE)
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_package_validator_mutation_rejected(
        self,
        name: str,
        needle: str,
        replacement: str,
        expected_diagnostic: str,
        *,
        scope: str = "helper",
        occurrence: int = 1,
        expected_count: int = 1,
    ) -> None:
        original = PACKAGE_VALIDATOR.read_text()
        function_start = original.index("verify_debian_packaged_pam_profile() {\n")
        function_end = original.index("\n}\n", function_start) + len("\n}\n")
        if scope == "helper":
            target_start = function_start
            target_end = function_end
        elif scope == "file":
            target_start = 0
            target_end = len(original)
        else:
            self.fail(f"unknown package-validator mutation scope: {scope}")
        target = original[target_start:target_end]
        self.assertEqual(
            target.count(needle),
            expected_count,
            f"mutation needle count changed for {name}: {needle!r}",
        )
        self.assertGreaterEqual(occurrence, 1)
        self.assertLessEqual(occurrence, expected_count)
        offset = 0
        for _ in range(occurrence):
            offset = target.index(needle, offset)
            if _ + 1 < occurrence:
                offset += len(needle)
        mutated_target = target[:offset] + replacement + target[offset + len(needle) :]
        mutated = original[:target_start] + mutated_target + original[target_end:]
        with tempfile.TemporaryDirectory(prefix="facelock-deb-source-contract-") as temp:
            package_validator = pathlib.Path(temp) / "pkg-validate.sh"
            package_validator.write_text(mutated)
            result = self.run_contract(package_validator=package_validator)
        self.assertNotEqual(result.returncode, 0, f"contract accepted {name} mutation")
        self.assertIn(
            f"deb source contract: {expected_diagnostic}",
            result.stderr,
            f"contract did not diagnose {name} mutation",
        )

    def assert_package_validator_line_mutations_rejected(
        self,
        name: str,
        needle: str,
        spoof: str,
        expected_diagnostic: str,
        **kwargs: object,
    ) -> None:
        mutations = {
            "removed": "",
            "commented": f"# {needle}",
            "spoofed": spoof,
        }
        for mutation, replacement in mutations.items():
            with self.subTest(operation=name, mutation=mutation):
                self.assert_package_validator_mutation_rejected(
                    f"{mutation} {name}",
                    needle,
                    replacement,
                    expected_diagnostic,
                    **kwargs,
                )

    def run_contract_with_package_validator_text(
        self, text: str
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="facelock-deb-source-contract-") as temp:
            package_validator = pathlib.Path(temp) / "pkg-validate.sh"
            package_validator.write_text(text)
            return self.run_contract(package_validator=package_validator)

    def test_packaged_profile_verifier_identifier_has_one_canonical_topology(self) -> None:
        original = PACKAGE_VALIDATOR.read_text()
        function_start = original.index("verify_debian_packaged_pam_profile() {\n")
        function_end = original.index("\n}\n", function_start) + len("\n}\n")
        extra_occurrences = {
            "exact duplicate": "\nverify_debian_packaged_pam_profile() {\n    :\n}\n",
            "trailing-comment signature": (
                "\nverify_debian_packaged_pam_profile() { # later override\n"
                "    :\n"
                "}\n"
            ),
            "split-line signature": (
                "\nverify_debian_packaged_pam_profile()\n"
                "{\n"
                "    :\n"
                "}\n"
            ),
            "function-form signature": (
                "\nfunction verify_debian_packaged_pam_profile {\n"
                "    :\n"
                "}\n"
            ),
            "eval string": (
                "\neval 'verify_debian_packaged_pam_profile() { :; }'\n"
            ),
            "comment": "\n# verify_debian_packaged_pam_profile() {\n# }\n",
            "command comment": (
                "\ntrue # verify_debian_packaged_pam_profile() {\n"
                "true # }\n"
            ),
        }
        diagnostic = (
            "deb source contract: packaged PAM profile verifier identifier must occur "
            "exactly at its canonical definition, export, and invocation"
        )
        for name, extra in extra_occurrences.items():
            with self.subTest(extra=name):
                mutated = original[:function_end] + extra + original[function_end:]
                result = self.run_contract_with_package_validator_text(mutated)
                self.assertNotEqual(
                    result.returncode,
                    0,
                    f"contract accepted extra packaged-profile identifier in {name}",
                )
                self.assertIn(diagnostic, result.stderr)

    def test_packaged_profile_reinstall_must_be_an_executable_full_line(self) -> None:
        self.assert_package_validator_line_mutations_rejected(
            "exact package reinstall",
            "    apt-get install -y --reinstall /facelock-test-package.deb || failed=1\n",
            "    true # apt-get install -y --reinstall /facelock-test-package.deb || failed=1\n",
            "packaged PAM profile verifier must execute exactly one full-line reinstall",
        )

    def test_packaged_profile_pass_label_must_invoke_verifier_directly(self) -> None:
        self.assert_package_validator_line_mutations_rejected(
            "direct verifier invocation",
            '        "verify_debian_packaged_pam_profile"\n',
            "        true # verify_debian_packaged_pam_profile\n",
            "packaged PAM profile PASS label must invoke its verifier directly",
            scope="file",
        )

    def test_packaged_profile_state_blocks_require_real_systemd_guards(self) -> None:
        guard = "    if [ -d /run/systemd/system ]; then\n"
        for occurrence, phase in ((1, "before"), (2, "after")):
            self.assert_package_validator_line_mutations_rejected(
                f"real {phase}-reinstall systemd guard",
                guard,
                "    if false; then # [ -d /run/systemd/system ]\n",
                "packaged PAM profile verifier must use exact systemd guards",
                occurrence=occurrence,
                expected_count=2,
            )

    def test_packaged_profile_state_captures_are_failure_checked(self) -> None:
        captures = {
            "expected ActiveState": (
                '        if ! active_before="$(systemctl show --property=ActiveState '
                '--value facelock-daemon.service 2>/dev/null)"; then\n',
                '        active_before="$(systemctl is-active facelock-daemon '
                '2>/dev/null || true)"\n',
            ),
            "expected UnitFileState": (
                '        if ! enabled_before="$(systemctl show --property=UnitFileState '
                '--value facelock-daemon.service 2>/dev/null)"; then\n',
                '        enabled_before="$(systemctl is-enabled facelock-daemon '
                '2>/dev/null || true)"\n',
            ),
            "actual ActiveState": (
                '        if ! active_after="$(systemctl show --property=ActiveState '
                '--value facelock-daemon.service 2>/dev/null)"; then\n',
                '        active_after="$(systemctl is-active facelock-daemon '
                '2>/dev/null || true)"\n',
            ),
            "actual UnitFileState": (
                '        if ! enabled_after="$(systemctl show --property=UnitFileState '
                '--value facelock-daemon.service 2>/dev/null)"; then\n',
                '        enabled_after="$(systemctl is-enabled facelock-daemon '
                '2>/dev/null || true)"\n',
            ),
        }
        for phase, (needle, spoof) in captures.items():
            self.assert_package_validator_line_mutations_rejected(
                f"failure-checked {phase} capture",
                needle,
                spoof,
                "packaged PAM profile verifier must failure-check nonempty state "
                "and emit labeled diagnostics",
            )

    def test_packaged_profile_state_captures_must_reject_empty_output(self) -> None:
        checks = (
            '        elif [ -z "$active_before" ]; then\n',
            '        elif [ -z "$enabled_before" ]; then\n',
            '        elif [ -z "$active_after" ]; then\n',
            '        elif [ -z "$enabled_after" ]; then\n',
        )
        for check in checks:
            self.assert_package_validator_line_mutations_rejected(
                f"nonempty check {check.strip()}",
                check,
                f"        elif false; then # {check.strip()}\n",
                "packaged PAM profile verifier must failure-check nonempty state "
                "and emit labeled diagnostics",
            )

    def test_packaged_profile_state_comparisons_cannot_be_fixed_or_vacuous(self) -> None:
        comparisons = {
            "ActiveState": (
                '        elif [ "$active_after" != "$active_before" ]; then\n',
                "        elif false; then # fixed inactive state\n",
            ),
            "UnitFileState": (
                '        elif [ "$enabled_after" != "$enabled_before" ]; then\n',
                "        elif false; then # fixed disabled state\n",
            ),
        }
        for property_name, (needle, spoof) in comparisons.items():
            self.assert_package_validator_line_mutations_rejected(
                f"exact {property_name} comparison",
                needle,
                spoof,
                "packaged PAM profile verifier must failure-check nonempty state "
                "and emit labeled diagnostics",
            )

    def test_packaged_profile_state_failures_emit_labeled_diagnostics(self) -> None:
        diagnostics = (
            "            printf '%s\\n' 'packaged PAM profile reinstall ActiveState: "
            "expected=<nonempty-before> actual=<command-error>' >&2\n",
            "            printf '%s\\n' 'packaged PAM profile reinstall UnitFileState: "
            "expected=<nonempty-before> actual=<empty>' >&2\n",
            "            printf 'packaged PAM profile reinstall ActiveState: expected=%s "
            "actual=<command-error>\\n' \"$active_before\" >&2\n",
            "            printf 'packaged PAM profile reinstall UnitFileState: expected=%s "
            "actual=%s\\n' \"$enabled_before\" \"$enabled_after\" >&2\n",
        )
        for diagnostic in diagnostics:
            self.assert_package_validator_line_mutations_rejected(
                f"labeled diagnostic {diagnostic.strip()}",
                diagnostic,
                f"            : # {diagnostic.strip()}\n",
                "packaged PAM profile verifier must failure-check nonempty state "
                "and emit labeled diagnostics",
            )

    def test_packaged_profile_state_failures_remain_failed(self) -> None:
        failure = "            failed=1\n"
        for occurrence in (1, 4, 5, 10):
            self.assert_package_validator_line_mutations_rejected(
                f"failed state result {occurrence}",
                failure,
                "            true # failed=1\n",
                "packaged PAM profile verifier must failure-check nonempty state "
                "and emit labeled diagnostics",
                occurrence=occurrence,
                expected_count=10,
            )

    def test_required_lifecycle_operations_cannot_be_removed_or_commented(self) -> None:
        operations = {
            "authoritative enrollment snapshot": (
                "    snapshot_enrollment_database_state\n",
                "Debian lifecycle must snapshot authoritative enrollment rows "
                "across versioned upgrades",
            ),
            "enrollment marker snapshot": (
                "    snapshot_enrollment_marker "
                "/var/lib/facelock/enrolled/testuser\n",
                "Debian lifecycle must snapshot enrollment-marker semantics "
                "across versioned upgrades",
            ),
            "authoritative model insert": (
                "connection.execute(\n"
                '    "INSERT INTO face_models "\n'
                '    "(user, label, created_at, embedder_model, device_id) "\n'
                '    "VALUES (?, ?, ?, ?, ?)",\n'
                '    ("testuser", "lifecycle-retained", 1700000000, "", None),\n'
                ")\n",
                "Debian retained-state fixture must seed an authoritative enrolled model",
            ),
            "model embedding insert": (
                "connection.execute(\n"
                '    "INSERT INTO face_embeddings (model_id, embedding, sealed) '
                'VALUES (?, ?, ?)",\n'
                "    (model_id, embedding, 0),\n"
                ")\n",
                "Debian retained-state fixture must seed the enrolled model embedding",
            ),
            "deterministic embedding construction": (
                'embedding = struct.pack("<512f", *((index + 1) / 512 '
                "for index in range(512)))\n",
                "Debian retained-state fixture must seed deterministic nonzero "
                "embedding data",
            ),
            "authoritative model count": (
                "model_count = connection.execute(\n"
                '    "SELECT COUNT(*) FROM face_models"\n'
                ").fetchone()[0]\n",
                "Debian enrollment snapshot must count authoritative model rows "
                "separately",
            ),
            "embedding row count": (
                "embedding_count = connection.execute(\n"
                '    "SELECT COUNT(*) FROM face_embeddings"\n'
                ").fetchone()[0]\n",
                "Debian enrollment snapshot must count embedding rows separately",
            ),
            "separate enrollment row cardinality assertion": (
                "if (model_count, embedding_count) != (1, 1):\n",
                "Debian enrollment snapshot must enforce separate authoritative "
                "row counts",
            ),
            "expected embedding digest": (
                "expected_embedding_digest = (\n"
                '    "82a0081de4c338fc91c362ed4d2ab615bca1dd45152aaa713322b5482078ddee"\n'
                ")\n",
                "Debian enrollment snapshot must assert the deterministic "
                "embedding digest",
            ),
            "embedding digest comparison": (
                "if embedding_digest != expected_embedding_digest:\n",
                "Debian enrollment snapshot must compare the deterministic "
                "embedding digest",
            ),
            "exact integer marker model count": (
                'if type(marker["models"]) is not int or marker["models"] != 1:\n',
                "Debian enrollment snapshot must require an exact integer marker "
                "model count",
            ),
        }
        for operation, (needle, diagnostic) in operations.items():
            for mutation in ("removed", "commented"):
                with self.subTest(operation=operation, mutation=mutation):
                    if mutation == "removed":
                        replacement = ""
                    else:
                        replacement = "".join(
                            f"# {line}" if line else "#\n"
                            for line in needle.splitlines(keepends=True)
                        )
                    self.assert_mutation_rejected(
                        f"{mutation} {operation}",
                        needle,
                        replacement,
                        diagnostic,
                    )


if __name__ == "__main__":
    unittest.main()
