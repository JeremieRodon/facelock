#!/usr/bin/env python3
"""Validate the executable structure of the just install-files recipe."""

from __future__ import annotations

import pathlib
import re
import shlex
import sys
import unicodedata


SOURCE_COMMAND = ["source", "scripts/source-install-daemon-lifecycle.sh"]
BEGIN_COMMAND = ["facelock_source_install_begin"]
COMPLETE_COMMAND = ["facelock_source_install_complete"]
DBUS_ACTIVATION_COMMAND = [
    "install",
    "-Dm644",
    "dbus/org.facelock.Daemon.service",
    "/usr/share/dbus-1/system-services/org.facelock.Daemon.service",
]
CONTAINER_HELPER_COPY = (
    "COPY scripts/source-install-daemon-lifecycle.sh "
    "/build/scripts/source-install-daemon-lifecycle.sh"
)
CONTAINER_MIGRATION_HELPER_COPY = (
    "COPY scripts/migrate-legacy-system-assets.sh "
    "/build/scripts/migrate-legacy-system-assets.sh"
)
CONTAINER_LEGACY_MANIFEST_COPY = "COPY dist/ /build/dist/"
CONTAINER_MARKER_COPY = (
    "COPY test/source-install-offline-image.marker "
    "/build/test/source-install-offline-image.marker"
)
CONTAINER_BOOTED_LIFECYCLE_FIXTURE_COPIES = (
    "COPY test/source-install-recipe-install-probe.sh "
    "/source-install-lifecycle/test/source-install-recipe-install-probe.sh",
    "COPY test/source-install-recipe-fake-systemctl.sh "
    "/source-install-lifecycle/test/source-install-recipe-fake-systemctl.sh",
    "COPY test/source-install-recipe-fake-busctl.sh "
    "/source-install-lifecycle/test/source-install-recipe-fake-busctl.sh",
)
CONTAINER_OFFLINE_PREFIX = "RUN FACELOCK_SOURCE_INSTALL_OFFLINE_IMAGE=container-build \\"
CONTAINER_OFFLINE_MARKER = (
    "FACELOCK_SOURCE_INSTALL_OFFLINE_MARKER="
    "/build/test/source-install-offline-image.marker \\"
)
SHELL_PUNCTUATION = "();<>|&{}"
SHELL_BOUNDARY_CONTINUATIONS = frozenset({"&&", "||", "|", "|&"})
SHELL_COMMAND_NAMES = frozenset({"bash", "dash", "sh"})
SHELL_STARTUP_ENV_NAMES = frozenset({"BASH_ENV", "ENV"})
MAX_NESTED_SHELL_DEPTH = 8
ASCII_BLANKS = " \t"
EXPECTED_SHEBANG = "    #!/usr/bin/bash -p"
EXPECTED_PRIVILEGED_ENTRYPOINTS = (
    "    /usr/bin/sudo /usr/bin/env PATH=/usr/bin:/bin /usr/bin/just install-files",
    "    /usr/bin/sudo /usr/bin/env PATH=/usr/bin:/bin /usr/bin/just uninstall-files",
)
SHELL_STARTUP_ENV_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:BASH_ENV|ENV)(?![A-Za-z0-9_])"
)
EXPECTED_PRELUDE = (
    "set -euo pipefail",
    "PATH=/usr/bin:/bin",
    "export PATH",
    "for f in target/release/facelock target/release/libpam_facelock.so; do",
    '[ -f "$f" ] || { echo "Error: $f not found. Run \'just build-release\' first."; exit 1; }',
    "done",
    "source scripts/source-install-daemon-lifecycle.sh",
    "facelock_source_install_begin",
)
EXPECTED_INSTALL_INTERVAL = (
    "facelock_source_install_begin",
    "install -Dm755 target/release/facelock /usr/bin/facelock",
    "install -Dm755 target/release/libpam_facelock.so /lib/security/pam_facelock.so",
    "install -Dm644 config/facelock.toml /etc/facelock/config.toml.default",
    "[ -f /etc/facelock/config.toml ] || cp /etc/facelock/config.toml.default /etc/facelock/config.toml",
    "install -dm755 /usr/share/facelock/quirks.d",
    "install -Dm644 config/quirks.d/*.toml /usr/share/facelock/quirks.d/",
    "if command -v msgfmt >/dev/null; then",
    "bash -p scripts/install-locale-catalogs.sh /usr/share/locale",
    "else",
    'echo "note: msgfmt not found; skipping translation catalogs (English is compiled in)"',
    "fi",
    "install -Dm644 systemd/facelock-daemon.service /usr/lib/systemd/system/facelock-daemon.service",
    "install -Dm644 dbus/org.facelock.Daemon.conf /usr/share/dbus-1/system.d/org.facelock.Daemon.conf",
    "install -Dm644 dbus/org.facelock.Daemon.service /usr/share/dbus-1/system-services/org.facelock.Daemon.service",
    "facelock_source_install_stage_and_record_legacy_migration /",
    "[ -f target/release/facelock-polkit-agent ] && install -Dm755 target/release/facelock-polkit-agent /usr/bin/facelock-polkit-agent || true",
    "install -dm711 -o root -g root /var/lib/facelock",
    "install -dm755 -o root -g root /var/lib/facelock/models",
    "install -dm711 -o root -g root /var/lib/facelock/enrolled",
    "install -dm700 -o root -g root /var/lib/facelock/pam-backups",
    "install -dm700 -o root -g root /var/log/facelock",
    "install -dm700 -o root -g root /var/log/facelock/snapshots",
    "[ -d /etc/facelock ] && chown root:root /etc/facelock && chmod 755 /etc/facelock || true",
    "[ -f /etc/facelock/config.toml ] && chown root:root /etc/facelock/config.toml && chmod 644 /etc/facelock/config.toml || true",
    "[ -f /etc/facelock/config.toml.default ] && chown root:root /etc/facelock/config.toml.default && chmod 644 /etc/facelock/config.toml.default || true",
    "[ -d /var/lib/facelock ] && chown root:root /var/lib/facelock && chmod 711 /var/lib/facelock || true",
    "[ -d /var/lib/facelock/models ] && chown root:root /var/lib/facelock/models && chmod 755 /var/lib/facelock/models || true",
    "[ -d /var/lib/facelock/enrolled ] && chown root:root /var/lib/facelock/enrolled && chmod 711 /var/lib/facelock/enrolled || true",
    "[ -d /var/lib/facelock/pam-backups ] && chown root:root /var/lib/facelock/pam-backups && chmod 700 /var/lib/facelock/pam-backups || true",
    "[ -d /var/log/facelock ] && chown root:root /var/log/facelock && chmod 700 /var/log/facelock || true",
    "[ -d /var/log/facelock/snapshots ] && chown root:root /var/log/facelock/snapshots && chmod 700 /var/log/facelock/snapshots || true",
    "[ -f /var/log/facelock/audit.jsonl ] && chown root:root /var/log/facelock/audit.jsonl && chmod 600 /var/log/facelock/audit.jsonl || true",
    "[ -d /run/facelock ] && chown root:root /run/facelock 2>/dev/null || true",
    "[ -d /var/lib/facelock/models ] && chmod 644 /var/lib/facelock/models/*.onnx 2>/dev/null || true",
    "[ -f /var/lib/facelock/facelock.db ] && chown root:root /var/lib/facelock/facelock.db && chmod 600 /var/lib/facelock/facelock.db || true",
    "[ -f /var/lib/facelock/facelock.db-wal ] && chown root:root /var/lib/facelock/facelock.db-wal && chmod 600 /var/lib/facelock/facelock.db-wal || true",
    "[ -f /var/lib/facelock/facelock.db-shm ] && chown root:root /var/lib/facelock/facelock.db-shm && chmod 600 /var/lib/facelock/facelock.db-shm || true",
    "if getent group facelock >/dev/null 2>&1; then",
    "groupdel facelock 2>/dev/null || true",
    "fi",
    "facelock_source_install_complete",
)
EXPECTED_POSTLUDE = (
    "facelock_source_install_complete",
    "if [ -d /run/systemd/system ]; then",
    'echo "D-Bus activation enabled."',
    "fi",
    'echo ""',
    'echo ""',
    "NEEDS_SETUP=false",
    "NEEDS_ORT=false",
    "if ! ls /var/lib/facelock/models/*.onnx >/dev/null 2>&1; then",
    "NEEDS_SETUP=true",
    "fi",
    "if [ ! -f /etc/facelock/config.toml ]; then",
    "NEEDS_SETUP=true",
    "fi",
    "if ! grep -qs pam_facelock /etc/pam.d/sudo 2>/dev/null; then",
    "NEEDS_SETUP=true",
    "fi",
    "if [ ! -f /usr/lib/libonnxruntime.so ] && \\",
    "[ ! -f /usr/lib64/libonnxruntime.so ] && \\",
    "[ ! -f /usr/lib/facelock/libonnxruntime.so ]; then",
    "NEEDS_ORT=true",
    "fi",
    "if $NEEDS_SETUP || $NEEDS_ORT; then",
    'echo "Installed."',
    "if $NEEDS_ORT; then",
    'echo ""',
    'echo "Requires: onnxruntime (pacman -S onnxruntime-cpu)"',
    'echo "Optional: onnxruntime-opt-cuda (NVIDIA) or onnxruntime-opt-rocm (AMD)"',
    "fi",
    "if $NEEDS_SETUP; then",
    'echo ""',
    'echo "Run \'sudo facelock setup\' to complete configuration."',
    'echo "  (downloads models, configures PAM services, enrolls your face)"',
    "fi",
    "else",
    'echo "Installed and up to date."',
    "fi",
)


def fail(message: str) -> None:
    print(f"source-install lifecycle structure: {message}", file=sys.stderr)
    raise SystemExit(1)


def ascii_strip(text: str) -> str:
    return text.strip(ASCII_BLANKS)


def ascii_lstrip(text: str) -> str:
    return text.lstrip(ASCII_BLANKS)


def ascii_rstrip(text: str) -> str:
    return text.rstrip(ASCII_BLANKS)


def physical_lines(path: pathlib.Path) -> list[str]:
    content = path.read_bytes()
    for offset, byte in enumerate(content):
        if byte == 0x7F or (byte < 0x20 and byte not in {0x09, 0x0A}):
            fail(
                f"disallowed control byte 0x{byte:02x} in {path} "
                f"at byte {offset}"
            )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{path} is not valid UTF-8: {error}")
    for character in text:
        codepoint = ord(character)
        if 0x80 <= codepoint <= 0x9F:
            fail(f"disallowed control character U+{codepoint:04X} in {path}")
        if character not in ASCII_BLANKS + "\n" and unicodedata.category(
            character
        ).startswith("Z"):
            fail(f"disallowed Unicode whitespace U+{codepoint:04X} in {path}")
    return text.split("\n")


def install_recipe(
    path: pathlib.Path, lines: list[str] | None = None
) -> list[tuple[int, str]]:
    if lines is None:
        lines = physical_lines(path)
    try:
        start = lines.index("install-files:") + 1
    except ValueError:
        fail(f"{path} has no install-files recipe")

    body: list[tuple[int, str]] = []
    for index in range(start, len(lines)):
        line = lines[index]
        if line and not line.startswith((" ", "\t", "#")):
            break
        body.append((index + 1, line))
    return body


def shell_tokens(line_number: int, line: str) -> list[str]:
    code = ascii_strip(line)
    if not code or code.startswith("#"):
        return []
    if code.endswith("\\"):
        code = ascii_rstrip(code[:-1])
    try:
        return shlex.split(code, comments=True, posix=True)
    except ValueError as error:
        fail(f"cannot parse install-files line {line_number}: {error}")


def shell_scan_tokens(line_number: int, line: str) -> list[str]:
    code = ascii_strip(line)
    if not code or code.startswith("#"):
        return []
    lexer = shlex.shlex(
        code,
        posix=True,
        punctuation_chars=SHELL_PUNCTUATION,
    )
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return list(lexer)
    except ValueError as error:
        fail(f"cannot analyze install-files line {line_number}: {error}")


def container_shell_tokens(line_number: int, line: str) -> list[str]:
    code = ascii_strip(line)
    if "$'" in code or '$"' in code:
        fail(f"unsupported shell quote syntax in Containerfile on line {line_number}")
    lexer = shlex.shlex(
        code,
        posix=True,
        punctuation_chars=SHELL_PUNCTUATION,
    )
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return list(lexer)
    except ValueError as error:
        fail(f"cannot parse Containerfile line {line_number}: {error}")


def count_container_install_invocations(
    line_number: int,
    tokens: list[str],
    depth: int = 0,
) -> int:
    if depth > MAX_NESTED_SHELL_DEPTH:
        fail(
            "nested Containerfile shell command depth exceeds "
            f"{MAX_NESTED_SHELL_DEPTH} on line {line_number}"
        )

    count = sum(
        1
        for index, token in enumerate(tokens)
        if pathlib.PurePosixPath(token).name == "just"
        and "install-files" in tokens[index + 1 :]
    )

    for index, token in enumerate(tokens):
        if pathlib.PurePosixPath(token).name not in SHELL_COMMAND_NAMES:
            continue
        option_index = index + 1
        while option_index < len(tokens):
            option = tokens[option_index]
            is_command_option = option == "-c" or (
                option.startswith("-")
                and not option.startswith("--")
                and "c" in option[1:]
            )
            if is_command_option:
                if option_index + 1 >= len(tokens):
                    fail(
                        "Containerfile shell -c has no command string on line "
                        f"{line_number}"
                    )
                nested = container_shell_tokens(
                    line_number, tokens[option_index + 1]
                )
                count += count_container_install_invocations(
                    line_number, nested, depth + 1
                )
                break
            if not option.startswith("-"):
                break
            option_index += 1
    return count


def logical_container_commands(
    active: list[tuple[int, str]],
) -> list[tuple[int, str]]:
    commands: list[tuple[int, str]] = []
    start_line: int | None = None
    command = ""

    for line_number, physical_line in active:
        if start_line is None:
            start_line = line_number
        if ends_with_shell_continuation(physical_line):
            command += physical_line[:-1]
            continue
        command += physical_line
        commands.append((start_line, command))
        start_line = None
        command = ""

    if start_line is not None:
        commands.append((start_line, command))
    return commands


def ends_with_shell_continuation(line: str) -> bool:
    trailing_backslashes = len(line) - len(line.rstrip("\\"))
    return trailing_backslashes % 2 == 1


def logical_shell_lines(recipe: list[tuple[int, str]]) -> list[tuple[int, str]]:
    logical_lines: list[tuple[int, str]] = []
    start_line: int | None = None
    logical_line = ""

    for line_number, recipe_line in recipe:
        shell_line = (
            recipe_line[4:] if recipe_line.startswith("    ") else recipe_line
        )
        if start_line is None:
            start_line = line_number
        if ends_with_shell_continuation(shell_line):
            logical_line += shell_line[:-1]
            continue
        logical_line += shell_line
        logical_lines.append((start_line, logical_line))
        start_line = None
        logical_line = ""

    if start_line is not None:
        logical_lines.append((start_line, logical_line))
    return logical_lines


def one_exact_command(
    parsed: list[tuple[int, list[str]]], command: list[str], description: str
) -> int:
    matches = [line for line, tokens in parsed if tokens == command]
    if len(matches) != 1:
        fail(f"expected one active {description}, found {len(matches)}")
    return matches[0]


def exact_active_lines(
    actual: list[tuple[int, str]], expected: tuple[str, ...], description: str
) -> None:
    if tuple(text for _, text in actual) == expected:
        return
    for index, expected_text in enumerate(expected):
        if index >= len(actual):
            fail(f"missing expected active {description} command: {expected_text}")
        line_number, actual_text = actual[index]
        if actual_text != expected_text:
            fail(
                f"unexpected active {description} command on line {line_number}: "
                f"{actual_text}"
            )
    line_number, actual_text = actual[len(expected)]
    fail(
        f"unexpected extra active {description} command on line {line_number}: "
        f"{actual_text}"
    )


def check(path: pathlib.Path) -> None:
    lines = physical_lines(path)
    for entrypoint in EXPECTED_PRIVILEGED_ENTRYPOINTS:
        if lines.count(entrypoint) != 1:
            fail(f"expected one exact privileged entrypoint: {entrypoint.strip()}")
    for line_number, line in enumerate(lines, start=1):
        code = ascii_lstrip(line)
        if not code or code.startswith("#"):
            continue
        if SHELL_STARTUP_ENV_PATTERN.search(code):
            fail(
                "shell startup environment is forbidden in Justfile "
                f"on line {line_number}"
            )
    recipe = install_recipe(path, lines)
    if not recipe or recipe[0][1] != EXPECTED_SHEBANG:
        fail("install-files recipe must start with the exact Bash shebang")
    for line_number, line in recipe:
        if "#" in line and ends_with_shell_continuation(line):
            fail(
                "install-files line has ambiguous comment/backslash syntax "
                f"on line {line_number}"
            )
    parsed = [
        (line_number, shell_tokens(line_number, line))
        for line_number, line in recipe
    ]
    recipe_lines = dict(recipe)
    active = [
        (line_number, ascii_strip(line))
        for line_number, line in recipe
        if ascii_strip(line) and not ascii_lstrip(line).startswith("#")
    ]

    source_line = one_exact_command(
        parsed, SOURCE_COMMAND, "lifecycle helper source command"
    )
    begin_line = one_exact_command(parsed, BEGIN_COMMAND, "lifecycle begin command")
    complete_line = one_exact_command(parsed, COMPLETE_COMMAND, "lifecycle complete command")
    one_exact_command(parsed, DBUS_ACTIVATION_COMMAND, "D-Bus activation install command")

    if source_line >= begin_line:
        fail("lifecycle helper must be sourced before lifecycle begin")
    if begin_line >= complete_line:
        fail("lifecycle completion must follow lifecycle begin")

    exact_active_lines(
        [(line_number, line) for line_number, line in active if line_number <= begin_line],
        EXPECTED_PRELUDE,
        "prelude",
    )
    exact_active_lines(
        [
            (line_number, line)
            for line_number, line in active
            if line_number >= complete_line
        ],
        EXPECTED_POSTLUDE,
        "post-completion",
    )

    for boundary_line, description, expected_predecessor in (
        (source_line, "lifecycle helper source", "done"),
        (
            begin_line,
            "lifecycle begin",
            "source scripts/source-install-daemon-lifecycle.sh",
        ),
        (complete_line, "lifecycle completion", "fi"),
    ):
        if ascii_rstrip(recipe_lines[boundary_line]).endswith("\\") or ascii_rstrip(
            recipe_lines.get(
            boundary_line - 1, ""
            )
        ).endswith("\\"):
            fail(f"{description} must be a complete shell command")
        previous_active_line = max(
            line_number
            for line_number, _ in active
            if line_number < boundary_line
        )
        previous_tokens = shell_scan_tokens(
            previous_active_line, recipe_lines[previous_active_line]
        )
        if (
            previous_tokens
            and previous_tokens[-1] in SHELL_BOUNDARY_CONTINUATIONS
        ):
            fail(f"{description} must not continue a preceding shell command")
        if ascii_strip(recipe_lines[previous_active_line]) != expected_predecessor:
            fail(f"{description} does not follow its canonical predecessor")

    for line_number, code in logical_shell_lines(recipe):
        scan_tokens = shell_scan_tokens(line_number, code)
        if not scan_tokens:
            continue
        if "systemctl" in code or any("systemctl" in token for token in scan_tokens):
            fail(f"systemctl literal is forbidden on line {line_number}")
        if "<<" in scan_tokens:
            fail(f"shell heredoc can absorb a lifecycle boundary on line {line_number}")

    exact_active_lines(
        [
            (line_number, line)
            for line_number, line in active
            if begin_line <= line_number <= complete_line
        ],
        EXPECTED_INSTALL_INTERVAL,
        "lifecycle install interval",
    )


def check_containerfile(path: pathlib.Path) -> None:
    active = [
        (index, ascii_strip(line))
        for index, line in enumerate(physical_lines(path), start=1)
        if ascii_strip(line) and not ascii_lstrip(line).startswith("#")
    ]
    helper_lines = [line for line, text in active if text == CONTAINER_HELPER_COPY]
    migration_helper_lines = [
        line for line, text in active if text == CONTAINER_MIGRATION_HELPER_COPY
    ]
    manifest_lines = [
        line for line, text in active if text == CONTAINER_LEGACY_MANIFEST_COPY
    ]
    marker_lines = [line for line, text in active if text == CONTAINER_MARKER_COPY]
    for fixture_copy in CONTAINER_BOOTED_LIFECYCLE_FIXTURE_COPIES:
        fixture_lines = [line for line, text in active if text == fixture_copy]
        if len(fixture_lines) != 1:
            fail(
                "missing booted systemd lifecycle fixture copy: "
                f"{fixture_copy}"
            )
    install_lines = [
        line
        for line, text in active
        if text == CONTAINER_OFFLINE_PREFIX
        and any(
            later_text == CONTAINER_OFFLINE_MARKER
            for later_line, later_text in active
            if later_line == line + 1
        )
        and any(
            later_text == "just install-files"
            for later_line, later_text in active
            if later_line == line + 2
        )
    ]
    install_invocations: list[int] = []
    for line, command in logical_container_commands(active):
        tokens = container_shell_tokens(line, command)
        for token in tokens:
            if token.partition("=")[0] in SHELL_STARTUP_ENV_NAMES:
                fail(
                    "shell startup environment is forbidden in Containerfile "
                    f"on line {line}"
                )
        install_invocations.extend(
            [line] * count_container_install_invocations(line, tokens)
        )
    if len(helper_lines) != 1:
        fail(
            "expected one active offline-image lifecycle helper copy, "
            f"found {len(helper_lines)}"
        )
    if len(migration_helper_lines) != 1:
        fail(
            "expected one active offline-image legacy migration helper copy, "
            f"found {len(migration_helper_lines)}"
        )
    if len(manifest_lines) != 1:
        fail(
            "expected one active offline-image legacy digest manifest copy, "
            f"found {len(manifest_lines)}"
        )
    if len(marker_lines) != 1:
        fail(f"expected one active offline-image marker copy, found {len(marker_lines)}")
    if len(install_lines) != 1:
        fail(
            "expected one active offline-image install command, "
            f"found {len(install_lines)}"
        )
    if len(install_invocations) != 1:
        fail(
            "expected the offline-image command to be the only active "
            f"install-files invocation, found {len(install_invocations)}"
        )
    if max(
        helper_lines[0],
        migration_helper_lines[0],
        manifest_lines[0],
        marker_lines[0],
    ) >= install_lines[0]:
        fail(
            "offline-image lifecycle helpers, manifest, and marker copies "
            "must precede install-files"
        )


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} JUSTFILE CONTAINERFILE", file=sys.stderr)
        return 2
    check(pathlib.Path(sys.argv[1]))
    check_containerfile(pathlib.Path(sys.argv[2]))
    print("source-install lifecycle structure: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
