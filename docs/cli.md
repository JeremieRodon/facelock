# CLI Reference

All commands are subcommands of the `facelock` binary.

## Global flags

The following flags are accepted by every subcommand (declared `global = true`):

| Flag | Description |
|------|-------------|
| `-c`, `--config <PATH>` | Override the config file path. Takes precedence over `FACELOCK_CONFIG`. |
| `-q`, `--quiet` | Suppress informational output on stdout. Errors (stderr), prompts and exit codes are unaffected. |

`--quiet` is complete for `facelock setup` except the PAM extension hint, which
[#174](https://github.com/tyvsmith/facelock/issues/174) converts along with the
rest of that region. Other commands still print some output directly rather than
through the message seam the flag gates, so they stay partly noisy until
[#140](https://github.com/tyvsmith/facelock/issues/140) is finished.

## Machine-readable output

Every command whose output a script would parse takes `--json`, and spells it
exactly that — one flag family, no short letter, no `--output json`. It is not
offered everywhere: a command gains it when it has a named consumer, which
today means `facelock is-enrolled`, `facelock capabilities`, `facelock list`,
`facelock devices`, `facelock preview`, `facelock pam add`,
`facelock pam remove` and `facelock pam status`. Each payload is described in
that command's section below; the rule behind the flag, and the promise each
payload carries, are in [`contracts.md`](contracts.md) under "CLI Machine
Output".

The payload goes to stdout and nothing else does — diagnostics are on stderr
whatever `RUST_LOG` says — so `facelock devices --json` is safe to pipe at any
log level. On `is-enrolled`, `capabilities` and `pam`, `--quiet` suppresses the
payload too, leaving the exit code as the whole answer; `list`, `devices` and
`preview` still print theirs directly rather than through the seam the flag
gates, so they stay noisy until
[#140](https://github.com/tyvsmith/facelock/issues/140) is finished.

## facelock setup

Interactive setup wizard. Walks through camera selection, model quality, inference device (CPU / CUDA / ROCm / OpenVINO), model downloads, encryption, enrollment, and PAM configuration. Can also be run with flags for individual setup tasks.

```bash
facelock setup                          # interactive wizard
facelock setup --non-interactive        # run wizard without prompts
facelock setup --systemd                # install systemd units
facelock setup --systemd --disable      # disable systemd units
facelock setup --pam                    # install to /etc/pam.d/sudo
facelock setup --pam --service polkit-1 # install to a specific service
facelock setup --pam --remove           # remove the PAM line
facelock setup --pam --remove --if-present  # a missing service file is success
facelock setup --pam --service sshd -y  # a sensitive service: -y is what unlocks it
```

`--pam` is an alias onto [`facelock pam add | remove`](#facelock-pam), which is
the primary spelling and the one that takes several services in one process.
Every `setup --pam` invocation keeps parsing and keeps its behaviour.

`system-auth`, `login` and `sshd` are gated: `facelock setup --pam --service login`
refuses until `-y` is added, and on `facelock pam add` the same gate is
`--allow-sensitive`. `--if-present` requires `--remove` and turns a missing
service file into a successful no-op — read, parse and write failures stay
fatal.

## facelock is-enrolled

Report whether a user has a usable face enrollment. Unprivileged and cheap
enough to call repeatedly from a lock screen: it reads one marker file under
`/var/lib/facelock/enrolled/` and never activates the daemon, opens a camera,
or reads the face database.

It never errors merely because the caller is outside the `facelock` group, but
it cannot report `enrolled` for one either: the marker sits under two
`0710 root:facelock` directories, so a non-member reads `EACCES` and is
reported `not-enrolled`. That is the correct answer — the group is required to
reach the daemon at all, so face auth genuinely is not operational for that
caller yet.

```bash
facelock is-enrolled                    # prints enrolled / not-enrolled
facelock is-enrolled --user alice       # specific user
facelock is-enrolled --json             # machine-readable
facelock is-enrolled --quiet            # no stdout; the exit code is the answer
```

The exit code is the contract — branch on it rather than parsing stdout:

| Code | Meaning |
|------|---------|
| 0 | the user has a usable enrollment |
| 1 | not enrolled; an absent or unreadable marker reports this way |
| 2 | error — an invalid `--user`, or a marker that exists but cannot be parsed |

`--json` emits one object and does not change the exit code:

```json
{"enrolled":true,"models":2,"updated":"2026-08-12T00:00:00Z"}
```

`models` is `0` and `updated` is `null` when the user is not enrolled. The
error case prints its reason on stderr and no payload at all.

The marker is a hint for deciding whether to offer a face-auth affordance; PAM
at authentication time remains authoritative and nothing in the auth path
consults it. See [`contracts.md`](contracts.md), "facelock is-enrolled Exit
Codes", for the stability promise and for how markers are reconciled with the
database.

## facelock capabilities

Report what this build can do, as capability names. Unprivileged: it answers
from the binary's own clap tree and compiled-in constants, reading no config
file, activating no daemon and opening no camera. It is what replaces grepping
`--help` in a wrapper script.

```bash
facelock capabilities                   # one name per line
facelock capabilities --json            # {"version", "capabilities"}
```

With the name array elided:

```json
{"capabilities":["capabilities","devices-json","is-enrolled"],"version":"0.1.4"}
```

Both forms exit 0 — the command has no failure mode — and `--quiet` suppresses
stdout, leaving the exit code as the whole answer. A build that predates the
command answers by failing: clap's unrecognized-subcommand error on stderr,
exit 2, nothing on stdout. A caller reads any non-zero exit as "no capabilities
at all", which is the true answer for that build.

Probe by name, never by version. The names this build emits, what each one
promises, and the stability rules that govern them are in
[`contracts.md`](contracts.md), "facelock capabilities".

## facelock enroll

Capture and store a face model.

```bash
facelock enroll                         # current user, auto-label
facelock enroll --user alice            # specific user
facelock enroll --label "office"        # specific label
```

Captures 3-10 frames over ~15 seconds. Requires exactly one face per frame. Re-enrolling with the same label replaces the previous model.

## facelock test

Test face recognition against enrolled models.

```bash
facelock test                           # current user
facelock test --user alice              # specific user
```

Reports match similarity and latency.

## facelock list

List enrolled face models.

```bash
facelock list                           # current user
facelock list --user alice              # specific user
facelock list --json                    # JSON output
```

`--json` emits an array of objects:

```json
[
  {
    "id": 1,
    "label": "office",
    "user": "alice",
    "created_at": 1700000000,
    "embedder_model": "arcface_r50"
  }
]
```

## facelock remove

Remove a specific face model by ID.

```bash
facelock remove 3                       # remove model #3
facelock remove 3 --user alice          # for specific user
facelock remove 3 --yes                 # skip confirmation
```

## facelock clear

Remove all face models for a user.

```bash
facelock clear                          # current user
facelock clear --user alice --yes       # skip confirmation
```

## facelock preview

Live camera preview with face detection overlay.

```bash
facelock preview                        # Wayland graphical window
facelock preview --json                 # one JSON object per frame on stdout
facelock preview --user alice           # match against specific user
```

`--json` shipped as `--text-only`, which stays a hidden alias and keeps
parsing; the payload is unchanged. One object per line, one per frame:

```json
{"faces":[{"confidence":0.5,"height":180.0,"recognized":true,"similarity":0.75,"width":180.0,"x":112.0,"y":88.0}],"fps":15.0,"frame":1,"height":480,"jpeg_size":24576,"recognized":1,"unrecognized":0,"width":640}
```

Keys come out sorted, which is `serde_json`'s doing and not a promise.
`jpeg_size` is present only when the daemon serves the frames; the direct
(oneshot) path has no JPEG and omits that key, and every other key is on both.
Numbers are `f32` rounded then widened to `f64`, so a rounded `0.988` reaches
you as `0.9879999756813049`: compare numerically, never as text.

## facelock devices

List available V4L2 video capture devices.

```bash
facelock devices                        # human-readable listing
facelock devices --json                 # JSON output
```

Shows device path, name, driver, formats, resolutions, and IR status.

`--json` emits an array of device objects with `path`, `name`, `driver`,
`is_ir`, and `formats`; each format carries `fourcc`, `description`, and
`sizes`, a list of `[width, height]` pairs. It is a typed schema derived from
the device struct, so a script reads it rather than parsing the listing above,
whose columns, indentation and `[IR]` tag are free to change.

`formats` is empty whenever the daemon answers: the D-Bus device type does not
carry format detail, so only the direct (oneshot) backend fills it in. The
human listing omits the section for the same reason. Read `formats` for
capability detection only when you know you are on the direct path.

## facelock status

Check system status — config, daemon, oneshot fallback, camera, models,
encryption, enrollment, security posture, notifications, PAM wiring. Requires
root. A check that cannot be performed (unreadable database, broken config) is
reported as "cannot determine" — never as a guessed value.

```bash
facelock status
```

## facelock config

Show or edit the configuration file.

```bash
facelock config                         # show config path and contents
facelock config --edit                  # open in $EDITOR
```

## facelock daemon

Run the persistent authentication daemon.

```bash
facelock daemon                         # use default config
facelock daemon -c /path/to/config.toml # short alias for --config
facelock daemon --config /path/to/config.toml
```

Normally managed by systemd, not run manually.

## facelock auth

One-shot authentication. Used by the PAM module in oneshot mode.

```bash
facelock auth --user alice              # authenticate
facelock auth --user alice --config /etc/facelock/config.toml
```

Exit codes: 0 = matched, 1 = no match, 2 = error.

## facelock tpm

TPM integration status and management.

### facelock tpm status

Report TPM availability and configuration.

```bash
facelock tpm status
```

### facelock tpm seal-key

Seal the AES encryption key with the TPM, migrating from a plaintext keyfile to TPM-backed storage.

```bash
facelock tpm seal-key
```

### facelock tpm unseal-key

Unseal the AES key from the TPM back to a plaintext keyfile, migrating from TPM-backed to keyfile storage.

```bash
facelock tpm unseal-key
```

### facelock tpm unseal-check

Read-only check that the sealed AES key still unseals under the current PCR
values. Writes nothing, and exits non-zero when it does not — which is the
signal to run [`facelock reseal`](#facelock-reseal).

```bash
sudo facelock tpm unseal-check
```

### facelock tpm pcr-baseline

Display the current PCR values for all configured PCR indices.

```bash
facelock tpm pcr-baseline
```

## facelock bench

Benchmark and calibration tools.

```bash
facelock bench cold-auth                # cold start authentication latency (model load + first auth)
facelock bench warm-auth                # warm authentication latency (pre-loaded models, 10 iterations)
facelock bench preview                  # frame capture + face detection latency
facelock bench enrollment               # time to capture and embed snapshots (dry run, embeddings not stored)
facelock bench model-load               # ONNX model load time (SCRFD + ArcFace)
facelock bench calibrate                # sweep FAR/FRR thresholds and recommend optimal value
facelock bench camera-reopen            # cost of reopening the camera: open / STREAMON / warmup split
facelock bench report                   # full benchmark report
```

**Every `bench` subcommand requires root** (DEC-6): direct-mode access needs the
`0600` root:root database whatever the subcommand, and the auth benchmarks may
need TPM access besides. `cold-auth`, `warm-auth`, `calibrate`, and `report`
additionally require enrolled faces.

`camera-reopen` needs no enrolled face and loads no models — but is root like
the rest: it closes and reopens the camera `--iterations` times (default 5) and
reports the per-phase median. That total is what `device.camera_release_secs`
trades LED-on time against — holding the stream warm after a failed attempt
buys a retry exactly this much (ADR 008).

## facelock pam

Manage the facelock line in `/etc/pam.d` service files. This command owns every
write to `/etc/pam.d`; `setup --pam` is an alias onto it, and the setup wizard
calls the same writer.

`--service` is repeatable on all three verbs and defaults to `sudo`, so several
services are configured in one process, under one root check. `add` and
`remove` require root and never offer to re-exec under `sudo`; `status` reads
only and needs no root.

### facelock pam add

```bash
sudo facelock pam add                                        # /etc/pam.d/sudo
sudo facelock pam add --service polkit-1 --service hyprlock  # several at once
sudo facelock pam add --service sshd --allow-sensitive       # unlock a gated service
sudo facelock pam add --service hyprlock --if-present        # a missing file is success
sudo facelock pam add --service sudo --dry-run               # print the plan, write nothing
sudo facelock pam add --service sudo --json                  # machine-readable result
```

| Flag | Meaning |
|------|---------|
| `--service <NAME>` | service to act on; repeat for several (default: `sudo`) |
| `-y`, `--yes` (alias `--no-confirm`) | skip the per-file confirmation, and nothing else |
| `--allow-sensitive` | also permit the gated services `system-auth`, `login`, `sshd` |
| `--if-present` | treat a missing service file as success instead of an error |
| `--dry-run` | print the resolved plan, write nothing, exit 0 |
| `--json` | emit one JSON document instead of human text |

`--yes` never implies `--allow-sensitive`: they are separate authorizations,
"do not ask me" and "yes, edit `system-auth`". Every service is validated before
any file is written, so a rejected service name leaves the rest untouched.
With no TTY on stdin the per-file confirmation is skipped as if `--yes` were
given — the gate is decided before any prompt exists, so an unattended
`pam add --service system-auth` still refuses.

`--dry-run` is honoured after the root check, so it still needs root.
`pam status` is the unprivileged read to reach for instead.

### facelock pam remove

```bash
sudo facelock pam remove                                     # /etc/pam.d/sudo
sudo facelock pam remove --service login                     # removal is never gated
sudo facelock pam remove --service hyprlock --if-present     # a missing file is success
sudo facelock pam remove --service sudo --dry-run --json
```

Takes the same flags as `add` except `--allow-sensitive`, which it does not
offer: removal can only take away a way to authenticate, so there is nothing to
gate. It never prompts either, and the `.facelock-backup` file written by `add`
is left in place.

### facelock pam status

```bash
facelock pam status                                          # /etc/pam.d/sudo
facelock pam status --service sudo --service polkit-1
facelock pam status --service sudo --json
```

Unprivileged, and the probe to branch on instead of grepping `/etc/pam.d`
yourself: it answers from the same file, without root, and reports "absent" and
"unreadable" as themselves rather than as "not configured". It offers
`--service` and `--json` and neither `--dry-run` nor `--allow-sensitive` —
there is no write to preview or gate. The exit code is the answer, on the same
0/1/2 scale as `is-enrolled` and `grep`:

| Code | Meaning |
|------|---------|
| 0 | every requested service carries the line |
| 1 | at least one exists without it |
| 2 | at least one is absent, unreadable, or misnamed |

Across several services the worst outcome wins. `--json` emits one document:

```json
{"command":"status","dry_run":false,"services":[{"action":"present","backup":null,"path":"/etc/pam.d/sudo","service":"sudo"}]}
```

The document's shape, the `action` vocabulary, and the rule that a consumer
must tolerate an `action` it does not recognize rather than treat it as an
error, are a stability contract — see [`contracts.md`](contracts.md), "facelock
pam Semantics", along with the exit codes for `add` and `remove` and what
`--json` does on a validation failure.

## facelock hyprlock

Manage hyprlock lock-screen integration: the face glyph in `placeholder_text`,
and the `ignore_empty_input = false` setting that lets a bare Enter submit to
PAM. Runs as your normal user and refuses to run as root, since it edits
`~/.config/hypr/hyprlock.conf` and root would leave root-owned files in `$HOME`.
A backup is taken before the first edit.

```bash
facelock hyprlock enable                # face icon, and allow the empty-Enter submit
facelock hyprlock enable --no-icon      # only set ignore_empty_input = false
facelock hyprlock disable               # undo
facelock hyprlock status                # report the current state
```

`--no-icon` is for a hyprlock font with no Nerd Font glyphs; it flips the
functional setting and leaves any existing icon alone. `disable` restores
`ignore_empty_input` only when no fingerprint icon coexists, so a machine using
both keeps working.

Wiring `/etc/pam.d/hyprlock` itself is a separate, root step — see
[`facelock pam`](#facelock-pam). This command touches no file outside `$HOME`.

## facelock encrypt

Encrypt all unencrypted embeddings in the database with AES-256-GCM.

```bash
facelock encrypt                        # encrypt using the configured key
facelock encrypt --generate-key         # generate a new key file (or seal a new TPM key) WITHOUT re-encrypting embeddings
```

`--generate-key` only creates the key material. Run `facelock encrypt` (without the flag) afterwards to encrypt the embeddings.

## facelock decrypt

Decrypt all software-encrypted embeddings in the database (reverting AES-256-GCM encryption).

```bash
facelock decrypt
```

## facelock reseal

Re-seal the TPM AES key under the current PCR values. This is the recovery step
after a firmware or kernel change moves a measured PCR and the sealed key stops
unsealing. Requires root, and applies only when `encryption.method = "tpm"` —
under any other method it errors rather than quietly doing nothing.

```bash
sudo facelock reseal
```

It prefers unsealing the existing blob, which still works while the PCR policy
is satisfied, so it is safe to run proactively before a firmware update; once
the PCRs have moved it falls back to the plaintext key backup. With neither
available there is nothing to re-seal and it fails. Run
`facelock tpm unseal-check` to find out which of those you are in.

## facelock audit

View the structured audit log of authentication events.

```bash
facelock audit                          # show last 20 entries (default)
facelock audit -l 50                    # show last 50 entries
facelock audit --lines 50               # long form
facelock audit -f                       # follow mode: stream new entries as they arrive
facelock audit --follow                 # long form
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--follow` | `-f` | false | Watch for new entries (like `tail -f`) |
| `--lines N` | `-l` | 20 | Number of recent entries to display |

## facelock restart

Restart the persistent daemon. On systemd systems, runs `systemctl restart facelock-daemon.service`. Otherwise, sends a D-Bus shutdown request and the daemon restarts on next use via D-Bus activation.

Requires root. If run interactively as a non-root user, the CLI prompts to re-run via `sudo`.

```bash
facelock restart
```

## User Resolution

For commands that accept `--user`:
1. Explicit `--user` flag (highest priority)
2. `SUDO_USER` environment variable
3. `DOAS_USER` environment variable
4. Current user (`$USER` or `getpwuid`)

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `FACELOCK_CONFIG` | Override config file path for unprivileged CLI commands. Ignored by privileged PAM/root auth flows; use `--config` there. |
| `RUST_LOG` | Control log verbosity (e.g., `facelock_daemon=debug`) |
