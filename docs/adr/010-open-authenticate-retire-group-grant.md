# ADR 010: `Authenticate` Open to Every Local User; the `facelock` Group Grants Nothing on the Auth Path

## Status

Accepted

## Date

2026-08-18

## Context

The system-bus policy admitted only root and the `facelock` group to
`org.facelock.Daemon`, and the state directory was `0710 root:facelock`. A
human therefore needed group membership for every user-run PAM stack
(hyprlock, swaylock, the polkit agent) and for `facelock is-enrolled`.
Supplementary groups are fixed per process at login, so nothing worked until a
full re-login: `sudo facelock setup` ran `usermod -aG facelock` and printed a
reminder forty lines before "Setup complete", which was true for `sudo` (PAM
as root) and false for the lock screen.

The daemon already authorizes per method on the caller's UID
(`authorize_method` in `crates/facelock-daemon/src/server.rs`).
`Authenticate` is the only user-scoped method — a non-root caller may target
only its own username — and every other method is root-only. `pre_check`
answers "no enrolled models" from SQLite before the camera is opened. The bus
group filter was a second wall in front of a check the daemon already makes.

fprintd, the closest analogue, lets the `default` context talk to
`net.reactivated.Fprint` and authorizes inside the daemon (peer UID plus
polkit); `pam_fprintd` works in user-run lockers with no group and no
re-login. Howdy avoids the group by having no privilege boundary at all: its
PAM module spawns `compare.py` in the caller's process, so whoever runs the
PAM stack reads the face model — the design facelock's `0600 root:root`
database exists to avoid.

## Decision

1. **Bus policy** (`dbus/org.facelock.Daemon.conf`): the `default` context
   may send `org.facelock.Daemon.Authenticate` to `org.facelock.Daemon` and
   nothing else. Root keeps the whole interface. The `facelock` group policy
   shrinks to signal receipt (`AuthAttempted`); it no longer grants method
   calls.
2. **State directory**: `/var/lib/facelock` and `/var/lib/facelock/enrolled`
   become `0711 root:root` — traverse for everyone, list for nobody. The
   database, its sidecars, the markers, the audit log and the snapshots keep
   their modes. `is-enrolled` needs no group.
3. **Setup**: `facelock setup` and `just install-files` stop adding users to
   the group. Setup still creates the system group (packaging does via
   sysusers) because the policy names it. Existing memberships are harmless
   and left alone.
4. **No daemon authorization change.** `Authenticate(other_user)` from a
   non-root caller is denied by `require_user_authorized`, as before.

## Consequences

- hyprlock/swaylock/polkit face unlock and the `is-enrolled` face icon work
  the moment enrollment finishes. No re-login, no `usermod`, no group hint.
- **New surface**: any local UID may call `Authenticate` **for itself**. An
  unenrolled UID gets a no-model reply from `pre_check` without the camera
  opening. An enrolled UID could already do this (it was in the group). No
  UID can target another user or learn another user's enrollment. Every
  attempt is audited when auditing is enabled (an unenrolled UID's calls
  are audited but not rate-limited, so a loop can rotate the audit log —
  see `docs/security.md` § 4 A); an enrolled UID's failed attempts are
  rate-limited per user, while an unenrolled UID's calls are answered by
  `pre_check` before the limiter and are not charged. Such a call still
  occupies the daemon's single capture slot for its brief duration, so any
  local UID can now contend with a lock screen for that slot where before
  only root and group members could — a local availability margin, not a
  bypass; recorded and accepted in `docs/security.md` § 4 A.
- **Residual widened**: any local user can `stat` a name it guesses under the
  state directory (`facelock.db` size/mtime, `enrolled/<name>` existence).
  Previously group members only. Accepted; recorded in `docs/security.md`
  § 3 A2.
- The CLI's `AccessDenied` hint no longer mentions the group: a bus-policy
  denial for a non-`Authenticate` method means "root required", the same as
  the daemon's own denial.
- **Upgrade**: modes and ownership converge through the existing channels
  (tmpfiles, package scriptlets, `ensure_state_layout` on daemon start,
  best-effort on the auth path). The policy file is replaced by the package
  or by `sudo facelock setup --systemd`; both bus implementations watch the
  policy directory, and setup and the scriptlets also ask for
  `org.freedesktop.DBus.ReloadConfig`, best-effort.

## Alternatives rejected

- **Automate the re-login** (`loginctl terminate-user`): destroys unsaved
  work, needs logind/elogind, and only papers over the requirement.
- **polkit for `Authenticate`** (fprintd's `allow_active`): PAM modules
  cannot answer interactive polkit prompts; UID-match is the right
  authorization for "authenticate me". A logind "active local session" check
  can be added later without touching the bus policy.
- **Keep the group's whole-interface grant**: every method it would admit is
  denied by the daemon anyway; keeping it only complicates the story.
