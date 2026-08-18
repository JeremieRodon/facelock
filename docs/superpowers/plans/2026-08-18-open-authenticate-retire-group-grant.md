# Open `Authenticate`, Retire the Group Grant — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Face unlock in user-run PAM stacks (hyprlock, swaylock, polkit agent) and `facelock is-enrolled` work the moment enrollment finishes — no `facelock` group membership, no `usermod`, no re-login — without weakening what the daemon and the on-disk layout protect.

**Architecture:** Three coordinated contract changes, one PR. (1) The system-bus policy lets the `default` context send exactly one method, `org.facelock.Daemon.Authenticate`; the daemon's existing per-method UID check (`authorize_method`) is now the boundary for that method, as it always was for user-vs-user. The `facelock` group policy shrinks to signal receipt. (2) `/var/lib/facelock` and `/var/lib/facelock/enrolled` go from `0710 root:facelock` to `0711 root:root` (traverse for everyone, list for nobody); everything below keeps its `0600` modes. (3) `facelock setup` / `just install-files` stop adding users to the group; the CLI's group hint goes away. Docs, packaging, container tests, and the translation catalog move with each change.

**Tech Stack:** Rust (workspace), D-Bus policy XML (dbus-daemon and dbus-broker), systemd tmpfiles/sysusers, pacman `.install`, Debian `postinst`, RPM spec, OpenRC, Nix module, bash container tests under podman, gettext (`just pot`).

**Spec:** `docs/adr/010-open-authenticate-retire-group-grant.md` — written in Task 1 of this plan; every later task argues from it.

**Execution:** orchestrated. One session (the orchestrator, Fable 5) dispatches a builder subagent per task and separate reviewer subagents, all working in dedicated git worktrees under `~/Code/facelock/.worktrees/`, on one feature branch that becomes **one draft PR** at the end. § 0 is the operating manual; Tasks 0–10 are the work. Model tier per task is in § 0.3 (Ty's directive: smartest model on design, security and every review; `opus` for mechanical builders; no `sonnet`/`haiku`).

## Global Constraints

- `docs/contracts.md` is updated in the same commit as any path, mode, policy, or CLI-behaviour change it records (repo rule, `AGENTS.md` § Core Rules).
- `docs/security.md` § 3 and § 4 must describe the shipped policy and layout; `AGENTS.md` § Security Rules line "D-Bus system bus policy: …" must match `dbus/org.facelock.Daemon.conf`.
- No daemon authorization change: `authorize_method` / `require_user_authorized` in `crates/facelock-daemon/src/server.rs` stay as they are. Their tests at `server.rs:2054-2142` are the evidence.
- The `facelock` system group keeps existing (sysusers, `groupadd -r` in setup and `just install-files`); nobody is added to it by facelock. Existing memberships are left alone.
- Message enums: every added/removed variant updates `VARIANT_COUNT` and `samples()` in the same file, and `just pot` is re-run so `po/facelock.pot` matches (CI diffs it).
- Commit titles: `<type>(<scope>): <subject>`, no AI attribution, no `Co-Authored-By` (user's global rules).
- Verify with: `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check`, `just test-arch-pam`, `just test-arch-layout`. Camera tiers (`just test-arch-integration`, `just test-arch-oneshot`) and host checks are Task 10 and need Ty.
- Commits at task ends are expected: Ty asked for the branch to be driven to a single draft PR. Nothing is pushed until Task 9; nothing is marked ready except by Ty.

---

## 0. How to run this plan

You are the orchestrator. You do not write code. You create worktrees, dispatch subagents with the briefs below, run every validation yourself in the worktree after a builder reports done (never trust the report — run the commands), dispatch reviewers, and merge. Fill in the **Run log** at the bottom as you go so a fresh session can resume.

### 0.1 Roles and agent types

| Role | `subagent_type` | Model | Writes code? |
|---|---|---|---|
| Builder | `general-purpose` | per § 0.3 | yes, in its assigned worktree only |
| Architecture / simplification reviewer | `ousterhout-reviewer` | inherit (pass no `model`) | no — findings only |
| Skeptic | `skeptical-reviewer` | inherit | no — verdicts only |
| Pre-flight claim check | skill `adversarial-validate` (orchestrator invokes) | inherit | no |
| Security review | skill `security-review` (orchestrator invokes, in the feature worktree) | inherit | no |
| Diff review | skill `code-review` at `high` (orchestrator invokes) | inherit | no |
| PR body | skill `pr-writer` (orchestrator invokes) | inherit | no |

Never let a builder review its own task. Never let a reviewer edit files — findings come back to you, and you dispatch a builder to apply the accepted ones.

### 0.2 Worktrees and branches

Repo root is `~/Code/facelock`. Everything happens in linked worktrees under `~/Code/facelock/.worktrees/`; the main checkout is never edited. If your session is itself pinned to an isolated worktree, run the `git worktree add` commands from that worktree — linked worktrees can be created from any worktree of the same repo — and always pass absolute paths.

```bash
cd ~/Code/facelock
git fetch origin && git status --short            # must be clean; note main's sha in the Run log
git worktree add .worktrees/adr010 -b feat/adr010-open-authenticate origin/main
# lanes for the parallel middle (create after Task 1's ADR commit is on the feature branch):
git worktree add .worktrees/adr010-a -b adr010/layout feat/adr010-open-authenticate   # Tasks 2 → 3
git worktree add .worktrees/adr010-b -b adr010/bus    feat/adr010-open-authenticate   # Task 4
```

Sequence: Task 0 and Task 1 on `feat/adr010-open-authenticate` → **lane A** (Task 2 then Task 3, same worktree, one builder each, sequential) **in parallel with lane B** (Task 4) → merge B then A back into the feature branch (§ 0.6) → Tasks 5, 6, 7, 8, 9 on the feature branch in `.worktrees/adr010` → Task 10 (Ty). Lane files were checked for overlap when this plan was written: the two lanes touch different hunks of `setup.rs`, `docs/security.md` (§ 3 vs § 4) and `docs/contracts.md` (Filesystem vs IPC), so the merges are expected to be clean; the sequential fallback (run Task 4 after Task 3 in `.worktrees/adr010`) costs about 45 minutes of wall-clock and zero merges — take it if you would rather not merge.

Rules every builder brief repeats verbatim:

- Work only in the worktree path you were given. Before every `git add`/`commit`, run `git -C <worktree> branch --show-current` and confirm the branch named in your brief; use `git -C <worktree>` and absolute paths for every git command (another agent's `EnterWorktree` can silently move a relative cwd).
- Never `git stash` (shared stash stack). Never rebase or force-push. Never touch `~/Code/facelock` (the main checkout) or another lane's worktree.
- Scratch files go under the scratchpad directory with your task prefix (`t2-…`), never bare names — the scratchpad is shared between concurrent agents.
- Container tiers (`just test-arch-*`) must be run pinned: `just -d <worktree> -f <worktree>/justfile <recipe>`. Run `just link-models` once per worktree first.
- Commit messages: `<type>(<scope>): <subject>`, no AI attribution, no `Co-Authored-By`.
- Report back: commit sha(s), files touched, every validation command you ran with its exit status, and anything you did differently from the plan and why. Do not paste logs.

### 0.3 Model tier per task

| Task | Builder model | Why |
|---|---|---|
| 0 bootstrap | orchestrator, no agent | worktrees and a verbatim file copy |
| 1 ADR + README row | `opus` | verbatim text from this plan |
| 2 layout `0711 root:root` | **inherit** | rewrites the guard tests that pin the security property, and § 3 of `security.md` |
| 3 packaging + layout container test | `opus` | mirrors modes into six fragments and a bash test; the container run is the judge |
| 4 bus policy | **inherit** | the security decision itself: policy XML, ordering, the camera-free harness, § 4 of `security.md` |
| 5 retire membership + hint | `opus` | deletions and rewording; compiler and `VARIANT_COUNT` sweeps catch drift |
| 6 CHANGELOG + sweep + verification | `opus` | mechanical; the orchestrator re-runs the verification ladder itself |
| 7 simplification pass — apply | **inherit** | changes to security-adjacent code on reviewer findings |
| 8 skeptic pass — apply | **inherit** | same |
| every reviewer, every skill | **inherit** | no exceptions |

### 0.4 Dispatch brief template

Every builder gets this, with the blanks filled:

```
You are the builder for Task <N> of docs/superpowers/plans/2026-08-18-open-authenticate-retire-group-grant.md
(read the whole plan header, § "Global Constraints", § 0.2 rules, and Task <N>; also read the ADR at
docs/adr/010-open-authenticate-retire-group-grant.md once it exists).
Worktree: <abs path>   Branch: <name>   (verify with git -C <abs path> branch --show-current before any commit)
Do the task's steps in order — write the failing test first where the task says so, run it, implement, run again,
then the task's validation commands, then commit with the message given. Every command that the task lists as
"Run:" you actually run and report the exit status of. If a step cannot be done as written (a line moved, an
API differs), do the closest correct thing, keep the intent, and say exactly what you changed in your report.
Do not widen scope. Do not touch files the task does not list unless the compiler forces you to (then say so).
Scratch files: prefix with t<N>-. No AI attribution anywhere. Report: sha, files, commands + exit codes, deviations.
```

Reviewers get: read-only instruction, the worktree path, `git -C <wt> diff origin/main...HEAD` as the scope, the ADR path, the specific attack/lens list from Task 7 or 8, and the required output shape (`APPROVED` or `CHANGES_REQUESTED` with `file:line`, claim, evidence, and for the skeptic a confidence per verdict).

### 0.5 Validation ladder (orchestrator runs these, in the worktree, after each builder)

| Rung | Command | When |
|---|---|---|
| 1 | `cargo fmt --all -- --check` | every task |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | every task |
| 3 | `cargo test --workspace` | every task |
| 4 | `just pot && git diff --exit-code -I '^"POT-Creation-Date: ' po/` | Task 5 (message strings changed) and Task 6 |
| 5 | `just test-arch-layout` (pinned) | Task 3, Task 6, after Tasks 7/8 if they touch `state_layout.rs` or `dist/` |
| 6 | `just test-arch-pam` (pinned) | Task 4, Task 5, Task 6, after Tasks 7/8 |
| 7 | `just check` | Task 6, Task 9 |
| 8 | `just test-arch-integration`, `just test-arch-oneshot`, host checks | Task 10 — Ty, camera |

`cargo build --workspace` is implied by rung 3.

### 0.6 Merging the lanes and finishing

```bash
cd ~/Code/facelock/.worktrees/adr010
git -C . branch --show-current                     # feat/adr010-open-authenticate
git -C . merge --no-ff adr010/bus    -m "merge: adr010/bus (Task 4)"
git -C . merge --no-ff adr010/layout -m "merge: adr010/layout (Tasks 2-3)"
```

Expected: no conflicts. If `docs/security.md` or `docs/contracts.md` conflict, the two sides edit disjoint sections — keep both. If `setup.rs` conflicts, lane A's hunk is `secure_setup_paths` and the deleted `facelock_group_gid`, lane B's is `reload_dbus_config` + `run_systemd` + one test — keep both. After the merge, run rungs 1–3, 5 and 6 on the feature branch before dispatching Task 5. Remove the lane worktrees (`git worktree remove .worktrees/adr010-a`, `-b`) only after Task 9's PR is open.

One PR, at the end (Task 9): `feat/adr010-open-authenticate` → `main`, draft, opened by `pr-writer`. No stacked PRs, no intermediate pushes.

### 0.7 Stop and ask Ty

- Task 0's `adversarial-validate` refutes any Decision in the ADR.
- The skeptic (Task 8) returns a `CHANGES_REQUESTED` that would change a Decision rather than the implementation.
- A builder wants to touch `authorize_method` / `require_user_authorized` in `facelock-daemon/src/server.rs`, or the PAM module — neither is in scope.
- Anything needs `sudo` on the host (Task 10 only). Batch the commands and ask once.
- Two review rounds on a task without `APPROVED` — park it, record both positions in the Run log, ask.

---

## File map

| File | Change |
|---|---|
| `docs/adr/010-open-authenticate-retire-group-grant.md` | new — the decision (spec) |
| `docs/adr/README.md` | add row 010 |
| `dbus/org.facelock.Daemon.conf` | default context may send `Authenticate`; group policy = signals only |
| `crates/facelock-cli/src/state_layout.rs` | modes `0o711`, ownership `root:root`, drop `Ownership`/`Owners`, `apply_layout(layout, chown_to_root: bool)`, guard tests |
| `crates/facelock-cli/src/commands/setup.rs` | `secure_setup_paths` uses new `apply_layout`; drop `facelock_group_gid`; replace `setup_group_membership` with `ensure_facelock_group`; drop `invoking_user`/`user_in_group`; `reload_dbus_config()` in `run_systemd`; policy-shape unit test |
| `crates/facelock-cli/src/commands/enrollment_marker.rs` | module docs + tests `0o710` → `0o711` |
| `crates/facelock-cli/src/commands/is_enrolled.rs` | module docs |
| `crates/facelock-cli/src/commands/auth.rs` | comment at line 81 |
| `crates/facelock-cli/src/message/system.rs` | remove 5 group-membership variants |
| `crates/facelock-cli/src/message/setup.rs` | reword `GroupStepFailed` |
| `crates/facelock-cli/src/message/access.rs` | remove `AccessDeniedGroupHint` |
| `crates/facelock-cli/src/ipc_client.rs` | `add_access_denied_hint` always root hint; tests |
| `crates/facelock-daemon/src/server.rs` | doc comment on `Scope` (line 452-454) |
| `systemd/facelock-daemon.service` | comment lines 73-74 |
| `dist/facelock.tmpfiles`, `dist/facelock.install`, `dist/debian/postinst`, `dist/openrc/facelock-daemon`, `dist/nix/module.nix`, `dist/facelock.sysusers`, `dist/facelock.spec` | modes/ownership; bus `ReloadConfig` best-effort |
| `justfile` | `install-files` no `usermod`; comments |
| `test/run-layout-tests.sh` | rewritten for `0711 root:root` and non-member semantics |
| `test/run-container-tests.sh` | bus-policy block with a root-owned fake daemon; bus started earlier; `ReloadConfig` before the peer overlay |
| `test/run-integration-tests.sh` | (d) non-member `Authenticate` self / other / `Ping` |
| `docs/security.md`, `docs/contracts.md`, `docs/cli.md`, `docs/troubleshooting.md`, `book/src/cli-reference.md`, `book/src/security.md`, `book/src/troubleshooting.md`, `man/facelock.1`, `README.md`, `AGENTS.md`, `website/index.html`, `CHANGELOG.md` | text |
| `po/facelock.pot` | regenerated by `just pot` |

---

### Task 0: Bootstrap and pre-flight claim check (orchestrator)

**Dispatch:** none — you do this yourself. The only writes are the worktree and a copy of this plan.

- [ ] **Step 1: Baseline**

```bash
cd ~/Code/facelock
git fetch origin
git status --short                                # clean
git log --oneline -1 origin/main                  # record sha in Run log
git worktree add .worktrees/adr010 -b feat/adr010-open-authenticate origin/main
cp <this plan's path> .worktrees/adr010/docs/superpowers/plans/2026-08-18-open-authenticate-retire-group-grant.md
git -C .worktrees/adr010 add docs/superpowers/plans/2026-08-18-open-authenticate-retire-group-grant.md
git -C .worktrees/adr010 commit -m "docs(plans): open Authenticate and retire the group grant"
cd .worktrees/adr010 && just link-models && just check   # baseline must be green; if not, record and stop
```

- [ ] **Step 2: Pre-flight claim check (Ty's rule: `adversarial-validate` before acting on a load-bearing claim)**

Invoke the `adversarial-validate` skill from the feature worktree with this claim, verbatim:

> "Opening `org.facelock.Daemon.Authenticate` to every local user at the D-Bus policy loses no protection that the code does not already provide: (a) `authorize_method`/`require_user_authorized` in `crates/facelock-daemon/src/server.rs` denies a non-root caller naming any username but its own, and every other method is root-only there; (b) `pre_check` in `crates/facelock-daemon/src/auth.rs` answers 'no enrolled models' from SQLite before any camera is opened; (c) nothing on the auth path — PAM module, polkit agent, `is-enrolled`, oneshot fallback — reads a file that only the `facelock` group can reach once `/var/lib/facelock` and `enrolled/` are `0711 root:root`; (d) both dbus-daemon and dbus-broker apply a later `<allow send_member=…>` over an earlier `<deny send_destination=…>` in the same `<policy context=\"default\">`, and match `send_destination` against the names owned by the receiver even when the message is addressed to the owner's unique bus name."

Any part refuted → stop, put the verdict in the Run log, ask Ty. Weakened-with-caveats → carry the caveats into the Task 4 and Task 8 briefs.

- [ ] **Step 3: Record**

Run log: baseline sha, `just check` result, adversarial-validate verdict and confidence.

---

### Task 1: ADR 010 (the spec)

**Dispatch:** builder, `model: "opus"`, worktree `~/Code/facelock/.worktrees/adr010`, branch `feat/adr010-open-authenticate`. Brief per § 0.4. **After it reports:** `git -C … log -1 --stat` shows the two files; open the ADR and diff it against the text below (it must be verbatim); then create the lane worktrees per § 0.2 and dispatch Task 2 (lane A) and Task 4 (lane B) together.

**Files:**
- Create: `docs/adr/010-open-authenticate-retire-group-grant.md`
- Modify: `docs/adr/README.md`

- [ ] **Step 1: Write the ADR**

Create `docs/adr/010-open-authenticate-retire-group-grant.md` with exactly this content:

````markdown
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
  UID can target another user or learn another user's enrollment, and every
  attempt is audited and rate-limited per user.
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
````

- [ ] **Step 2: Add the README row**

In `docs/adr/README.md`, after the 009 row, add:

```markdown
| [010](010-open-authenticate-retire-group-grant.md) | `Authenticate` open to every local user; the `facelock` group grants nothing on the auth path | Accepted |
```

- [ ] **Step 3: Commit**

```bash
git add docs/adr/010-open-authenticate-retire-group-grant.md docs/adr/README.md
git commit -m "docs(adr): ADR 010 opens Authenticate to every local user and retires the group grant"
```

---

### Task 2: State layout `0711 root:root`

**Dispatch:** builder, **inherit** (no `model`), lane A worktree `~/Code/facelock/.worktrees/adr010-a`, branch `adr010/layout`. **After it reports:** rungs 1–3 in the lane worktree; read the diff of `state_layout.rs` yourself and confirm `Ownership`/`Owners` are gone and every `apply_layout` call site compiles; then dispatch Task 3 in the same worktree.

**Files:**
- Modify: `crates/facelock-cli/src/state_layout.rs` (whole non-test body + tests)
- Modify: `crates/facelock-cli/src/commands/setup.rs:2479-2486` (delete `facelock_group_gid`), `:2520-2528` (`secure_setup_paths`)
- Modify: `crates/facelock-cli/src/commands/enrollment_marker.rs:1-30, 45-47, 503-504, 723, 893`
- Modify: `crates/facelock-cli/src/commands/is_enrolled.rs:20-31, 44-46`
- Modify: `crates/facelock-cli/src/commands/auth.rs:81-82`
- Modify: `systemd/facelock-daemon.service:73-74`
- Modify: `docs/contracts.md` (Filesystem Paths table, "One gate at the top", "Contract change" section, `is-enrolled` row 60)
- Modify: `docs/security.md` (§ 2 B paragraph, § 3 A2, guard-test paragraph, § 3 A3), `book/src/security.md:92`

**Interfaces:**
- Produces: `state_layout::apply_layout(layout: &StateLayout, chown_to_root: bool) -> anyhow::Result<()>`; `STATE_DIR_MODE == 0o711`, `ENROLLED_DIR_MODE == 0o711`. `Ownership` and `Owners` are deleted. `ensure_state_layout(config)` and `ensure_state_layout_best_effort(config)` keep their signatures.

- [ ] **Step 1: Write the failing tests first — replace the contract tests in `state_layout.rs`**

In `crates/facelock-cli/src/state_layout.rs`, replace `the_layout_contract_is_the_documented_one`, `enrolled_dir_contract_is_mode_and_ownership`, and `nothing_under_the_state_directory_is_reachable_by_other` with:

```rust
    /// The documented layout, spelled out. A change to any mode here is a
    /// change to `docs/contracts.md` and every packaging fragment — this test
    /// failing is the reminder.
    #[test]
    fn the_layout_contract_is_the_documented_one() {
        let layout = StateLayout::from_config(&test_config()).unwrap();
        let specs = layout.dir_specs();

        let find = |path: &Path| {
            specs
                .iter()
                .find(|s| s.path == path)
                .copied()
                .unwrap_or_else(|| panic!("{} is not managed", path.display()))
        };

        assert_eq!(find(Path::new("/var/lib/facelock")).mode, 0o711);
        assert_eq!(find(Path::new("/var/lib/facelock/models")).mode, 0o755);
        assert_eq!(find(Path::new("/var/lib/facelock/enrolled")).mode, 0o711);
        assert_eq!(DB_FILE_MODE, 0o600, "the database is root-only");
    }

    /// ADR 010: both directories are traversable by everyone (`--x` for
    /// "other") and listable by nobody but root (no `r` for group or other).
    /// Traversal is what lets an unprivileged `is-enrolled` open its own
    /// `0600` marker by name without any group membership.
    #[test]
    fn state_and_enrolled_dirs_are_traversable_by_all_and_listable_by_none() {
        for mode in [STATE_DIR_MODE, ENROLLED_DIR_MODE] {
            assert_eq!(mode & 0o007, 0o001, "other: traverse only");
            assert_eq!(mode & 0o070, 0o010, "group: traverse only, no listing");
            assert_eq!(mode & 0o700, 0o700, "root: everything");
        }
    }

    /// Walks the applied tree and asserts the property the layout exists for:
    /// no file under the state directory carries any "other" bit, and no
    /// directory carries "other" read or write — traversal (`--x`) is the
    /// only thing granted, so a local user can open a name it knows and
    /// enumerate nothing. `models/` is the one subtree allowed to carry
    /// "other" bits of its own (public, SHA-256-verified downloads).
    #[test]
    fn nothing_under_the_state_directory_is_readable_or_listable_by_other() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_at(tmp.path());
        fs::create_dir_all(&layout.state_dir).unwrap();
        fs::write(&layout.db_path, b"stub").unwrap();

        apply_layout(&layout, false).unwrap();
        // Simulate later runtime artifacts.
        fs::write(layout.state_dir.join("facelock.db-wal"), b"stub").unwrap();
        apply_layout(&layout, false).unwrap();

        assert_eq!(
            mode(&layout.state_dir) & 0o007,
            0o001,
            "the state directory grants 'other' traversal and nothing else"
        );

        fn walk(dir: &Path, allow_other: &dyn Fn(&Path) -> bool) {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                let other = fs::metadata(&path).unwrap().permissions().mode() & 0o007;
                if !allow_other(&path) {
                    let allowed = if path.is_dir() { 0o001 } else { 0o000 };
                    assert_eq!(
                        other & !allowed,
                        0,
                        "{} is readable/writable by 'other'. The state directory holds \
                         biometric data: files carry no 'other' bits and directories \
                         at most traverse (models/ is the only exception — public data).",
                        path.display()
                    );
                }
                if path.is_dir() {
                    walk(&path, allow_other);
                }
            }
        }
        let models_dir = layout.models_dir.clone();
        walk(&layout.state_dir, &|p: &Path| p.starts_with(&models_dir));
    }
```

Also change every other `apply_layout(&layout, None)` in the tests to `apply_layout(&layout, false)` (`final_modes_match_the_documented_layout`, `applying_the_layout_twice_is_a_no_op`, `a_loosened_database_is_retightened`, `apply_layout_never_creates_a_database`).

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p facelock-cli state_layout -- --nocapture 2>&1 | tail -30`
Expected: compile errors (`apply_layout` takes `Option<Owners>`; `Ownership` still referenced) — that is the failure signal for this step.

- [ ] **Step 3: Rewrite the non-test body of `state_layout.rs`**

Replace everything from the top of the file down to (not including) `#[cfg(test)]` with:

```rust
//! The `/var/lib/facelock` on-disk layout.
//!
//! ```text
//! /var/lib/facelock/            0711 root:root   traverse-only, not listable
//!   facelock.db                 0600 root:root
//!   facelock.db-wal / -shm      0600 root:root
//!   models/                     0755 root:root   public, SHA-256 verified
//!   enrolled/                   0711 root:root   is-enrolled markers only
//!     <user>                    0600 <user>:<user>
//! ```
//!
//! Three properties are load-bearing (ADR 010):
//!
//! 1. **Traversal for everyone, listing for nobody.** Both directories carry
//!    `--x` for group and other and no `r`: any local user can open a path it
//!    already knows by name — its own `enrolled/<user>` marker, a model file —
//!    but nobody except root can enumerate the directory. Which accounts are
//!    enrolled stays private because each marker is `0600` and owned by its
//!    user, not because of who may enter the directory.
//! 2. **Every secret is locked in its own right.** The database and its
//!    sidecars are `0600 root:root`; nothing under the state directory except
//!    `models/` (public, SHA-256-verified downloads) carries "other" read or
//!    write bits. There is no group grant: the `facelock` group owns nothing
//!    here and reads nothing here that anyone else cannot.
//! 3. **Applying the layout is idempotent and never touches data.** It is a
//!    handful of `mkdir`/`chmod`/`chown` calls; the database and models never
//!    move, and nothing here creates, copies, or deletes a database. There is
//!    deliberately no migration machinery to get wrong.
//!
//! The guard tests at the bottom pin all three.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use facelock_core::Config;
use facelock_core::fs_security::ensure_private_dir;

// ---------------------------------------------------------------------------
// Names and modes
// ---------------------------------------------------------------------------

/// Per-user `is-enrolled` markers.
pub const ENROLLED_DIR_NAME: &str = "enrolled";

/// ONNX model files, directly in the state directory.
pub const MODELS_DIR_NAME: &str = "models";

/// `root:root`, traverse-only for everyone else: any local user can open
/// `enrolled/<user>` or a model file by name; nobody but root can list it.
pub const STATE_DIR_MODE: u32 = 0o711;

/// `root:root`. The models are public downloads, SHA-256 verified at load —
/// there is no reason to restrict them.
pub const MODELS_DIR_MODE: u32 = 0o755;

/// Same shape as the state directory. Traversal to a `0600 <user>:<user>`
/// marker is what `facelock is-enrolled` means by "operational for me"; the
/// marker's own mode is what keeps "am I enrolled?" answerable by that user
/// alone. No group is involved (ADR 010).
pub const ENROLLED_DIR_MODE: u32 = 0o711;

/// The database and its `-wal`/`-shm` sidecars: `root:root`, no group access.
/// Encrypted biometric templates are read by the daemon (root) only.
pub const DB_FILE_MODE: u32 = 0o600;

const SIDECAR_SUFFIXES: [&str; 2] = ["-wal", "-shm"];

// ---------------------------------------------------------------------------
// Deriving the layout from a config
// ---------------------------------------------------------------------------

/// The state directory implied by a database path: its parent directory.
pub fn state_dir_for_db(db_path: &Path) -> Option<&Path> {
    db_path.parent().filter(|p| !p.as_os_str().is_empty())
}

/// Every path the layout manages, derived from one `storage.db_path`.
///
/// Derived rather than hardcoded so an alternate install root — or a test
/// pointing an entire installation at a tempdir — stays internally consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLayout {
    pub state_dir: PathBuf,
    /// The configured `daemon.model_dir` when derived from a [`Config`],
    /// otherwise the built-in `<state_dir>/models`.
    pub models_dir: PathBuf,
    pub enrolled_dir: PathBuf,
    /// The configured `storage.db_path`.
    pub db_path: PathBuf,
}

impl StateLayout {
    /// Derive the layout from a database path, or `None` when the path has no
    /// usable parent (a bare filename, say).
    pub fn from_db_path(db_path: &Path) -> Option<Self> {
        let state_dir = state_dir_for_db(db_path)?.to_path_buf();
        Some(Self {
            models_dir: state_dir.join(MODELS_DIR_NAME),
            enrolled_dir: state_dir.join(ENROLLED_DIR_NAME),
            db_path: db_path.to_path_buf(),
            state_dir,
        })
    }

    pub fn from_config(config: &Config) -> Option<Self> {
        let mut layout = Self::from_db_path(Path::new(&config.storage.db_path))?;
        layout.models_dir = PathBuf::from(&config.daemon.model_dir);
        Some(layout)
    }

    /// The directories this layout manages, with their modes. All of them are
    /// `root:root`.
    ///
    /// A `model_dir` pinned outside the state directory is excluded: the guard
    /// property is "everything under the state directory carries these modes",
    /// and a path like `/opt/facelock-models` belongs to whoever pinned it.
    fn dir_specs(&self) -> Vec<DirSpec<'_>> {
        let mut specs = vec![DirSpec {
            path: &self.state_dir,
            mode: STATE_DIR_MODE,
        }];
        if self.models_dir.starts_with(&self.state_dir) {
            specs.push(DirSpec {
                path: &self.models_dir,
                mode: MODELS_DIR_MODE,
            });
        }
        specs.push(DirSpec {
            path: &self.enrolled_dir,
            mode: ENROLLED_DIR_MODE,
        });
        specs
    }

    /// The database file and its WAL sidecars — tightened when present, never
    /// created.
    fn db_files(&self) -> Vec<PathBuf> {
        let mut files = vec![self.db_path.clone()];
        for suffix in SIDECAR_SUFFIXES {
            let mut name = self.db_path.as_os_str().to_os_string();
            name.push(suffix);
            files.push(PathBuf::from(name));
        }
        files
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirSpec<'a> {
    path: &'a Path,
    mode: u32,
}

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------

/// `chown(2)` to `root:root`.
fn chown_root(path: &Path) -> anyhow::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains embedded NUL: {}", path.display()))?;
    if unsafe { libc::chown(c_path.as_ptr(), 0, 0) } != 0 {
        bail!(
            "failed to chown {} to root:root: {}",
            path.display(),
            io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Create-or-tighten one directory, then optionally make it `root:root`.
///
/// Already-correct directories are left entirely alone rather than re-`chmod`ed
/// and re-`chown`ed: this can run on the PAM path on every authentication, so
/// the steady state must cost one `stat` per path and no writes.
fn apply_dir(path: &Path, mode: u32, chown_to_root: bool) -> anyhow::Result<()> {
    let current = fs::metadata(path).ok().filter(|m| m.is_dir());
    let mode_ok = current
        .as_ref()
        .is_some_and(|m| m.permissions().mode() & 0o7777 == mode);
    let owner_ok = !chown_to_root
        || current
            .as_ref()
            .is_some_and(|m| m.uid() == 0 && m.gid() == 0);

    if !mode_ok {
        ensure_private_dir(path, mode)
            .with_context(|| format!("failed to create or secure {}", path.display()))?;
    }
    if !owner_ok {
        chown_root(path)?;
    }
    Ok(())
}

/// Tighten one file if it exists. Never creates it.
fn apply_file(path: &Path, mode: u32, chown_to_root: bool) -> anyhow::Result<()> {
    let Ok(meta) = fs::metadata(path) else {
        return Ok(());
    };
    if !meta.is_file() {
        return Ok(());
    }
    if meta.permissions().mode() & 0o7777 != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    if chown_to_root && (meta.uid() != 0 || meta.gid() != 0) {
        chown_root(path)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

/// Bring the state directory to the layout in the module docs.
///
/// Idempotent, and touches no data: directories are created or re-`chmod`ed,
/// the database is re-`chmod`ed **only if it already exists**, and nothing is
/// ever moved, copied, or deleted. `chown_to_root` also enforces `root:root`
/// ownership — pass `false` from unprivileged code (tests), since `chown(2)`
/// to root needs root.
pub fn apply_layout(layout: &StateLayout, chown_to_root: bool) -> anyhow::Result<()> {
    for spec in layout.dir_specs() {
        apply_dir(spec.path, spec.mode, chown_to_root)?;
    }
    for file in layout.db_files() {
        apply_file(&file, DB_FILE_MODE, chown_to_root)?;
    }
    Ok(())
}

/// [`apply_layout`] derived from a config, enforcing ownership when root. A
/// config whose `db_path` has no usable parent has no layout to apply and is
/// a no-op.
pub fn ensure_state_layout(config: &Config) -> anyhow::Result<()> {
    match StateLayout::from_config(config) {
        Some(layout) => apply_layout(&layout, nix::unistd::Uid::current().is_root()),
        None => Ok(()),
    }
}

/// Best-effort [`ensure_state_layout`]: applied on the authentication path and
/// in front of every direct-mode store open.
///
/// A failure here must never block the caller: the layout only sets modes,
/// which cannot change what is about to be read. It runs on these paths at all
/// so an install upgraded without re-running `setup` still converges on the
/// documented modes the first time a root invocation comes through.
pub fn ensure_state_layout_best_effort(config: &Config) {
    if let Err(e) = ensure_state_layout(config) {
        tracing::warn!(error = %format!("{e:#}"), "could not fully apply the state directory layout");
    }
}
```

- [ ] **Step 4: Update `secure_setup_paths` in `setup.rs` and delete `facelock_group_gid`**

Delete the function at `setup.rs:2479-2486`:

```rust
fn facelock_group_gid() -> anyhow::Result<u32> {
    ...
}
```

In `secure_setup_paths` (starts at `setup.rs:2520`), delete the line `let facelock_gid = facelock_group_gid()?;` and replace

```rust
    // The state directory subtree — state dir, models/, enrolled/, and the
    // database file modes — is owned by `state_layout`. Re-applied here
    // because setup only creates the `facelock` group partway through, so the
    // earlier call could not chown.
    if let Some(layout) = crate::state_layout::StateLayout::from_config(config) {
        let owners = nix::unistd::Uid::current()
            .is_root()
            .then_some(crate::state_layout::Owners { facelock_gid });
        crate::state_layout::apply_layout(&layout, owners)?;
    }
```

with

```rust
    // The state directory subtree — state dir, models/, enrolled/, and the
    // database file modes — is owned by `state_layout`. Re-applied here so a
    // path created earlier in setup with a looser mode converges before the
    // marker reconcile runs.
    if let Some(layout) = crate::state_layout::StateLayout::from_config(config) {
        crate::state_layout::apply_layout(&layout, nix::unistd::Uid::current().is_root())?;
    }
```

- [ ] **Step 5: `enrollment_marker.rs` docs and tests**

Replace the module doc block (lines 1-30) with:

```rust
//! Per-user enrollment marker files backing `facelock is-enrolled`.
//!
//! Layout (see [`crate::state_layout`], which owns it):
//!
//! ```text
//! /var/lib/facelock/                   0711 root:root  traverse-only, not listable
//! /var/lib/facelock/enrolled/          0711 root:root  markers only
//! /var/lib/facelock/enrolled/<user>    0600 <user>:<user>
//! ```
//!
//! The markers live **inside** the state directory. Both directories grant
//! everyone traversal (`--x`) and nobody but root listing (ADR 010), so any
//! local user can open its own marker by name but cannot `readdir` the
//! directory: which *other* accounts have face auth enrolled stays private.
//! Each marker is `0600` and owned by its user, so "am I enrolled?" is
//! answerable by that user and nobody else — the same privacy property as
//! `~/.ssh/authorized_keys`. No group membership is involved; `is-enrolled`
//! answers `enrolled` as soon as the marker exists.
//!
//! The marker is a **hint, not authority**; see the module docs in
//! [`crate::commands::is_enrolled`]. Every write is best-effort: a marker that
//! cannot be written must never fail the enrollment (or removal) that produced
//! it.
//!
//! Writes are atomic (temp file + `rename`) so a concurrent read never
//! observes a half-written marker.
```

Change the doc comment on `MARKER_DIR_MODE` (line 45-47) to:

```rust
/// Traversable by everyone, listable by nobody but root — equals
/// [`crate::state_layout::ENROLLED_DIR_MODE`].
```

In the tests, change the three assertions:
- line ~503: `0o710,` → `0o711,` and its message `"marker dir must be group-traversable, not listable, and closed to other"` → `"marker dir must be traversable by all and listable by none"`
- line ~723: `assert_eq!(mode_of(&base), 0o710);` → `0o711`
- line ~893: same → `0o711`

- [ ] **Step 6: `is_enrolled.rs` docs, `auth.rs` comment, unit comment**

`is_enrolled.rs` lines 20-31 — replace with:

```rust
//! # "Enrolled" means "face auth is operational for me"
//!
//! This command answers from the per-user marker file written by
//! [`crate::commands::enrollment_marker`] — never from the database, which is
//! `0600 root:root`. The marker sits under two `0711 root:root` directories,
//! so any local user can open its own `0600` marker by name (ADR 010): one
//! `open(2)` answers the question with no group membership, no daemon and no
//! camera. `EACCES` on that open (a hardened or foreign layout) is reported
//! as not-enrolled rather than as an error — an indicator that fails to show
//! is the safe way to be wrong.
```

`is_enrolled.rs` lines 44-46: change `must never error merely because the caller lacks `facelock` group membership.` to `must never error merely because the marker is unreadable.`

`auth.rs:81-82`: change `// Open a writable store (the oneshot path runs as root or the facelock` / `// group). The rate limiter…` to `// Open a writable store (the oneshot path runs as root). The rate limiter…`.

`systemd/facelock-daemon.service:73-74`: change `chowns /var/lib/facelock (and the files under it) to root:facelock` to `chowns /var/lib/facelock (and the files under it) to root:root, which an install upgraded from the root:facelock layout still needs`.

- [ ] **Step 7: Run tests and clippy**

Run: `cargo test -p facelock-cli 2>&1 | tail -15 && cargo clippy -p facelock-cli -- -D warnings 2>&1 | tail -5`
Expected: all `state_layout` and `enrollment_marker` tests pass; clippy clean (if `Owners`/`Ownership` are referenced anywhere else, the compiler names the site — fix it the same way as `secure_setup_paths`).

- [ ] **Step 8: `docs/contracts.md` — Filesystem Paths, One gate, contract-change history, `is-enrolled` row**

Filesystem Paths table rows — replace:

```markdown
| `/var/lib/facelock/` | root:root | 711 | State dir. Traversable by every local user, listable by root only: anyone can open a path it knows by name (its own enrollment marker, a model file) but nobody can enumerate what is there |
| `/var/lib/facelock/facelock.db` | root:root | 600 | Face embeddings. Read by the daemon (root) only; user-run PAM stacks request authentication through the daemon, they never read templates |
| `/var/lib/facelock/models/` | root:root | 755 | ONNX models — public, SHA256-verified downloads |
| `/var/lib/facelock/enrolled/` | root:root | 711 | Enrollment markers; traversable by all, listable by none |
```

Replace the whole `#### One gate at the top` subsection with:

```markdown
#### Traversal for everyone, listing for nobody (ADR 010)

The state directory and `enrolled/` are `0711 root:root`: any local user may
*enter* them, nobody but root may *list* them. That is the whole grant. Every
entry below is locked down in its own right — `0600 root:root` database and
sidecars, `0600 <user>:<user>` markers — and `models/` is the one subtree that
carries "other" read bits of its own, because its contents are public,
SHA256-verified downloads. There is no group in the file contract: the
`facelock` group owns nothing under `/var/lib/facelock` and reads nothing
there that any other user cannot.

D-Bus is required for user-run screen lockers (hyprlock/swaylock) and the
polkit agent — their PAM stack runs as the user, and nothing makes the `0600
root:root` database or encryption key readable to them — and the bus admits
their `Authenticate` call without any group (see IPC Protocol). Root-invoked
PAM (`sudo`, `login`, `sshd`) can also use the oneshot fallback, which reads
the files directly as root.

Known residual: any local user can `stat` a path it can guess by name —
`facelock.db` (size, mtime) or `enrolled/<user>` (existence) — because
traversal permits exactly that. Closing it would mean denying the traversal
that `is-enrolled` and model loading depend on. Accepted; before ADR 010 the
same residual existed for `facelock` group members.
```

Under `#### Contract change: permissions tightened (no paths moved)`, keep the existing table and paragraph, then append a second block:

```markdown
#### Contract change: traversal opened to every local user (ADR 010)

No paths move. The two directories that carried a group grant drop it:

| Path | Was | Now |
|------|-----|-----|
| `/var/lib/facelock/` | 710 root:facelock | 711 root:root |
| `/var/lib/facelock/enrolled/` | 710 root:facelock | 711 root:root |

Everything else in the table above is unchanged. For an existing install the
on-disk change is a `chmod`/`chown` of those two directories — idempotent,
applied by packaging (tmpfiles, install scriptlets) and re-applied by any root
invocation of the binary (`ensure_state_layout` on daemon start, best-effort on
the auth path). Existing `facelock` group memberships are left alone; they
grant nothing on the auth path any more and may be removed with
`sudo gpasswd -d <user> facelock`.
```

CLI table row 60 — replace with:

```markdown
| `facelock is-enrolled` | Report whether face auth is operational for a user. Exit code is the contract; no daemon activation, no camera, no group membership: it opens the caller's own `0600` marker under `0711` directories (ADR 010) |
```

- [ ] **Step 9: `docs/security.md` § 2 B, § 3 A2, guard-test paragraph, § 3 A3; `book/src/security.md:92`**

§ 2 B paragraph (around line 339-343) — replace:

```markdown
The model files are public, SHA-256-verified downloads, so their own modes are
permissive; see `docs/contracts.md` § *Traversal for everyone, listing for
nobody*. What the modes here must guarantee is only that nobody but root can
**write** them.
```

§ 3 A2 heading and body (from `#### A2. One Gate at the Top` through the "Known residual" bullet) — replace with:

```markdown
#### A2. Traversal for Everyone, Listing for Nobody (`/var/lib/facelock` is 0711)

```
/var/lib/facelock/            0711 root:root       traverse-only, NOT listable
  facelock.db                 0600 root:root
  facelock.db-wal / -shm      0600 root:root
  models/                     0755 root:root       public, SHA-256 verified
  enrolled/                   0711 root:root       markers only
    <user>                    0600 <user>:<user>

/var/log/facelock/            0700 root:root
  audit.jsonl                 0600 root:root
  snapshots/                  0700 root:root
```

The state directory grants every local user traversal (`--x`) and nobody but
root listing (no `r` for group or other). Anyone can `open()` a path it
already knows by name — its own `enrolled/<user>` marker, a model file — and
nobody can `readdir` the directory, read the `0600 root:root` database, or
reach the audit log or snapshots. Every secret is protected by its own mode;
the directory protects only *what is there* from enumeration. There is no
group grant (ADR 010): the `facelock` group owns nothing here.

Two consequences worth stating explicitly:

- **D-Bus is required for user-run screen lockers** (hyprlock/swaylock) and
  the polkit agent. Their PAM stack runs as the user, and nothing makes the
  database or the `0600 root:root` encryption key readable to them, so the
  daemon is the only path — and the bus admits their `Authenticate` without a
  group (§ 4 A). Root-invoked PAM (`sudo`, `login`, `sshd`) additionally has
  the oneshot fallback, which reads the files directly as root.
- **Known residual**: any local user can `stat` a name it can guess —
  `facelock.db` (size, mtime), `enrolled/<user>` (existence) — because
  traversal permits exactly that. Closing it would mean denying the traversal
  that `is-enrolled` and model loading depend on. Accepted; before ADR 010 the
  same residual existed for group members.
```

Guard-test paragraph — replace with:

```markdown
**The enforcement mechanism is a guard test, not this document.** The test in
`crates/facelock-cli/src/state_layout.rs` walks every entry under the state
directory and asserts that no file carries any "other" bit and no directory
carries "other" read or write — traversal is the only thing granted — with
`models/` (public data) as the single allowed exception. A future change that
drops a world-readable file into the state directory fails that test with a
message that explains the rule.
```

§ 3 A3 — replace the heading and the first paragraph and the bullet list with:

```markdown
#### A3. Enrollment Markers (`/var/lib/facelock/enrolled` is 0711)

`facelock is-enrolled` must not activate the daemon or open a camera — it runs
repeatedly on the lock screen. It answers from a marker file rather than from
the database, and *"enrolled"* means **"face auth is operational for me"**:
the caller opens its own `0600` marker by name through two `0711 root:root`
directories. No group membership is involved (ADR 010): the answer is
`enrolled` the moment enrollment writes the marker.

```
/var/lib/facelock/enrolled/          0711 root:root
/var/lib/facelock/enrolled/<user>    0600 <user>:<user>
```

- **`0711` on the directory** permits traversal to a known filename but not
  `readdir`, so which accounts have face auth enrolled is not listable.
- **`0600` owned by the user** means "am I enrolled?" is answerable by that
  user and by nobody else — the same privacy property as
  `~/.ssh/authorized_keys`.
- `EACCES` and `ENOENT` are both reported as not-enrolled, never as an error.
  An indicator that fails to show is the safe way to be wrong.
```

`book/src/security.md:92`: change the comment `# Database owned by root, readable only by root and facelock group` to `# Database owned by root, readable by root only`.

- [ ] **Step 10: Commit**

```bash
git add crates/facelock-cli/src/state_layout.rs crates/facelock-cli/src/commands/setup.rs \
  crates/facelock-cli/src/commands/enrollment_marker.rs crates/facelock-cli/src/commands/is_enrolled.rs \
  crates/facelock-cli/src/commands/auth.rs systemd/facelock-daemon.service \
  docs/contracts.md docs/security.md book/src/security.md
git commit -m "feat(layout): state and enrolled dirs become 0711 root:root, no group grant"
```

---

### Task 3: Packaging fragments and the layout container test

**Dispatch:** builder, `model: "opus"`, lane A worktree `~/Code/facelock/.worktrees/adr010-a`, branch `adr010/layout` (on top of Task 2's commit). **After it reports:** rungs 1–3 and rung 5 (`just -d … -f …/justfile test-arch-layout`) yourself; the layout tier is the judge for this task. Lane A is done when it is green.

**Files:**
- Modify: `dist/facelock.tmpfiles`, `dist/facelock.install`, `dist/debian/postinst`, `dist/openrc/facelock-daemon`, `dist/nix/module.nix`, `dist/facelock.sysusers`
- Modify: `justfile:80-86, 97-101`
- Rewrite: `test/run-layout-tests.sh`

- [ ] **Step 1: Rewrite `test/run-layout-tests.sh` (the failing test)**

Replace the file with:

```bash
#!/bin/bash
# State-layout conformance tests (camera-free).
#
# Asserts the exact on-disk contract from docs/contracts.md (ADR 010):
#
#   /var/lib/facelock/       0711 root:root    traverse-only, not listable
#     facelock.db            0600 root:root
#     facelock.db-wal/-shm   0600 root:root
#     models/                0755 root:root    public, SHA256-verified
#     enrolled/              0711 root:root
#       <user>               0600 <user>:<user>
#   /var/log/facelock/       0700 root:root
#     snapshots/             0700 root:root
#
# The image is built with `just install-files`, so this is the one place the
# packaging wiring (install recipe + built-in defaults) is exercised end to
# end. It also asserts the semantics the modes exist for: any local user —
# no group membership — can traverse to a marker it knows by name but cannot
# list the state directory or read the database.
set -uo pipefail

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    local expected_result="${3:-0}"

    echo -n "TEST: $name ... "
    # Run command without pipefail so piped greps work correctly
    if bash -c "$cmd" > /tmp/test-output 2>&1; then
        result=0
    else
        result=$?
    fi

    if [ "$expected_result" = "any" ] || [ "$result" -eq "$expected_result" ]; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (exit=$result, expected=$expected_result)"
        cat /tmp/test-output
        FAIL=$((FAIL + 1))
    fi
}

# stat-based assertion: mode owner group, e.g. assert_path /var/lib/facelock 711 root root
assert_path() {
    local path="$1" mode="$2" owner="$3" group="$4"
    run_test "$path is $mode $owner:$group" \
        "[ \"\$(stat -c '%a %U %G' $path)\" = '$mode $owner $group' ]" \
        0
}

echo "=== Facelock state-layout tests ==="
echo ""

# ---------------------------------------------------------------------------
# The static layout, as `just install-files` shipped it
# ---------------------------------------------------------------------------

assert_path /var/lib/facelock          711 root root
assert_path /var/lib/facelock/models   755 root root
assert_path /var/lib/facelock/enrolled 711 root root
assert_path /var/log/facelock          700 root root
assert_path /var/log/facelock/snapshots 700 root root

# ---------------------------------------------------------------------------
# The binary converges an older install back onto the layout
# ---------------------------------------------------------------------------

# Simulate the pre-ADR-010 layout (0710 root:facelock, group-readable
# database) plus a wide-open state dir.
install -m 640 -o root -g facelock /dev/null /var/lib/facelock/facelock.db
chown root:facelock /var/lib/facelock /var/lib/facelock/enrolled
chmod 710 /var/lib/facelock/enrolled
chmod 755 /var/lib/facelock

# Any root invocation that touches the store applies the layout first; `list`
# is the cheapest one that needs no camera. Its own exit code is irrelevant
# here (the seeded database is empty).
facelock list --user testuser > /dev/null 2>&1 || true

assert_path /var/lib/facelock             711 root root
assert_path /var/lib/facelock/enrolled    711 root root
assert_path /var/lib/facelock/facelock.db 600 root root

# ---------------------------------------------------------------------------
# Nothing under the state directory is readable or listable by "other"
# ---------------------------------------------------------------------------

# Files carry no "other" bits; directories carry at most traverse (o+x).
# models/ is the single subtree allowed to carry "other" bits of its own
# (public data).
run_test "no file under the state dir is other-accessible (models/ excepted)" \
    "[ -z \"\$(find /var/lib/facelock -mindepth 1 -path /var/lib/facelock/models -prune -o -type f -perm /o+rwx -print)\" ]" \
    0

run_test "no directory under the state dir is other-readable or -writable (models/ excepted)" \
    "[ -z \"\$(find /var/lib/facelock -mindepth 1 -path /var/lib/facelock/models -prune -o -type d -perm /o+rw -print)\" ]" \
    0

run_test "the state dir grants 'other' traversal only" \
    "[ \$(( 0\$(stat -c '%a' /var/lib/facelock) & 07 )) -eq 1 ]" \
    0

run_test "the state dir grants group traversal only (no listing)" \
    "[ \$(( 0\$(stat -c '%a' /var/lib/facelock) & 070 )) -eq 010 ]" \
    0

# ---------------------------------------------------------------------------
# Semantics for a plain local user: traverse by name, list nothing, read no
# secret. `outsider` is deliberately NOT in the facelock group (ADR 010).
# ---------------------------------------------------------------------------

useradd -m outsider

# A marker for outsider, as enrollment would write it.
install -m 600 -o outsider -g outsider /dev/null /var/lib/facelock/enrolled/outsider
echo '{"models":2,"updated":"2026-08-13T00:00:00Z"}' > /var/lib/facelock/enrolled/outsider
# And one for testuser, which outsider must not be able to read.
install -m 600 -o testuser -g testuser /dev/null /var/lib/facelock/enrolled/testuser
echo '{"models":1,"updated":"2026-08-13T00:00:00Z"}' > /var/lib/facelock/enrolled/testuser

run_test "non-member reads own marker through 0711 dirs" \
    "runuser -u outsider -- cat /var/lib/facelock/enrolled/outsider" \
    0

run_test "non-member cannot read another user's marker" \
    "runuser -u outsider -- cat /var/lib/facelock/enrolled/testuser" \
    1

run_test "non-member cannot list the state dir" \
    "runuser -u outsider -- ls /var/lib/facelock" \
    2

run_test "non-member cannot list enrolled/" \
    "runuser -u outsider -- ls /var/lib/facelock/enrolled" \
    2

run_test "non-member cannot read the database" \
    "runuser -u outsider -- cat /var/lib/facelock/facelock.db" \
    1

run_test "non-member can read a model file by name" \
    "touch /var/lib/facelock/models/probe.onnx && chmod 644 /var/lib/facelock/models/probe.onnx && runuser -u outsider -- cat /var/lib/facelock/models/probe.onnx && rm /var/lib/facelock/models/probe.onnx" \
    0

run_test "non-member cannot read the audit log directory" \
    "runuser -u outsider -- ls /var/log/facelock" \
    2

# Group membership buys nothing on disk: same answers for a member.
usermod -aG facelock testuser
run_test "group member cannot list the state dir either" \
    "runuser -u testuser -- ls /var/lib/facelock" \
    2
run_test "group member cannot read the database either" \
    "runuser -u testuser -- cat /var/lib/facelock/facelock.db" \
    1

# ---------------------------------------------------------------------------
# is-enrolled answers from the marker, for any local user
# ---------------------------------------------------------------------------

run_test "is-enrolled exits 0 for an enrolled non-member" \
    "runuser -u outsider -- facelock is-enrolled" \
    0

run_test "is-enrolled --json reports the model count for a non-member" \
    "runuser -u outsider -- facelock is-enrolled --json | grep -q '\"models\":2'" \
    0

useradd -m nobody-enrolled
run_test "is-enrolled exits 1 for a user with no marker" \
    "runuser -u nobody-enrolled -- facelock is-enrolled" \
    1

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
```

- [ ] **Step 2: Run the layout tier to see it fail against the old packaging**

Run: `just test-arch-layout 2>&1 | tail -40`
Expected: FAIL on `/var/lib/facelock is 711 root:root` (image still installs `0710 root:facelock`).

- [ ] **Step 3: `dist/facelock.tmpfiles`**

Replace the state-directory and enrolled blocks so the file reads:

```
# Runtime directory for facelock daemon
d /run/facelock 0755 root facelock -

# State directory (biometric data - restricted).
# 0711 root:root = traversable by every local user, listable by nobody but
# root (ADR 010). Anyone can open a path it knows by name — its own
# enrolled/<user> marker, a model file — and nobody can enumerate what is
# there. Every secret below carries its own 0600 mode. No group grant.
# Parent must come before its children.
d /var/lib/facelock 0711 root root -

# ONNX models. Public downloads, SHA256-verified at load.
d /var/lib/facelock/models 0755 root root -

# Enrollment markers for `facelock is-enrolled`, and nothing else.
# 0711 root:root: a user can open its own 0600 marker by name but cannot
# enumerate who else is enrolled.
d /var/lib/facelock/enrolled 0711 root root -

# The database and its WAL sidecars hold encrypted biometric templates and are
# read by the daemon (root) only. `z` adjusts an existing file and never
# creates one, so these are no-ops on a fresh install and tighten an upgraded
# one (pre-0710 layouts shipped the database group-readable at 0640).
z /var/lib/facelock/facelock.db 0600 root root -
z /var/lib/facelock/facelock.db-wal 0600 root root -
z /var/lib/facelock/facelock.db-shm 0600 root root -

# Log directory. The audit log holds per-user auth history and snapshots hold
# raw face images — both root-only, strictly more sensitive than the encrypted
# templates.
d /var/log/facelock 0700 root root -
d /var/log/facelock/snapshots 0700 root root -
z /var/log/facelock/audit.jsonl 0600 root root -
```

- [ ] **Step 4: `dist/facelock.install`**

In `_facelock_secure_paths`, replace the first three comment/command groups with:

```sh
    # State dir: traversable by everyone, listable by root only (ADR 010).
    chown root:root /var/lib/facelock 2>/dev/null || true
    chmod 711 /var/lib/facelock 2>/dev/null || true
    # Models are public, SHA256-verified downloads.
    chown root:root /var/lib/facelock/models 2>/dev/null || true
    chmod 755 /var/lib/facelock/models 2>/dev/null || true
    # `facelock is-enrolled` marker dir: traversable by all, listable by none.
    install -d -o root -g root -m 0711 /var/lib/facelock/enrolled 2>/dev/null || true
    chown root:root /var/lib/facelock/enrolled 2>/dev/null || true
    chmod 711 /var/lib/facelock/enrolled 2>/dev/null || true
```

(`install -d` on an existing directory does not reliably re-apply owner/mode; the explicit `chown`/`chmod` after it does.)

In both `post_install()` and `post_upgrade()`, after `_facelock_secure_paths`, add:

```sh
    # The bus policy may have changed (ADR 010). Both dbus-daemon and
    # dbus-broker watch the policy directory, but a running lock screen may
    # call Authenticate before they notice — ask explicitly, best-effort.
    dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
        /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig 2>/dev/null || true
```

- [ ] **Step 5: `dist/debian/postinst`**

Replace the corresponding lines:

```sh
        # State dir: traversable by everyone, listable by root only (ADR 010).
        chown root:root /var/lib/facelock 2>/dev/null || true
        chmod 711 /var/lib/facelock 2>/dev/null || true
        # Models are public, SHA256-verified downloads.
        chown root:root /var/lib/facelock/models 2>/dev/null || true
        chmod 755 /var/lib/facelock/models 2>/dev/null || true
        # `facelock is-enrolled` marker dir: traversable by all, listable by none.
        install -d -o root -g root -m 0711 /var/lib/facelock/enrolled 2>/dev/null || true
        chown root:root /var/lib/facelock/enrolled 2>/dev/null || true
        chmod 711 /var/lib/facelock/enrolled 2>/dev/null || true
```

and after the `systemctl daemon-reload` block add:

```sh
        # Bus policy may have changed (ADR 010); ask the bus to re-read it.
        dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
            /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig 2>/dev/null || true
```

- [ ] **Step 6: `dist/openrc/facelock-daemon`, `dist/nix/module.nix`, `dist/facelock.sysusers`, `dist/facelock.spec`**

OpenRC `start_pre` — replace the two `checkpath` lines and comments:

```sh
    # checkpath does not create parents, so the state dir comes first.
    # 0711 root:root: traversable by everyone, listable by root only (ADR 010).
    checkpath --directory --owner root:root --mode 0711 /var/lib/facelock
    # Models are public, SHA256-verified downloads.
    checkpath --directory --owner root:root --mode 0755 /var/lib/facelock/models
    # `facelock is-enrolled` markers: traversable by all, listable by none.
    checkpath --directory --owner root:root --mode 0711 /var/lib/facelock/enrolled
```

Nix `systemd.tmpfiles.rules` — replace the three commented lines and their rules:

```nix
      # 0711 root:root = traversable by everyone, listable by root only
      # (ADR 010). Parent must come before its children.
      "d /var/lib/facelock 0711 root root -"
      # Public, SHA256-verified downloads.
      "d /var/lib/facelock/models 0755 root root -"
      # Markers only: a user can open its own 0600 marker by name but cannot
      # enumerate who else is enrolled.
      "d /var/lib/facelock/enrolled 0711 root root -"
```

Nix `# Create facelock group` comment → `# The facelock system group: the bus policy names it (members may receive AuthAttempted signals); it grants nothing on the auth path (ADR 010).`

`dist/facelock.sysusers` — replace the comment line:

```
# facelock system group. Named by the D-Bus policy (members may receive the
# daemon's AuthAttempted signals); grants nothing on the auth path (ADR 010).
g facelock -
```

`dist/facelock.spec` `%post` — after `%tmpfiles_create_compat dist/facelock.tmpfiles` add:

```
# Bus policy may have changed (ADR 010); ask the bus to re-read it.
dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig 2>/dev/null || true
```

- [ ] **Step 7: `justfile` comments**

Lines 80-85 (`test-arch-layout` comment) — replace with:

```
# Automated state-layout test (Arch container, camera-free).
# Asserts the exact modes and ownership of everything under /var/lib/facelock
# and /var/log/facelock, including that any local user can traverse to its own
# enrollment marker but list nothing and read no secret. This is the only test
# that exercises the packaging wiring (install-files modes + the built-in
# defaults) end to end — unit tests cannot.
```

Lines 97-101 (link-models note) — replace `The models are 0644 under a 0755 dir, so reading them needs no sudo — but /var/lib/facelock itself is 0710 root:facelock, so getting in needs the facelock group (or root).` with `The models are 0644 under a 0755 dir behind a 0711 state dir, so reading them by name needs no sudo and no group.`

- [ ] **Step 8: Run the layout tier**

Run: `just test-arch-layout 2>&1 | tail -40`
Expected: `=== Results: N passed, 0 failed ===`.

- [ ] **Step 9: Commit**

```bash
git add dist/facelock.tmpfiles dist/facelock.install dist/debian/postinst dist/openrc/facelock-daemon \
  dist/nix/module.nix dist/facelock.sysusers dist/facelock.spec justfile test/run-layout-tests.sh
git commit -m "build(dist): ship the 0711 root:root state layout and reload the bus policy on upgrade"
```

---

### Task 4: Bus policy — `Authenticate` open to the default context

**Dispatch:** builder, **inherit** (no `model`), lane B worktree `~/Code/facelock/.worktrees/adr010-b`, branch `adr010/bus`. Runs in parallel with lane A. Add any caveats from Task 0's `adversarial-validate` verdict to the brief. **After it reports:** rungs 1–3 and rung 6 (`just -d … -f …/justfile test-arch-pam`) yourself; read `dbus/org.facelock.Daemon.conf` and confirm the allow follows the deny and the group block has no `send_destination`. Lane B is done when it is green. Then merge per § 0.6 once lane A is also done.

**Files:**
- Modify: `dbus/org.facelock.Daemon.conf` (whole file)
- Modify: `crates/facelock-cli/src/commands/setup.rs` (`run_systemd`, new `reload_dbus_config`, new test)
- Modify: `crates/facelock-daemon/src/server.rs:452-454` (comment)
- Modify: `test/run-container-tests.sh` (bus started earlier; new block; `ReloadConfig` before peer overlay)
- Modify: `test/run-integration-tests.sh` (new block (d))
- Modify: `docs/security.md` § 4 A and A4; `docs/contracts.md` IPC paragraph and Signals; `AGENTS.md:59`; `README.md:225`; `website/index.html:167`

- [ ] **Step 1: Write the failing policy-shape unit test in `setup.rs`**

Inside the existing `#[cfg(test)] mod tests` of `setup.rs`, add:

```rust
    /// ADR 010: the default context may call exactly `Authenticate`; the
    /// group grants signals only. Pinned on the embedded policy so a "cleanup"
    /// of the XML cannot silently close the lock screen out again or reopen
    /// the whole interface. Order matters — dbus-daemon and dbus-broker apply
    /// the last matching rule in a context — so the allow must follow the
    /// deny.
    #[test]
    fn dbus_policy_opens_authenticate_to_the_default_context_only() {
        let policy = DBUS_POLICY;
        let default_start = policy
            .find(r#"<policy context="default">"#)
            .expect("default context policy");
        let default_end = policy[default_start..]
            .find("</policy>")
            .map(|i| default_start + i)
            .expect("default context closes");
        let default = &policy[default_start..default_end];

        let deny = default
            .find(r#"<deny send_destination="org.facelock.Daemon"/>"#)
            .expect("default context denies the interface");
        assert_eq!(
            default.matches("<allow").count(),
            1,
            "exactly one allow in the default context"
        );
        let allow_start = default.find("<allow").expect("the one allow");
        let allow_end = default[allow_start..]
            .find("/>")
            .map(|i| allow_start + i)
            .expect("allow element closes");
        let allow = &default[allow_start..allow_end];
        assert!(allow_start > deny, "the Authenticate allow must follow the deny");
        for attr in [
            r#"send_destination="org.facelock.Daemon""#,
            r#"send_interface="org.facelock.Daemon""#,
            r#"send_member="Authenticate""#,
        ] {
            assert!(allow.contains(attr), "allow lacks {attr}: {allow}");
        }
        assert!(
            default.contains(r#"<deny receive_sender="org.facelock.Daemon" receive_type="signal"/>"#),
            "signals stay denied to the default context"
        );

        let group_start = policy
            .find(r#"<policy group="facelock">"#)
            .expect("group policy");
        let group_end = policy[group_start..]
            .find("</policy>")
            .map(|i| group_start + i)
            .expect("group policy closes");
        let group = &policy[group_start..group_end];
        assert!(
            !group.contains("send_destination"),
            "the facelock group grants no method calls (ADR 010)"
        );
        assert!(
            group.contains(r#"receive_type="signal""#),
            "the facelock group may receive signals"
        );
    }
```

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test -p facelock-cli dbus_policy_opens_authenticate -- --nocapture 2>&1 | tail -15`
Expected: FAIL at "default context allows Authenticate".

- [ ] **Step 3: Rewrite `dbus/org.facelock.Daemon.conf`**

```xml
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.facelock.Daemon"/>
    <allow send_destination="org.facelock.Daemon"/>
    <allow send_interface="org.facelock.Daemon"/>
    <allow receive_sender="org.facelock.Daemon" receive_type="signal"/>
  </policy>

  <policy context="default">
    <!-- Name-squatting protection: explicit deny so only root (above) may
         own the daemon name, independent of system-wide defaults. -->
    <deny own="org.facelock.Daemon"/>
    <deny send_destination="org.facelock.Daemon"/>
    <!-- ADR 010: the one user-scoped method. Screen lockers and the polkit
         agent run their PAM stack as the user, so any local user may ask the
         daemon to authenticate — the daemon checks that the caller's UID owns
         the username it names (authorize_method) and every other method is
         root-only there too. Last matching rule wins, so this allow must
         follow the deny above. -->
    <allow send_destination="org.facelock.Daemon"
           send_interface="org.facelock.Daemon"
           send_member="Authenticate"/>
    <!-- Auth-attempt signals are not for unprivileged eavesdroppers:
         only root and the facelock group may receive them. -->
    <deny receive_sender="org.facelock.Daemon" receive_type="signal"/>
  </policy>

  <!-- The facelock group grants signal receipt and nothing else. Membership
       is optional and facelock never adds anyone to it (ADR 010). -->
  <policy group="facelock">
    <allow receive_sender="org.facelock.Daemon" receive_type="signal"/>
  </policy>
</busconfig>
```

- [ ] **Step 4: Run the unit test again**

Run: `cargo test -p facelock-cli dbus_policy_opens_authenticate 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: `reload_dbus_config` in `run_systemd`**

In `setup.rs`, next to `run_cmd`, add:

```rust
/// Ask the running system bus to re-read its policy directory.
///
/// dbus-daemon and dbus-broker both watch the directory with inotify, so this
/// is belt and braces for the one window that matters after ADR 010: a lock
/// screen calling `Authenticate` between the policy file changing and the bus
/// noticing. Best-effort — a bus that is not running has nothing to reload,
/// and a missing `dbus-send` is not setup's problem.
fn reload_dbus_config() {
    if let Err(e) = run_cmd(
        "dbus-send",
        &[
            "--system",
            "--type=method_call",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.ReloadConfig",
        ],
    ) {
        tracing::debug!("D-Bus ReloadConfig not sent: {e}");
    }
}
```

In `run_systemd`, immediately after the `refresh_legacy_copy_if_present(Path::new(LEGACY_DBUS_SYSTEM_CONF_PATH), DBUS_POLICY, "org.facelock.Daemon")?;` call, add `reload_dbus_config();`.

- [ ] **Step 6: `server.rs` comment**

Replace lines 452-454:

```rust
/// Who may call a D-Bus method. The bus policy admits root to the whole
/// interface and every local user to `Authenticate` only (ADR 010); this
/// in-daemon check (keyed on the caller UID from `GetConnectionUnixUser`) is
/// the per-method decision, and for `Authenticate` it is the boundary.
```

- [ ] **Step 7: Camera-free container test — bus policy with a root-owned fake daemon**

In `test/run-container-tests.sh`, replace the block that starts at `# (c) Peer-UID check:` and ends just before `run_test "Peer-UID harness: fake non-root daemon replies matched=true"` with:

```bash
# (c) Bus policy (ADR 010): the default context may call Authenticate and
# nothing else; the facelock group grants signals only. A fake daemon owned by
# ROOT stands in for the real one — the real daemon needs a camera to start,
# and the bus enforces the policy regardless of who answers. `outsider` is a
# plain account: not root, not in the facelock group. The daemon-side check
# that a caller may only name its own username has its own unit tests
# (facelock-daemon server.rs) and runs live in the integration tier.
useradd -m outsider 2>/dev/null || true
mkdir -p /run/dbus
dbus-uuidgen --ensure=/etc/machine-id > /dev/null 2>&1 || true
dbus-daemon --system --fork --nopidfile

wait_for_daemon_name() {
    for _ in $(seq 1 40); do
        dbus-send --system --print-reply --dest=org.freedesktop.DBus \
            /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner \
            string:org.facelock.Daemon 2>/dev/null | grep -q 'boolean true' && return 0
        sleep 0.25
    done
    return 1
}

python3 /fake-facelock-daemon.py > /tmp/fake-daemon-root.log 2>&1 &
FAKE_ROOT_PID=$!
wait_for_daemon_name || echo "warning: root fake daemon did not claim the name"

run_test "bus policy: a non-member user may call Authenticate" \
    "runuser -u outsider -- dbus-send --system --print-reply --dest=org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Authenticate string:outsider | grep -q 'boolean true'" \
    0

run_test "bus policy: a non-member user cannot call Ping" \
    "runuser -u outsider -- dbus-send --system --print-reply --dest=org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Ping 2>&1 | grep -q AccessDenied" \
    0

run_test "bus policy: a non-member user cannot call ListModels" \
    "runuser -u outsider -- dbus-send --system --print-reply --dest=org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.ListModels 2>&1 | grep -q AccessDenied" \
    0

usermod -aG facelock testuser
run_test "bus policy: a group member cannot call Ping either (group grants signals only)" \
    "runuser -u testuser -- dbus-send --system --print-reply --dest=org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Ping 2>&1 | grep -q AccessDenied" \
    0

run_test "bus policy: a group member may still call Authenticate" \
    "runuser -u testuser -- dbus-send --system --print-reply --dest=org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Authenticate string:testuser | grep -q 'boolean true'" \
    0

kill "$FAKE_ROOT_PID" 2>/dev/null || true
wait "$FAKE_ROOT_PID" 2>/dev/null || true

# (d) Peer-UID check: a non-root process owning org.facelock.Daemon and
# replying matched=true must never produce PAM_SUCCESS. A deliberately
# loosened bus policy simulates a broken/compromised policy file. The bus is
# already running, so ask it to re-read the policy directory.
cat > /usr/share/dbus-1/system.d/zz-facelock-peer-test.conf <<'EOF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="testuser">
    <allow own="org.facelock.Daemon"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.facelock.Daemon"/>
  </policy>
</busconfig>
EOF
dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig
sleep 1
runuser -u testuser -- python3 /fake-facelock-daemon.py > /tmp/fake-daemon.log 2>&1 &
```

Keep the existing `FAKE_PID=$!` line and everything after it as it is (the wait loop, the two Peer-UID tests, the kill, the `rm -f` of the overlay).

- [ ] **Step 8: Run the camera-free tier**

Run: `just test-arch-pam 2>&1 | tail -30`
Expected: the five new `bus policy:` tests PASS and both Peer-UID tests still PASS; `0 failed`.

If "a group member cannot call Ping" fails with `UnknownMethod` instead of `AccessDenied`, the group grant is still open — re-check Step 3. If the Peer-UID harness fails to own the name, the `ReloadConfig` did not take: add `sleep 2` after it and re-run once; if it still fails, replace the reload with `pkill dbus-daemon; dbus-daemon --system --fork --nopidfile` at that point.

- [ ] **Step 9: Integration tier (camera) — new block (a2); runs in Task 10**

In `test/run-integration-tests.sh`, after the `run_test "Unprivileged user receives no AuthAttempted signal"` test and before `# Policy: the default context explicitly denies owning the daemon name`, add:

```bash
# (a2) ADR 010: Authenticate is open to every local user for its own username
# and nothing else is. sigwatcher is not enrolled and not in the group, so its
# own Authenticate is answered by the enrollment pre-check (model_id -1, or -3
# under suppress_unknown) without opening the camera; naming another user is
# refused by the daemon; Ping is refused by the bus.
run_test_contains "Non-member Authenticate for own user reaches the daemon (no model)" \
    "runuser -u sigwatcher -- dbus-send --system --print-reply --reply-timeout=30000 --dest=org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Authenticate string:sigwatcher" \
    "int32 -[13]"

check_denied_as() {
    # $1 = user, $2 = method, $3.. = dbus-send args
    local user="$1" method="$2"
    shift 2
    local out rc
    set +e
    out=$(runuser -u "$user" -- dbus-send --system --print-reply --reply-timeout=30000 \
        --dest=org.facelock.Daemon /org/facelock/Daemon "org.facelock.Daemon.$method" "$@" 2>&1)
    rc=$?
    set -e
    echo "$out"
    [ "$rc" -ne 0 ] || { echo "$method unexpectedly succeeded for $user"; return 1; }
    echo "$out" | grep -qi "AccessDenied" || return 1
    return 0
}
run_test "Non-member Authenticate for another user is denied by the daemon" \
    "check_denied_as sigwatcher Authenticate string:testuser"
run_test "Non-member Ping is denied by the bus" \
    "check_denied_as sigwatcher Ping"
```

Also update the comment two lines above `useradd -m sigwatcher`:

```bash
# sigwatcher: unprivileged, NOT in the facelock group — a plain local user
# under ADR 010 (may call Authenticate for itself, receives no signals).
# testuser: added to the facelock group (may receive signals; the group grants
# nothing else).
```

- [ ] **Step 10: Docs for the policy**

`docs/security.md` § 4 A — replace the paragraph starting `Access to the daemon is restricted by the D-Bus system bus policy` with:

```markdown
Access to the daemon is governed by the D-Bus system bus policy in
`dbus/org.facelock.Daemon.conf`, installed to `/usr/share/dbus-1/system.d/`
and enforced by the bus itself (dbus-daemon or dbus-broker). Setup and package
install may also refresh a legacy `/etc/dbus-1/system.d/` copy when present,
but `/usr/share/...` is the canonical install path. Three grants (ADR 010):

- **root**: may own the name and send anything on the interface.
- **every local user** (`default` context): may send exactly one method,
  `org.facelock.Daemon.Authenticate`. Screen lockers and the polkit agent run
  their PAM stack as the user, so this is what lets face unlock work with no
  group membership and no re-login. Everything else stays denied at the bus.
- **the `facelock` group**: may receive the daemon's signals. It grants no
  method calls; membership is optional and facelock never adds anyone to it.

Because the bus lets any local user reach `Authenticate`, the in-daemon
per-method check is the boundary for it, not a second layer:
```

(then the existing bullet list `The daemon must also verify the caller UID via GetConnectionUnixUser…` follows — keep it, changing its lead-in sentence to `The daemon verifies the caller UID via `GetConnectionUnixUser` on every method call and applies method-level authorization:`.)

Add after that bullet list, before "The scope table's catch-all arm":

```markdown
What opening `Authenticate` exposes, and why it is acceptable: any local UID
may ask the daemon to authenticate **itself**. An unenrolled UID is answered by
`pre_check` from SQLite (`has_models`) before the camera is opened. An enrolled
UID could already do this — it was in the group. No UID can name another user
(`require_user_authorized`), learn another user's enrollment, or see a
similarity score (redacted for non-root), and every attempt is audited and
rate-limited per user. This is the same shape as fprintd, whose bus policy
admits every user and whose daemon authorizes per call.
```

`docs/security.md` § 4 A4, second bullet — keep as is (`only root and facelock-group members may receive it`); it is still true.

`docs/contracts.md` IPC paragraph (the `Every other method — … — is root only.` bullet) — replace the parenthetical `The bus policy (dbus/org.facelock.Daemon.conf) stays interface-scoped (grants send access to root and the facelock group for the whole interface, so adding a method needs no policy edit); the per-method root/user-scoped decision is the in-daemon check…` with:

```markdown
  The bus policy (`dbus/org.facelock.Daemon.conf`) grants root the whole
  interface and every local user exactly `Authenticate` (ADR 010) — so
  adding a root-only method needs no policy edit, and a future user-scoped
  method needs one deliberately; the `facelock` group grants signal receipt
  only. The per-method root/user-scoped decision is the in-daemon check on
  the caller UID from `GetConnectionUnixUser`, keyed by a table-driven scope
  (`authorize_method` in `facelock_daemon::server`) so a new method is
  root-only by default until deliberately opened up.
```

`AGENTS.md:59` — replace with: `- D-Bus system bus policy: deny-all default; every local user may send `Authenticate` only (daemon checks caller UID == target user), root gets the whole interface, the `facelock` group gets signals only (ADR 010).`

`README.md:225` — replace with: `- D-Bus system bus policy: deny-all default; `Authenticate` open to every local user (daemon-checked UID), everything else root-only`

`website/index.html:167` — replace the `<p>` with: `<p>D-Bus system bus policy restricts daemon access. Any local user may request authentication for itself; the daemon verifies the caller's UID and every other method is root-only.</p>`

- [ ] **Step 11: Verify and commit**

Run: `cargo test -p facelock-cli 2>&1 | tail -5 && cargo clippy --workspace -- -D warnings 2>&1 | tail -3 && just test-arch-pam 2>&1 | tail -5`
Expected: all pass, `0 failed`.

```bash
git add dbus/org.facelock.Daemon.conf crates/facelock-cli/src/commands/setup.rs crates/facelock-daemon/src/server.rs \
  test/run-container-tests.sh test/run-integration-tests.sh docs/security.md docs/contracts.md AGENTS.md README.md website/index.html
git commit -m "feat(dbus): open Authenticate to every local user; group grants signals only"
```

---

### Task 5: Retire group membership in setup and the CLI hint

**Dispatch:** builder, `model: "opus"`, feature worktree `~/Code/facelock/.worktrees/adr010`, branch `feat/adr010-open-authenticate`, after both lanes are merged (§ 0.6) and the post-merge rungs are green. **After it reports:** rungs 1–4 and rung 6 yourself; `grep -rn "usermod\|AccessDeniedGroupHint\|setup_group_membership\|invoking_user\|user_in_group" crates/ justfile` must return nothing.

**Files:**
- Modify: `crates/facelock-cli/src/commands/setup.rs:590-597, 2288-2290, 2406-2478`
- Modify: `crates/facelock-cli/src/message/system.rs`, `message/setup.rs:266-270`, `message/access.rs`
- Modify: `crates/facelock-cli/src/ipc_client.rs:171-203, 444-471`
- Modify: `justfile:452-458`
- Modify: `docs/cli.md:76`, `book/src/cli-reference.md:61,229`, `man/facelock.1:51-53`, `docs/contracts.md:52, 617-631`, `README.md:126`, `docs/troubleshooting.md:200-210`, `book/src/troubleshooting.md:179-186`
- Regenerate: `po/facelock.pot`

- [ ] **Step 1: Write the failing hint tests in `ipc_client.rs`**

Replace `access_denied_fdo_error_gets_group_hint` (line ~444) with:

```rust
    // Covers the locally constructed FDO variant, not the wire path: a denial
    // from the bus or the daemon arrives as `zbus::Error::MethodError`, whose
    // name is checked by `is_access_denied_name` above.
    //
    // ADR 010: a bus-policy denial can only mean a non-root caller reached
    // for a root-only method (every local user may send `Authenticate`), so
    // the hint says root — never "join the group", which grants nothing.
    #[test]
    fn access_denied_bus_policy_denial_gets_root_hint() {
        let err = anyhow::Error::new(zbus::Error::FDO(Box::new(zbus::fdo::Error::AccessDenied(
            "rejected by policy".into(),
        ))))
        .context("D-Bus PreviewFrame call failed");
        let hinted = add_access_denied_hint(err);
        let msg = format!("{hinted:#}");
        assert!(msg.contains("requires root"), "got: {msg}");
        assert!(!msg.contains("usermod"), "got: {msg}");
        assert!(!msg.contains("facelock' group"), "got: {msg}");
    }
```

Keep `access_denied_root_required_gets_root_hint` and `non_access_denied_error_is_unchanged`.

- [ ] **Step 2: Run to see it fail**

Run: `cargo test -p facelock-cli access_denied_bus_policy 2>&1 | tail -8`
Expected: FAIL (`requires root` not present — the group hint is still emitted).

- [ ] **Step 3: Simplify `add_access_denied_hint`**

In `ipc_client.rs`, delete `is_root_required_denial` (lines ~171-179) and replace `add_access_denied_hint` with:

```rust
/// Append an actionable hint to AccessDenied errors.
///
/// Under DEC-6 (root-by-default CLI) every method the CLI calls over D-Bus is
/// root-only, and under ADR 010 the bus itself admits a non-root caller to
/// `Authenticate` alone — so whether the denial came from the daemon's own
/// `require_root` or from the bus policy, the fix is the same: run as root.
/// (Issue #108: telling a root-only rejection to "join the facelock group"
/// was actively wrong even before the group stopped granting method calls.)
fn add_access_denied_hint(err: anyhow::Error) -> anyhow::Error {
    if !is_access_denied(&err) {
        return err;
    }
    // Context strings render on stderr for a human, so they localize (D10);
    // `explain` also emits the machine line the sinks emit, so the hint stays
    // visible in the debug event stream.
    err.context(explain(&AccessMessage::AccessDeniedRootHint))
}
```

- [ ] **Step 4: Remove `AccessDeniedGroupHint`**

In `message/access.rs`: delete the `AccessDeniedGroupHint,` variant, its `localized` arm, and its `samples()` entry; set `VARIANT_COUNT` from `10` to `9`.

- [ ] **Step 5: Replace the setup group step**

In `setup.rs`, replace the whole block from the `// facelock group membership` banner (line ~2406) through the end of `setup_group_membership` (line ~2478) — i.e. delete `invoking_user`, `user_in_group`, `setup_group_membership` — with:

```rust
// ---------------------------------------------------------------------------
// facelock system group
// ---------------------------------------------------------------------------

/// Ensure the `facelock` system group exists. Nobody is added to it.
///
/// Nothing on the auth path needs membership any more (ADR 010): the bus
/// admits `Authenticate` from any local user and the state directory is
/// traversable by everyone. The group survives because the bus policy still
/// names it (members may receive `AuthAttempted` signals) and packaging
/// creates it through sysusers, so a source install should match.
fn ensure_facelock_group() -> anyhow::Result<()> {
    if nix::unistd::Group::from_name("facelock")
        .context("failed to look up facelock group")?
        .is_none()
    {
        Terminal.info(&SystemMessage::CreatingFacelockGroup);
        run_cmd("groupadd", &["-r", "facelock"])?;
    }
    Ok(())
}
```

Wizard call site (line ~590-597) — replace with:

```rust
    // Packaging parity only (ADR 010): the group grants nothing on the auth
    // path, so a failure here is reported, not fatal.
    if let Err(e) = ensure_facelock_group() {
        Terminal.info(&SetupMessage::GroupStepFailed {
            error: e.to_string(),
        });
    }
```

Non-interactive call site (line ~2288-2290) — replace with:

```rust
    // Packaging parity only (ADR 010): the bus policy names the group.
    ensure_facelock_group()?;
```

- [ ] **Step 6: Messages**

`message/system.rs`: delete the variants `GroupMembershipNote`, `AlreadyInGroup { user }`, `ConfirmAddToGroup { user }`, `GroupAddSkipped { user }`, `AddedToGroup { user }` — from the enum, from `localized()`, and from `samples()`; set `VARIANT_COUNT` from `19` to `14`. Keep `CreatingFacelockGroup`. Change the `// -- group membership --` section comment to `// -- the facelock system group --`.

`message/setup.rs:266-270` — replace the `GroupStepFailed` arm's text with:

```rust
            GroupStepFailed { error } => fill(
                translate(
                    "  Could not create the 'facelock' system group: {error}\n  Create it manually: sudo groupadd -r facelock",
                ),
                &[("error", error.clone())],
            ),
```

- [ ] **Step 7: `justfile` `install-files`**

Replace

```
    # Create facelock system group and add the installing user
    getent group facelock >/dev/null || groupadd -r facelock
    REAL_USER="${SUDO_USER:-${DOAS_USER:-}}"
    if [ -n "$REAL_USER" ] && ! id -nG "$REAL_USER" 2>/dev/null | grep -qw facelock; then
        usermod -aG facelock "$REAL_USER"
        echo "Added $REAL_USER to facelock group (log out and back in to take effect)."
    fi
```

with

```
    # Create the facelock system group (packaging parity; the bus policy names
    # it). Nobody is added to it — face unlock needs no membership (ADR 010).
    getent group facelock >/dev/null || groupadd -r facelock
```

- [ ] **Step 8: Build, test, clippy, pot**

Run: `cargo build --workspace 2>&1 | tail -3 && cargo test -p facelock-cli 2>&1 | tail -5 && cargo clippy --workspace -- -D warnings 2>&1 | tail -3`
Expected: clean. If clippy reports an unused import (e.g. `Confirm`) in `setup.rs`, remove it only if nothing else uses it — `wizard_hyprlock_handoff` still does.

Run: `just pot && git status --short po/`
Expected: `po/facelock.pot` modified (the removed strings gone, `GroupStepFailed` text updated).

- [ ] **Step 9: Docs**

`docs/cli.md:76` and `book/src/cli-reference.md:61` — in the `--non-interactive` row replace `directories, model download and verification, encryption, group membership, path permissions.` with `directories, model download and verification, encryption, path permissions.`

`man/facelock.1:51-53` — replace `directories, model download and verification, encryption, group membership and` / `path permissions.` with `directories, model download and verification, encryption and path` / `permissions.`

`book/src/cli-reference.md:229` — replace the bullet with: `- error merely because the caller's marker is unreadable — a missing or unreadable marker reports `not-enrolled`, never an error; no group membership is involved (ADR 010)`

`docs/contracts.md:52` — replace the `facelock setup` row with: `| `facelock setup` | Interactive setup wizard (camera, models, inference device, encryption, enrollment, PAM); creates the `facelock` system group if missing (packaging parity — it grants nothing on the auth path, ADR 010) |`

`docs/contracts.md` C6 paragraph — replace `so a facelock-group member (who lacks root) would confirm` with `so a non-root user would confirm`.

`docs/contracts.md` **AccessDenied hint** paragraph — replace with:

```markdown
**AccessDenied hint.** A D-Bus `AccessDenied` reply carries one actionable
hint (`ipc_client::add_access_denied_hint`): root is required. Since almost
every D-Bus method is root-only (see IPC Protocol below) and, under ADR 010,
the bus admits a non-root caller to `Authenticate` alone, a denial from the
daemon's `require_root` and a denial from the bus policy have the same fix.
The hint never suggests joining the `facelock` group — the group grants no
method calls.
```

`README.md:126` — replace `It answers "enrolled" only when face auth is actually operational for the caller — which includes `facelock` group membership; a caller outside the group reports `not-enrolled` rather than erroring.` with `It answers "enrolled" as soon as the caller's own enrollment marker exists — no group membership, no re-login (ADR 010); an unreadable or missing marker reports `not-enrolled` rather than erroring.`

`docs/troubleshooting.md` — replace the subsection from `### "Permission denied" / "AccessDenied" when running facelock commands` through the code block with:

```markdown
### "Permission denied" / "AccessDenied" when running facelock commands

**Symptom**: `facelock preview`, `facelock test`, `facelock list` or another
command fails with a D-Bus `AccessDenied` error as a normal user (root works
fine).

Every management command is root-only; the CLI offers to re-run itself under
`sudo` on a terminal. Face unlock itself (hyprlock, swaylock, the polkit
agent, `facelock is-enrolled`) needs no group and no re-login: the bus admits
any local user's `Authenticate` for their own account (ADR 010). If a lock
screen still reports `AccessDenied` right after an upgrade, the bus has not
re-read the policy yet — `sudo facelock setup --systemd` rewrites it and asks
for a reload, or reboot.

Membership in the `facelock` group is optional (it only lets a member receive
the daemon's `AuthAttempted` signals) and is safe to drop:
```bash
sudo gpasswd -d $USER facelock
```
```

`book/src/troubleshooting.md:179-186` — replace with the same text as above (both files are separate copies).

- [ ] **Step 10: Commit**

```bash
git add crates/facelock-cli/src/commands/setup.rs crates/facelock-cli/src/message/system.rs \
  crates/facelock-cli/src/message/setup.rs crates/facelock-cli/src/message/access.rs \
  crates/facelock-cli/src/ipc_client.rs justfile po/facelock.pot \
  docs/cli.md book/src/cli-reference.md man/facelock.1 docs/contracts.md README.md \
  docs/troubleshooting.md book/src/troubleshooting.md
git commit -m "refactor(setup): stop adding users to the facelock group; root-only AccessDenied hint"
```

---

### Task 6: CHANGELOG, residual sweep, full verification

**Dispatch:** builder, `model: "opus"`, feature worktree `~/Code/facelock/.worktrees/adr010`, branch `feat/adr010-open-authenticate`. **After it reports:** run the Step 2 sweep and the whole Step 3 ladder yourself — this is the last builder before the review passes, and the ladder result here is the baseline Tasks 7–8 must keep green.

**Files:**
- Modify: `CHANGELOG.md` (Unreleased)
- Verify: everything

- [ ] **Step 1: CHANGELOG**

Under `## [Unreleased]`, add a `### Changed` section (create it if absent; keep it after `### Added`) with:

```markdown
### Changed

- **Face unlock needs no group membership and no re-login** (ADR 010): the
  system-bus policy now admits any local user's `Authenticate` for their own
  account — the daemon already checks that the caller's UID owns the username
  it names, and every other method stays root-only at both the bus and the
  daemon. hyprlock/swaylock/polkit face unlock and the `is-enrolled` face
  icon work the moment enrollment finishes. `/var/lib/facelock` and
  `/var/lib/facelock/enrolled` are `0711 root:root` (traversable by all,
  listable by none; database and markers keep their `0600` modes); the
  `facelock` group grants signal receipt only, `sudo facelock setup` and `just
  install-files` no longer add anyone to it, and the CLI's `AccessDenied` hint
  says "root required" instead of "join the group". Existing memberships are
  harmless. Upgrades converge through tmpfiles, the package scriptlets, and
  the binary's own layout enforcement; the scriptlets and `setup --systemd`
  also ask the bus to reload its policy. Widened residual, accepted: any local
  user can `stat` a name it guesses under the state directory (previously
  group members only).
```

- [ ] **Step 2: Residual sweep**

Run:

```bash
grep -rn "0710\|usermod -aG facelock\|facelock group\|facelock' group\|root:facelock\|group membership\|One gate at the top\|Ownership::\|Owners" \
  --exclude-dir=target --exclude-dir=.git --exclude-dir=.omc . \
  | grep -v "^./CHANGELOG.md\|^./docs/adr/010\|^./docs/superpowers\|^./po/\|^./Cargo.lock"
```

Expected residual (everything else is a miss to fix):
- `docs/contracts.md` — the two "Contract change" history tables (`710 root:facelock` in the *Was* column) and the "Known residual … before ADR 010" sentence
- `docs/security.md` — the "before ADR 010" sentence in § 3 A2
- `dist/facelock.tmpfiles` — the `pre-0710 layouts` comment on the `z` lines
- `test/run-layout-tests.sh` — the "pre-ADR-010 layout" simulation and the two group-member checks
- `test/run-integration-tests.sh` — the `usermod -aG facelock testuser` for the signal test
- `test/run-container-tests.sh` — the `usermod -aG facelock testuser` for the group-member policy checks
- `test/pkg-validate.sh:95` — "facelock group exists (sysusers)"
- `justfile` uninstall message (`gpasswd -d`, `groupdel`)
- `dbus/org.facelock.Daemon.conf` and `docs/security.md` § 4 A / A4 — the group's signal grant
- `docs/troubleshooting.md` / `book/src/troubleshooting.md` — the "optional … `gpasswd -d`" paragraph

- [ ] **Step 3: Full verification**

Run each; all must pass:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
just pot && git diff --exit-code -I '^"POT-Creation-Date: ' po/
just test-arch-pam
just test-arch-layout
just check-pam-standalone
```

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): face unlock without group membership (ADR 010)"
```

The PR is not opened here — Tasks 7 and 8 still change the branch. Task 9 opens it.

---

### Task 7: Architectural simplification pass

**Dispatch (review):** `subagent_type: "ousterhout-reviewer"`, **inherit**, read-only, feature worktree `~/Code/facelock/.worktrees/adr010`. Scope: `git -C ~/Code/facelock/.worktrees/adr010 diff origin/main...HEAD` plus the whole of `crates/facelock-cli/src/state_layout.rs`, the group/`run_systemd` regions of `crates/facelock-cli/src/commands/setup.rs`, `crates/facelock-cli/src/ipc_client.rs` (hint code), `dbus/org.facelock.Daemon.conf`, and the three container test scripts.

**Dispatch (apply):** builder, **inherit**, same worktree, only for findings you accept.

- [ ] **Step 1: Reviewer brief**

Give the reviewer the ADR path and this lens list, and ask for a ranked list — each item `file:line`, the complexity signal, the concrete simpler shape, and whether it changes behaviour:

- `state_layout.rs`: after removing `Ownership`/`Owners`, is `apply_layout(layout, chown_to_root: bool)` the right interface, or should ownership enforcement be decided inside (`Uid::current().is_root()`) with the bool gone? Is `DirSpec` still pulling its weight with one field beside `path`? Is `apply_dir`/`apply_file` duplication worth a shared helper, or clearer as two?
- `setup.rs`: `ensure_facelock_group` is called from two places with different failure handling (wizard reports, non-interactive bails). Justified, or should both bail / both report? Does `reload_dbus_config` belong next to `run_cmd`, or with the D-Bus install block?
- `ipc_client.rs`: with one hint left, does `add_access_denied_hint` + `hinted` + `explain` still earn three layers?
- Message enums: any variant left that is only constructed once and could be inlined without losing the machine event line?
- The container tests: three scripts now each declare an `outsider`/`sigwatcher` user and a `wait_for_…` loop — is a shared helper worth it given they run in different tiers, or is duplication the honest answer?
- The bus policy XML comments: do they explain *why* (ADR 010) without restating what the XML says?
- Any information leak across the `state_layout` ↔ `enrollment_marker` boundary now that both spell `0o711`? (`MARKER_DIR_MODE` aliases `ENROLLED_DIR_MODE` — is the alias still needed?)
- Docs: any paragraph that now says the same thing twice in `docs/security.md` § 3 A2 and § 3 A3, or in `docs/contracts.md` "Traversal for everyone…" and the contract-change block?

Do **not** ask it to review the daemon's `authorize_method` — out of scope.

- [ ] **Step 2: Triage**

Accept a finding only if it (a) removes a concept, a parameter, or a duplicated rule, and (b) keeps every test in the plan meaningful. Reject anything that widens scope (e.g. "also refactor `secure_setup_paths`"). Record accepted/rejected with one line each in the Run log.

- [ ] **Step 3: Apply**

Dispatch a builder (inherit) with the accepted list verbatim. It commits one commit: `refactor(<scope>): simplify after ADR 010 review` (or `polish(...)` if only comments/docs). Then you run rungs 1–3, and rung 5/6 if `state_layout.rs`, `dist/`, `dbus/` or a test script changed.

---

### Task 8: Skeptic pass

**Dispatch (review):** `subagent_type: "skeptical-reviewer"`, **inherit**, read-only, feature worktree. Scope: the ADR and `git -C ~/Code/facelock/.worktrees/adr010 diff origin/main...HEAD`. Its default stance is disbelief; the burden is on the branch.

**Dispatch (apply):** builder, **inherit**, same worktree, only for confirmed findings.

- [ ] **Step 1: Skeptic brief — the claims to attack**

Ask for, per claim: `REFUTED` / `HOLDS` / `HOLDS WITH CAVEAT`, evidence with `file:line` or a command it ran, and confidence. Claims:

1. The `default` context can send **only** `Authenticate`. Attack: any other `<allow` in the default block; `send_interface`-only rules; whether `org.freedesktop.DBus.Introspectable`/`Properties`/`Peer` on the daemon are reachable (they should not be, and nothing in PAM/polkit needs them — verify by reading `crates/pam-facelock/src/lib.rs` `verify_daemon_peer`/proxy code and `crates/facelock-polkit/src/main.rs` `try_face_auth`).
2. Ordering: the allow follows the deny in the same context, and both dbus-daemon and dbus-broker apply last-match-wins within a context. Attack with the dbus-daemon(1) man page semantics and the dbus-broker policy wiki; and check the unit test in `setup.rs` really pins the order.
3. Unique-name addressing: the PAM module pins `Authenticate` to the owner's unique name (`verify_daemon_peer`), and `send_destination="org.facelock.Daemon"` still matches. Attack: find the rule semantics ("names owned by the receiver") in dbus-daemon and dbus-broker; note the same rule shape already served group members before this change (evidence, not proof).
4. Replies to `default`-context callers are delivered (no `<deny receive_…>` for method returns). Attack: read the policy; the signal deny is `receive_type="signal"` only.
5. `pre_check` runs `has_models` before any camera open, so an unenrolled UID's `Authenticate` never touches the camera or the capture slot. Attack: trace `handle_authenticate` in `handler.rs` and `pre_check_with_context` in `auth.rs`; look for any camera warm-up that precedes `pre_check` (ADR 008 warm reuse).
6. `require_user_authorized` denies `Authenticate(other)` for non-root, and resolves the caller by UID, not by any caller-supplied string. Attack: `server.rs` — is `caller.username` derived from `GetConnectionUnixUser` → `getpwuid`, never from the message?
7. Nothing on the auth path still needs the group: PAM daemon path, PAM oneshot path (root), polkit agent, `is-enrolled`, `AuthAttempted` consumers, `facelock status`, Omarchy scripts under `dist/omarchy/`, `just link-models`. Attack with `grep -rn` for group/`0710`/`root:facelock` — the Task 6 sweep list is the expected residual; anything else is a miss.
8. Layout: with `0711` on both dirs, no file under `/var/lib/facelock` except `models/*` is readable by "other", and the daemon-written marker is `0600 <user>:<user>` (chown still happens — `Owners` removal did not drop the marker chown in `enrollment_marker.rs`). Attack: read `write_marker_in` and the daemon's marker reconcile path.
9. Migration: an install at `0710 root:facelock` converges to `0711 root:root` through **each** of: tmpfiles at boot, pacman `post_upgrade`, deb `postinst`, rpm `%post`, OpenRC `start_pre`, `ensure_state_layout` on daemon start, best-effort on `facelock auth`. Attack: `apply_dir` — does it chown when only ownership is wrong and the mode is already right? Does `install -d` on an existing dir apply mode/owner (the plan added explicit `chown`/`chmod` after it — confirm they are there)?
10. The policy reaches the running bus on upgrade: package replaces the file; inotify reload on dbus-daemon and dbus-broker; `ReloadConfig` best-effort in setup and scriptlets. Attack: is `dbus-send` present where the scriptlets run (`|| true` guards it)? Is there a window where hyprlock gets `AccessDenied`, and is it documented (troubleshooting)?
11. `is-enrolled` for a non-member: exit 0 with a marker, exit 1 without, never exit 2 — and it opens exactly one file. Attack: `is_enrolled.rs` error mapping.
12. Nothing here re-opens the hill-climbing oracle: `PreviewDetectFrame`/`TestAuthenticate` stay root-only at both layers; similarity stays redacted for non-root on `Authenticate`. Attack: `authorize_method` scope table and `sanitize`/redaction code paths.
13. Docs: `AGENTS.md`, `docs/security.md` § 4 A, `docs/contracts.md` IPC, and `dbus/org.facelock.Daemon.conf` all describe the same three grants. Attack: read all four and diff the claims.
14. The `!` in the PR title is warranted: name the recorded contracts that changed (`is-enrolled` semantics, bus policy, layout modes) and confirm nothing that parsed before stops parsing.

- [ ] **Step 2: Triage**

`REFUTED` on claims 1–6 or 12 → stop and ask Ty (§ 0.7) unless the fix is a plain implementation bug (then dispatch the apply builder). `REFUTED` on 7–11, 13, 14 → dispatch the apply builder with the finding verbatim. `HOLDS WITH CAVEAT` → decide whether the caveat needs a doc line or a test; if so, include it in the apply brief. Record every verdict in the Run log.

- [ ] **Step 3: Apply and re-verify**

Builder (inherit) commits fixes as `fix(<scope>): …` or `docs(...)`. You run rungs 1–3 and whichever of 4–6 the touched files call for. If a fix touched `dbus/`, `state_layout.rs`, `dist/` or a test script, re-run rungs 5 and 6 in full.

---

### Task 9: Final gates and the single draft PR

**Dispatch:** none for the gates — you invoke the skills yourself in the feature worktree. `pr-writer` opens the PR.

- [ ] **Step 1: Full ladder on the final tree**

In `~/Code/facelock/.worktrees/adr010`:

```bash
git -C . branch --show-current          # feat/adr010-open-authenticate
git -C . status --short                 # clean
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
just pot && git diff --exit-code -I '^"POT-Creation-Date: ' po/
just check
just test-arch-pam
just test-arch-layout
```

- [ ] **Step 2: Security review**

Invoke the `security-review` skill (it reviews the pending changes on the current branch). Anything it raises at high/medium goes to an inherit builder as a fix commit; re-run the affected rungs. Record the outcome in the Run log.

- [ ] **Step 3: Diff review**

Invoke `code-review` at `high` on the branch. Same handling: fix commits for confirmed findings, re-run rungs. Do not `--fix` blind; triage first.

- [ ] **Step 4: Open the draft PR**

```bash
git -C ~/Code/facelock/.worktrees/adr010 push -u origin feat/adr010-open-authenticate
```

Invoke `pr-writer`: **draft**, base `main`, title `feat(dbus)!: open Authenticate to every local user and retire the facelock group grant`. The `!` because `is-enrolled` semantics, the bus policy, and the layout modes are recorded contracts. Body per Ty's rules: bullets, verb-first, lowercase; `Why` in prose ≤ 4 sentences (the ADR's Context compressed); a `Validation` line naming the tiers run (unit, clippy, `test-arch-pam`, `test-arch-layout`, security-review, code-review) and the ones owed to Task 10 — names only, no results, no logs. Link the ADR. Record the PR URL in the Run log. Then remove the lane worktrees (§ 0.6).

---

### Task 10: Camera tiers and host validation (Ty)

These need a camera or the real host bus. Nothing in earlier tasks depends on them; the PR stays draft until they are done. Every `sudo` here is one batched ask.

- [ ] **Step 1: Camera container tiers (from the feature worktree)**

```bash
just test-arch-integration
just test-arch-oneshot
```

Expected: the three new `(a2)` tests pass alongside the existing suite; oneshot tier unchanged.

- [ ] **Step 2: Host install (needs `sudo` — one approval for the batch)**

```bash
just build-release
sudo env PATH="$PATH" just install-files
sudo facelock setup --systemd          # rewrites the policy and asks the bus to reload
```

- [ ] **Step 3: Host checks (dbus-broker is the host bus — this is the broker validation)**

```bash
stat -c '%a %U %G' /var/lib/facelock /var/lib/facelock/enrolled     # 711 root root, twice
# a plain account, not in the group, not enrolled: bus + daemon admit its own Authenticate
sudo runuser -u nobody -- busctl --system call org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Authenticate s nobody
#   expect: (bisd) false -1 "" 0   (or -3 under suppress_unknown) — no camera LED
sudo runuser -u nobody -- busctl --system call org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Authenticate s "$USER"
#   expect: Access denied (daemon: not authorized for user)
sudo runuser -u nobody -- busctl --system call org.facelock.Daemon /org/facelock/Daemon org.facelock.Daemon.Ping
#   expect: Access denied (bus policy)
sudo runuser -u nobody -- facelock is-enrolled; echo "exit=$?"     # exit=1, no EACCES error text
facelock is-enrolled; echo "exit=$?"                                # exit=0 for the enrolled account
```

- [ ] **Step 4: Lock-screen check**

Lock with hyprlock; face unlock must work and the face icon must show — from a session that was **not** re-logged-in after any group change (any existing session qualifies now). If it does not: `journalctl -b -t pam_facelock -n 20` and `busctl --system status org.facelock.Daemon`; an `AccessDenied` there means the running bus still has the old policy — `systemctl reload dbus-broker` (or `dbus`) and retry once, then report.

- [ ] **Step 5: Mark the PR ready**

Only after Steps 1–4 pass. Ty marks PRs ready.

---

## Run log

Fill in as you go. A fresh session resumes from here.

| When | What | Result / sha / verdict |
|---|---|---|
| 2026-08-18 | Baseline `origin/main` sha | 2fd65f0 (plan written at 23908db; symbols unchanged, line numbers drifted); later merged origin/main 7c4b3e9 (#200/#208/#210) into the branch at 7d91ce5 |
| 2026-08-18 | Task 0 `just check` on baseline | exit 0 (plan copy commit b0d165e) |
| 2026-08-18 | Task 0 `adversarial-validate` verdict + confidence | WEAKENED WITH CAVEATS (skill: UNCERTAIN as worded). Parts (a)–(d) each HOLD, high confidence; (d) proven at runtime on dbus-broker 37 and dbus-daemon 1.16.2. Umbrella "loses no protection" false on availability: capture slot is taken before `pre_check`, unenrolled calls are unmetered, `maybe_reload_handler` runs pre-authz. No ADR Decision refuted. Caveats → ADR "New surface" bullet amended (not verbatim), Task 4/5/8 briefs. |
| 2026-08-18 | Task 1 ADR commit | 7f4101b (verbatim except the amended "New surface" bullet) |
| 2026-08-18 | Lane A Task 2 sha + rungs | 1470beb; fmt/clippy/test 0; `state_layout.rs` body verbatim |
| 2026-08-18 | Lane A Task 3 sha + `test-arch-layout` | a82fe69; 24 passed 0 failed. Deviations accepted: `install-files` modes 710→711 root:root (plan gap); `[ … -eq 010 ]` decimal/octal bug in the plan's script fixed with `$(( ))` |
| 2026-08-18 | Lane B Task 4 sha + `test-arch-pam` | f293b3e; 70 passed 0 failed (7 bus-policy tests incl. two unique-name checks from the pre-flight caveats) |
| 2026-08-18 | Merge B, merge A, post-merge rungs | 976e9cf, 7bcd6a3; no conflicts; fmt/clippy/test 0, layout 24/0, pam 70/0 |
| 2026-08-18 | Task 5 sha + rungs + pot | 3dd863a; fmt/clippy/test/pot 0, pot diff clean, pam 70/0; sweep = two negative test assertions only |
| 2026-08-18 | Task 6 sha + sweep residual + ladder | 096931a; 12 misses fixed + `book/src/security.md` three-grants rewrite; residual = accepted list; build/test/clippy/fmt/pot/`check-pam-standalone` 0, pam 70/0, layout 24/0 |
| 2026-08-18 | Task 7 ousterhout findings: accepted / rejected | 8 findings. Accepted: `secure_setup_paths`→`ensure_state_layout_or_bail`; drop `MARKER_DIR_MODE` alias; reuse `wait_for_daemon_name`; merge § 4 A double lead-in; banner rename. Rejected: drop `chown_to_root` bool (fixed decision); single failure policy for `ensure_facelock_group` (behaviour change); § 3 A3 bullet and contracts second block (plan text); `/run/facelock` (scope) |
| 2026-08-18 | Task 7 apply sha | bb28a36; fmt/clippy/test 0, pam 70/0, layout 24/0 |
| 2026-08-18 | Task 8 skeptic verdicts (14 claims) | 1 HOLDS h; 2 HOLDS+CAVEAT h (guard test sliced first default block only); 3 HOLDS h; 4 HOLDS h; 5 HOLDS+CAVEAT h (`maybe_reload_handler` pre-authz undocumented); 6 HOLDS h; 7 HOLDS+CAVEAT h; 8 HOLDS h; 9 HOLDS+CAVEAT m (rpm `%post` tmpfiles macro no-op); 10 HOLDS h; 11 HOLDS h; 12 HOLDS h; 13 HOLDS+CAVEAT m (two stale security.md sentences; audit-rotation amplifier unstated); 14 HOLDS h. None refuted. 7 doc/test/spec fixes accepted |
| 2026-08-18 | Task 8 apply sha | aca0923; then 1efe54e (`%tmpfiles_create_compat` does not exist in systemd-rpm-macros — verified in a fedora container — replaced by `%tmpfiles_create`) |
| 2026-08-18 | Task 9 security-review, code-review outcomes | security-review: no findings ≥0.7. code-review (high): 10 findings; accepted 6 → 1e048b8 (legacy `/etc/dbus-1` copy refresh in scriptlets; `install-files` reload; `.install` helper), 1337671 (`FAKE_OWNER` under `set -e`; non-root `pamtester` through `pam_facelock` vs root fake daemon — passes), f55f463 (probe-by-name residual wording; `/run/facelock` clause). Rejected/deferred: daemon per-UID budget, plan-copy location, `chown_root` into core, `apply_layout` bool, `secure_setup_paths` re-apply, `install -d` belt-and-braces, non-interactive `?`, deb `dbus` Depends. Final ladder at f55f463: fmt/clippy/test/pot/`just check` 0, pam 71/0, layout 24/0 |
| 2026-08-18 | Task 9 PR URL | https://github.com/tyvsmith/facelock/pull/215 (draft) |
| | Task 10 (Ty) camera tiers, host checks, hyprlock | owed |

Open decisions for Ty (append here, do not resolve silently):

- Daemon-side availability margin (pre-flight + skeptic + code-review, all accepted as documented, none applied — daemon change out of plan scope): (i) move `last_activity.store` and `maybe_reload_handler()` below `authorize_method` in `server.rs::run_authentication`, and store the config mtime on the failing-rebuild arm; (ii) take the capture slot after a cheap `has_models`, or add a per-UID token bucket in front of it (an unenrolled UID's `Authenticate` is never charged and can hold the slot in a loop; hyprlock then falls back to the password); (iii) audit rows are written per unmetered call, so a loop can rotate `audit.jsonl` (off by default). Follow-up PR or accept as recorded.
- ADR 010 Consequences "New surface" bullet was amended from the plan's verbatim text (the original "every attempt is audited and rate-limited per user" is false for unenrolled UIDs). Revert or keep.
- `ensure_facelock_group`: wizard reports on failure, `--non-interactive` bails (`?`). Plan-mandated; two reviewers asked for one policy. Keep or unify.
- Plan copy committed under `docs/superpowers/plans/` per Task 0; code-review notes prior convention keeps plans untracked in `.omc/`. Keep in the PR or drop the file.
- `dist/debian/control` has no `dbus` (→ `dbus-bin`) Depends, so the postinst `dbus-send … ReloadConfig` may silently no-op on Debian (guarded by `|| true`; inotify covers it). Add the dependency or leave.
- `dist/facelock.spec` `%pre` `%sysusers_create_compat dist/facelock.sysusers` is `%nil` on current Fedora (rpm handles sysusers.d natively); left alone.
- Authz guard test `interface_methods_and_the_authz_matrix_are_the_same_set` scans `async fn ` only (a `pub async fn` in the `#[interface]` block would be invisible); daemon SSH gate reads the daemon's own environment (dead on the systemd path; PAM enforces client-side); `chown_root` is a third `libc::chown` wrapper in facelock-cli. All pre-existing; follow-ups.
- Group as a per-user off-switch: removing a user from `facelock` no longer disables face unlock for them (troubleshooting says remove their models). Documented; no other per-user disable exists.

---

## Self-review

- **Spec coverage**: ADR Decision 1 → Task 4; Decision 2 → Tasks 2-3; Decision 3 → Task 5; Decision 4 → no code (server.rs tests cited in Global Constraints; skeptic claim 6 re-checks it). Consequences: hint → Task 5; residual → Task 2 docs; upgrade → Task 3 (scriptlets, ReloadConfig) + Task 2 (`ensure_state_layout`), skeptic claims 9–10; CHANGELOG → Task 6.
- **Orchestration coverage**: every task names its agent type, model, worktree and branch; reviewers never write; the pre-flight claim check (Task 0), the simplification pass (Task 7), the skeptic pass (Task 8), and the security/diff reviews (Task 9) each have a brief and a triage rule; the lane merge has an expected-conflict map; there is exactly one PR and it opens in Task 9.
- **Type consistency**: `apply_layout(&StateLayout, bool)` in Task 2 body, Task 2 tests, and `secure_setup_paths`. `ensure_facelock_group()` name used in both call sites. `AccessDeniedRootHint` is the only remaining hint variant. `run_test_contains` and `check_denied_as` match the helpers in `run-integration-tests.sh`. Branch and worktree names match between § 0.2, § 0.6 and every Dispatch block.
- **Placeholders**: none — every code step carries the code, every doc step the text, every review step its brief.
