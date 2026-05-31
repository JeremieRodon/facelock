# Website marketing refresh — design

Date: 2026-05-30
Scope: `website/index.html` (single file; reuse existing `website/style.css` classes where possible, add minimal new CSS only if required for install tabs)
Out of scope: docs/ rewrites, README rewrite beyond a light wizard-emphasis tweak, any code changes in `crates/`

## Problem

Three concrete problems with the current marketing site, plus a holistic positioning gap:

1. **Hero terminal demo is fabricated.** The shown lines `Frame N/5 detected (confidence: 0.XX)` never appear in the user-facing CLI. Those are internal `tracing::info!` logs that go to journald, not stdout. The real `sudo facelock enroll` prints two lines before the camera capture and three lines after — nothing per-frame. Likewise `facelock test` does not print `Authenticating...` and does not show `latency: 192ms`; it prints `Testing face recognition...`, `Look at the camera.`, and `Matched model #N 'label' (similarity: X.XX) in X.XXs`.

2. **Install section misrepresents the experience.** Shows 6 sequential `sudo` commands (`just install`, `facelock setup`, `enroll`, `test`, `setup --systemd`, `setup --pam`). In reality `sudo facelock setup` is an interactive 9-step wizard that already runs camera selection, model download, encryption, enrollment, recognition test, daemon configuration, and PAM configuration. The flags `--systemd` and `--pam` are escape hatches, not the happy path. Only Arch is shown as a tab even though README documents AUR, APT (tysmith.me repo), COPR (`tyvsmith/facelock`), and a Nix flake (`dist/nix/flake.nix`).

3. **Comparison table is technically detailed but value-blind, and a few Howdy claims are too absolute.** Reads like a feature spec. Doesn't tell a non-expert reader why each row matters. Some claims overstate ("Audit logging: No" — Howdy does emit some syslog, just not structured). Misses the strongest positioning beat: Howdy is in maintenance after a CVE history; Facelock is a fresh, hardened rewrite.

4. **Holistic positioning.** Hero paragraph is four clauses; buries the lead. Security (the strongest persona-aligned differentiator) sits below Features. There is no above-the-fold trust signal row (distros, license, "no telemetry") and no "Who it's for" / use-case framing. Meta description duplicates hero text instead of being SEO-tight.

## Target persona

Security-aware Linux user — likely on Arch, Fedora, NixOS, or Debian/Ubuntu — who wants Windows Hello-style face unlock but refuses telemetry, cloud, and re-skinned dlib. Already comfortable with terminals, systemd, PAM. Likely came from Howdy or rejected Howdy on principle. Cares about TPM, IR enforcement, anti-spoofing, and audit trails — not because they're cool features but because they want to actually deploy this on a daily-driver machine.

## Changes

### 1. Hero terminal demo — replace with truthful wizard + test (Area A)

Replace the fake frame-by-frame block (lines 53–66 of `index.html`) with output that matches the real CLI. Use the wizard summary because it tells the strongest honest story: "one command does everything."

New terminal body content:

```
$ sudo facelock setup
  Facelock v0.1.3
  Linux face authentication

  Detecting camera...
  Auto-selected IR camera: /dev/video2

  Models: standard (SCRFD 2.5G + ArcFace R50)
  Inference: CPU
  Encryption: AES-256-GCM (TPM-sealed key)
  Daemon: enabled (D-Bus activation)
  PAM: sudo, hyprlock
  Face: enrolled

  Setup complete.

$ sudo facelock test
Testing face recognition for user 'ty'...
Look at the camera.
Matched model #1 '2026-05-30-1' (similarity: 0.92) in 0.19s
```

Format rules: every visible line must be a real CLI output. The wizard summary block is taken verbatim from the end of `wizard_run()` in `crates/facelock-cli/src/commands/setup.rs`. The compressed elision (no per-step prompts) is fair compression of a real 9-step wizard, not invention.

### 2. Hero copy + above-the-fold trust signals (part of Area D)

Replace the four-clause hero paragraph (line 38) with:

> **Face unlock for Linux that earns root.**
> IR-enforced anti-spoofing, sub-second daemon auth, optional TPM-sealed encryption. 100% local — your face never leaves the machine.

Add a small "trust signals" row beneath the buttons and above the terminal:

> Arch · Debian/Ubuntu · Fedora · NixOS · MIT/Apache 2.0 · No telemetry

Implementation: a new `<div class="hero-trust">` with inline-styled small text using existing color tokens. No new CSS file changes if possible — use a `style="..."` inline declaration limited to font-size + color + letter-spacing, OR add a single CSS rule to `style.css`. Decision: add one CSS rule to `style.css` for `.hero-trust` to keep the HTML clean.

### 3. Section reorder (Area D)

New order:

1. Hero
2. How It Works (unchanged)
3. **Security** (moved up — was after Features)
4. **Who it's for** (new section — see §5)
5. Features (now reads as "and here's the rest")
6. Privacy (unchanged)
7. Install (rewritten — see §4)
8. Comparison (rewritten intro + per-row benefits — see §6)
9. Footer

Update the nav links list (lines 22–28) to match the new order and add "Use Cases" pointing at the new `#use-cases` anchor.

### 4. Install section rewrite (Area B)

Replace install block (lines 277–319) with a multi-tab block. Tabs in this order:

- **Arch Linux**
- **Debian / Ubuntu**
- **Fedora / RHEL**
- **NixOS**
- **From source**

Each tab contains a single terminal block ending with `sudo facelock setup`. Content per tab:

**Arch Linux**
```
# Install from AUR
$ yay -S facelock          # or: paru -S facelock

# Run the interactive setup wizard
$ sudo facelock setup
```

**Debian / Ubuntu**
```
# Add signing key + repo (modern: Debian trixie+, Ubuntu 25.04+)
$ sudo install -d -m 0755 /etc/apt/keyrings
$ curl -fsSL https://tysmith.me/facelock/apt/tysmith-archive-keyring.gpg \
    | sudo tee /etc/apt/keyrings/tysmith-archive-keyring.gpg >/dev/null
$ echo "deb [signed-by=/etc/apt/keyrings/tysmith-archive-keyring.gpg] \
    https://tysmith.me/facelock/apt main facelock" \
    | sudo tee /etc/apt/sources.list.d/facelock.list

# Install + run setup wizard
$ sudo apt update && sudo apt install facelock
$ sudo facelock setup
```

**Fedora / RHEL**
```
# Enable COPR + install
$ sudo dnf copr enable tyvsmith/facelock
$ sudo dnf install facelock

# Run the interactive setup wizard
$ sudo facelock setup
```

**NixOS**
```
# Add to flake inputs
inputs.facelock.url = "github:tyvsmith/facelock";

# Enable the module in configuration.nix
services.facelock.enable = true;

# Rebuild + run setup wizard
$ sudo nixos-rebuild switch
$ sudo facelock setup
```

**From source**
```
$ just install
$ sudo facelock setup
```

Subtext under the tabbed terminal (replaces the current "Also available as .deb, .rpm, and Nix flake" line):

> `sudo facelock setup` runs an interactive wizard: camera detection, model download (~170 MB), encryption (TPM-sealed when available), face enrollment, recognition test, daemon, and PAM for sudo + your screen locker. No further commands needed for the happy path. See [docs](docs/quickstart.html) for manual control.

JS for tab switching: minimal vanilla `addEventListener('click', …)` inline `<script>` at the end of `<body>`. Reuse existing `.install-tab` and `.install-tab.active` classes; tabs become button-like by adding `role="tab"` and `aria-selected`. Each tab body is a sibling div hidden/shown via a `hidden` attribute or `display:none`. Add a single tiny CSS rule for `.install-tab` cursor:pointer if not already styled.

### 5. New "Who it's for" section (Area D)

Insert a section between Security and Features:

```
<section id="use-cases">
  ...header: "Where Facelock fits"
  ...subtitle: "Three places it pays for itself the first day you install it."
  ...three cards:
    1. Sudo without typing — every `sudo` prompt becomes a glance
    2. Screen lock unlock — Hyprlock, swaylock, KDE Plasma, GNOME Shell (wayland)
    3. Display manager login — GDM/SDDM/LightDM (experimental; see docs)
</section>
```

Reuse the existing `.features-grid` and `.feature-card` styles — no new CSS. Each card gets one of the existing SVG icon styles plus 1–2 lines of plainspoken benefit text.

### 6. Comparison table — accuracy + value (Area C)

**Intro rewrite** (line 328):

> Howdy proved face auth on Linux was possible. Facelock is the production rewrite — Rust, hardened by default, and engineered to be safe to actually deploy.

**Per-row treatment**: add a small `<span class="cmp-why">…</span>` after the row label in the Feature column, holding a one-line "what this gets you" in dim text. Reuse a single new CSS rule for `.cmp-why { display:block; font-size:.85em; color:var(--muted); margin-top:2px; }`.

Examples of benefit lines (full list applied in implementation):

| Feature row label | Benefit subtitle |
|---|---|
| Language: Rust | Memory-safe at compile time; no runtime crashes on bad input. |
| Daemon mode | Auth completes before you finish typing your password. |
| IR enforcement (default on) | Phone screens and printed photos are rejected without configuration. |
| Frame variance check | A still photo can't produce two different frames; rejected automatically. |
| TPM encryption | Even a copied disk image can't decrypt your face data. |
| Model verification (SHA256 every load) | Swapped or tampered models fail to load instead of mis-authenticating. |
| Rate limiting (5/user/60s) | Bricked rapid-retry brute force at the daemon. |
| D-Bus activation | Daemon only runs when something asks for auth — zero idle cost. |
| Constant-time matching | Match scores can't be reconstructed by timing the response. |
| GPU acceleration | Drop auth latency to tens of milliseconds on supported hardware. |
| Audit logging (JSONL + syslog) | Every attempt is grep-able and SIEM-friendly. |
| systemd hardening | Daemon runs without write access to / and without ambient capabilities. |
| PAM module size | Tiny PAM module — no Python runtime in the auth path. |

**Howdy-side accuracy softening**: change two cells that overstate:

- `Audit logging`: was "No" → "syslog only (no structured fields)"
- `IR enforcement`: keep "Not enforced" but the row benefit subtitle now carries the why; this stays accurate (Howdy supports IR but does not enforce it)

All other Howdy cells stay as-is — they are accurate per upstream code.

### 7. README touch-up (minimal)

Inside the existing "Post-Install" block (README.md lines 50–58), tighten the message to match the website's new "one wizard does it all" framing:

> ```bash
> sudo facelock setup       # interactive wizard: camera, models, encryption,
>                           # enrollment, daemon, PAM for sudo + screen lock
> ```
>
> That's it. Open a new terminal and run `sudo echo` to verify face auth fires for sudo.

No structural README changes. The website should not be the only source of truth on the wizard story, hence the small README adjustment.

### 8. SEO meta + share preview

Tighten meta description (lines 7, 9) to match new hero:

> Face unlock for Linux. IR anti-spoofing, sub-second daemon auth, TPM-sealable encryption — 100% local, no telemetry. Drop-in PAM module for sudo, screen lock, and display managers.

## Non-changes (explicit YAGNI)

- No new dark/light theme work.
- No screenshots, no animated GIFs, no video — terminal blocks only.
- No interactive demo, no live wasm playground, no "try it" widget.
- No "blog" or "changelog" surfacing on the marketing page.
- No analytics tags (would directly violate the "no telemetry" claim we make on the page).
- No JS frameworks. Vanilla DOM only, in a `<script>` block ≤30 lines.
- No deletion of the existing How It Works / Privacy sections — they're working.

## Files touched

| File | Type of change |
|---|---|
| `website/index.html` | Replace hero terminal block, hero paragraph, install section; reorder sections; add Use Cases section; rewrite Comparison intro and add per-row benefit subtitles; add ~30 lines of inline tab-switching JS; update nav links; tighten meta description. |
| `website/style.css` | Add three small rules: `.hero-trust`, `.cmp-why`, and any tab-switching styles missing (e.g., cursor, hidden state). Net additions <40 lines. |
| `README.md` | Tighten Post-Install block (~3 lines) to mirror "wizard does everything" framing. |
| `docs/superpowers/specs/2026-05-30-website-marketing-refresh-design.md` | This file. |

## Verification

Manual:
1. Open `website/index.html` in a browser. Confirm:
   - Hero terminal output appears legit and matches `sudo facelock setup` + `sudo facelock test`.
   - Trust signal row renders between buttons and terminal.
   - Nav order matches new section order.
   - Each install tab switches independently and the active tab is visibly highlighted.
   - Comparison rows show benefit subtitles in dim text under each feature label.
2. View source on the meta description; confirm it matches the new tagline.
3. Resize the window to mobile width; confirm install tabs and comparison table still scroll/stack gracefully (existing `.comparison-wrap` handles overflow).
4. Confirm no broken anchors: `#how-it-works`, `#security`, `#use-cases`, `#features`, `#privacy`, `#install`, `#comparison`.

No automated tests for a static marketing site. Acceptable.

## PR description outline

- Title: `docs(website): truthful CLI demo, multi-distro install tabs, comparison reframe`
- Summary:
  - Replace fabricated hero terminal output with real `sudo facelock setup` + `facelock test` output.
  - Add Debian/Ubuntu, Fedora/RHEL, NixOS, and From-source install tabs alongside Arch.
  - Rewrite comparison intro and add per-row "what this gets you" subtitles.
  - Reorder sections, add Who-It's-For block, add trust-signal row, tighten hero.
- Test plan: browser preview, mobile resize check, link/anchor sweep.
