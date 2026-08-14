//! Parsed vs resolved configuration (D7).
//!
//! Two different questions, two types:
//!
//! - [`ConfigLoad`] — **what the file says.** `main` performs the one read and
//!   parse for the process and hands every command a `&Config`. Commands do
//!   not re-read the file mid-flow; the deliberate exceptions each carry a
//!   comment at their load site (`daemon` reloads on mtime change, `auth` is
//!   its own one-shot process, `setup` bootstraps and edits the file,
//!   `config` displays/edits the file itself, and `is-enrolled` tolerates a
//!   missing config on its unprivileged path).
//!
//! - [`ResolvedConfig`] — **what is actually true.** A config value like
//!   `execution_provider = "cuda"` or `device.path = "/dev/video2"` is a
//!   *claim*; whether CUDA exists in the installed ONNX Runtime or the device
//!   node is present is discovered by an explicit probe, once, instead of
//!   being re-derived ad hoc at each use site. Each fact carries a
//!   [`Provenance`] tag. Resolution is for the heavyweight paths only
//!   (daemon startup, status, enroll, test); lighter commands probe just the
//!   fact they consume.
//!
//! # `is-enrolled` never comes here
//!
//! `is-enrolled` is dispatched in `main` *before* [`ConfigLoad::read`] runs
//! and must never construct any resolution machinery: no bus, no camera, no
//! store, no probes. See the module docs in `commands/is_enrolled.rs`; a
//! source-level pin lives in this module's tests.

use std::path::{Path, PathBuf};

use facelock_core::Config;
use facelock_core::config::ConfigError;
use facelock_face::ProviderKind;

/// The outcome of the process's single config read.
///
/// Carries the failure instead of unwrapping it so `status` can render a
/// broken config file as a finding; every other command goes through
/// [`ConfigLoad::require`], which is the one place load errors are worded.
pub struct ConfigLoad {
    /// The path that was read (after any `--config` override).
    pub path: PathBuf,
    pub result: Result<Config, ConfigError>,
}

impl ConfigLoad {
    /// Read and parse the config file once, from the process's resolved path.
    pub fn read() -> Self {
        Self::read_from(facelock_core::paths::config_path())
    }

    fn read_from(path: PathBuf) -> Self {
        let result = Config::load_from(&path);
        ConfigLoad { path, result }
    }

    /// The parsed config, or the unified load error (D7 item 4): missing file
    /// points at `facelock setup`; a broken file names the path and the parse
    /// error. Every command that needs a config fails through here, so the
    /// wording cannot drift per command.
    pub fn require(self) -> anyhow::Result<Config> {
        match self.result {
            Ok(config) => Ok(config),
            Err(ConfigError::NotFound(_)) => anyhow::bail!(
                "no config file at {} — run 'sudo facelock setup' to create one",
                self.path.display()
            ),
            Err(e) => anyhow::bail!("invalid config at {}: {e}", self.path.display()),
        }
    }

    /// Borrow the config when it parsed; `None` otherwise. For renderers
    /// (`status`) that degrade instead of failing.
    pub fn config(&self) -> Option<&Config> {
        self.result.as_ref().ok()
    }
}

// ---------------------------------------------------------------------------
// ResolvedConfig — what is actually true
// ---------------------------------------------------------------------------

/// How a resolved fact was determined.
///
/// Deliberately minimal: H8 (Health) will grow this into a richer `Fact`
/// type carrying *unknown-is-not-false* across privilege and reachability;
/// until then, a provenance tag per fact is all resolution promises. A
/// daemon-reachability fact slots in beside the existing ones the same way
/// (H6 — Backend owns that probe, not this module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Verified against the live system by this process (file stat, ORT
    /// query).
    Probed,
    /// Taken from the config without verification — a claim, not a checked
    /// fact.
    Claimed,
}

/// A fact plus how it was established.
#[derive(Debug, Clone)]
pub struct Resolved<T> {
    pub value: T,
    pub provenance: Provenance,
}

/// One file the config names, and whether it is on disk.
#[derive(Debug, Clone)]
pub struct ProbedFile {
    pub path: PathBuf,
    pub present: bool,
}

impl ProbedFile {
    fn probe(path: PathBuf) -> Self {
        let present = path.is_file();
        ProbedFile { path, present }
    }
}

/// Presence of the configured detector/embedder ONNX files.
///
/// Presence only, by design: content integrity stays where it already lives —
/// `FaceEngine` verifies SHA256 at load time, and setup's download flow
/// checks hashes as part of its repair loop.
#[derive(Debug, Clone)]
pub struct ModelFiles {
    pub dir: PathBuf,
    pub dir_present: bool,
    pub detector: ProbedFile,
    pub embedder: ProbedFile,
}

impl ModelFiles {
    pub fn probe(config: &Config) -> Resolved<ModelFiles> {
        let dir = PathBuf::from(&config.daemon.model_dir);
        let value = ModelFiles {
            dir_present: dir.is_dir(),
            detector: ProbedFile::probe(dir.join(&config.recognition.detector_model)),
            embedder: ProbedFile::probe(dir.join(&config.recognition.embedder_model)),
            dir,
        };
        Resolved {
            value,
            provenance: Provenance::Probed,
        }
    }

    pub fn all_present(&self) -> bool {
        self.detector.present && self.embedder.present
    }

    /// Paths of the configured model files that are not on disk.
    pub fn missing(&self) -> Vec<&Path> {
        [&self.detector, &self.embedder]
            .into_iter()
            .filter(|f| !f.present)
            .map(|f| f.path.as_path())
            .collect()
    }
}

/// What the config claims about the camera, resolved as far as a presence
/// check can take it.
///
/// Only "does the configured node exist" — which is what `status` and setup
/// were each re-deriving. Full device interrogation (formats, IR
/// classification, quirks, siblings) is the camera domain's job (D8,
/// `direct::resolve_camera_device` and friends) and is *not* duplicated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CameraPresence {
    /// No path configured: detection happens at open time; nothing to probe
    /// yet, so this fact stays a claim.
    AutoDetect,
    Configured {
        path: String,
        present: bool,
    },
}

impl CameraPresence {
    pub fn probe(config: &Config) -> Resolved<CameraPresence> {
        match config.device.path.as_deref() {
            None => Resolved {
                value: CameraPresence::AutoDetect,
                provenance: Provenance::Claimed,
            },
            Some(path) => Resolved {
                value: CameraPresence::Configured {
                    path: path.to_string(),
                    present: Path::new(path).exists(),
                },
                provenance: Provenance::Probed,
            },
        }
    }
}

/// The configured execution provider, resolved against the ONNX Runtime that
/// is actually installed — availability is a property of the ORT *build*, not
/// the hardware (see `facelock_face::detect_execution_provider`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProviderFact {
    pub configured: String,
    pub status: EpStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpStatus {
    /// Not a name the provider registry knows; engine load will fail with the
    /// registry's error naming the valid values.
    UnknownName,
    /// The installed ONNX Runtime can use it (CPU is available by
    /// construction).
    Available,
    /// A valid name, but the installed ORT was not built with it — ORT falls
    /// back to CPU silently at session creation, which is exactly the
    /// misconfiguration this fact exists to surface.
    NotBuiltIn,
    /// The ONNX Runtime shared library could not be loaded or queried.
    Unqueryable(String),
}

impl ExecutionProviderFact {
    /// Probe the installed ONNX Runtime. Loads the ORT shared library unless
    /// the configured provider is `cpu` (or unknown), so call this only on
    /// paths that will load the engine anyway or exist to diagnose (status).
    pub fn probe(config: &Config) -> Resolved<ExecutionProviderFact> {
        let value = Self::status_of(&config.recognition.execution_provider, || {
            facelock_face::detect_execution_provider().map(|d| d.available)
        });
        Resolved {
            value,
            provenance: Provenance::Probed,
        }
    }

    /// The decision rule, split from the ORT query so it is testable without
    /// a GPU-enabled runtime (same shape as `select_by_priority` upstream).
    fn status_of(
        configured: &str,
        detect: impl FnOnce() -> Result<Vec<ProviderKind>, String>,
    ) -> ExecutionProviderFact {
        let status = match ProviderKind::parse(configured) {
            None => EpStatus::UnknownName,
            Some(ProviderKind::Cpu) => EpStatus::Available,
            Some(kind) => match detect() {
                Ok(available) if available.contains(&kind) => EpStatus::Available,
                Ok(_) => EpStatus::NotBuiltIn,
                Err(e) => EpStatus::Unqueryable(e),
            },
        };
        ExecutionProviderFact {
            configured: configured.to_string(),
            status,
        }
    }
}

/// The full resolution pass, for the paths that consume every fact (daemon
/// startup logging, `status`). Commands that need one fact probe it directly.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub models: Resolved<ModelFiles>,
    pub camera: Resolved<CameraPresence>,
    pub execution_provider: Resolved<ExecutionProviderFact>,
}

impl ResolvedConfig {
    pub fn resolve(config: &Config) -> Self {
        ResolvedConfig {
            models: ModelFiles::probe(config),
            camera: CameraPresence::probe(config),
            execution_provider: ExecutionProviderFact::probe(config),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    #[test]
    fn require_on_missing_file_points_at_setup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let err = ConfigLoad::read_from(path.clone()).require().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no config file"), "{msg}");
        assert!(msg.contains("facelock setup"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }

    #[test]
    fn require_on_broken_file_names_path_and_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[device\npath=").unwrap();

        let err = ConfigLoad::read_from(path.clone()).require().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid config"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }

    /// The ownership contract: after the one read, the `Config` value is the
    /// source of truth — commands hold `&Config` and keep working even if the
    /// file disappears, because nothing on their path re-reads it.
    #[test]
    fn parsed_config_outlives_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[storage]\ndb_path = \"/srv/faces/facelock.db\"\n").unwrap();

        let config = ConfigLoad::read_from(path.clone()).require().unwrap();
        fs::remove_file(&path).unwrap();

        assert_eq!(config.storage.db_path, "/srv/faces/facelock.db");
        // A hypothetical re-read would now fail — which is exactly why
        // commands must not perform one.
        assert!(matches!(
            ConfigLoad::read_from(path).result,
            Err(ConfigError::NotFound(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Facts
    // -----------------------------------------------------------------------

    fn config_with(toml: &str) -> Config {
        Config::parse(toml).expect("test config parses")
    }

    #[test]
    fn model_probe_reports_each_file_and_the_missing_set() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("det.onnx"), b"x").unwrap();

        let config = config_with(&format!(
            "[daemon]\nmodel_dir = \"{}\"\n\n[recognition]\n\
             detector_model = \"det.onnx\"\nembedder_model = \"emb.onnx\"\n",
            dir.path().display()
        ));
        let models = ModelFiles::probe(&config);

        assert_eq!(models.provenance, Provenance::Probed);
        assert!(models.value.dir_present);
        assert!(models.value.detector.present);
        assert!(!models.value.embedder.present);
        assert!(!models.value.all_present());
        assert_eq!(
            models.value.missing(),
            vec![dir.path().join("emb.onnx").as_path()]
        );

        fs::write(dir.path().join("emb.onnx"), b"x").unwrap();
        let models = ModelFiles::probe(&config).value;
        assert!(models.all_present());
        assert!(models.missing().is_empty());
    }

    #[test]
    fn model_probe_on_missing_directory_is_all_absent() {
        let config = config_with("[daemon]\nmodel_dir = \"/nonexistent/facelock-test-models\"\n");
        let models = ModelFiles::probe(&config).value;
        assert!(!models.dir_present);
        assert!(!models.all_present());
        assert_eq!(models.missing().len(), 2);
    }

    #[test]
    fn camera_probe_distinguishes_claim_from_probed_presence() {
        // No path: a claim — detection is deferred to open time.
        let auto = CameraPresence::probe(&config_with(""));
        assert_eq!(auto.value, CameraPresence::AutoDetect);
        assert_eq!(auto.provenance, Provenance::Claimed);

        // Configured and present.
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("video9");
        fs::write(&node, b"").unwrap();
        let present = CameraPresence::probe(&config_with(&format!(
            "[device]\npath = \"{}\"\n",
            node.display()
        )));
        assert_eq!(present.provenance, Provenance::Probed);
        assert_eq!(
            present.value,
            CameraPresence::Configured {
                path: node.display().to_string(),
                present: true
            }
        );

        // Configured and absent.
        let absent = CameraPresence::probe(&config_with(
            "[device]\npath = \"/dev/facelock-no-such-video\"\n",
        ));
        assert_eq!(
            absent.value,
            CameraPresence::Configured {
                path: "/dev/facelock-no-such-video".into(),
                present: false
            }
        );
    }

    #[test]
    fn ep_status_unknown_name_never_queries_ort() {
        let fact = ExecutionProviderFact::status_of("tensorrt", || {
            panic!("an unknown name must not trigger an ORT query")
        });
        assert_eq!(fact.status, EpStatus::UnknownName);
    }

    #[test]
    fn ep_status_cpu_is_available_without_querying_ort() {
        let fact =
            ExecutionProviderFact::status_of("cpu", || panic!("cpu must not trigger an ORT query"));
        assert_eq!(fact.status, EpStatus::Available);
    }

    #[test]
    fn ep_status_gpu_resolves_against_the_ort_build() {
        let cuda_in = ExecutionProviderFact::status_of("cuda", || Ok(vec![ProviderKind::Cuda]));
        assert_eq!(cuda_in.status, EpStatus::Available);

        let cuda_out = ExecutionProviderFact::status_of("cuda", || Ok(vec![]));
        assert_eq!(cuda_out.status, EpStatus::NotBuiltIn);

        let rocm_elsewhere =
            ExecutionProviderFact::status_of("rocm", || Ok(vec![ProviderKind::Cuda]));
        assert_eq!(rocm_elsewhere.status, EpStatus::NotBuiltIn);

        let broken = ExecutionProviderFact::status_of("cuda", || Err("no dylib".into()));
        assert_eq!(broken.status, EpStatus::Unqueryable("no dylib".into()));
    }

    // -----------------------------------------------------------------------
    // Structural pins (source scan)
    // -----------------------------------------------------------------------
    //
    // These read the crate's own sources at test time. They are blunt — a
    // token count cannot prove call-graph properties — but they turn "parse
    // once" and "is-enrolled probes nothing" from conventions into failures
    // with a file name attached. Comment lines are ignored so prose may
    // mention the tokens.

    fn source_files() -> Vec<(PathBuf, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(PathBuf, String)>) {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let content = fs::read_to_string(&path).unwrap();
                    out.push((path, content));
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        out
    }

    fn count_code_occurrences(content: &str, needle: &str) -> usize {
        content
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .map(|l| l.matches(needle).count())
            .sum()
    }

    /// Parse-once pin. `Config::load()` (the global-path read) is allowed only
    /// at the sites below, each of which documents why it re-reads. Adding one
    /// anywhere else re-introduces the 29-call-site sprawl D7 removed — route
    /// the command through the `&Config` that `main` already parsed.
    #[test]
    fn config_load_call_sites_are_pinned() {
        let allowed: &[(&str, usize)] = &[
            // One-shot auth process: its own top-of-process parse.
            ("commands/auth.rs", 1),
            // Daemon startup + mtime-triggered reload both go through
            // build_handler.
            ("commands/daemon.rs", 1),
            // is-enrolled's tolerant read: must answer even with no config.
            ("commands/enrollment_marker.rs", 1),
            // Bootstrap: load-or-create-default, in both wizard and
            // non-interactive entry points (2 sites x 2 calls).
            ("commands/setup.rs", 4),
        ];

        // Assembled at runtime so this test's own literals don't count.
        let needle = format!("Config::load{}", "()");
        for (path, content) in source_files() {
            let rel = path
                .to_string_lossy()
                .split("/src/")
                .last()
                .unwrap()
                .to_string();
            let count = count_code_occurrences(&content, &needle);
            let expected = allowed
                .iter()
                .find(|(p, _)| *p == rel)
                .map(|(_, n)| *n)
                .unwrap_or(0);
            assert_eq!(
                count, expected,
                "{rel}: found {count} global-path config read(s) ({needle}), \
                 expected {expected}. Commands receive &Config from main (see \
                 resolved::ConfigLoad); a mid-command re-read is a D7 regression."
            );
        }
    }

    /// `is-enrolled` isolation pin: its module must not name the resolution
    /// machinery or any transport/store entry point. This guarantees only that
    /// the module itself stays clean — indirect calls would need a reviewer —
    /// but every past regression started with one of these tokens appearing
    /// here.
    #[test]
    fn is_enrolled_module_stays_probe_free() {
        let forbidden = [
            "ConfigLoad",
            "ResolvedConfig",
            "resolved::",
            "send_request(",
            "should_use_direct(",
            "open_store",
            "Camera",
        ];
        let (_, content) = source_files()
            .into_iter()
            .find(|(p, _)| p.ends_with("commands/is_enrolled.rs"))
            .expect("is_enrolled.rs must exist");
        for token in forbidden {
            assert_eq!(
                count_code_occurrences(&content, token),
                0,
                "is_enrolled.rs must not reference {token:?} — it is dispatched \
                 before all resolution machinery and probes nothing (domain map §5)"
            );
        }
    }
}
