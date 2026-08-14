use ort::session::builder::SessionBuilder;

/// Paths to search for a system-installed libonnxruntime.so.
/// A GPU-enabled system ORT (e.g. onnxruntime-opt-cuda) is preferred
/// so that GPU execution providers work. The bundled CPU-only ORT
/// is used as a last resort.
const SYSTEM_ORT_PATHS: &[&str] = &[
    "/usr/lib/libonnxruntime.so",
    "/usr/lib64/libonnxruntime.so",
    "/usr/local/lib/libonnxruntime.so",
];

/// Bundled CPU-only ORT fallback, shipped with the facelock package.
/// Debian/Ubuntu use /usr/lib/, Fedora/RHEL use /usr/lib64/ on x86_64.
const BUNDLED_ORT_PATHS: &[&str] = &[
    "/usr/lib/facelock/libonnxruntime.so",
    "/usr/lib64/facelock/libonnxruntime.so",
];

/// Load the ONNX Runtime shared library.
///
/// Search order:
/// 1. `ORT_DYLIB_PATH` env var (explicit override)
/// 2. System paths (may have GPU support)
/// 3. Bundled CPU-only fallback
fn load_ort() -> std::result::Result<(), String> {
    use std::sync::Once;

    static INIT: Once = Once::new();
    let mut init_err: Option<String> = None;

    INIT.call_once(|| {
        // Check ORT_DYLIB_PATH env var first
        if let Ok(path) = std::env::var("ORT_DYLIB_PATH") {
            if std::path::Path::new(&path).exists() {
                if let Err(e) = ort::init_from(std::path::Path::new(&path)) {
                    init_err = Some(format!(
                        "Failed to load ORT from ORT_DYLIB_PATH={path}: {e}"
                    ));
                }
                return;
            }
        }

        // Search system paths (may have GPU support)
        for path_str in SYSTEM_ORT_PATHS {
            let path = std::path::Path::new(path_str);
            if path.exists() {
                match ort::init_from(path) {
                    Ok(_) => {
                        tracing::info!("Loaded system ONNX Runtime from {path_str}");
                        return;
                    }
                    Err(e) => {
                        tracing::warn!("Found {path_str} but failed to load: {e}");
                    }
                }
            }
        }

        // Fall back to bundled CPU-only ORT
        for bundled_path in BUNDLED_ORT_PATHS {
            let bundled = std::path::Path::new(bundled_path);
            if bundled.exists() {
                match ort::init_from(bundled) {
                    Ok(_) => {
                        tracing::info!("Loaded bundled CPU ONNX Runtime from {bundled_path}");
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Found bundled ORT at {bundled_path} but failed to load: {e}"
                        );
                    }
                }
            }
        }

        init_err = Some(
            "Could not find libonnxruntime.so. \
             Ensure the facelock package is installed correctly, \
             or set ORT_DYLIB_PATH to point to a compatible libonnxruntime.so"
                .into(),
        );
    });

    if let Some(e) = init_err {
        Err(e)
    } else {
        Ok(())
    }
}

/// Ensure the ONNX Runtime shared library is loaded before any session builders
/// are created. Some ORT builds can deadlock if session construction re-enters
/// runtime initialization.
pub(crate) fn ensure_runtime_loaded() -> std::result::Result<(), String> {
    load_ort()
}

/// An execution provider facelock knows how to register.
///
/// This enum is the single source of truth for the set of valid provider
/// names. Both `register_execution_provider` (which turns a config string into
/// an ORT session) and `detect_execution_provider` (which picks one for
/// `--execution-provider=auto`) go through it, so the two cannot drift into
/// disagreeing about which names are legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Cpu,
    Cuda,
    Rocm,
    OpenVino,
}

impl ProviderKind {
    /// Every provider, in the order the "valid values" error message lists them.
    ///
    /// Public so user-facing text that enumerates providers can be checked
    /// against it instead of hardcoding a parallel list — see
    /// [`ProviderKind::all_names`].
    pub const ALL: [ProviderKind; 4] = [
        ProviderKind::Cpu,
        ProviderKind::Cuda,
        ProviderKind::Rocm,
        ProviderKind::OpenVino,
    ];

    /// The config-file spellings of every provider, in message order.
    pub fn all_names() -> impl Iterator<Item = &'static str> {
        ProviderKind::ALL.into_iter().map(ProviderKind::as_str)
    }

    /// GPU providers in auto-selection priority order: the first one the
    /// installed ONNX Runtime actually supports wins. CPU is not listed —
    /// it is the fallback, and is always available.
    const AUTO_PRIORITY: [ProviderKind; 3] = [
        ProviderKind::Cuda,
        ProviderKind::Rocm,
        ProviderKind::OpenVino,
    ];

    /// The config-file / CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Cpu => "cpu",
            ProviderKind::Cuda => "cuda",
            ProviderKind::Rocm => "rocm",
            ProviderKind::OpenVino => "openvino",
        }
    }

    /// Parse a config-file / CLI value. `None` for anything unrecognized.
    pub fn parse(name: &str) -> Option<Self> {
        ProviderKind::ALL.into_iter().find(|k| k.as_str() == name)
    }

    /// Whether the loaded ONNX Runtime was *built* with support for this
    /// provider. Answers "could this ORT ever use CUDA", not "will this
    /// specific model run on it" — see `ExecutionProvider::is_available`.
    ///
    /// A load or FFI failure is reported as "not available" rather than an
    /// error: an unavailable provider and an unanswerable question lead to the
    /// same decision, and detection must always be able to fall back to CPU.
    fn is_available(self) -> bool {
        use ort::ep::ExecutionProvider;

        // `ort::api()` panics if the dylib cannot be loaded. `load_ort` uses a
        // `Once`, so a failure on a previous call is not re-reported here.
        // Detection is best-effort by contract, so contain the panic rather
        // than let it escape into the setup wizard.
        std::panic::catch_unwind(|| match self {
            ProviderKind::Cpu => Ok(true),
            ProviderKind::Cuda => ort::ep::CUDA::default().is_available(),
            ProviderKind::Rocm => ort::ep::ROCm::default().is_available(),
            ProviderKind::OpenVino => ort::ep::OpenVINO::default().is_available(),
        })
        .unwrap_or_else(|_| {
            tracing::warn!(
                "ONNX Runtime panicked while querying {} availability",
                self.as_str()
            );
            Ok(false)
        })
        .unwrap_or_else(|e| {
            tracing::warn!("Could not query {} availability: {e}", self.as_str());
            false
        })
    }
}

/// Result of `detect_execution_provider`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDetection {
    /// The chosen provider. Always a value `register_execution_provider` accepts.
    pub provider: ProviderKind,
    /// GPU providers the installed ONNX Runtime reports it was built with,
    /// in priority order. Empty on a CPU-only ORT build.
    pub available: Vec<ProviderKind>,
}

impl ProviderDetection {
    /// One line explaining the choice, suitable for the setup wizard. The
    /// point of `auto` is that a user on a CPU-only ORT learns *why* they got
    /// CPU rather than silently getting it.
    pub fn explain(&self) -> String {
        if self.available.is_empty() {
            "the installed ONNX Runtime has no GPU execution providers compiled in; \
             selecting cpu"
                .to_string()
        } else {
            let names: Vec<&str> = self.available.iter().map(|k| k.as_str()).collect();
            format!(
                "the installed ONNX Runtime supports {}; selecting {}",
                names.join(", "),
                self.provider.as_str()
            )
        }
    }
}

/// Pick a provider from a set of known-available GPU providers.
///
/// Split out from the ORT query so the priority rule (cuda > rocm > openvino >
/// cpu) is testable without a GPU-enabled ONNX Runtime on the test machine.
fn select_by_priority(available: &[ProviderKind]) -> ProviderKind {
    ProviderKind::AUTO_PRIORITY
        .into_iter()
        .find(|k| available.contains(k))
        .unwrap_or(ProviderKind::Cpu)
}

/// Detect the best execution provider the installed ONNX Runtime can use.
///
/// Selection order is cuda > rocm > openvino > cpu. Availability is a property
/// of the *ORT build*, not of the hardware: the bundled CPU-only runtime
/// reports no GPU providers even on a machine with an NVIDIA card, while a
/// system `onnxruntime-opt-cuda` reports CUDA. That is the distinction this
/// exists to make — a driver device node proves nothing about what ORT can do.
///
/// Errors only when the ONNX Runtime shared library cannot be loaded at all,
/// in which case nothing can be queried. Never panics.
pub fn detect_execution_provider() -> std::result::Result<ProviderDetection, String> {
    ensure_runtime_loaded()?;

    let available: Vec<ProviderKind> = ProviderKind::AUTO_PRIORITY
        .into_iter()
        .filter(|k| k.is_available())
        .collect();

    let provider = select_by_priority(&available);
    tracing::info!("Detected execution provider: {}", provider.as_str());
    Ok(ProviderDetection {
        provider,
        available,
    })
}

/// Register an execution provider on the session builder based on config.
///
/// All providers load the ONNX Runtime shared library at runtime.
/// GPU providers (cuda, rocm, openvino) require a system ORT built
/// with the corresponding support — install the appropriate package
/// (e.g. `onnxruntime-opt-cuda`) and it will be picked up automatically.
pub(crate) fn register_execution_provider(
    builder: SessionBuilder,
    provider: &str,
) -> std::result::Result<SessionBuilder, String> {
    load_ort()?;

    let Some(kind) = ProviderKind::parse(provider) else {
        let valid: Vec<&str> = ProviderKind::ALL.iter().map(|k| k.as_str()).collect();
        return Err(format!(
            "Unknown execution provider '{provider}'. Valid values: {}",
            valid.join(", ")
        ));
    };

    tracing::info!("Using execution provider: {provider}");
    match kind {
        ProviderKind::Cpu => Ok(builder),

        ProviderKind::Cuda => builder
            .with_execution_providers([ort::ep::CUDA::default().build()])
            .map_err(|e| format!("CUDA execution provider: {e}")),

        ProviderKind::Rocm => builder
            .with_execution_providers([ort::ep::ROCm::default().build()])
            .map_err(|e| format!("ROCm execution provider: {e}")),

        ProviderKind::OpenVino => builder
            .with_execution_providers([ort::ep::OpenVINO::default().build()])
            .map_err(|e| format!("OpenVINO execution provider: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- priority rule ------------------------------------------------------
    //
    // Pure over a set of available providers, so these run identically on a
    // CPU-only CI box and on a CUDA workstation.

    #[test]
    fn cuda_wins_over_rocm() {
        assert_eq!(
            select_by_priority(&[ProviderKind::Cuda, ProviderKind::Rocm]),
            ProviderKind::Cuda
        );
    }

    #[test]
    fn rocm_wins_over_openvino() {
        assert_eq!(
            select_by_priority(&[ProviderKind::Rocm, ProviderKind::OpenVino]),
            ProviderKind::Rocm
        );
    }

    #[test]
    fn openvino_alone_is_selected() {
        assert_eq!(
            select_by_priority(&[ProviderKind::OpenVino]),
            ProviderKind::OpenVino
        );
    }

    #[test]
    fn nothing_available_falls_back_to_cpu() {
        assert_eq!(select_by_priority(&[]), ProviderKind::Cpu);
    }

    #[test]
    fn everything_available_selects_cuda() {
        assert_eq!(
            select_by_priority(&[
                ProviderKind::Cuda,
                ProviderKind::Rocm,
                ProviderKind::OpenVino
            ]),
            ProviderKind::Cuda
        );
    }

    /// The priority list must not accidentally include CPU: CPU is the
    /// fallback, and listing it would make every other arm unreachable if it
    /// were ever placed first.
    #[test]
    fn auto_priority_is_gpu_only_and_ordered() {
        assert_eq!(
            ProviderKind::AUTO_PRIORITY,
            [
                ProviderKind::Cuda,
                ProviderKind::Rocm,
                ProviderKind::OpenVino
            ]
        );
        assert!(!ProviderKind::AUTO_PRIORITY.contains(&ProviderKind::Cpu));
    }

    // -- name round-trip ----------------------------------------------------

    /// Guards the two lists against drifting: anything detection can select
    /// must parse back to a kind `register_execution_provider` handles.
    #[test]
    fn every_kind_round_trips_through_parse() {
        for kind in ProviderKind::ALL {
            assert_eq!(ProviderKind::parse(kind.as_str()), Some(kind), "{kind:?}");
        }
        // Anything detection can return is one of ALL, by construction of
        // select_by_priority, but assert it over the priority list too.
        for kind in ProviderKind::AUTO_PRIORITY {
            assert!(ProviderKind::ALL.contains(&kind), "{kind:?}");
        }
    }

    #[test]
    fn unknown_provider_names_do_not_parse() {
        for name in ["", "CPU", "gpu", "tensorrt", "cpu "] {
            assert_eq!(ProviderKind::parse(name), None, "{name:?}");
        }
    }

    #[test]
    fn cpu_is_always_a_valid_selection() {
        assert_eq!(ProviderKind::parse("cpu"), Some(ProviderKind::Cpu));
        assert_eq!(select_by_priority(&[]).as_str(), "cpu");
    }

    // -- explanation --------------------------------------------------------

    #[test]
    fn cpu_only_runtime_explains_itself() {
        let detection = ProviderDetection {
            provider: ProviderKind::Cpu,
            available: vec![],
        };
        let msg = detection.explain();
        assert!(msg.contains("no GPU execution providers"), "{msg}");
        assert!(msg.contains("cpu"), "{msg}");
    }

    #[test]
    fn gpu_runtime_names_what_it_found() {
        let detection = ProviderDetection {
            provider: ProviderKind::Cuda,
            available: vec![ProviderKind::Cuda, ProviderKind::Rocm],
        };
        let msg = detection.explain();
        assert!(msg.contains("cuda, rocm"), "{msg}");
        assert!(msg.ends_with("selecting cuda"), "{msg}");
    }

    // -- live detection -----------------------------------------------------

    /// Requires a loadable libonnxruntime.so, which is a packaging artifact
    /// rather than something `cargo test` provides — hence `#[ignore]`, per the
    /// tier-2 hardware-test convention in AGENTS.md. Deliberately asserts only
    /// that the answer is *usable*, never that a specific GPU was found: the
    /// result depends entirely on which ORT build the host has installed.
    #[test]
    #[ignore]
    fn live_detection_returns_a_registerable_provider() {
        let detection = detect_execution_provider().expect("ORT must be loadable");
        // Run with --nocapture to see what this host's ORT actually reports.
        println!("{}", detection.explain());
        assert_eq!(
            ProviderKind::parse(detection.provider.as_str()),
            Some(detection.provider)
        );
        assert!(ProviderKind::ALL.contains(&detection.provider));
        if detection.available.is_empty() {
            assert_eq!(detection.provider, ProviderKind::Cpu);
        } else {
            assert_eq!(detection.provider, detection.available[0]);
        }
    }
}
