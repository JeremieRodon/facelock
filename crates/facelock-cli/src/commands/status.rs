use std::path::Path;

use facelock_core::Config;
use facelock_core::config::EncryptionMethod;
use facelock_core::ipc::{DaemonRequest, DaemonResponse};

use crate::ipc_client;

pub fn run(loaded: crate::resolved::ConfigLoad) -> anyhow::Result<()> {
    // DEC-6/N4: every D-Bus method `status` calls (`Ping`, and `ListModels`
    // via `check_enrolled`) is root-only now, and its direct-mode reads hit
    // the same 0600 root:root database. Check before the first line of
    // output (C6).
    ipc_client::require_root("sudo facelock status")?;

    println!("facelock system status\n");

    // 1. Config — renders the process's one parse outcome (D7); a broken
    // config file is a finding to report, not an exit.
    check_config(&loaded);
    let config = loaded.config();

    // 2. Daemon
    check_daemon(config);

    // 3. Camera
    check_camera(config);

    // 4. Models
    check_models(config);

    // 5. Inference
    check_inference(config);

    // 6. Encryption
    check_encryption(config);

    // 7. Enrolled faces
    check_enrolled(config);

    // 8. Security
    check_security(config);

    // 9. Notifications
    check_notifications(config);

    // 10. PAM
    check_pam();

    Ok(())
}

fn check_config(loaded: &crate::resolved::ConfigLoad) {
    print_status_item("Config file", &loaded.path.display().to_string());

    match &loaded.result {
        Ok(config) => {
            print_result(true, "valid");
            print_detail(
                "device.path",
                config.device.path.as_deref().unwrap_or("(auto-detect)"),
            );
        }
        Err(facelock_core::config::ConfigError::NotFound(_)) => {
            print_result(false, "not found");
        }
        Err(e) => {
            print_result(false, &format!("invalid: {e}"));
        }
    }
}

fn check_daemon(config: Option<&Config>) {
    let Some(config) = config else {
        print_status_item("Daemon", "");
        print_result(false, "config not loaded, cannot check daemon");
        return;
    };

    print_status_item("Daemon", "org.facelock.Daemon (D-Bus system bus)");

    if config.daemon.mode == facelock_core::config::DaemonMode::Oneshot {
        print_result(true, "oneshot mode (no daemon)");
        return;
    }

    // Try to ping — this may trigger D-Bus activation if the daemon
    // isn't running yet but activation is configured.
    let request = DaemonRequest::Ping;
    match ipc_client::send_request(&request) {
        Ok(DaemonResponse::Ok) => {
            print_result(true, "responding");
        }
        Ok(_) => {
            print_result(true, "connected (unexpected response)");
        }
        Err(e) => {
            print_result(false, &format!("not responding: {e}"));
        }
    }
}

fn check_camera(config: Option<&Config>) {
    let Some(config) = config else {
        print_status_item("Camera", "");
        print_result(false, "config not available");
        return;
    };

    match crate::resolved::CameraPresence::probe(config).value {
        crate::resolved::CameraPresence::Configured { path, present } => {
            print_status_item("Camera device", &path);
            print_result(
                present,
                if present {
                    "device exists"
                } else {
                    "device not found"
                },
            );
        }
        crate::resolved::CameraPresence::AutoDetect => {
            print_status_item("Camera device", "(auto-detect)");
            print_result(true, "auto-detect enabled");
        }
    }
}

fn check_models(config: Option<&Config>) {
    let Some(config) = config else {
        print_status_item("Models", "");
        print_result(false, "config not available");
        return;
    };

    // The configured model files (not just defaults), through the shared
    // probe (D7).
    let models = crate::resolved::ModelFiles::probe(config).value;
    print_status_item("Model directory", &models.dir.display().to_string());

    if !models.dir_present {
        print_result(false, "directory not found");
        return;
    }

    for (purpose, file) in [
        ("detector", &models.detector),
        ("embedder", &models.embedder),
    ] {
        let filename = file.path.file_name().unwrap_or_default().to_string_lossy();
        print_detail(
            &format!("{purpose} ({filename})"),
            if file.present { "present" } else { "MISSING" },
        );
    }

    if models.all_present() {
        print_result(true, "all configured models present");
    } else {
        print_result(false, "some models missing (run 'facelock setup')");
    }
}

fn check_inference(config: Option<&Config>) {
    let Some(config) = config else {
        return;
    };

    // Resolved against the installed ONNX Runtime (D7): the old check listed
    // .so paths — a copy of the provider module's search list that could
    // drift, and one that said nothing about whether the *configured*
    // provider is actually compiled into that runtime.
    let ep = crate::resolved::ExecutionProviderFact::probe(config).value;
    let label = match ep.configured.as_str() {
        "cpu" => "CPU",
        "cuda" => "CUDA (NVIDIA GPU)",
        "rocm" => "ROCm (AMD GPU)",
        "openvino" => "OpenVINO (Intel)",
        other => other,
    };
    print_status_item("Execution provider", label);

    match &ep.status {
        crate::resolved::EpStatus::Available => {
            print_result(true, "supported by the installed ONNX Runtime");
        }
        crate::resolved::EpStatus::NotBuiltIn => {
            print_result(
                false,
                "not built into the installed ONNX Runtime — inference will fall back to CPU",
            );
        }
        crate::resolved::EpStatus::UnknownName => {
            print_result(
                false,
                "unknown execution provider (valid: cpu, cuda, rocm, openvino)",
            );
        }
        crate::resolved::EpStatus::Unqueryable(e) => {
            print_result(false, &format!("ONNX Runtime not loadable: {e}"));
        }
    }
}

fn check_encryption(config: Option<&Config>) {
    let Some(config) = config else {
        return;
    };

    let method_str = match config.encryption.method {
        EncryptionMethod::Tpm => "AES-256-GCM (TPM-sealed key)",
        EncryptionMethod::Keyfile => "AES-256-GCM (keyfile)",
        EncryptionMethod::None => "none",
    };
    print_status_item("Encryption", method_str);

    match config.encryption.method {
        EncryptionMethod::Tpm => {
            let sealed_exists = Path::new(&config.encryption.sealed_key_path).exists();
            let device_path = config
                .tpm
                .tcti
                .strip_prefix("device:")
                .unwrap_or(&config.tpm.tcti);
            let device_exists = Path::new(device_path).exists();
            if sealed_exists && device_exists {
                print_result(
                    true,
                    &format!("sealed key: {}", config.encryption.sealed_key_path),
                );
            } else if !sealed_exists {
                print_result(
                    false,
                    &format!("sealed key missing: {}", config.encryption.sealed_key_path),
                );
            } else {
                print_result(false, &format!("TPM device missing: {}", device_path));
            }
        }
        EncryptionMethod::Keyfile => {
            let key_exists = Path::new(&config.encryption.key_path).exists();
            if key_exists {
                print_result(true, &format!("key file: {}", config.encryption.key_path));
            } else {
                print_result(
                    false,
                    &format!("key file missing: {}", config.encryption.key_path),
                );
            }
        }
        EncryptionMethod::None => {
            print_result(
                false,
                "embeddings stored as plaintext (run 'facelock setup' to enable encryption)",
            );
        }
    }

    // Show DB encryption stats if readable
    if let Ok(store) = facelock_store::FaceStore::open_readonly(Path::new(&config.storage.db_path))
    {
        if let Ok((sealed, unsealed)) = store.count_sealed() {
            if sealed + unsealed > 0 {
                print_detail("encrypted", &sealed.to_string());
                print_detail("plaintext", &unsealed.to_string());
            }
        }
    }
}

fn check_enrolled(config: Option<&Config>) {
    let Some(config) = config else {
        return;
    };

    // One user-resolution implementation (C5, issue #105): the local
    // SUDO_USER→USER chain this replaces omitted DOAS_USER and the getpwuid
    // fallback, so `doas facelock status` reported root's enrollment.
    let user = crate::ipc_client::resolve_user(None);

    print_status_item("Enrolled faces", &user);

    match facelock_store::FaceStore::open_readonly(Path::new(&config.storage.db_path)) {
        Ok(store) => match store.list_models(&user) {
            Ok(models) if models.is_empty() => {
                print_result(false, "no faces enrolled (run 'facelock enroll')");
            }
            Ok(models) => {
                print_result(true, &format!("{} model(s)", models.len()));
                for m in &models {
                    print_detail(&format!("#{}", m.id), &m.label);
                }
            }
            Err(e) => {
                print_result(false, &format!("error reading models: {e}"));
            }
        },
        Err(_) => {
            print_detail("database", "not accessible (may need root)");
        }
    }
}

fn check_security(config: Option<&Config>) {
    let Some(config) = config else {
        return;
    };

    print_status_item("Security", "");
    if config.security.disabled {
        print_result(false, "ALL SECURITY CHECKS DISABLED");
        return;
    }
    print_detail(
        "require_ir",
        if config.security.require_ir {
            "yes"
        } else {
            "no"
        },
    );
    print_detail(
        "liveness (frame variance)",
        if config.security.require_frame_variance {
            "yes"
        } else {
            "no"
        },
    );
    print_detail(
        "liveness (landmark movement)",
        if config.security.require_landmark_liveness {
            "yes"
        } else {
            "no"
        },
    );
    print_detail(
        "min_auth_frames",
        &config.security.min_auth_frames.to_string(),
    );
}

fn check_notifications(config: Option<&Config>) {
    let Some(config) = config else {
        return;
    };

    let mode_str = match config.notification.mode {
        facelock_core::config::NotificationMode::Off => "off",
        facelock_core::config::NotificationMode::Terminal => "terminal",
        facelock_core::config::NotificationMode::Desktop => "desktop",
        facelock_core::config::NotificationMode::Both => "terminal + desktop",
    };
    print_status_item("Notifications", mode_str);
    if config.notification.mode != facelock_core::config::NotificationMode::Off {
        print_detail(
            "prompt",
            if config.notification.notify_prompt {
                "yes"
            } else {
                "no"
            },
        );
        print_detail(
            "on success",
            if config.notification.notify_on_success {
                "yes"
            } else {
                "no"
            },
        );
        print_detail(
            "on failure",
            if config.notification.notify_on_failure {
                "yes"
            } else {
                "no"
            },
        );
    }
}

fn check_pam() {
    let pam_path = "/lib/security/pam_facelock.so";
    print_status_item("PAM module", pam_path);

    if Path::new(pam_path).exists() {
        print_result(true, "installed");
    } else {
        // Also check /usr/lib path
        let alt_path = "/usr/lib/security/pam_facelock.so";
        if Path::new(alt_path).exists() {
            print_result(true, &format!("installed at {alt_path}"));
        } else {
            print_result(false, "not installed");
        }
    }

    // Check if sudo is configured
    let sudo_pam = "/etc/pam.d/sudo";
    if Path::new(sudo_pam).exists() {
        if let Ok(content) = std::fs::read_to_string(sudo_pam) {
            if content.contains("pam_facelock") {
                print_detail("sudo PAM", "configured");
            } else {
                print_detail("sudo PAM", "not configured for facelock");
            }
        }
    }
}

fn print_status_item(label: &str, value: &str) {
    if value.is_empty() {
        println!("  {label}:");
    } else {
        println!("  {label}: {value}");
    }
}

fn print_result(ok: bool, message: &str) {
    let indicator = if ok { "[ok]" } else { "[!!]" };
    println!("    {indicator} {message}");
}

fn print_detail(key: &str, value: &str) {
    println!("    - {key}: {value}");
}
