//! The one embedding-decrypt implementation (N10).
//!
//! The daemon handler and the CLI's direct path both load a user's stored
//! templates and decrypt software-encrypted (version byte 0x02) or TPM-sealed
//! (0x01/0x03) rows. The per-row logic used to live twice — `Handler` and
//! `facelock-cli`'s `direct::load_user_embeddings` — and drifted once already
//! (B3: the direct copy predated `seal_database` handling). This module is
//! that loop, once.
//!
//! What stays with the callers, deliberately:
//! - the fast path (`get_user_embeddings` when nothing could have written an
//!   encrypted row) and the raw-row fetch, because they belong to each
//!   caller's store-access policy;
//! - sealer *initialization* policy — the daemon fails enroll closed on a
//!   broken keyfile while auth continues, the direct path propagates — which
//!   is a real posture difference, not duplication.
//!
//! Errors are plain strings: the handler wraps them in
//! `DaemonResponse::Error`, the direct path in `anyhow`. They are
//! machine-facing (they cross D-Bus and land in logs) and must not localize.

use facelock_core::config::Config;
use facelock_core::types::FaceEmbedding;

/// How the decrypt loop reaches a TPM sealer when a TPM-sealed row appears.
///
/// The two callers hold the sealer differently and that difference is worth
/// keeping: the daemon initializes once at startup (a failure there is warned
/// once and every sealed row afterwards reports it), while the one-shot direct
/// path connects lazily so unsealed stores never pay a TPM round-trip.
pub enum TpmAccess<'a> {
    /// A long-lived sealer initialized at handler construction. `None` means
    /// `tpm.seal_database` is configured but initialization failed at startup.
    Held(Option<&'a mut facelock_tpm::TpmSealer>),
    /// Connect on the first sealed row, using the configured TCTI. Without
    /// the `tpm` feature the passthrough sealer connects trivially and each
    /// unseal reports a clear "compile with tpm" error instead of misreading
    /// the blob.
    Lazy {
        tcti: &'a str,
        sealer: Option<facelock_tpm::TpmSealer>,
    },
}

impl TpmAccess<'_> {
    fn sealer(&mut self) -> Result<&mut facelock_tpm::TpmSealer, String> {
        match self {
            TpmAccess::Held(Some(sealer)) => Ok(sealer),
            TpmAccess::Held(None) => {
                Err("TPM-sealed embeddings exist but TPM is not available".into())
            }
            TpmAccess::Lazy { tcti, sealer } => {
                if sealer.is_none() {
                    let connected = facelock_tpm::TpmSealer::new(tcti)
                        .map_err(|e| format!("TPM initialization failed: {e}"))?;
                    *sealer = Some(connected);
                }
                Ok(sealer.as_mut().expect("just connected"))
            }
        }
    }
}

/// True when the store must be read through the raw-row path: either a
/// software sealer is active, or `tpm.seal_database` says TPM-sealed rows may
/// exist. The `seal_database` half matters even when the sealer failed to
/// initialize (or TPM support is not compiled in): the fast path would hand
/// sealed blobs to callers as if they were raw embeddings, which at best
/// reports a misleading "corrupt store" and at worst misreads a template (the
/// B3 class — the handler previously made exactly this mistake).
pub fn needs_raw_rows(config: &Config, software_sealer_active: bool) -> bool {
    software_sealer_active || config.tpm.seal_database
}

/// Decrypt raw `(id, blob, sealed, device_id)` rows into embeddings.
///
/// Per row: software-encrypted blobs unseal with the configured key and this
/// template's own device-derived AAD (opt-in, matching enroll); TPM-sealed
/// blobs unseal through `tpm`; plaintext rows are size-checked and cast. The
/// first failing row fails the whole load — a partial compare set would
/// silently narrow authentication.
pub fn decrypt_user_embeddings(
    raw_rows: &[(u32, Vec<u8>, bool, Option<String>)],
    config: &Config,
    software_sealer: Option<&facelock_tpm::SoftwareSealer>,
    mut tpm: TpmAccess<'_>,
) -> Result<Vec<(u32, FaceEmbedding)>, String> {
    let mut results = Vec::with_capacity(raw_rows.len());
    for (id, blob, sealed, device_id) in raw_rows {
        let embedding = if *sealed && facelock_tpm::is_software_encrypted(blob) {
            // Software-encrypted (version byte 0x02)
            let sealer = software_sealer.ok_or_else(|| {
                format!("embedding {id} is software-encrypted but no key is configured")
            })?;
            let aad = config.security.device_aad(device_id.as_deref());
            sealer
                .unseal_embedding_with_aad(blob, aad.as_deref())
                .map_err(|e| format!("software decryption failed for embedding {id}: {e}"))?
        } else if *sealed {
            // TPM-sealed (version byte 0x01/0x03)
            tpm.sealer()?
                .unseal_embedding(blob)
                .map_err(|e| format!("TPM unseal failed for embedding {id}: {e}"))?
        } else {
            // Plaintext raw embedding
            if blob.len() != 512 * 4 {
                return Err(format!(
                    "invalid raw embedding size for id {id}: expected {} bytes, got {}",
                    512 * 4,
                    blob.len()
                ));
            }
            let floats: &[f32] = bytemuck::cast_slice(blob);
            let mut emb = [0f32; 512];
            emb.copy_from_slice(floats);
            emb
        };
        results.push((*id, embedding));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plaintext_row(id: u32, value: f32) -> (u32, Vec<u8>, bool, Option<String>) {
        let emb: FaceEmbedding = [value; 512];
        (id, bytemuck::cast_slice(&emb).to_vec(), false, None)
    }

    #[test]
    fn plaintext_rows_round_trip() {
        let config = Config::parse("").unwrap();
        let rows = vec![plaintext_row(1, 0.25), plaintext_row(2, 0.75)];
        let out = decrypt_user_embeddings(&rows, &config, None, TpmAccess::Held(None)).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], (1, [0.25; 512]));
        assert_eq!(out[1], (2, [0.75; 512]));
    }

    #[test]
    fn wrong_size_plaintext_row_fails_the_load() {
        let config = Config::parse("").unwrap();
        let rows = vec![(7u32, vec![0u8; 100], false, None)];
        let err = decrypt_user_embeddings(&rows, &config, None, TpmAccess::Held(None)).unwrap_err();
        assert!(err.contains("invalid raw embedding size for id 7"), "{err}");
    }

    #[test]
    fn software_row_without_key_names_the_row() {
        let config = Config::parse("").unwrap();
        // Version byte 0x02 marks software encryption.
        let mut blob = vec![0x02u8];
        blob.extend_from_slice(&[0u8; 64]);
        let rows = vec![(3u32, blob, true, None)];
        let err = decrypt_user_embeddings(&rows, &config, None, TpmAccess::Held(None)).unwrap_err();
        assert_eq!(
            err,
            "embedding 3 is software-encrypted but no key is configured"
        );
    }

    #[test]
    fn software_rows_decrypt_with_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("facelock.key");
        facelock_tpm::SoftwareSealer::generate_key_file(&key_path).unwrap();
        let sealer = facelock_tpm::SoftwareSealer::from_key_file(&key_path).unwrap();

        let emb: FaceEmbedding = [0.5; 512];
        let blob = sealer.seal_embedding(&emb).unwrap();
        let rows = vec![(4u32, blob, true, None)];

        let config = Config::parse("").unwrap();
        let out =
            decrypt_user_embeddings(&rows, &config, Some(&sealer), TpmAccess::Held(None)).unwrap();
        assert_eq!(out, vec![(4, emb)]);
    }

    /// The daemon's held-sealer failure mode: seal_database configured but
    /// TPM init failed at startup — every sealed row reports it.
    #[test]
    fn tpm_row_with_no_held_sealer_reports_unavailable() {
        let config = Config::parse("").unwrap();
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&[0u8; 64]);
        let rows = vec![(5u32, blob, true, None)];
        let err = decrypt_user_embeddings(&rows, &config, None, TpmAccess::Held(None)).unwrap_err();
        assert_eq!(err, "TPM-sealed embeddings exist but TPM is not available");
    }

    /// The direct path's lazy connection (B3 pin, relocated with the loop):
    /// without the `tpm` feature the passthrough sealer connects and reports
    /// a clear per-row error instead of misreading the blob.
    #[cfg(not(feature = "tpm"))]
    #[test]
    fn tpm_row_via_lazy_passthrough_errors_clearly() {
        let config = Config::parse("").unwrap();
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&[0u8; 64]);
        let rows = vec![(6u32, blob, true, None)];
        let err = decrypt_user_embeddings(
            &rows,
            &config,
            None,
            TpmAccess::Lazy {
                tcti: "device",
                sealer: None,
            },
        )
        .unwrap_err();
        assert!(err.contains("TPM unseal failed for embedding 6"), "{err}");
        assert!(err.contains("without TPM support"), "{err}");
    }

    /// `needs_raw_rows` forces the slow path whenever sealed rows may exist,
    /// even with no working sealer — the fast path must never hand a sealed
    /// blob to a caller as a raw embedding.
    #[test]
    fn seal_database_forces_raw_rows_without_a_sealer() {
        let sealed = Config::parse("[tpm]\nseal_database = true\n").unwrap();
        assert!(needs_raw_rows(&sealed, false));

        let plain = Config::parse("").unwrap();
        assert!(!needs_raw_rows(&plain, false));
        assert!(needs_raw_rows(&plain, true));
    }
}
