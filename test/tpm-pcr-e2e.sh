#!/bin/bash
# TPM PCR-binding regression (finding #5), run inside the deb-tpm E2E container
# against a software TPM (swtpm). No camera required.
#
# Proves the PCR policy is actually ENFORCED on unseal:
#   seal key under PCR binding -> unseal OK
#   -> extend a bound PCR -> unseal FAILS (this is the regression: it used to
#      succeed because the sealed object's userWithAuth let empty auth pass)
#   -> `facelock tpm reseal` re-seals under the new PCRs -> unseal OK again.
set -uo pipefail

PASS=0
FAIL=0
TCTI="swtpm:host=127.0.0.1,port=2321"
export TPM2TOOLS_TCTI="$TCTI"
CFG=/etc/facelock/config.toml
# 64 hex chars for tpm2_pcrextend (a sha256 digest to fold into PCR 16).
EXTEND_HEX="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

run_expect() { # name cmd expected_exit
    local name="$1" cmd="$2" exp="${3:-0}"
    echo -n "TEST: $name ... "
    if bash -c "$cmd" >/tmp/tpm-out 2>&1; then r=0; else r=$?; fi
    if [ "$r" -eq "$exp" ]; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (exit=$r, expected=$exp)"
        cat /tmp/tpm-out
        FAIL=$((FAIL + 1))
    fi
}

echo "=== TPM PCR-binding E2E (swtpm, finding #5) ==="

# 1. Start a software TPM and wait until it answers.
mkdir -p /tmp/swtpm
swtpm socket --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --tpmstate dir=/tmp/swtpm \
    --flags startup-clear \
    --daemon
started=0
for _ in $(seq 1 30); do
    if tpm2_pcrread sha256:16 >/dev/null 2>&1; then
        started=1
        break
    fi
    tpm2_startup -c >/dev/null 2>&1 || true
    sleep 0.3
done
if [ "$started" != 1 ]; then
    echo "FATAL: swtpm not reachable via $TCTI"
    exit 1
fi

# 2. Point facelock at swtpm with PCR binding on PCR 16 (a resettable debug PCR).
cat > "$CFG" <<EOF
[storage]
db_path = "/tmp/facelock-tpm-test.db"

[encryption]
method = "keyfile"
key_path = "/etc/facelock/encryption.key"
sealed_key_path = "/etc/facelock/encryption.key.sealed"

[tpm]
pcr_binding = true
pcr_indices = [16]
tcti = "$TCTI"
EOF
rm -f /etc/facelock/encryption.key /etc/facelock/encryption.key.sealed

# 3. Generate a plaintext key (kept as the reseal backup), then seal it under the
#    current PCR 16 state. seal-key flips encryption.method to "tpm".
run_expect "generate plaintext key (backup)" "facelock tpm encrypt --generate-key" 0
run_expect "seal AES key under PCR 16" "facelock tpm seal-key" 0

# 4. Unseal succeeds while PCR 16 is unchanged (policy satisfiable).
run_expect "unseal-check OK with matching PCRs" "facelock tpm unseal-check" 0

# 5. Change a bound PCR (simulates a firmware/kernel measurement change).
run_expect "extend PCR 16" "tpm2_pcrextend 16:sha256=$EXTEND_HEX" 0

# 6. THE REGRESSION GATE: unseal must now FAIL (non-zero). Before the fix this
#    unsealed successfully, silently defeating PCR binding.
run_expect "unseal-check FAILS after bound PCR changed (finding #5)" \
    "facelock tpm unseal-check" 1

# 7. Recovery: reseal re-seals the key (recovered from the plaintext backup)
#    under the new PCR state, and unseal works again.
run_expect "facelock tpm reseal restores under new PCRs" "facelock tpm reseal" 0
run_expect "unseal-check OK again after reseal" "facelock tpm unseal-check" 0

echo ""
echo "=== TPM PCR Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
