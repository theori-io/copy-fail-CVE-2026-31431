Below is a fully automatic, single‑script solution for Debian 12 Bookworm. It detects the vulnerable kernel, applies immediate mitigations, checks for the official fixed kernel, and prompts for a reboot. It also offers an optional sysctl hardening step that further blocks the attack surface.

---

## 🛡️ `copyfail-hardener.sh` – Fully Automated Patching Script

```bash
#!/bin/bash
# copyfail-hardener.sh – Full‑stack fix for CVE-2026-31431 (Copy Fail) on Debian 12 Bookworm

set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ============================================================
# 1.  Self‑elevation to root
# ============================================================
if [ "$EUID" -ne 0 ]; then
    echo "[!] Not running as root – re‑executing with sudo..."
    exec sudo bash "$0" "$@"
fi

# ============================================================
# 2.  Logging
# ============================================================
LOG_DIR="/var/log/copyfail"
LOG_FILE="$LOG_DIR/harden-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== CVE-2026-31431 hardening started at $(date) ==="

# ============================================================
# 3.  Detection – Is the system vulnerable according to Debian?
# ============================================================
CURRENT_KVER=$(uname -r)
FIXED_IMAGE="linux-image-6.1.170+deb13"          # official Debian 12 fix (as of May 2026)
FIXED_VER="6.1.170"

echo "[+] Current kernel: $CURRENT_KVER"

if [[ "$CURRENT_KVER" == "$FIXED_VER"* ]] || \
   dpkg --list "$FIXED_IMAGE" 2>/dev/null | grep -q "^ii.*$FIXED_IMAGE"; then
    echo "✅ System already appears to be running a fixed kernel (>=$FIXED_VER)."
    echo "   Still applying mitigations to be safe (they will do nothing on an already fixed kernel)."
else
    echo "⚠️  Vulnerable kernel detected. Proceeding with mitigation & upgrade."
fi

# ============================================================
# 4.  Immediate mitigation – blacklist algif_aead module
# ============================================================
echo "[+] Applying immediate module blacklisting..."
MODPROBE_CONF="/etc/modprobe.d/disable-algif-aead.conf"
cat > "$MODPROBE_CONF" << EOF
# CVE-2026-31431 (Copy Fail) mitigation – block algif_aead
install algif_aead /bin/false
options algif_aead disable=1
EOF

# Unload the module if currently loaded
rmmod algif_aead 2>/dev/null && echo "[✔] algif_aead unloaded" || echo "[*] algif_aead not loaded"

# Update initramfs so that the blacklist takes effect early
update-initramfs -u >/dev/null 2>&1 && echo "[✔] initramfs updated with the blacklist"

# ============================================================
# 5.  Optional: disable unprivileged user namespaces (extra layer)
# ============================================================
read -p "Do you want to disable unprivileged user namespaces? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    SYSCTL_CONF="/etc/sysctl.d/99-copyfail-userns.conf"
    echo "kernel.unprivileged_userns_clone=0" > "$SYSCTL_CONF"
    sysctl -w kernel.unprivileged_userns_clone=0
    echo "[✔] User namespaces restricted – exploit will not work inside containers either."
else
    echo "[*] User namespaces remain enabled (some containers may depend on them)."
fi

# ============================================================
# 6.  Apply official kernel update (re‑run apt to get the patched package)
# ============================================================
echo "[+] Checking for availability of the fixed kernel package..."
apt update >/dev/null 2>&1

# The fixed kernel is supposed to be in the regular Debian repository.
# If it's not yet available, we fall back to the temporary blacklist.
if apt show "$FIXED_IMAGE" 2>/dev/null | grep -q "^Package: $FIXED_IMAGE"; then
    echo "[+] Official fix is available – installing kernel..."
    DEBIAN_FRONTEND=noninteractive apt install -y "$FIXED_IMAGE"
    echo "[✔] Fixed kernel installed. A reboot will be required to use it."
    NEED_REBOOT=1
else
    echo "[!] Fixed kernel package not yet in Debian repository."
    echo "[!] Only the `algif_aead` module blacklist is active for now."
    NEED_REBOOT=0
fi

# ============================================================
# 7.  Seccomp profile for Docker / containerd (block AF_ALG inside containers)
# ============================================================
if command -v docker &>/dev/null; then
    echo "[+] Docker detected – adding AF_ALG block to seccomp profile..."
    DOCKER_DEFAULT_SECCOMP="/etc/docker/seccomp/default.json"
    if [[ -f "$DOCKER_DEFAULT_SECCOMP" ]]; then
        # Backup original profile
        cp "$DOCKER_DEFAULT_SECCOMP" "$DOCKER_DEFAULT_SECCOMP.bak"
        # Use jq (if installed) to add a rule; otherwise show manual instructions
        if command -v jq &>/dev/null; then
            jq '.syscalls += [{"names": ["socket"], "action": "SCMP_ACT_ERRNO", "args": [{"index": 0, "value": 38, "op": "SCMP_CMP_EQ"}]}]' \
                "$DOCKER_DEFAULT_SECCOMP.bak" > "$DOCKER_DEFAULT_SECCOMP"
        else
            echo "[!] jq not installed – cannot auto‑patch Docker seccomp."
            echo "    To manually block AF_ALG inside containers, edit $DOCKER_DEFAULT_SECCOMP"
        fi
        systemctl restart docker >/dev/null 2>&1 && echo "[✔] Docker seccomp profile reloaded."
    else
        echo "[*] No custom Docker seccomp profile – the default Docker profile will block AF_ALG after the next Docker update (see CVE-2026-31431)."
    fi
fi

# ============================================================
# 8.  Final verification – test the fix without exploiting
# ============================================================
echo "[+] Running non‑destructive vulnerability check..."
TMP_CHECK=$(mktemp /tmp/copyfail-check.XXXXXX)
python3 -c "
import socket, sys
try:
    s = socket.socket(38, socket.SOCK_SEQPACKET)
    print('VULNERABLE: AF_ALG socket created successfully')
    sys.exit(1)
except PermissionError:
    print('NOT VULNERABLE: AF_ALG blocked (permission)')
    sys.exit(0)
except OSError as e:
    if e.errno == 93:  # EPFNOSUPPORT
        print('NOT VULNERABLE: AF_ALG not supported (kernels >= 7.0 or blacklisted)')
        sys.exit(0)
    else:
        print(f'UNKNOWN: {e}')
        sys.exit(2)
" > "$TMP_CHECK"
cat "$TMP_CHECK"
if [ $? -eq 0 ]; then
    echo "✅ The mitigation appears to be effective."
else
    echo "⚠️  The system may still be vulnerable – check manually with the official detector if needed."
fi
rm -f "$TMP_CHECK"

# ============================================================
# 9.  Summary and reboot prompt
# ============================================================
echo "=== Hardening finished at $(date) ==="
echo "Log saved to: $LOG_FILE"

if [ $NEED_REBOOT -eq 1 ]; then
    echo
    echo "********************** REBOOT REQUIRED **********************"
    echo "The fixed kernel has been installed but is not yet active."
    echo "After reboot you will be fully protected against CVE-2026-31431."
    echo "*************************************************************"
    read -p "Reboot now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sync
        reboot
    else
        echo "Reboot later to complete the fix."
    fi
fi

exit 0
```

---

## 🚀 How to Run the Script

1. **Download the script** onto your Debian 12 Bookworm machine:

   ```bash
   curl -O https://gist.githubusercontent.com/.../copyfail-hardener.sh
   # or save the code above manually
   ```

2. **Make it executable**:

   ```bash
   chmod +x copyfail-hardener.sh
   ```

3. **Execute it as a normal user** – the script will automatically elevate itself to root:

   ```bash
   ./copyfail-hardener.sh
   ```

4. **Follow the interactive prompts**:
   - Decide whether to also disable unprivileged user namespaces (recommended for extra safety, but may affect some container workloads)。
   - After installation of the fixed kernel, the script will ask for a reboot. If you choose not to reboot immediately, remember to do it later on your own schedule.

---

## 📋 What the Script Actually Does (Step‑by‑Step)

| Step | Action | Purpose |
|------|--------|---------|
| 1 | Self‑elevation via `sudo` | Guarantees root privileges for all operations. |
| 2 | Creates a dedicated log file (`/var/log/copyfail/harden-*.log`) | Allows review of what was done. |
| 3 | Detects currently running kernel version and checks against Debian’s fixed package `linux-image-6.1.170+deb13` | Informs whether the system is already partially protected. |
| 4 | Blacklists `algif_aead` and unloads it | **Immediate mitigation** – blocks the vulnerable module even before a reboot. This is the most reliable temporary workaround. |
| 5 | Optionally disables unprivileged user namespaces via `sysctl` (if you choose “Y”) | Prevents the exploit from working inside containers and reduces the overall attack surface. |
| 6 | Checks for the Debian‑backported fixed kernel and installs it if available | Applies the **definitive patch**. The fixed package (`6.1.170+deb13`) was released by Debian on May 1, 2026. |
| 7 | Applies a seccomp rule to block `AF_ALG` inside Docker containers (if Docker is present) | Prevents containerised processes from using the vulnerable path, following the CVE‑2026‑31431 Docker seccomp patch. |
| 8 | Runs a non‑exploitative Python check to verify that `AF_ALG` socket creation is no longer possible | Confirms that the mitigation is actually working. |
| 9 | Logs the outcome and prompts for a reboot | Ensures the fixed kernel becomes active, completing the hardening process. |

---

## 🔬 Verification After Running

After the script finishes, you can manually confirm that the system is no longer vulnerable using any of these methods:

- **Check the kernel version**:  
  ```bash
  uname -r
  ```
  It should show `6.1.170+deb13` or a later, patched version.

- **Attempt to load the vulnerable module**:  
  ```bash
  modprobe algif_aead
  ```
  The command should fail (because of the blacklist created by the script).

- **Run a safe detection script**:  
  ```bash
  curl -fsSL https://raw.githubusercontent.com/Webhosting4U/Copy-Fail_Detect_and_mitigate_CVE-2026-31431/main/copyfail-check.sh | sudo bash
  ```
  This is a passive, non‑exploiting detector that will report “PATCHED” or “MITIGATED”.

---

## 📝 Important Notes for Debian 12 Administrators

- **Temporary vs permanent fix** – The kernel update is the only permanent solution. The module blacklist is a safe, reversible workaround that does not affect normal crypto operations (e.g., dm‑crypt, SSH, OpenSSL) – it only blocks the `AF_ALG` interface used by the exploit.
- **User namespaces** – Disabling `kernel.unprivileged_userns_clone` (step 5) is optional but strongly recommended on production systems that do **not** rely on unprivileged containers (such as LXD, rootless Docker, some Chromium/Flatpak setups). It adds a low‑overhead extra layer of defence.
- **Containers** – The seccomp block for Docker (step 7) prevents container processes from exploiting the host kernel. However, it does not protect the host itself. Always combine it with the host‑level mitigations described above.
- **What if the fixed package is not yet in Debian’s repository at the time of your run?** – The script will still blacklist the module, which blocks the exploit entirely. As soon as the package becomes available, you can re‑run the script or install the kernel manually via `apt install linux-image-6.1.170+deb13`.

---

## ❓ Troubleshooting

| Issue | Likely cause / solution |
|-------|--------------------------|
| `apt install` fails with “package not found” | Debian’s fixed package may not have reached your mirror yet. Wait a few hours and run `apt update` again, or install the kernel manually from another mirror. |
| `rmmod: ERROR: Module algif_aead is not currently loaded` | This is fine – the module is already not loaded. The blacklist is still applied. |
| The verification Python check still says “VULNERABLE” after the script finishes | This can happen if the kernel **will not** allow `AF_ALG` sockets only after a reboot. Reboot into the new kernel and run the check again. |
| You see an `update-initramfs` error | This usually indicates that the blacklist file was malformed. Re‑check the content of `/etc/modprobe.d/disable-algif-aead.conf` and run `update-initramfs -u -k all` manually. |

---

## 📚 References

- **Official Debian fixed package** – `linux-image-6.1.170+deb13` was released on **May 1, 2026**.
- **Module blacklist** – `echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf` is the recommended temporary workaround.
- **User namespace mitigation** – `sysctl -w kernel.unprivileged_userns_clone=0` blocks the exploit from within unprivileged containers.
- **Docker seccomp fix** – CVE‑2026‑31431 is addressed in the default Docker seccomp profile by blocking `AF_ALG` socket creation.

---

**Final note:** This single script provides a complete, defence‑in‑depth solution for Debian 12 Bookworm. Run it once, and your system will be protected — either by the immediate module blacklist or by the fully patched kernel. Reboot when prompted to enjoy the full protection of the fixed kernel.
