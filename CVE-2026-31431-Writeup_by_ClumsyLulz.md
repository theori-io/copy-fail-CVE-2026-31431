# CVE-2026-31431 (Copy Fail) — Comprehensive Technical Write‑up

## Executive Summary

CVE-2026-31431, publicly disclosed on April 29, 2026, is a local privilege escalation (LPE) vulnerability in the Linux kernel’s cryptographic subsystem. Dubbed *Copy Fail*, it allows any unprivileged local user to write four attacker‑controlled bytes into the page cache of any readable file on the system — including setuid binaries and `/etc/passwd`. A single 732‑byte Python script successfully escalates to root on essentially every Linux distribution released since 2017. The flaw has a CVSSv3 score of **7.8 (High)**, requires no race condition, no per‑distribution offsets, and works reliably across Ubuntu, RHEL, Amazon Linux, SUSE, Debian, and many others.

The vulnerability was discovered by Taeyang Lee of Theori using an AI‑driven source‑code analysis tool called *Xint Code*, which surfaced the bug in approximately one hour of focused scanning against the Linux crypto subsystem. It was reported to the Linux kernel security team on March 23, 2026; a patch was merged into mainline on April 1, 2026; and the CVE was assigned on April 22, 2026, before full public disclosure on April 29, 2026.

---

## Vulnerability Details

### Affected Kernel Versions

The vulnerability affects all Linux kernels built between **2017** (when an in‑place optimisation was introduced) and the availability of the fix, i.e., versions **4.14 through 6.18.21** (and earlier backported trees). Patched kernel versions include **6.18.22, 6.19.12, 7.0, and later**, along with numerous backported releases (e.g., 6.12.85, 6.6.137, 6.1.170, 5.15.204, 5.10.254).

The fix is mainline commit `a664bf3d603d`, which reverts the vulnerable in‑place optimisation.

### Root Cause Analysis

The vulnerability stems from the interaction of three independent changes that were introduced into the Linux kernel over several years:

1. **authencesn template (2011)** – Added to support IPsec Extended Sequence Numbers (ESN). It performs a 4‑byte write of the sequence number low field into the destination scatter‑list beyond the expected boundary.
2. **AF_ALG AEAD support (2015)** – Allowed userspace to submit Authenticated Encryption with Associated Data (AEAD) operations via the AF_ALG socket family, including using `splice()` to feed page‑cached file data directly into the kernel.
3. **In‑place optimisation in algif_aead.c (2017, commit `72548b093ee3`)** – Modified the AEAD request to operate **in‑place** (`req->src == req->dst`). This placed live page‑cache pages into a *writable* destination scatter‑list, rather than copying data to a separate kernel buffer.

When an unprivileged user feeds a file’s page‑cache pages into an AF_ALG socket via `splice()` and then triggers an AEAD *decryption* request with the `authencesn` algorithm, the kernel performs the following:

```
sendmsg(alg_socket, MSG_SPLICE_PAGES)
  → af_alg_sendmsg() splices file pages into the RX buffer
  → algif_aead moves the tag pages by reference into the destination scatterlist
  → crypto_authenc_esn_decrypt() finds req->src == req->dst
  → writes 4 bytes (seqno_lo) into dst[assoclen + cryptlen]
    → that write lands directly in the spliced file's page‑cache page
```

Crucially, the **4‑byte write occurs even when the authentication tag is invalid** — the decryption fails with `‑EBADMSG`, but the corruption has already happened.

As a result, an unprivileged local user gains a **controlled 4‑byte arbitrary write primitive against the page cache of any readable file** on the system.

---

## Exploit Chain: From unprivileged user to root

### Attack Prerequisites
- Local shell access as an **unprivileged user** on a vulnerable system
- The `AF_ALG` socket family must be available (true by default; not blocked by any standard seccomp profile)
- A setuid‑root binary such as `/usr/bin/su` or `/usr/bin/sudo` must exist (true on essentially every Linux distribution)

### Exploit Steps (High‑Level)

1. **Open AF_ALG socket** – `socket(AF_ALG, SOCK_SEQPACKET, 0)`
2. **Bind to the vulnerable algorithm** – `bind("authencesn(hmac(sha256),cbc(aes))")`
3. **Set cryptographic parameters** – `setsockopt(ALG_SET_KEY, ...)`
4. **Accept a request socket** – `accept()`
5. **Splice file pages into the socket** – Use `splice()` to feed the target file’s page‑cache pages into the algorithm’s RX buffer
6. **Send crafted AAD via `sendmsg()`** – Bytes 4–7 of the AAD contain the **4‑byte value** to be written into the page cache
7. **Trigger the flawed decryption** – The kernel writes those 4 bytes into the destination scatter‑list, over‑writing the corresponding 4 bytes in the page‑cache copy of the file
8. **Write the full payload** – Repeat steps 5–7 for each 4‑byte chunk of the attacker’s shellcode, writing it sequentially into the target file’s page cache
9. **Execute the corrupted binary** – Run the setuid binary (e.g., `/usr/bin/su`). The kernel loads the (now corrupted) page‑cache version, executes the injected code with root privileges, and spawns a root shell.

### Why the Exploit Is So Effective
- **No race condition** – The bug is a straight‑line logic flaw, not a race. Reliability is 100% on the first attempt.
- **No per‑kernel offsets** – The same exploit script works unchanged across all vulnerable distributions and kernel versions.
- **No special privileges** – AF_ALG is accessible to any unprivileged process by default, and `splice()` is similarly unprivileged.
- **Stealth** – Only the **page cache** (in‑memory copy) is modified; the on‑disk file remains untouched. Traditional file integrity monitoring (FIM) tools see no change, and the corruption disappears upon reboot or page eviction.
- **Containers are not safe** – Because containers on the same host share the host kernel’s page cache, a malicious container can corrupt files in the shared base layer, potentially escaping to the host.

---

## PoC / Exploit Availability

Within hours of public disclosure, multiple working exploits were published:
- The **original 732‑byte Python PoC** from Theori (theori‑io/copy‑fail‑CVE‑2026‑31431)
- A **universal Python exploit** that dynamically calculates ELF entry point offsets (no hardcoded addresses)
- **C implementations** (e.g., `rootsecdev/cve_2026_31431`) for environments without Python
- A **Rust implementation** capable of injecting Meterpreter shellcode
- A **tiny ELF version** weighing only 801 bytes

All published PoCs are deterministic and work reliably on the first attempt across major distributions.

---

## Affected Products & Patch Status

### Verified Vulnerable Distributions (at disclosure)

| Distribution | Kernel Version |
|--------------|----------------|
| Ubuntu 24.04 LTS | 6.17.0‑1007‑aws |
| Amazon Linux 2023 | 6.18.8‑9.213.amzn2023 |
| RHEL 10.1 | 6.12.0‑124.45.1.el10_1 |
| SUSE 16 | 6.12.0‑160000‑9.default |

*Extrapolated implicit vulnerable distributions include Debian, Arch Linux, Fedora, Rocky Linux, AlmaLinux, Oracle Linux, and many others*.

### Patch Availability (as of early May 2026)

| Distribution | Status | Notes |
|--------------|--------|-------|
| **Upstream Linux** | ✅ Patched (commit a664bf3d603d) | Merged 2026‑04‑01 |
| **Debian (sid/unstable)** | ✅ Patched | Fix available |
| **Debian (stable/bookworm)** | ❌ Not patched | No confirmed backport yet |
| **Ubuntu (all LTS)** | ❌ Not patched (mostly) | No broadly released fixed kernels |
| **RHEL 8/9** | ⚠️ Patching in progress | Gradual rollout of backported fixes |
| **SUSE / SLES** | ⚠️ Patching in progress | Updates depend on service pack |
| **Amazon Linux** | ⚠️ Patching in progress | Kernel updates rolling out |
| **Fedora** | ⚠️ Patching in progress | Newer kernels likely include fix |

*Status as of early May 2026*

---

## Detection

### Vulnerability Detection Scripts

Several non‑destructive detectors can safely determine if a system is vulnerable without modifying any system binaries:
- **Theori’s official detector** (included with their PoC)
- **cipapakiyo’s Python detector** – `python3 -c "$(curl -fsSL https://raw.githubusercontent.com/cipapakiyo/cve_2026_31431/main/test_cve_2026_31431.py)"`
- **liamromanis101’s detection script** – `CVE-2026-31431-Copy-Fail---Vulnerability-Detection-Script`

These detectors create a temporary test file, attempt the 4‑byte write primitive on it, and report whether the write succeeded.

### Investigating Suspected Exploit Attempts

The following auditd rules can detect potential exploitation attempts:

```
-a always,exit -S socket -F family=38
-a always,exit -S splice
-a always,exit -S sendmsg
-a always,exit -S openat -F success=1 -F path=/etc/passwd
-a always,exit -S openat -F success=1 -F path=/usr/bin/su
```

Additional IoCs include access to the `authencesn(hmac(sha256),cbc(aes))` algorithm via `/proc/crypto` and the presence of the `algif_aead` kernel module.

---

## Mitigation & Remediation

### Permanent Fix (Recommended)
**Update the kernel** to a version containing the upstream fix (commit `a664bf3d603d`) or your distribution’s patched kernel as soon as it becomes available.

### Temporary Mitigations (until a patched kernel is available)

#### 1. **Disable the `algif_aead` kernel module**

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

This does **not** affect dm‑crypt/LUKS, kTLS, IPsec/XFRM, OpenSSL, GnuTLS, NSS, or SSH. It may affect applications explicitly using `afalg` engine or binding AEAD sockets.

#### 2. **Boot parameter blacklist**

Add `initcall_blacklist=algif_aead_init` to your kernel command line in `/etc/default/grub` (requires reboot).

#### 3. **Set `no_new_privs` for containers / workloads**

In Kubernetes, set `allowPrivilegeEscalation: false` in the security context. This causes the kernel to ignore setuid/setgid bits on `execve()`, blocking the final escalation step even if the page cache is corrupted.

#### 4. **BPF‑LSM blocking (no‑reboot option)**

Use the `copy-fail-blocker` DaemonSet to deny all `AF_ALG` socket creation via a small eBPF program attached to the `socket_create` LSM hook:

```bash
kubectl apply -f https://raw.githubusercontent.com/cozystack/copy-fail-blocker/v0.2.1/manifests/copy-fail-blocker.yaml
```

This works cluster‑wide on kernels with `CONFIG_BPF_LSM=y` and `lsm=...,bpf`.

#### 5. **Seccomp profiles (container‑specific)**

Block the `AF_ALG` socket family (38) in your container runtime’s seccomp profile. This is effective per workload but does not protect the host itself.

---

## Impact Assessment

| Environment | `no_new_privs` | Container Root | Host Root | Risk Level |
|-------------|----------------|----------------|-----------|-------------|
| **RHEL 8/9 (local user)** | n/a | n/a | Yes | **Critical** |
| **Kubernetes Pod — PSS Restricted** | false (`allowPrivilegeEscalation=false`) | No | No | **Low** |
| **Kubernetes Pod — default** | true (default) | Yes | No | **High** |
| **Docker default** | true (default) | Yes | No | **High** |
| **Docker + `--security-opt no-new-privileges`** | false | No | No | **Low** |

*Based on mitigation analysis*

**Why this matters in 2026 cloud environments:** A kernel LPE collapses the isolation boundary between tenants on a shared host. A realistic threat chain: attacker exploits a WordPress plugin → gets shell as `www‑data` → runs the 732‑byte Python script → gains root on the host → accesses every other guest, container, and tenant on that machine.

---

## Discovery Context: AI‑Driven Vulnerability Research

The vulnerability was discovered using **Xint Code**, an AI‑powered source‑code analysis tool built by Theori. With “one operator prompt, no harnessing,” the system surfaced the logic flaw in approximately **one hour** of scanning time against the Linux crypto subsystem. Theori, as a team, has won DEF CON CTF nine times and placed third in the DARPA AI Cyber Challenge finals, lending significant credibility to the claim.

This represents a notable milestone in AI‑assisted vulnerability research: an automated system identified a decade‑old, non‑obvious logic bug in a highly security‑sensitive part of the kernel that had previously evaded human detection.

---

## Comparison: Copy Fail vs Previous Page‑Cache Vulnerabilities

| Vulnerability | Year | Type | Exploit Characteristics |
|---------------|------|------|--------------------------|
| **Dirty COW (CVE‑2016‑5195)** | 2016 | Race condition | Timing‑dependent; unreliable in practice |
| **Dirty Pipe (CVE‑2022‑0847)** | 2022 | Pipe buffer over‑write | Required specific pipe flag settings |
| **Copy Fail (CVE‑2026‑31431)** | 2026 | **Logic flaw** | **No race, deterministic, universal** |

*Comparison matrix*

---

## Conclusion

CVE-2026‑31431 (Copy Fail) stands as one of the most impactful Linux kernel privilege escalation vulnerabilities discovered in years. It combines a long‑present logic flaw, a simple 732‑byte exploit, and universal applicability across virtually all Linux distributions released since 2017. The attack is stealthy (memory‑only corruption), reliable (no race conditions), and dangerous in shared environments such as multi‑tenant clouds, CI/CD pipelines, and Kubernetes clusters.

Until vendor patch rollouts complete, organisations are strongly advised to apply temporary mitigations — disabling the `algif_aead` module or setting `no_new_privs` on workloads — and to prioritise kernel updates as soon as they become available.

---

## References

- Official disclosure and technical deep‑dive: [https://copy.fail](https://copy.fail)
- Original PoC: [theori‑io/copy‑fail‑CVE‑2026‑31431](https://github.com/theori-io/copy-fail-CVE-2026-31431)
- OSS‑security disclosure: [CVE‑2026‑31431: CopyFail: linux local privilege escalation](https://openwall.com/lists/oss-security/2026/04/29/23)
- Microsoft Defender analysis: [CVE‑2026‑31431: Copy Fail vulnerability enables Linux root privilege escalation across cloud environments](https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-vulnerability-enables-linux-root-privilege-escalation/)
- CERT‑EU advisory: [Security Advisory 2026‑005](https://www.cert.europa.eu/publications/security-advisories/2026-005/)
