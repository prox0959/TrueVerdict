#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TrueVerdict - Live False-Positive Stress Benchmark & Adversarial Test Suite
===========================================================================
Empirically proves TrueVerdict's near-zero False Positive rate by evaluating:
  1. Real Windows System32 / SysWOW64 / Developer binaries on the host OS
     (testing Catalog signing, Reproducible Build timestamps, .rsrc entropy,
     and unsigned clean developer builds).
  2. Synthetic Adversarial PE64 Specimens (testing RWX shellcode stubs,
     Process Hollowing IAT clusters, Rich Header forgery, Authenticode
     byte-tampering, and svchost.exe masquerading/typosquatting).
"""

import os
import random
import struct
import sys
import tempfile
import time
from typing import List, Tuple

from fp_suppressor import FalsePositiveSuppressor, VerdictReport
from pe_analyzer import PEAnalyzer, _rol32
from trust_verifier import TrustVerifier


class SyntheticPEBuilder:
    """
    Constructs valid, inert PE32+ (64-bit) binaries in a temporary folder to
    deterministically test both clean unsigned developer builds and adversarial
    malware anomalies without any executable payload.
    """

    @staticmethod
    def build_pe64(
        *,
        valid_rich_header: bool = True,
        repro_debug: bool = False,
        timestamp: int = 1710000000,
        rwx_code: bool = False,
        high_code_entropy: bool = False,
        imports: List[Tuple[str, List[str]]] = None,
        fake_cert_table: bool = False,
        spoof_ms_version: bool = False,
    ) -> bytes:
        buf = bytearray(0x4000)

        # 1. DOS Header
        struct.pack_into("<H", buf, 0x00, 0x5A4D)  # MZ
        e_lfanew = 0x100
        struct.pack_into("<I", buf, 0x3C, e_lfanew)

        # 2. Optional Rich Header at 0x80..0xB0
        if valid_rich_header is not None:
            dans_pos = 0x80
            entries = [(0x0104, 30139, 12), (0x0105, 30139, 8)]
            checksum = dans_pos
            for i in range(dans_pos):
                if 0x3C <= i < 0x40:
                    continue
                checksum = (checksum + _rol32(buf[i], i)) & 0xFFFFFFFF
            for prod_id, build_num, count in entries:
                comp_id = (prod_id << 16) | build_num
                checksum = (checksum + _rol32(comp_id, count)) & 0xFFFFFFFF

            xor_key = checksum if valid_rich_header else (checksum ^ 0xDEADBEEF)
            struct.pack_into("<I", buf, dans_pos, 0x536E6144 ^ xor_key)  # "DanS"
            struct.pack_into("<I", buf, dans_pos + 4, xor_key)
            struct.pack_into("<I", buf, dans_pos + 8, xor_key)
            struct.pack_into("<I", buf, dans_pos + 12, xor_key)

            cur = dans_pos + 16
            for prod_id, build_num, count in entries:
                comp_id = (prod_id << 16) | build_num
                struct.pack_into("<I", buf, cur, comp_id ^ xor_key)
                struct.pack_into("<I", buf, cur + 4, count ^ xor_key)
                cur += 8

            buf[cur : cur + 4] = b"Rich"
            struct.pack_into("<I", buf, cur + 4, xor_key)

        # 3. NT Headers (PE\0\0 + COFF + OptionalHeader64)
        struct.pack_into("<I", buf, e_lfanew, 0x00004550)
        coff_off = e_lfanew + 4
        num_sections = 3
        opt_size = 240
        struct.pack_into(
            "<HHIIIHH",
            buf,
            coff_off,
            0x8664,      # AMD64
            num_sections,
            timestamp,
            0,
            0,
            opt_size,
            0x0022,      # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        )

        opt_off = coff_off + 20
        struct.pack_into("<HBB", buf, opt_off, 0x20B, 14, 38)  # PE32+, MSVC 14.38
        struct.pack_into("<I", buf, opt_off + 16, 0x1000)      # EntryPoint RVA
        struct.pack_into("<Q", buf, opt_off + 24, 0x140000000) # ImageBase
        struct.pack_into("<II", buf, opt_off + 32, 0x1000, 0x200)
        struct.pack_into("<I", buf, opt_off + 56, 0x5000)      # SizeOfImage
        struct.pack_into("<I", buf, opt_off + 60, 0x400)       # SizeOfHeaders
        struct.pack_into("<HH", buf, opt_off + 68, 3, 0x8160)  # CUI, ASLR+DEP+CFG
        struct.pack_into("<I", buf, opt_off + 108, 16)         # NumberOfRvaAndSizes

        dd_off = opt_off + 112

        # Section Table at opt_off + 240
        sec_off = opt_off + opt_size

        # Section 1: .text (RVA 0x1000, Raw 0x400, Size 0x1000)
        text_chars = 0x60000020 | (0x80000000 if rwx_code else 0)
        buf[sec_off : sec_off + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIIIIIHHI", buf, sec_off + 8, 0x1000, 0x1000, 0x1000, 0x400, 0, 0, 0, 0, text_chars)

        # Section 2: .rdata (RVA 0x2000, Raw 0x1400, Size 0x1000) -> Imports & Debug
        s2_off = sec_off + 40
        buf[s2_off : s2_off + 8] = b".rdata\x00\x00"
        struct.pack_into("<IIIIIIHHI", buf, s2_off + 8, 0x1000, 0x2000, 0x1000, 0x1400, 0, 0, 0, 0, 0x40000040)

        # Section 3: .rsrc (RVA 0x3000, Raw 0x2400, Size 0x1000) -> Version Info
        s3_off = sec_off + 80
        buf[s3_off : s3_off + 8] = b".rsrc\x00\x00\x00"
        struct.pack_into("<IIIIIIHHI", buf, s3_off + 8, 0x1000, 0x3000, 0x1000, 0x2400, 0, 0, 0, 0, 0x40000040)

        # Fill .text content
        if high_code_entropy:
            rng = random.Random(42)
            buf[0x400:0x1400] = bytes(rng.getrandbits(8) for _ in range(0x1000))
        else:
            # Realistic low-entropy x64 prologue/epilogue pattern
            pattern = b"\x48\x89\x5c\x24\x08\x48\x83\xec\x20\x33\xc0\x48\x83\xc4\x20\xc3"
            buf[0x400:0x1400] = pattern * (0x1000 // len(pattern))

        # Populate Imports in .rdata (Raw 0x1400 -> RVA 0x2000)
        if imports:
            struct.pack_into("<II", buf, dd_off + 1 * 8, 0x2000, 0x200)
            desc_cursor = 0x1400
            thunk_cursor = 0x1500
            str_cursor = 0x1800

            for dll_name, func_list in imports:
                dll_rva = 0x2000 + (str_cursor - 0x1400)
                dll_bytes = dll_name.encode("ascii") + b"\x00"
                buf[str_cursor : str_cursor + len(dll_bytes)] = dll_bytes
                str_cursor += len(dll_bytes)

                thunk_rva = 0x2000 + (thunk_cursor - 0x1400)
                for fn in func_list:
                    hint_rva = 0x2000 + (str_cursor - 0x1400)
                    fn_bytes = b"\x00\x00" + fn.encode("ascii") + b"\x00"
                    buf[str_cursor : str_cursor + len(fn_bytes)] = fn_bytes
                    str_cursor += len(fn_bytes)
                    struct.pack_into("<Q", buf, thunk_cursor, hint_rva)
                    thunk_cursor += 8
                # Null terminator thunk
                struct.pack_into("<Q", buf, thunk_cursor, 0)
                thunk_cursor += 8

                struct.pack_into("<IIIII", buf, desc_cursor, thunk_rva, 0, 0, dll_rva, thunk_rva)
                desc_cursor += 20

        # Optional Reproducible Build Debug Entry in .rdata (offset 0x1D00 -> RVA 0x2900)
        if repro_debug:
            struct.pack_into("<II", buf, dd_off + 6 * 8, 0x2900, 28)
            struct.pack_into("<IIHHIIII", buf, 0x1D00, 0, timestamp, 0, 0, 16, 0, 0, 0)

        # Optional Version Info string in .rsrc (offset 0x2500)
        if spoof_ms_version:
            blob = (
                "CompanyName".encode("utf-16-le")
                + b"\x00\x00"
                + "Microsoft Corporation".encode("utf-16-le")
                + b"\x00\x00"
            )
            buf[0x2500 : 0x2500 + len(blob)] = blob

        # Optional Corrupt/Tampered PKCS#7 Security Directory
        if fake_cert_table:
            cert_off = 0x3400
            cert_len = 0x200
            struct.pack_into("<II", buf, dd_off + 4 * 8, cert_off, cert_len)
            struct.pack_into("<IHH", buf, cert_off, cert_len, 0x0200, 0x0002)
            buf[cert_off + 8 : cert_off + cert_len] = b"\x30\x82\x01\xf0" + b"\xaa" * (cert_len - 12)

        return bytes(buf)


def run_live_benchmark() -> int:
    analyzer = PEAnalyzer()
    verifier = TrustVerifier()
    suppressor = FalsePositiveSuppressor()

    print("=" * 86)
    print("  TRUEVERDICT - LIVE FALSE-POSITIVE STRESS BENCHMARK & ADVERSARIAL VALIDATION")
    print("=" * 86)

    # 1. Discover legitimate Windows & Developer binaries on the host machine
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    sys32 = os.path.join(sys_root, "System32")
    candidate_names = [
        "notepad.exe",
        "cmd.exe",
        "svchost.exe",
        "calc.exe",
        "taskmgr.exe",
        "conhost.exe",
        "dwm.exe",
        "explorer.exe",
        "regedit.exe",
        "whoami.exe",
        "ipconfig.exe",
        "ping.exe",
        "netstat.exe",
        "certutil.exe",
        "rundll32.exe",
        "msiexec.exe",
        "dllhost.exe",
        "services.exe",
        "lsass.exe",
        "spoolsv.exe",
        "taskhostw.exe",
        "RuntimeBroker.exe",
        "findstr.exe",
        "attrib.exe",
        "sc.exe",
        "WindowsPowerShell\\v1.0\\powershell.exe",
        "kernel32.dll",
        "ntdll.dll",
        "user32.dll",
        "advapi32.dll",
    ]

    legit_paths: List[str] = []
    for rel in candidate_names:
        p = os.path.join(sys32, rel) if not os.path.isabs(rel) else rel
        if not os.path.isfile(p):
            alt = os.path.join(sys_root, rel)
            if os.path.isfile(alt):
                p = alt
        if os.path.isfile(p) and p not in legit_paths:
            legit_paths.append(p)

    if os.path.isfile(sys.executable) and sys.executable not in legit_paths:
        legit_paths.append(sys.executable)

    with tempfile.TemporaryDirectory(prefix="trueverdict_bench_") as tmpdir:
        # Also include a clean, UNSIGNED developer C/C++ build to prove Unsigned != False Positive!
        clean_unsigned_path = os.path.join(tmpdir, "clean_unsigned_dev_tool.exe")
        with open(clean_unsigned_path, "wb") as f:
            f.write(
                SyntheticPEBuilder.build_pe64(
                    valid_rich_header=True,
                    repro_debug=False,
                    timestamp=1711100000,
                    rwx_code=False,
                    high_code_entropy=False,
                    imports=[
                        ("KERNEL32.dll", ["GetCurrentProcessId", "GetSystemTimeAsFileTime", "ExitProcess"]),
                        ("ucrtbase.dll", ["printf", "malloc", "free", "exit"]),
                    ],
                )
            )
        legit_paths.append(clean_unsigned_path)

        print(f"\n[PHASE 1] Scanning {len(legit_paths)} Legitimate OS & Developer Binaries...")
        print("-" * 86)
        print(f"{'BINARY NAME':<28} | {'SIGNING MODE':<22} | {'NAIVE':<6} | {'FINAL':<6} | {'VERDICT'}")
        print("-" * 86)

        t0 = time.perf_counter()
        naive_fp_count = 0
        trueverdict_fp_count = 0
        total_fp_points_saved = 0

        for path in legit_paths:
            pe_rep = analyzer.analyze(path)
            sig_rep = verifier.verify_file(path, has_embedded_cert_table=pe_rep.has_embedded_cert_table)
            verdict = suppressor.evaluate(pe_rep, sig_rep)

            if verdict.raw_heuristic_score >= 45:
                naive_fp_count += 1
            if verdict.verdict in ("SUSPICIOUS", "MALICIOUS"):
                trueverdict_fp_count += 1
            total_fp_points_saved += verdict.fp_reduction_points

            print(
                f"{verdict.file_name[:28]:<28} | "
                f"{verdict.signature_summary[:22]:<22} | "
                f"{verdict.raw_heuristic_score:>5}  | "
                f"{verdict.final_risk_score:>5}  | "
                f"{verdict.verdict} ({verdict.confidence_pct}%)"
            )

        # 2. Construct and test 5 Adversarial Malware Specimens
        threat_specs: List[Tuple[str, str, bytes]] = [
            (
                "svchost.exe",
                "Masqueraded System Binary outside System32 + Spoofed MS VersionInfo",
                SyntheticPEBuilder.build_pe64(
                    valid_rich_header=False,
                    spoof_ms_version=True,
                    imports=[("KERNEL32.dll", ["OpenProcess", "VirtualAllocEx"])],
                ),
            ),
            (
                "scvhost.exe",
                "Process Typosquatting (scvhost.exe) + Forged Rich Header Checksum",
                SyntheticPEBuilder.build_pe64(
                    valid_rich_header=False,
                    imports=[("KERNEL32.dll", ["CreateProcessW"])],
                ),
            ),
            (
                "reflective_rwx_stub.exe",
                "RWX Shellcode Section + High Code Entropy (7.8+) + Stripped IAT (0 Imports)",
                SyntheticPEBuilder.build_pe64(
                    valid_rich_header=None,
                    rwx_code=True,
                    high_code_entropy=True,
                    imports=None,
                ),
            ),
            (
                "hollow_injector.exe",
                "Process Hollowing IAT Cluster + Sparse Imports + Forged Rich Header",
                SyntheticPEBuilder.build_pe64(
                    valid_rich_header=False,
                    timestamp=0x11223344,
                    imports=[
                        (
                            "KERNEL32.dll",
                            [
                                "VirtualAllocEx",
                                "WriteProcessMemory",
                                "CreateRemoteThread",
                                "SetThreadContext",
                                "ResumeThread",
                            ],
                        ),
                        ("ntdll.dll", ["NtUnmapViewOfSection"]),
                    ],
                ),
            ),
            (
                "tampered_cert_implant.exe",
                "Byte-Patched Binary with Invalid/Corrupt Authenticode PKCS#7 Signature",
                SyntheticPEBuilder.build_pe64(
                    valid_rich_header=False,
                    fake_cert_table=True,
                    imports=[("KERNEL32.dll", ["VirtualAlloc", "CreateThread"])],
                ),
            ),
        ]

        print(f"\n[PHASE 2] Scanning {len(threat_specs)} Synthetic Adversarial Threat Specimens...")
        print("-" * 86)
        print(f"{'THREAT SPECIMEN':<28} | {'PRIMARY DETECTION VECTORS':<28} | {'SCORE':<6} | {'VERDICT'}")
        print("-" * 86)

        tp_detected = 0
        for fname, desc, raw_bytes in threat_specs:
            t_path = os.path.join(tmpdir, fname)
            with open(t_path, "wb") as f:
                f.write(raw_bytes)
            pe_rep = analyzer.analyze(t_path)
            sig_rep = verifier.verify_file(t_path, has_embedded_cert_table=pe_rep.has_embedded_cert_table)
            verdict = suppressor.evaluate(pe_rep, sig_rep)

            if verdict.verdict in ("MALICIOUS", "SUSPICIOUS"):
                tp_detected += 1

            layers_str = ",".join(r.layer[:9] for r in verdict.risk_factors[:2])
            print(
                f"{verdict.file_name[:28]:<28} | "
                f"{layers_str[:28]:<28} | "
                f"{verdict.final_risk_score:>5}  | "
                f"{verdict.verdict} ({verdict.confidence_pct}%)"
            )

        elapsed = time.perf_counter() - t0

        naive_fpr = (naive_fp_count / len(legit_paths)) * 100.0
        tv_fpr = (trueverdict_fp_count / len(legit_paths)) * 100.0
        tv_tpr = (tp_detected / len(threat_specs)) * 100.0

        print("\n" + "=" * 86)
        print("  BENCHMARK SUMMARY: NAIVE HEURISTICS vs. TRUEVERDICT CORROBORATION ENGINE")
        print("=" * 86)
        print(f"  Total Binaries Evaluated           : {len(legit_paths) + len(threat_specs)} ({elapsed:.2f}s)")
        print(f"  Naive Heuristic False Positives    : {naive_fp_count}/{len(legit_paths)} ({naive_fpr:.2f}% FPR)")
        print(f"  TrueVerdict False Positives        : {trueverdict_fp_count}/{len(legit_paths)} ({tv_fpr:.2f}% FPR)")
        print(f"  Total False-Positive Risk Suppressed: -{total_fp_points_saved} heuristic noise points")
        print(f"  Adversarial Threat Detection Rate  : {tp_detected}/{len(threat_specs)} ({tv_tpr:.2f}% TPR)")
        print("=" * 86)

        return 0 if (trueverdict_fp_count == 0 and tp_detected == len(threat_specs)) else 1


if __name__ == "__main__":
    sys.exit(run_live_benchmark())
