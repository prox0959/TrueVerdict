#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TrueVerdict - Deterministic PE Provenance & False-Positive Reduction Engine
===========================================================================
Zero-dependency Windows binary triage engine that eliminates false positives
on legitimate OS binaries, developer builds, and packed installers by combining:
  - Dual-path Cryptographic Verification (Embedded Authenticode + OS Security Catalogs)
  - Rich Header ('DanS') XOR Decryption & ROL32 Checksum Validation
  - Windows 10/11 Reproducible Build (IMAGE_DEBUG_TYPE_REPRO) Recognition
  - Differential Section Entropy (.text vs .rsrc / Application Containers)
  - Combinatorial Import Table (IAT) Density Profiling
  - Multi-Vector Corroboration Gating (Unsigned != Malicious)

Author : Cinar (@prox0959)
License: MIT
"""

import argparse
from dataclasses import asdict
import json
import os
import sys
from typing import List

from benchmark_suite import run_live_benchmark
from fp_suppressor import FalsePositiveSuppressor, VerdictReport
from pe_analyzer import PEAnalysisReport, PEAnalyzer
from trust_verifier import SignatureResult, TrustVerifier


def print_detailed_report(pe: PEAnalysisReport, sig: SignatureResult, verdict: VerdictReport) -> None:
    print("=" * 84)
    print(f"  TRUEVERDICT FORENSIC TRIAGE REPORT : {pe.file_name}")
    print("=" * 84)
    if not pe.is_valid_pe:
        print(f"  [!] Not a valid PE binary: {pe.error_message}")
        print("=" * 84)
        return

    print(f"  File Path         : {pe.file_path}")
    print(f"  File Size         : {pe.file_size:,} bytes")
    print(f"  SHA-256           : {pe.sha256}")
    print(f"  Imphash (MD5)     : {pe.imphash or 'N/A (No static imports)'}")
    print(f"  Architecture      : {pe.architecture} | Linker: {pe.linker_version} | Container: {pe.detected_container}")
    print(
        f"  Compile Timestamp : {pe.compile_date_utc} "
        f"{'[REPRODUCIBLE_BUILD_HASH]' if pe.is_reproducible_build else ''}"
    )

    print("\n  [1] CRYPTOGRAPHIC PROVENANCE (AUTHENTICODE + OS CATALOG)")
    print("  " + "-" * 78)
    print(f"  Verification Mode : {sig.signature_type}")
    print(f"  Status            : {sig.status_label}")
    print(f"  Verified Signer   : {sig.signer_subject or 'None'}")
    print(f"  Certificate Issuer: {sig.issuer_subject or 'None'}")
    if sig.catalog_path:
        print(f"  OS Security Cat   : {sig.catalog_path}")

    print("\n  [2] COMPILER PROVENANCE (RICH HEADER & DEBUG METADATA)")
    print("  " + "-" * 78)
    if pe.rich_header.present:
        chk_status = "VALID (Authentic MSVC Build)" if pe.rich_header.checksum_valid else "MISMATCH (Forged/Tampered)"
        print(
            f"  Rich Header (DanS): Present | XOR Key: 0x{pe.rich_header.xor_key:08X} | "
            f"ROL32 Checksum: {chk_status}"
        )
        print(f"  Toolchain Objects : {pe.rich_header.entry_count} @comp.id records")
    else:
        print("  Rich Header (DanS): Not Present (Non-MSVC compiler or stripped)")
    if pe.has_debug_pdb:
        print(f"  CodeView PDB Path : {pe.pdb_path}")

    print("\n  [3] DIFFERENTIAL SECTION ENTROPY & MEMORY PERMISSIONS")
    print("  " + "-" * 78)
    print(
        f"  Overall Entropy   : {pe.overall_entropy:.3f} | "
        f"Executable (.text): {pe.code_entropy:.3f} | "
        f"Resources (.rsrc): {pe.resource_entropy:.3f}"
    )
    print(f"  {'SECTION':<10} {'CATEGORY':<18} {'VSIZE':>10} {'RAWSIZE':>10} {'ENTROPY':>9} {'PERMS'}")
    for sec in pe.sections:
        perms = (
            ("R" if (sec.characteristics & 0x40000000) else "-")
            + ("W" if sec.is_writable else "-")
            + ("X" if sec.is_executable else "-")
        )
        rwx_tag = " [RWX!]" if sec.is_rwx else ""
        print(
            f"  {sec.name:<10} {sec.category:<18} {sec.virtual_size:>10,} "
            f"{sec.raw_size:>10,} {sec.entropy:>9.3f} {perms}{rwx_tag}"
        )

    print("\n  [4] IMPORT DENSITY & CAPABILITY CLUSTERING")
    print("  " + "-" * 78)
    print(
        f"  Imported DLLs     : {len(pe.imported_dlls)} | "
        f"Total Functions: {pe.total_imported_functions} | "
        f"Benign CRT/OS Functions: {pe.benign_import_count}"
    )
    if pe.capability_clusters:
        print(f"  Capability Hits   : {'; '.join(pe.capability_clusters)}")
    else:
        print("  Capability Hits   : None (No concentrated offensive API chains)")

    print("\n  [5] FALSE-POSITIVE SUPPRESSION & CORROBORATION MATRIX")
    print("  " + "-" * 78)
    if verdict.trust_anchors:
        for item in verdict.trust_anchors:
            print(f"  [+] TRUST ANCHOR  [{item.layer:<22}] ({item.weight:+d}) {item.description}")
    if verdict.suppressed_false_positives:
        for item in verdict.suppressed_false_positives:
            print(f"  [~] FP SUPPRESSED [{item.layer:<22}] (-{item.weight:d}) {item.description}")
    if verdict.risk_factors:
        for item in verdict.risk_factors:
            print(f"  [!] RISK VECTOR   [{item.layer:<22}] (+{item.weight:d}) {item.description}")
    if not verdict.risk_factors:
        print("  [*] Active Risk Vectors: 0 (Zero corroborated threat indicators)")

    print("\n" + "=" * 84)
    print(
        f"  NAIVE HEURISTIC SCORE : {verdict.raw_heuristic_score}/100  -->  "
        f"TRUEVERDICT FINAL SCORE : {verdict.final_risk_score}/100 "
        f"(-{verdict.fp_reduction_points} FP noise suppressed)"
    )
    print(
        f"  FINAL VERDICT         : {verdict.verdict} "
        f"(Confidence: {verdict.confidence_pct}% | Corroborated Layers: {verdict.active_risk_vectors})"
    )
    print("=" * 84)


def scan_directory(dir_path: str, limit: int) -> List[VerdictReport]:
    analyzer = PEAnalyzer()
    verifier = TrustVerifier()
    suppressor = FalsePositiveSuppressor()

    reports: List[VerdictReport] = []
    pe_exts = (".exe", ".dll", ".sys", ".scr", ".cpl")

    files_to_scan: List[str] = []
    for root, _, files in os.walk(dir_path):
        for fn in files:
            if fn.lower().endswith(pe_exts):
                files_to_scan.append(os.path.join(root, fn))
                if len(files_to_scan) >= limit:
                    break
        if len(files_to_scan) >= limit:
            break

    print("=" * 88)
    print(f"  TRUEVERDICT DIRECTORY TRIAGE : {dir_path} ({len(files_to_scan)} binaries)")
    print("=" * 88)
    print(f"{'BINARY':<28} | {'SIGNATURE MODE':<22} | {'NAIVE':<5} | {'FINAL':<5} | {'VERDICT'}")
    print("-" * 88)

    for path in files_to_scan:
        pe_rep = analyzer.analyze(path)
        if not pe_rep.is_valid_pe:
            continue
        sig_rep = verifier.verify_file(path, has_embedded_cert_table=pe_rep.has_embedded_cert_table)
        verdict = suppressor.evaluate(pe_rep, sig_rep)
        reports.append(verdict)
        print(
            f"{verdict.file_name[:28]:<28} | "
            f"{verdict.signature_summary[:22]:<22} | "
            f"{verdict.raw_heuristic_score:>5} | "
            f"{verdict.final_risk_score:>5} | "
            f"{verdict.verdict} ({verdict.confidence_pct}%)"
        )

    print("=" * 88)
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TrueVerdict - Zero-Dependency PE Provenance & False-Positive Reduction Engine"
    )
    parser.add_argument("target", nargs="?", help="Path to a PE binary (.exe, .dll, .sys) to analyze")
    parser.add_argument("--dir", help="Scan a directory of PE binaries")
    parser.add_argument("--limit", type=int, default=25, help="Max binaries to scan in --dir mode")
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run live False-Positive Stress Benchmark on host OS binaries + synthetic threats",
    )
    parser.add_argument("--json", help="Export detailed triage verdict to a JSON file")

    args = parser.parse_args()

    if args.benchmark:
        return run_live_benchmark()

    if args.dir:
        reports = scan_directory(args.dir, args.limit)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump([asdict(r) for r in reports], f, indent=2)
            print(f"[+] Saved JSON directory report to: {args.json}")
        return 0

    if not args.target:
        parser.print_help()
        print("\nTip: Run 'python trueverdict.py --benchmark' to execute the live 0% False-Positive stress test.")
        return 0

    analyzer = PEAnalyzer()
    verifier = TrustVerifier()
    suppressor = FalsePositiveSuppressor()

    pe_rep = analyzer.analyze(args.target)
    sig_rep = verifier.verify_file(args.target, has_embedded_cert_table=pe_rep.has_embedded_cert_table)
    verdict = suppressor.evaluate(pe_rep, sig_rep)

    print_detailed_report(pe_rep, sig_rep, verdict)

    if args.json:
        payload = {
            "verdict": asdict(verdict),
            "pe_analysis": asdict(pe_rep),
            "signature": asdict(sig_rep),
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"[+] Exported JSON report to: {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
