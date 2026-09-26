#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TrueVerdict - Multi-Gate Bayesian False-Positive Suppression Engine
===================================================================
Implements a deterministic corroboration matrix designed to drive false-positive
rates to near-zero (0.0%) on legitimate OS binaries, developer builds, packed
installers, and JIT runtimes, while isolating genuine malware implants.

Core Engineering Principles:
  1. Unsigned != Malicious: Lack of a signature adds 0 baseline risk on its own.
     Local developer builds (MSVC, Clang, MinGW, Rust, Go) are never penalized
     merely for being unsigned.
  2. Multi-Vector Corroboration Gate: A binary cannot be classified as SUSPICIOUS
     or MALICIOUS from a single heuristic trigger (unless a cryptographic
     digest is actively tampered or a critical OS binary is masqueraded).
  3. Active False-Positive Suppression Logging: Explicitly records every naive
     heuristic alert that was neutralized by contextual evidence (e.g., Repro
     build timestamps, .rsrc entropy, OS Catalog signatures, high-density IAT).
"""

from dataclasses import dataclass, field
import datetime
import os
from typing import List, Tuple

from pe_analyzer import PEAnalysisReport
from trust_verifier import SignatureResult


@dataclass
class EvidenceItem:
    layer: str
    description: str
    weight: int          # Positive = risk indicator, Negative = trust/mitigation credit
    category: str        # "RISK_VECTOR", "TRUST_ANCHOR", "FP_SUPPRESSED"


@dataclass
class VerdictReport:
    file_path: str
    file_name: str
    sha256: str
    verdict: str                     # "BENIGN", "LOW_RISK_ANOMALY", "SUSPICIOUS", "MALICIOUS"
    confidence_pct: float            # e.g. 99.4%
    raw_heuristic_score: int         # What a naive scanner would have scored
    final_risk_score: int            # 0 - 100 after FP suppression & corroboration gates
    fp_reduction_points: int         # Points saved by False-Positive Suppression
    active_risk_vectors: int         # Count of independent corroborated risk layers
    signature_summary: str
    publisher: str
    container_type: str
    risk_factors: List[EvidenceItem] = field(default_factory=list)
    trust_anchors: List[EvidenceItem] = field(default_factory=list)
    suppressed_false_positives: List[EvidenceItem] = field(default_factory=list)


class FalsePositiveSuppressor:
    """
    Evaluates PE structural analysis + Win32 cryptographic trust through a
    7-Layer Corroboration & False-Positive Suppression Matrix.
    """

    # Critical Windows system processes frequently targeted for masquerading / typosquatting
    PROTECTED_SYSTEM_BINARIES = {
        "svchost.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\"),
        "lsass.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "csrss.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "smss.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "services.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "wininit.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "winlogon.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "dwm.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "spoolsv.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "taskhostw.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "RuntimeBroker.exe": ("\\windows\\system32\\", "\\windows\\winsxs\\"),
        "explorer.exe": ("\\windows\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\"),
    }

    def evaluate(self, pe: PEAnalysisReport, sig: SignatureResult) -> VerdictReport:
        if not pe.is_valid_pe:
            return VerdictReport(
                file_path=pe.file_path,
                file_name=pe.file_name,
                sha256=pe.sha256,
                verdict="INVALID_PE",
                confidence_pct=100.0,
                raw_heuristic_score=0,
                final_risk_score=0,
                fp_reduction_points=0,
                active_risk_vectors=0,
                signature_summary="N/A",
                publisher="N/A",
                container_type="NOT_A_PE_BINARY",
            )

        risks: List[EvidenceItem] = []
        anchors: List[EvidenceItem] = []
        suppressed: List[EvidenceItem] = []
        independent_layers_triggered = set()

        naive_score = 0

        # -------------------------------------------------------------------
        # LAYER 1: Cryptographic Authenticode & OS Security Catalog Gate
        # -------------------------------------------------------------------
        if sig.is_trusted:
            credit = -75 if sig.is_microsoft_signed else -60
            anchors.append(
                EvidenceItem(
                    layer="L1_CRYPTO_TRUST",
                    description=f"{sig.status_label} ({sig.signer_subject})",
                    weight=credit,
                    category="TRUST_ANCHOR",
                )
            )
            if sig.signature_type == "OS_CATALOG":
                # A naive scanner only checking embedded PKCS#7 would flag this as unsigned
                naive_score += 20
                suppressed.append(
                    EvidenceItem(
                        layer="L1_CATALOG_RECOVERY",
                        description=(
                            f"Binary has no embedded Authenticode table, but matched verified OS Catalog "
                            f"({os.path.basename(sig.catalog_path)})"
                        ),
                        weight=20,
                        category="FP_SUPPRESSED",
                    )
                )
        elif sig.signature_type == "INVALID_OR_TAMPERED" or pe.has_embedded_cert_table:
            naive_score += 85
            independent_layers_triggered.add("L1_CRYPTO_TAMPER")
            desc = (
                f"Cryptographic signature validation failed: {sig.status_label}"
                if sig.signature_type == "INVALID_OR_TAMPERED"
                else f"Malformed or tampered WIN_CERTIFICATE table ({pe.embedded_cert_size} bytes) rejected by WinVerifyTrust"
            )
            risks.append(
                EvidenceItem(
                    layer="L1_CRYPTO_TAMPER",
                    description=desc,
                    weight=85,
                    category="RISK_VECTOR",
                )
            )
        else:
            # UNSIGNED: Naive scanners penalize unsigned binaries by +20.
            # TrueVerdict suppresses standalone unsigned penalties (Unsigned != Malicious).
            naive_score += 20
            suppressed.append(
                EvidenceItem(
                    layer="L1_UNSIGNED_NEUTRAL",
                    description="Unsigned binary penalty suppressed (Unsigned alone is not a threat indicator)",
                    weight=20,
                    category="FP_SUPPRESSED",
                )
            )

        # -------------------------------------------------------------------
        # LAYER 2: Rich Header (DanS) Checksum & Compiler Provenance Gate
        # -------------------------------------------------------------------
        if pe.rich_header.present:
            if pe.rich_header.checksum_valid:
                if "L1_CRYPTO_TAMPER" not in independent_layers_triggered:
                    anchors.append(
                        EvidenceItem(
                            layer="L2_RICH_PROVENANCE",
                            description=(
                                f"Authentic MSVC Rich Header ('DanS') verified via ROL32 checksum "
                                f"(0x{pe.rich_header.xor_key:08X}, {pe.rich_header.entry_count} toolchain build objects)"
                            ),
                            weight=-15,
                            category="TRUST_ANCHOR",
                        )
                    )
            else:
                naive_score += 35
                independent_layers_triggered.add("L2_RICH_FORGERY")
                risks.append(
                    EvidenceItem(
                        layer="L2_RICH_FORGERY",
                        description=(
                            f"Corrupted or forged Rich Header: embedded key 0x{pe.rich_header.xor_key:08X} "
                            f"!= recomputed ROL32 0x{pe.rich_header.computed_checksum:08X}"
                        ),
                        weight=35,
                        category="RISK_VECTOR",
                    )
                )

        # -------------------------------------------------------------------
        # LAYER 3: Reproducible Build (Brepro) vs. Timestamp Anomaly Gate
        # -------------------------------------------------------------------
        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        ts_anomalous = pe.compile_timestamp < 631152000 or pe.compile_timestamp > (now_ts + 86400 * 30)
        if ts_anomalous:
            naive_score += 25
            if pe.is_reproducible_build or sig.is_trusted:
                suppressed.append(
                    EvidenceItem(
                        layer="L3_BREPRO_TIMESTAMP",
                        description=(
                            f"Non-chronological PE TimeDateStamp (0x{pe.compile_timestamp:08X}) verified as "
                            f"deterministic Reproducible Build (IMAGE_DEBUG_TYPE_REPRO) hash"
                        ),
                        weight=25,
                        category="FP_SUPPRESSED",
                    )
                )
            else:
                independent_layers_triggered.add("L3_TIMESTAMP_ANOMALY")
                risks.append(
                    EvidenceItem(
                        layer="L3_TIMESTAMP_ANOMALY",
                        description=(
                            f"Anomalous COFF TimeDateStamp ({pe.compile_date_utc}) without "
                            f"IMAGE_DEBUG_TYPE_REPRO entry"
                        ),
                        weight=15,
                        category="RISK_VECTOR",
                    )
                )

        # -------------------------------------------------------------------
        # LAYER 4: Section Permissions & Differential Entropy Gate
        # -------------------------------------------------------------------
        # 4A. Check RWX (Write + Execute) memory permissions
        if pe.has_rwx_section:
            naive_score += 45
            if sig.is_trusted and pe.detected_container in ("INNO_SETUP_INSTALLER", "NSIS_INSTALLER"):
                suppressed.append(
                    EvidenceItem(
                        layer="L4_INSTALLER_RWX",
                        description=f"Signed installer stub RWX section ({', '.join(pe.rwx_section_names)}) suppressed",
                        weight=45,
                        category="FP_SUPPRESSED",
                    )
                )
            else:
                independent_layers_triggered.add("L4_RWX_MEMORY")
                risks.append(
                    EvidenceItem(
                        layer="L4_RWX_MEMORY",
                        description=(
                            f"Writable + Executable (RWX) section detected: {', '.join(pe.rwx_section_names)} "
                            f"(classic shellcode/unpacking stub indicator)"
                        ),
                        weight=40,
                        category="RISK_VECTOR",
                    )
                )

        # 4B. Context-Aware Entropy Evaluation
        if pe.overall_entropy >= 7.15 or pe.resource_entropy >= 7.25 or pe.overlay_entropy >= 7.25:
            naive_score += 30
            if pe.code_entropy < 7.10 and (pe.resource_entropy >= 7.15 or pe.overlay_entropy >= 7.15):
                # High entropy is strictly inside non-executable .rsrc or installer overlay!
                suppressed.append(
                    EvidenceItem(
                        layer="L4_BENIGN_RSRC_ENTROPY",
                        description=(
                            f"High file/resource entropy (Overall={pe.overall_entropy:.2f}, .rsrc={pe.resource_entropy:.2f}, "
                            f"overlay={pe.overlay_entropy:.2f}) suppressed because executable code entropy "
                            f"(.text={pe.code_entropy:.2f}) is normal"
                        ),
                        weight=30,
                        category="FP_SUPPRESSED",
                    )
                )
            elif pe.detected_container in (
                "DOTNET_CLR_ASSEMBLY",
                "PYINSTALLER_BUNDLE",
                "INNO_SETUP_INSTALLER",
                "NSIS_INSTALLER",
                "7ZIP_SFX_ARCHIVE",
                "ELECTRON_CHROMIUM_APP",
            ):
                suppressed.append(
                    EvidenceItem(
                        layer="L4_CONTAINER_ENTROPY",
                        description=(
                            f"High entropy ({pe.overall_entropy:.2f} bits/byte) suppressed for recognized "
                            f"application container: {pe.detected_container}"
                        ),
                        weight=30,
                        category="FP_SUPPRESSED",
                    )
                )
            elif pe.overlay_entropy >= 7.15 and pe.code_entropy < 7.10 and pe.resource_entropy < 7.15:
                # Overlay-only high entropy (e.g., appended archive/update data) with normal code — suppress
                suppressed.append(
                    EvidenceItem(
                        layer="L4_BENIGN_OVERLAY_ENTROPY",
                        description=(
                            f"High overlay entropy ({pe.overlay_entropy:.2f} bits/byte, {pe.overlay_size:,} bytes) "
                            f"suppressed: executable code entropy ({pe.code_entropy:.2f}) is within normal range"
                        ),
                        weight=30,
                        category="FP_SUPPRESSED",
                    )
                )

        if pe.code_entropy >= 7.35:
            naive_score += 35
            if sig.is_trusted:
                suppressed.append(
                    EvidenceItem(
                        layer="L4_SIGNED_HIGH_ENTROPY_CODE",
                        description=(
                            f"High executable section entropy ({pe.code_entropy:.2f}) suppressed due to "
                            f"valid cryptographic signature ({sig.signer_subject})"
                        ),
                        weight=35,
                        category="FP_SUPPRESSED",
                    )
                )
            elif pe.total_imported_functions < 15 or pe.has_rwx_section or pe.detected_container == "UPX_PACKED":
                independent_layers_triggered.add("L4_PACKED_CODE")
                risks.append(
                    EvidenceItem(
                        layer="L4_PACKED_CODE",
                        description=(
                            f"Encrypted/packed executable code section (entropy={pe.code_entropy:.2f} bits/byte) "
                            f"coupled with sparse IAT ({pe.total_imported_functions} imports)"
                        ),
                        weight=35,
                        category="RISK_VECTOR",
                    )
                )

        # -------------------------------------------------------------------
        # LAYER 5: Combinatorial IAT Profiling & Import Density Gate
        # -------------------------------------------------------------------
        if pe.suspicious_apis_found:
            naive_score += 35
            # Calculate whether this is a legitimate high-density runtime (e.g., Python, Chrome, Debugger)
            is_high_density_benign = (
                pe.total_imported_functions >= 55
                and pe.benign_import_count >= 12
                and (sig.is_trusted or pe.rich_header.checksum_valid)
            )
            if sig.is_trusted or is_high_density_benign:
                suppressed.append(
                    EvidenceItem(
                        layer="L5_DUAL_USE_API_SUPPRESSION",
                        description=(
                            f"Dual-use Win32 APIs ({', '.join(pe.suspicious_apis_found[:4])}) suppressed "
                            f"within high-density/trusted IAT ({pe.total_imported_functions} total imports)"
                        ),
                        weight=35,
                        category="FP_SUPPRESSED",
                    )
                )
            elif pe.capability_clusters:
                independent_layers_triggered.add("L5_OFFENSIVE_IAT_CLUSTER")
                cluster_weight = 40 if pe.total_imported_functions < 35 else 25
                risks.append(
                    EvidenceItem(
                        layer="L5_OFFENSIVE_IAT_CLUSTER",
                        description=(
                            f"Offensive API capability cluster in unsigned low-density binary "
                            f"({pe.total_imported_functions} total imports): {'; '.join(pe.capability_clusters)}"
                        ),
                        weight=cluster_weight,
                        category="RISK_VECTOR",
                    )
                )
            else:
                suppressed.append(
                    EvidenceItem(
                        layer="L5_SINGLE_API_SUPPRESSION",
                        description=(
                            f"Isolated sensitive API import ({', '.join(pe.suspicious_apis_found)}) "
                            f"lacks full injection/hollowing execution chain; suppressed"
                        ),
                        weight=35,
                        category="FP_SUPPRESSED",
                    )
                )

        # Extremely minimal or stripped Import Table on a native non-.NET binary
        if not pe.is_dotnet and pe.total_imported_functions == 0 and not sig.is_trusted:
            naive_score += 30
            independent_layers_triggered.add("L5_STRIPPED_IAT")
            risks.append(
                EvidenceItem(
                    layer="L5_STRIPPED_IAT",
                    description="Zero static imports (dynamic API hashing / reflective loader stub)",
                    weight=30,
                    category="RISK_VECTOR",
                )
            )

        # -------------------------------------------------------------------
        # LAYER 6: Path Canonicalization, Masquerading & Typosquatting Gate
        # -------------------------------------------------------------------
        masq_detected, masq_desc, masq_weight = self._check_masquerading(pe, sig)
        if masq_detected:
            naive_score += masq_weight
            independent_layers_triggered.add("L6_MASQUERADING")
            risks.append(
                EvidenceItem(
                    layer="L6_MASQUERADING",
                    description=masq_desc,
                    weight=masq_weight,
                    category="RISK_VECTOR",
                )
            )

        # -------------------------------------------------------------------
        # LAYER 7: Multi-Gate Corroboration & Final Score Synthesis
        # -------------------------------------------------------------------
        positive_risk_sum = sum(item.weight for item in risks)
        trust_credit_sum = sum(item.weight for item in anchors)  # Negative values
        suppressed_sum = sum(item.weight for item in suppressed)

        active_vectors = len(independent_layers_triggered)

        # High-severity deterministic triggers that bypass the 3-vector minimum:
        # 1. Cryptographically tampered signature (TRUST_E_BAD_DIGEST)
        # 2. Direct OS system process masquerading / typosquatting
        has_deterministic_override = (
            "L1_CRYPTO_TAMPER" in independent_layers_triggered
            or "L6_MASQUERADING" in independent_layers_triggered
        )

        raw_combined = max(0, positive_risk_sum + trust_credit_sum)

        if not has_deterministic_override and active_vectors < 2:
            # Gate B: Single isolated heuristic anomaly CANNOT flag a binary as suspicious!
            if raw_combined > 0:
                suppressed.append(
                    EvidenceItem(
                        layer="L7_CORROBORATION_GATE",
                        description=(
                            f"Single uncorroborated heuristic vector ({active_vectors} layer) blocked by "
                            f"Multi-Vector Corroboration Gate (requires >= 2 independent layers)"
                        ),
                        weight=raw_combined,
                        category="FP_SUPPRESSED",
                    )
                )
                suppressed_sum += raw_combined
                final_score = 0
            else:
                final_score = 0
        elif not has_deterministic_override and active_vectors == 2 and raw_combined >= 50:
            # Cap 2-vector non-cryptographic anomalies below MALICIOUS threshold unless score is extreme
            final_score = min(raw_combined, 65)
        else:
            final_score = min(100, raw_combined)

        # Classify Verdict & Confidence
        if final_score >= 70:
            verdict = "MALICIOUS"
            confidence = min(99.8, 85.0 + (final_score - 70) * 0.48)
        elif final_score >= 45:
            verdict = "SUSPICIOUS"
            confidence = round(75.0 + (final_score - 45) * 0.6, 1)
        elif final_score >= 20:
            verdict = "LOW_RISK_ANOMALY"
            confidence = 88.0
        else:
            verdict = "BENIGN"
            if sig.is_trusted:
                confidence = 99.9
            elif pe.rich_header.checksum_valid:
                confidence = 98.5
            else:
                confidence = 95.0

        return VerdictReport(
            file_path=pe.file_path,
            file_name=pe.file_name,
            sha256=pe.sha256,
            verdict=verdict,
            confidence_pct=round(confidence, 1),
            raw_heuristic_score=min(100, naive_score),
            final_risk_score=final_score,
            fp_reduction_points=suppressed_sum,
            active_risk_vectors=active_vectors,
            signature_summary=sig.signature_type,
            publisher=sig.signer_subject or "Unsigned",
            container_type=pe.detected_container,
            risk_factors=risks,
            trust_anchors=anchors,
            suppressed_false_positives=suppressed,
        )

    def _check_masquerading(
        self, pe: PEAnalysisReport, sig: SignatureResult
    ) -> Tuple[bool, str, int]:
        """
        Detects canonical Windows binary masquerading, typosquatting (Levenshtein distance 1),
        and internal VS_VERSIONINFO OriginalFilename spoofing.
        Uses strict SystemRoot prefix anchoring to prevent C:\\Temp\\windows\\system32\\ bypasses.
        """
        fname_low = pe.file_name.lower()
        norm_full = os.path.normcase(os.path.normpath(os.path.abspath(pe.file_path)))
        sys_root = os.path.normcase(
            os.path.normpath(os.environ.get("SystemRoot", r"C:\Windows"))
        )
        drive_root = os.path.splitdrive(sys_root)[0] or "c:"

        # 1. Exact filename match against protected Windows processes
        for sys_bin, valid_dirs in self.PROTECTED_SYSTEM_BINARIES.items():
            if fname_low == sys_bin.lower():
                anchored_prefixes = [
                    os.path.normcase(os.path.normpath(drive_root + vd)) + os.sep
                    for vd in valid_dirs
                ]
                in_valid_dir = any(norm_full.startswith(pref) for pref in anchored_prefixes)
                if not in_valid_dir and not sig.is_microsoft_signed:
                    return (
                        True,
                        f"Critical OS binary masquerade: '{pe.file_name}' executing outside canonical "
                        f"SystemRoot directory ({pe.file_path}) and lacks Microsoft signature",
                        85,
                    )
                if not sig.is_trusted:
                    return (
                        True,
                        f"Unsigned binary masquerading as protected Windows process '{pe.file_name}'",
                        85,
                    )

        # 2. Typosquatting check (Edit distance == 1 against protected processes, e.g., scvhost.exe, svch0st.exe, 1sass.exe)
        for sys_bin in self.PROTECTED_SYSTEM_BINARIES:
            target = sys_bin.lower()
            if fname_low != target and self._is_typosquat(fname_low, target):
                if not sig.is_microsoft_signed:
                    return (
                        True,
                        f"Process typosquatting detected: '{pe.file_name}' mimics protected system binary '{sys_bin}'",
                        80,
                    )

        # 3. VS_VERSIONINFO claims Microsoft Corporation on an unsigned binary
        company = pe.version_info.get("CompanyName", "")
        if "microsoft" in company.lower() and not sig.is_trusted:
            return (
                True,
                f"Spoofed VS_VERSIONINFO metadata: claims CompanyName='{company}' but lacks valid Microsoft signature",
                75,
            )

        return False, "", 0

    @staticmethod
    def _is_typosquat(name_a: str, name_b: str) -> bool:
        """Returns True if name_a is within Levenshtein edit distance 1 or a character swap of name_b."""
        if abs(len(name_a) - len(name_b)) > 1:
            return False
        # Adjacent transposition (e.g., svchost.exe vs scvhost.exe)
        if len(name_a) == len(name_b):
            diffs = [i for i in range(len(name_a)) if name_a[i] != name_b[i]]
            if len(diffs) == 1:
                return True
            if (
                len(diffs) == 2
                and diffs[1] == diffs[0] + 1
                and name_a[diffs[0]] == name_b[diffs[1]]
                and name_a[diffs[1]] == name_b[diffs[0]]
            ):
                return True
            return False
        # Insertion/deletion of 1 char (e.g., csrss.exe vs csrs.exe)
        longer, shorter = (name_a, name_b) if len(name_a) > len(name_b) else (name_b, name_a)
        for i in range(len(longer)):
            if longer[:i] + longer[i + 1 :] == shorter:
                return True
        return False
