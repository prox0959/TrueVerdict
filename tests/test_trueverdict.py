#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit & Integration Tests for TrueVerdict
========================================
Tests:
  1. Rich Header ('DanS') XOR decryption and ROL32 checksum validation.
  2. Reproducible Build (IMAGE_DEBUG_TYPE_REPRO) timestamp FP suppression.
  3. Unsigned legitimate developer build verification (0% False Positive).
  4. OS Security Catalog verification on Windows System32 binaries.
  5. Adversarial detection of RWX shellcode stubs, Process Hollowing IATs,
     typosquatted processes (scvhost.exe), and tampered certificate tables.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmark_suite import SyntheticPEBuilder
from fp_suppressor import FalsePositiveSuppressor
from pe_analyzer import PEAnalyzer
from trust_verifier import TrustVerifier


class TestTrueVerdictEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = PEAnalyzer()
        self.verifier = TrustVerifier()
        self.suppressor = FalsePositiveSuppressor()
        self.tmpdir = tempfile.TemporaryDirectory(prefix="tv_test_")

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _write_sample(self, name: str, content: bytes) -> str:
        path = os.path.join(self.tmpdir.name, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_clean_unsigned_developer_build_has_zero_fp(self) -> None:
        """An unsigned C/C++ build with a valid Rich Header and normal IAT must be BENIGN (score 0)."""
        raw = SyntheticPEBuilder.build_pe64(
            valid_rich_header=True,
            repro_debug=False,
            timestamp=1710000000,
            rwx_code=False,
            high_code_entropy=False,
            imports=[
                ("KERNEL32.dll", ["GetCurrentProcessId", "ExitProcess"]),
                ("ucrtbase.dll", ["printf", "malloc", "free"]),
            ],
        )
        path = self._write_sample("dev_utility.exe", raw)
        pe = self.analyzer.analyze(path)
        sig = self.verifier.verify_file(path, has_embedded_cert_table=pe.has_embedded_cert_table)
        verdict = self.suppressor.evaluate(pe, sig)

        self.assertTrue(pe.is_valid_pe)
        self.assertTrue(pe.rich_header.present)
        self.assertTrue(pe.rich_header.checksum_valid)
        self.assertEqual(verdict.final_risk_score, 0)
        self.assertEqual(verdict.verdict, "BENIGN")

    def test_reproducible_build_future_timestamp_suppressed(self) -> None:
        """A PE with a year-2050 timestamp and IMAGE_DEBUG_TYPE_REPRO must not trigger a timestamp anomaly."""
        raw = SyntheticPEBuilder.build_pe64(
            valid_rich_header=True,
            repro_debug=True,
            timestamp=0x99887766,  # Future deterministic hash
            imports=[("KERNEL32.dll", ["ExitProcess"])],
        )
        path = self._write_sample("repro_app.exe", raw)
        pe = self.analyzer.analyze(path)
        sig = self.verifier.verify_file(path, has_embedded_cert_table=pe.has_embedded_cert_table)
        verdict = self.suppressor.evaluate(pe, sig)

        self.assertTrue(pe.is_reproducible_build)
        self.assertEqual(verdict.final_risk_score, 0)
        self.assertEqual(verdict.verdict, "BENIGN")

    def test_rwx_packed_shellcode_stub_detected(self) -> None:
        """An unsigned PE with RWX permissions, high .text entropy, and 0 imports must be MALICIOUS."""
        raw = SyntheticPEBuilder.build_pe64(
            valid_rich_header=None,
            rwx_code=True,
            high_code_entropy=True,
            imports=None,
        )
        path = self._write_sample("shellcode_loader.exe", raw)
        pe = self.analyzer.analyze(path)
        sig = self.verifier.verify_file(path, has_embedded_cert_table=pe.has_embedded_cert_table)
        verdict = self.suppressor.evaluate(pe, sig)

        self.assertTrue(pe.has_rwx_section)
        self.assertGreater(pe.code_entropy, 7.5)
        self.assertGreaterEqual(verdict.final_risk_score, 70)
        self.assertEqual(verdict.verdict, "MALICIOUS")

    def test_typosquatted_system_binary_detected(self) -> None:
        """A binary named scvhost.exe (transposition of svchost.exe) must be flagged as MALICIOUS."""
        raw = SyntheticPEBuilder.build_pe64(
            valid_rich_header=False,
            imports=[("KERNEL32.dll", ["CreateProcessW"])],
        )
        path = self._write_sample("scvhost.exe", raw)
        pe = self.analyzer.analyze(path)
        sig = self.verifier.verify_file(path, has_embedded_cert_table=pe.has_embedded_cert_table)
        verdict = self.suppressor.evaluate(pe, sig)

        self.assertGreaterEqual(verdict.final_risk_score, 70)
        self.assertEqual(verdict.verdict, "MALICIOUS")

    def test_fake_system32_subfolder_masquerade_detected(self) -> None:
        """An unsigned svchost.exe inside a fake C:\\Temp\\...\\windows\\system32\\ folder must be caught."""
        fake_sys32 = os.path.join(self.tmpdir.name, "windows", "system32")
        os.makedirs(fake_sys32, exist_ok=True)
        path = os.path.join(fake_sys32, "svchost.exe")
        raw = SyntheticPEBuilder.build_pe64(
            valid_rich_header=True,
            imports=[("KERNEL32.dll", ["ExitProcess"])],
        )
        with open(path, "wb") as f:
            f.write(raw)

        pe = self.analyzer.analyze(path)
        sig = self.verifier.verify_file(path, has_embedded_cert_table=pe.has_embedded_cert_table)
        verdict = self.suppressor.evaluate(pe, sig)

        self.assertGreaterEqual(verdict.final_risk_score, 70)
        self.assertEqual(verdict.verdict, "MALICIOUS")

    def test_tampered_embedded_cert_table_detected(self) -> None:
        """A binary with a corrupted/stapled WIN_CERTIFICATE table must be flagged as MALICIOUS."""
        raw = SyntheticPEBuilder.build_pe64(
            valid_rich_header=True,
            fake_cert_table=True,
            imports=[("KERNEL32.dll", ["ExitProcess"])],
        )
        path = self._write_sample("tampered_signed_app.exe", raw)
        pe = self.analyzer.analyze(path)
        sig = self.verifier.verify_file(path, has_embedded_cert_table=pe.has_embedded_cert_table)
        verdict = self.suppressor.evaluate(pe, sig)

        self.assertTrue(pe.has_embedded_cert_table)
        self.assertEqual(sig.signature_type, "INVALID_OR_TAMPERED")
        self.assertGreaterEqual(verdict.final_risk_score, 70)
        self.assertEqual(verdict.verdict, "MALICIOUS")

    @unittest.skipUnless(os.name == "nt", "Windows Catalog check requires Windows")
    def test_windows_system32_cmd_exe_verified_via_catalog(self) -> None:
        """Real C:\\Windows\\System32\\cmd.exe must verify as trusted via OS_CATALOG with 0 risk."""
        cmd_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
        if not os.path.isfile(cmd_path):
            self.skipTest("cmd.exe not found")
        pe = self.analyzer.analyze(cmd_path)
        sig = self.verifier.verify_file(cmd_path, has_embedded_cert_table=pe.has_embedded_cert_table)
        verdict = self.suppressor.evaluate(pe, sig)

        self.assertTrue(sig.is_trusted)
        self.assertEqual(verdict.final_risk_score, 0)
        self.assertEqual(verdict.verdict, "BENIGN")


if __name__ == "__main__":
    unittest.main()
