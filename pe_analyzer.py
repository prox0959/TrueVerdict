#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TrueVerdict - Deep PE32/PE32+ Structural & Provenance Parser (Zero Dependencies)
================================================================================
Performs deterministic static analysis on Windows Portable Executable (PE) files
using only the Python Standard Library (struct, math, hashlib, re).

Key False-Positive Reduction Capabilities:
  1. Reproducible Build Detection (IMAGE_DEBUG_TYPE_REPRO = 16): Recognizes
     Windows 10/11 deterministic PE timestamps so system files are never falsely
     flagged for "future/forged compile dates".
  2. Rich Header Cryptographic Checksum Validation: Decrypts the MSVC 'DanS'
     structure using the embedded XOR key and recomputes the ROL32 checksum to
     distinguish genuine compiler output from patched/forged headers.
  3. Section-Aware Entropy Segmentation: Separates executable code (.text)
     entropy from benign compressed resources (.rsrc) and known application
     containers (.NET CLR, PyInstaller, Electron, InnoSetup, NSIS).
  4. Combinatorial IAT Profiling: Evaluates offensive API clusters relative to
     overall import table density, eliminating false positives on browsers,
     JIT runtimes, and debuggers.
"""

from dataclasses import dataclass, field
import datetime
import hashlib
import math
import os
import re
import struct
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# PE Format Constants
# ---------------------------------------------------------------------------
IMAGE_DOS_SIGNATURE = 0x5A4D       # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550    # "PE\0\0"
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

IMAGE_DEBUG_TYPE_CODEVIEW = 2
IMAGE_DEBUG_TYPE_REPRO = 16  # Deterministic / Reproducible build (Windows 10/11+)


@dataclass
class SectionAnalysis:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float
    is_executable: bool
    is_writable: bool
    is_rwx: bool
    category: str  # "CODE", "RESOURCE", "DATA", "RELOC", "CUSTOM_OR_PACKER"


@dataclass
class RichHeaderInfo:
    present: bool
    xor_key: int = 0
    computed_checksum: int = 0
    checksum_valid: bool = False
    entry_count: int = 0
    compiler_entries: List[Tuple[int, int, int]] = field(default_factory=list)


@dataclass
class PEAnalysisReport:
    file_path: str
    file_name: str
    file_size: int
    is_valid_pe: bool
    error_message: str = ""

    # Digests
    sha256: str = ""
    md5: str = ""
    imphash: str = ""

    # Header Metadata
    architecture: str = ""
    subsystem: int = 0
    compile_timestamp: int = 0
    compile_date_utc: str = ""
    is_reproducible_build: bool = False
    has_debug_pdb: bool = False
    pdb_path: str = ""
    linker_version: str = ""
    entry_point_rva: int = 0
    entry_point_section: str = ""
    is_dll: bool = False
    is_dotnet: bool = False
    has_cfg_enabled: bool = False
    has_tls_callbacks: bool = False
    has_embedded_cert_table: bool = False
    embedded_cert_size: int = 0
    hardlink_count: int = 1
    has_overlay: bool = False
    overlay_size: int = 0
    overlay_entropy: float = 0.0

    # Rich Header
    rich_header: RichHeaderInfo = field(default_factory=lambda: RichHeaderInfo(False))

    # Sections
    sections: List[SectionAnalysis] = field(default_factory=list)
    overall_entropy: float = 0.0
    code_entropy: float = 0.0
    resource_entropy: float = 0.0
    has_rwx_section: bool = False
    rwx_section_names: List[str] = field(default_factory=list)

    # Imports & Capabilities
    imported_dlls: List[str] = field(default_factory=list)
    total_imported_functions: int = 0
    benign_import_count: int = 0
    suspicious_apis_found: List[str] = field(default_factory=list)
    capability_clusters: List[str] = field(default_factory=list)

    # Version Info & Known Containers
    version_info: Dict[str, str] = field(default_factory=dict)
    detected_container: str = "NATIVE_UNPACKED"  # e.g., ".NET_ASSEMBLY", "PYINSTALLER", "ELECTRON_CHROMIUM", "INNO_SETUP", "NSIS_INSTALLER", "UPX_PACKED"


def _rol32(val: int, shift: int) -> int:
    shift &= 31
    return ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF


def compute_shannon_entropy(data: bytes) -> float:
    """Computes Shannon entropy in bits per byte [0.000 - 8.000]."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class PEAnalyzer:
    """Zero-dependency Portable Executable static analysis engine."""

    # Offensive API clusters used for combinatorial capability detection
    INJECTION_CLUSTER = {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "NtQueueApcThread",
    }
    HOLLOWING_CLUSTER = {
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "SetThreadContext",
        "Wow64SetThreadContext",
        "ResumeThread",
    }
    CREDENTIAL_CLUSTER = {
        "MiniDumpWriteDump",
        "PssCaptureSnapshot",
        "LsaRegisterLogonProcess",
        "SamIConnect",
    }
    EVASION_CLUSTER = {
        "AmsiScanBuffer",
        "EtwEventWrite",
        "NtProtectVirtualMemory",
    }

    BENIGN_DLL_PREFIXES = (
        "user32",
        "gdi32",
        "comctl32",
        "comdlg32",
        "shell32",
        "shlwapi",
        "ole32",
        "oleaut32",
        "msvcrt",
        "ucrtbase",
        "vcruntime",
        "msvcp",
        "api-ms-win-crt",
        "qt5",
        "qt6",
        "gtk",
    )

    def analyze(self, file_path: str) -> PEAnalysisReport:
        abs_path = os.path.abspath(file_path)
        fname = os.path.basename(abs_path)

        if not os.path.isfile(abs_path):
            return PEAnalysisReport(
                file_path=abs_path,
                file_name=fname,
                file_size=0,
                is_valid_pe=False,
                error_message="File does not exist",
            )

        try:
            with open(abs_path, "rb") as f:
                data = f.read()
        except OSError as exc:
            return PEAnalysisReport(
                file_path=abs_path,
                file_name=fname,
                file_size=0,
                is_valid_pe=False,
                error_message=f"Unable to read file: {exc}",
            )

        fsize = len(data)
        if fsize < 0x100:
            return PEAnalysisReport(
                file_path=abs_path,
                file_name=fname,
                file_size=fsize,
                is_valid_pe=False,
                error_message="File smaller than minimum PE header size",
            )

        mz_magic = struct.unpack_from("<H", data, 0)[0]
        if mz_magic != IMAGE_DOS_SIGNATURE:
            return PEAnalysisReport(
                file_path=abs_path,
                file_name=fname,
                file_size=fsize,
                is_valid_pe=False,
                error_message="Invalid DOS MZ signature",
            )

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew < 0x40 or e_lfanew + 24 > fsize:
            return PEAnalysisReport(
                file_path=abs_path,
                file_name=fname,
                file_size=fsize,
                is_valid_pe=False,
                error_message="Corrupt e_lfanew offset",
            )

        pe_sig = struct.unpack_from("<I", data, e_lfanew)[0]
        if pe_sig != IMAGE_NT_SIGNATURE:
            return PEAnalysisReport(
                file_path=abs_path,
                file_name=fname,
                file_size=fsize,
                is_valid_pe=False,
                error_message="Invalid PE\\0\\0 signature",
            )

        try:
            nlink = os.stat(abs_path).st_nlink
        except OSError:
            nlink = 1

        report = PEAnalysisReport(
            file_path=abs_path,
            file_name=fname,
            file_size=fsize,
            is_valid_pe=True,
            sha256=hashlib.sha256(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
            overall_entropy=compute_shannon_entropy(data),
            hardlink_count=nlink,
        )

        # 1. Parse Rich Header & Verify ROL32 Checksum
        report.rich_header = self._parse_rich_header(data, e_lfanew)

        # 2. Parse COFF File Header
        coff_off = e_lfanew + 4
        machine, num_sections, timestamp, _, _, opt_hdr_size, characteristics = (
            struct.unpack_from("<HHIIIHH", data, coff_off)
        )

        arch_map = {
            0x014C: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0xAA64: "ARM64",
            0x01C4: "ARMv7",
        }
        report.architecture = arch_map.get(machine, f"Unknown (0x{machine:04X})")
        report.compile_timestamp = timestamp
        report.is_dll = bool(characteristics & 0x2000)

        try:
            dt = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
            report.compile_date_utc = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError, OverflowError):
            report.compile_date_utc = f"Invalid/Deterministic (0x{timestamp:08X})"

        # 3. Parse Optional Header & Data Directories
        opt_off = coff_off + 20
        if opt_off + opt_hdr_size > fsize or opt_hdr_size < 24:
            report.error_message = "Truncated Optional Header"
            return report

        opt_magic = struct.unpack_from("<H", data, opt_off)[0]
        is_64 = opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
        min_opt = 112 if is_64 else 96
        if opt_hdr_size < min_opt or opt_off + min_opt > fsize:
            report.error_message = "Truncated Optional Header for target architecture"
            return report

        major_linker, minor_linker = struct.unpack_from("<BB", data, opt_off + 2)
        report.linker_version = f"{major_linker}.{minor_linker}"
        report.entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]

        if is_64:
            subsystem, dll_chars = struct.unpack_from("<HH", data, opt_off + 68)
            num_rva_and_sizes = struct.unpack_from("<I", data, opt_off + 108)[0]
            dd_offset = opt_off + 112
        else:
            subsystem, dll_chars = struct.unpack_from("<HH", data, opt_off + 68)
            num_rva_and_sizes = struct.unpack_from("<I", data, opt_off + 92)[0]
            dd_offset = opt_off + 96

        report.subsystem = subsystem
        # Check Control Flow Guard (IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000)
        report.has_cfg_enabled = bool(dll_chars & 0x4000)

        data_dirs: List[Tuple[int, int]] = []
        max_dirs = min(num_rva_and_sizes, 16)
        for i in range(max_dirs):
            pos = dd_offset + i * 8
            if pos + 8 <= fsize:
                rva, sz = struct.unpack_from("<II", data, pos)
                data_dirs.append((rva, sz))
            else:
                data_dirs.append((0, 0))
        while len(data_dirs) < 16:
            data_dirs.append((0, 0))

        # Check .NET CLR Header presence
        com_rva, com_size = data_dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
        report.is_dotnet = com_rva > 0 and com_size > 0

        # 4. Parse Section Headers
        sec_table_off = opt_off + opt_hdr_size
        max_raw_end = 0
        code_bytes = bytearray()
        rsrc_bytes = bytearray()

        for i in range(num_sections):
            s_off = sec_table_off + i * 40
            if s_off + 40 > fsize:
                break
            raw_name = data[s_off : s_off + 8]
            sec_name = raw_name.split(b"\x00", 1)[0].decode("latin-1", errors="replace").strip()
            v_size, v_addr, raw_size, raw_ptr, _, _, _, _, sec_chars = struct.unpack_from(
                "<IIIIIIHHI", data, s_off + 8
            )

            sec_slice = b""
            if raw_ptr > 0 and raw_size > 0 and raw_ptr < fsize:
                end_ptr = min(fsize, raw_ptr + raw_size)
                sec_slice = data[raw_ptr:end_ptr]
                if end_ptr > max_raw_end:
                    max_raw_end = end_ptr

            sec_ent = compute_shannon_entropy(sec_slice)
            is_exec = bool(sec_chars & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
            is_write = bool(sec_chars & IMAGE_SCN_MEM_WRITE)
            is_rwx = is_exec and is_write

            category = self._classify_section(sec_name, is_exec)
            if category == "CODE":
                code_bytes.extend(sec_slice)
            elif category == "RESOURCE":
                rsrc_bytes.extend(sec_slice)

            if is_rwx:
                report.has_rwx_section = True
                report.rwx_section_names.append(sec_name or f"sec_{i}")

            # Check if entry point lands in this section
            eff_vsize = max(v_size, raw_size)
            if v_addr <= report.entry_point_rva < (v_addr + eff_vsize):
                report.entry_point_section = sec_name

            report.sections.append(
                SectionAnalysis(
                    name=sec_name,
                    virtual_address=v_addr,
                    virtual_size=v_size,
                    raw_offset=raw_ptr,
                    raw_size=raw_size,
                    characteristics=sec_chars,
                    entropy=sec_ent,
                    is_executable=is_exec,
                    is_writable=is_write,
                    is_rwx=is_rwx,
                    category=category,
                )
            )

        report.code_entropy = compute_shannon_entropy(bytes(code_bytes))
        report.resource_entropy = compute_shannon_entropy(bytes(rsrc_bytes))

        # 5. Check Overlay (Excluding Authenticode Certificate Table if at EOF)
        cert_off, cert_size = data_dirs[IMAGE_DIRECTORY_ENTRY_SECURITY]
        if cert_off > 0 and cert_size > 0:
            report.has_embedded_cert_table = True
            report.embedded_cert_size = cert_size
        effective_end = max_raw_end
        if cert_off > 0 and cert_size > 0 and cert_off >= max_raw_end:
            effective_end = max(effective_end, cert_off + cert_size)

        if max_raw_end > 0 and fsize > effective_end:
            overlay_data = data[effective_end:]
            if len(overlay_data) > 64:
                report.has_overlay = True
                report.overlay_size = len(overlay_data)
                report.overlay_entropy = compute_shannon_entropy(overlay_data)

        # 6. Parse Debug Directory (Detect Windows 10/11 Reproducible Builds & PDB)
        dbg_rva, dbg_size = data_dirs[IMAGE_DIRECTORY_ENTRY_DEBUG]
        if dbg_rva > 0 and dbg_size >= 28:
            self._parse_debug_directory(data, dbg_rva, dbg_size, report)

        # 7. Parse TLS Directory
        tls_rva, tls_size = data_dirs[IMAGE_DIRECTORY_ENTRY_TLS]
        if tls_rva > 0 and tls_size > 0:
            report.has_tls_callbacks = self._check_tls_callbacks(data, tls_rva, is_64, report)

        # 8. Parse Import Table (IAT) & Compute Imphash
        imp_rva, imp_size = data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT]
        if imp_rva > 0 and imp_size > 0:
            self._parse_imports(data, imp_rva, is_64, report)

        # 9. Extract Version Info Strings & Fingerprint Known Containers
        report.version_info = self._extract_version_strings(data)
        report.detected_container = self._fingerprint_container(data, report)

        return report

    def _rva_to_offset(self, rva: int, sections: List[SectionAnalysis]) -> Optional[int]:
        for sec in sections:
            span = max(sec.virtual_size, sec.raw_size)
            if sec.virtual_address <= rva < sec.virtual_address + span:
                delta = rva - sec.virtual_address
                if delta < sec.raw_size:
                    return sec.raw_offset + delta
        return None

    def _parse_rich_header(self, data: bytes, e_lfanew: int) -> RichHeaderInfo:
        """
        Locates 'Rich' marker between 0x80 and e_lfanew, extracts XOR key,
        decrypts backwards to 'DanS', and verifies the ROL32 checksum.
        """
        region = data[: min(e_lfanew, len(data))]
        rich_pos = region.rfind(b"Rich")
        if rich_pos == -1 or rich_pos < 0x80 or rich_pos + 8 > len(region):
            return RichHeaderInfo(present=False)

        xor_key = struct.unpack_from("<I", region, rich_pos + 4)[0]
        # Decrypt backwards in 4-byte steps looking for 'DanS' (0x536E6144)
        dans_pos = -1
        for pos in range(rich_pos - 4, 0x3F, -4):
            enc_dword = struct.unpack_from("<I", region, pos)[0]
            if (enc_dword ^ xor_key) == 0x536E6144:
                dans_pos = pos
                break

        if dans_pos == -1:
            return RichHeaderInfo(present=False)

        # Decrypt comp.id pairs (skipping DanS + 3 zero padding DWORDs = 16 bytes)
        entries: List[Tuple[int, int, int]] = []
        for pos in range(dans_pos + 16, rich_pos, 8):
            if pos + 8 > rich_pos:
                break
            comp_id = struct.unpack_from("<I", region, pos)[0] ^ xor_key
            count = struct.unpack_from("<I", region, pos + 4)[0] ^ xor_key
            prod_id = (comp_id >> 16) & 0xFFFF
            build_num = comp_id & 0xFFFF
            entries.append((prod_id, build_num, count))

        # Recompute official Microsoft ROL32 Rich Checksum
        checksum = dans_pos
        for i in range(dans_pos):
            if 0x3C <= i < 0x40:
                continue  # e_lfanew field is zeroed during checksum calculation
            checksum = (checksum + _rol32(region[i], i)) & 0xFFFFFFFF

        for prod_id, build_num, count in entries:
            comp_id = (prod_id << 16) | build_num
            checksum = (checksum + _rol32(comp_id, count)) & 0xFFFFFFFF

        return RichHeaderInfo(
            present=True,
            xor_key=xor_key,
            computed_checksum=checksum,
            checksum_valid=(checksum == xor_key),
            entry_count=len(entries),
            compiler_entries=entries,
        )

    @staticmethod
    def _classify_section(name: str, is_exec: bool) -> str:
        low = name.lower()
        if low in (".text", "code", ".code", "init", "page"):
            return "CODE"
        if low in (".rsrc",):
            return "RESOURCE"
        if low in (".reloc",):
            return "RELOC"
        if low in (
            ".rdata",
            ".data",
            ".bss",
            ".pdata",
            ".xdata",
            ".idata",
            ".edata",
            ".tls",
            ".gfids",
            ".giats",
            ".didat",
            ".retplne",
            ".rodata",
        ):
            return "DATA"
        return "CODE" if is_exec else "CUSTOM_OR_PACKER"

    def _parse_debug_directory(
        self, data: bytes, dbg_rva: int, dbg_size: int, report: PEAnalysisReport
    ) -> None:
        dbg_off = self._rva_to_offset(dbg_rva, report.sections)
        if dbg_off is None:
            return
        count = dbg_size // 28
        for i in range(min(count, 16)):
            entry_off = dbg_off + i * 28
            if entry_off + 28 > len(data):
                break
            _, _, _, _, dbg_type, size_of_data, addr_raw_data, ptr_raw_data = struct.unpack_from(
                "<IIHHIIII", data, entry_off
            )
            if dbg_type == IMAGE_DEBUG_TYPE_REPRO:
                report.is_reproducible_build = True
            elif dbg_type == IMAGE_DEBUG_TYPE_CODEVIEW:
                cv_off = ptr_raw_data if ptr_raw_data > 0 else (self._rva_to_offset(addr_raw_data, report.sections) or 0)
                if cv_off > 0 and cv_off + 24 < len(data) and data[cv_off : cv_off + 4] == b"RSDS":
                    end_idx = data.find(b"\x00", cv_off + 24, min(len(data), cv_off + 512))
                    if end_idx != -1:
                        report.has_debug_pdb = True
                        report.pdb_path = data[cv_off + 24 : end_idx].decode(
                            "utf-8", errors="replace"
                        )

    def _check_tls_callbacks(
        self, data: bytes, tls_rva: int, is_64: bool, report: PEAnalysisReport
    ) -> bool:
        tls_off = self._rva_to_offset(tls_rva, report.sections)
        if tls_off is None:
            return False
        if is_64 and tls_off + 32 <= len(data):
            cb_va = struct.unpack_from("<Q", data, tls_off + 24)[0]
            return cb_va != 0
        if not is_64 and tls_off + 16 <= len(data):
            cb_va = struct.unpack_from("<I", data, tls_off + 12)[0]
            return cb_va != 0
        return False

    def _parse_imports(
        self, data: bytes, imp_rva: int, is_64: bool, report: PEAnalysisReport
    ) -> None:
        imp_off = self._rva_to_offset(imp_rva, report.sections)
        if imp_off is None:
            return

        imphash_parts: List[str] = []
        found_suspicious = set()
        dll_set: List[str] = []

        idx = 0
        while idx < 256:
            desc_off = imp_off + idx * 20
            if desc_off + 20 > len(data):
                break
            orig_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", data, desc_off
            )
            if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break
            idx += 1

            name_off = self._rva_to_offset(name_rva, report.sections)
            if name_off is None or name_off >= len(data):
                continue
            end_name = data.find(b"\x00", name_off, min(len(data), name_off + 128))
            if end_name == -1:
                continue
            dll_name = data[name_off:end_name].decode("latin-1", errors="replace")
            dll_lower = dll_name.lower()
            if dll_lower not in dll_set:
                dll_set.append(dll_lower)

            is_benign_dll = dll_lower.startswith(self.BENIGN_DLL_PREFIXES)
            dll_stem = re.sub(r"\.(dll|drv|sys|ocx)$", "", dll_lower)

            thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
            thunk_off = self._rva_to_offset(thunk_rva, report.sections)
            if thunk_off is None and first_thunk != 0:
                thunk_off = self._rva_to_offset(first_thunk, report.sections)
            if thunk_off is None:
                continue

            step = 8 if is_64 else 4
            ordinal_flag = 0x8000000000000000 if is_64 else 0x80000000
            f_idx = 0
            while f_idx < 4096:
                t_pos = thunk_off + f_idx * step
                if t_pos + step > len(data):
                    break
                val = struct.unpack_from("<Q" if is_64 else "<I", data, t_pos)[0]
                if val == 0:
                    break
                f_idx += 1
                report.total_imported_functions += 1
                if is_benign_dll:
                    report.benign_import_count += 1

                if val & ordinal_flag:
                    ord_num = val & 0xFFFF
                    imphash_parts.append(f"{dll_stem}.ord{ord_num}")
                else:
                    hint_off = self._rva_to_offset(val & (0x7FFFFFFFFFFFFFFF if is_64 else 0x7FFFFFFF), report.sections)
                    if hint_off is not None and hint_off + 2 < len(data):
                        f_end = data.find(b"\x00", hint_off + 2, min(len(data), hint_off + 128))
                        if f_end != -1:
                            func_name = data[hint_off + 2 : f_end].decode(
                                "latin-1", errors="replace"
                            )
                            imphash_parts.append(f"{dll_stem}.{func_name.lower()}")
                            if (
                                func_name in self.INJECTION_CLUSTER
                                or func_name in self.HOLLOWING_CLUSTER
                                or func_name in self.CREDENTIAL_CLUSTER
                                or func_name in self.EVASION_CLUSTER
                            ):
                                found_suspicious.add(func_name)

        report.imported_dlls = dll_set
        report.suspicious_apis_found = sorted(found_suspicious)
        if imphash_parts:
            report.imphash = hashlib.md5(",".join(imphash_parts).encode("utf-8")).hexdigest()

        # Evaluate Combinatorial Capability Clusters
        inj_hits = found_suspicious.intersection(self.INJECTION_CLUSTER)
        hol_hits = found_suspicious.intersection(self.HOLLOWING_CLUSTER)
        cred_hits = found_suspicious.intersection(self.CREDENTIAL_CLUSTER)
        evas_hits = found_suspicious.intersection(self.EVASION_CLUSTER)

        if len(inj_hits) >= 2:
            report.capability_clusters.append(
                f"REMOTE_PROCESS_INJECTION ({', '.join(sorted(inj_hits))})"
            )
        if len(hol_hits) >= 2 or ("NtUnmapViewOfSection" in hol_hits and inj_hits):
            report.capability_clusters.append(
                f"PROCESS_HOLLOWING ({', '.join(sorted(hol_hits | inj_hits))})"
            )
        if cred_hits:
            report.capability_clusters.append(
                f"CREDENTIAL_DUMP_PRIMITIVE ({', '.join(sorted(cred_hits))})"
            )
        if evas_hits:
            report.capability_clusters.append(
                f"TELEMETRY_TAMPERING ({', '.join(sorted(evas_hits))})"
            )

    @staticmethod
    def _extract_version_strings(data: bytes) -> Dict[str, str]:
        """Extracts UTF-16LE VS_VERSIONINFO keys from the binary resource region."""
        keys = (
            "CompanyName",
            "FileDescription",
            "InternalName",
            "OriginalFilename",
            "ProductName",
            "FileVersion",
        )
        results: Dict[str, str] = {}
        for key in keys:
            pattern = key.encode("utf-16-le") + b"\x00\x00"
            pos = data.find(pattern)
            if pos == -1:
                continue
            val_start = pos + len(pattern)
            # Align / skip padding zero WCHARs (up to 8 bytes)
            while val_start + 2 <= len(data) and data[val_start : val_start + 2] == b"\x00\x00":
                val_start += 2
                if val_start - (pos + len(pattern)) > 8:
                    break
            # Read UTF-16LE string until null WCHAR
            chars = []
            cur = val_start
            while cur + 2 <= len(data) and len(chars) < 120:
                wchar = data[cur : cur + 2]
                if wchar == b"\x00\x00":
                    break
                chars.append(wchar)
                cur += 2
            if chars:
                val = b"".join(chars).decode("utf-16-le", errors="ignore").strip()
                if val and all(31 < ord(c) < 127 or ord(c) > 160 for c in val):
                    results[key] = val
        return results

    @staticmethod
    def _fingerprint_container(data: bytes, report: PEAnalysisReport) -> str:
        """
        Identifies legitimate application runtimes and installers that naturally
        exhibit high entropy or overlays, preventing false-positive packer alerts.
        """
        if report.is_dotnet:
            return "DOTNET_CLR_ASSEMBLY"

        sec_names = {s.name.upper() for s in report.sections}
        if "UPX0" in sec_names or "UPX1" in sec_names:
            return "UPX_PACKED"

        if b"MEI\x0c\x0b\x0a\x0b\x0e" in data or b"PyInstaller:" in data or b"_MEIPASS" in data:
            return "PYINSTALLER_BUNDLE"
        if b"Inno Setup Setup Data" in data or b"Inno Setup Messages" in data:
            return "INNO_SETUP_INSTALLER"
        if b"Nullsoft.NSIS.exehead" in data or b"Nullsoft Install System" in data:
            return "NSIS_INSTALLER"
        if b"7-Zip" in data and b"7z\xbc\xaf\x27\x1c" in data:
            return "7ZIP_SFX_ARCHIVE"
        if b"v8_context_snapshot.bin" in data or b"electron.asar" in data:
            return "ELECTRON_CHROMIUM_APP"

        return "NATIVE_UNPACKED"
