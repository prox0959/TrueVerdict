#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TrueVerdict - Cryptographic Trust & Provenance Verifier (Zero Dependencies)
===========================================================================
Eliminates false positives on legitimate Windows and third-party binaries by
performing dual-path cryptographic verification via native Win32 APIs:
  1. Embedded Authenticode PKCS#7 verification (wintrust.dll :: WinVerifyTrust)
  2. OS Security Catalog (.cat) SHA-256 & SHA-1 lookup (wintrust.dll :: CryptCATAdmin*)
  3. Leaf X.509 Signer Subject / Issuer extraction (crypt32.dll :: CryptQueryObject)

TR: Windows sistem dosyalarinin cogu (.exe/.dll) icinde gomulu sertifika tasimaz;
bunun yerine C:\\Windows\\System32\\CatRoot altindaki katalog (.cat) dosyalariyla
imzalanir. Klasik araclar sadece gomulu imzaya baktigi icin temiz Windows
dosyalarina yanlis alarm (False Positive) uretir. Bu modul hem SHA-256 hem SHA-1
katalog imzalarini ve gomulu imzalari dogrular.
"""

import ctypes
from ctypes import wintypes
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Win32 Constants & GUID Definitions
# ---------------------------------------------------------------------------
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 0x00000001
WTD_STATEACTION_CLOSE = 0x00000002
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000

TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
TRUST_E_BAD_DIGEST = 0x80096010
CERT_E_EXPIRED = 0x800B0101
CERT_E_UNTRUSTEDROOT = 0x800B0109
CRYPT_E_SECURITY_SETTINGS = 0x80092026

CERT_QUERY_OBJECT_FILE = 1
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_ISSUER_FLAG = 0x1

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", ctypes.c_void_p),
    ]


class _WINTRUST_UNION(ctypes.Union):
    _fields_ = [
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("pCatalog", ctypes.POINTER(WINTRUST_CATALOG_INFO)),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("u", _WINTRUST_UNION),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("wszCatalogFile", ctypes.c_wchar * 260),
    ]


@dataclass
class SignatureResult:
    """Structured result of dual-path Authenticode + OS Catalog verification."""
    is_trusted: bool
    signature_type: str          # "EMBEDDED_AUTHENTICODE", "OS_CATALOG", "UNSIGNED", "INVALID_OR_TAMPERED"
    status_code: int             # Raw WinVerifyTrust HRESULT
    status_label: str            # Human-readable status description
    signer_subject: str          # e.g. "Microsoft Windows", "Google LLC"
    issuer_subject: str          # e.g. "Microsoft Windows Production PCA 2011"
    catalog_path: str            # Path to .cat file if catalog-signed
    is_microsoft_signed: bool    # True if verified publisher is Microsoft


class TrustVerifier:
    """
    Native Win32 Authenticode & Security Catalog verifier.
    Prevents false positives on legitimate system binaries that use catalog signing.
    """

    def __init__(self) -> None:
        self._available = os.name == "nt"
        self._has_cat_v2 = False
        if self._available:
            self._wintrust = ctypes.WinDLL("wintrust.dll", use_last_error=True)
            self._crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
            self._kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
            self._setup_prototypes()

    def _setup_prototypes(self) -> None:
        self._wintrust.WinVerifyTrust.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(GUID),
            ctypes.POINTER(WINTRUST_DATA),
        ]
        self._wintrust.WinVerifyTrust.restype = wintypes.LONG

        # Legacy SHA-1 Catalog APIs
        self._wintrust.CryptCATAdminAcquireContext.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(GUID),
            wintypes.DWORD,
        ]
        self._wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL

        self._wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.DWORD,
        ]
        self._wintrust.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL

        # Modern SHA-256 Catalog APIs (Windows 8 / 10 / 11+)
        if hasattr(self._wintrust, "CryptCATAdminAcquireContext2") and hasattr(
            self._wintrust, "CryptCATAdminCalcHashFromFileHandle2"
        ):
            self._has_cat_v2 = True
            self._wintrust.CryptCATAdminAcquireContext2.argtypes = [
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(GUID),
                wintypes.LPCWSTR,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            self._wintrust.CryptCATAdminAcquireContext2.restype = wintypes.BOOL

            self._wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
                ctypes.c_void_p,
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(ctypes.c_ubyte),
                wintypes.DWORD,
            ]
            self._wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL

        self._wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p

        self._wintrust.CryptCATCatalogInfoFromContext.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(CATALOG_INFO),
            wintypes.DWORD,
        ]
        self._wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL

        self._wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self._wintrust.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL

        self._wintrust.CryptCATAdminReleaseContext.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self._wintrust.CryptCATAdminReleaseContext.restype = wintypes.BOOL

        # Kernel32 file handle APIs
        self._kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self._kernel32.CreateFileW.restype = wintypes.HANDLE
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL

        # Crypt32 cert extraction APIs
        self._crypt32.CryptQueryObject.argtypes = [
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._crypt32.CryptQueryObject.restype = wintypes.BOOL

        self._crypt32.CertEnumCertificatesInStore.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._crypt32.CertEnumCertificatesInStore.restype = ctypes.c_void_p

        self._crypt32.CertGetNameStringW.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        self._crypt32.CertGetNameStringW.restype = wintypes.DWORD

        self._crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
        self._crypt32.CertFreeCertificateContext.restype = wintypes.BOOL

        self._crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self._crypt32.CertCloseStore.restype = wintypes.BOOL

        self._crypt32.CryptMsgClose.argtypes = [ctypes.c_void_p]
        self._crypt32.CryptMsgClose.restype = wintypes.BOOL

    def verify_file(
        self, file_path: str, has_embedded_cert_table: bool = False
    ) -> SignatureResult:
        """
        Runs dual-path verification:
          Step 1: Check embedded Authenticode PKCS#7 signature.
          Step 2: If no embedded signature exists, check Windows Security Catalogs (SHA-256 + SHA-1).
          Step 3: Extract leaf publisher & issuer names from the certificate store.
        """
        if not self._available or not os.path.isfile(file_path):
            return SignatureResult(
                is_trusted=False,
                signature_type="UNSIGNED",
                status_code=-1,
                status_label="Platform not supported or file missing",
                signer_subject="",
                issuer_subject="",
                catalog_path="",
                is_microsoft_signed=False,
            )

        abs_path = os.path.abspath(file_path)

        # 1. Try Embedded Authenticode first
        emb_status = self._verify_embedded(abs_path)
        if emb_status == 0:
            signer, issuer = self._extract_cert_names(abs_path)
            is_ms = self._check_microsoft_name(signer, issuer)
            return SignatureResult(
                is_trusted=True,
                signature_type="EMBEDDED_AUTHENTICODE",
                status_code=0,
                status_label="Valid Embedded Authenticode Signature",
                signer_subject=signer or "Verified Publisher",
                issuer_subject=issuer or "Trusted Root CA",
                catalog_path="",
                is_microsoft_signed=is_ms,
            )

        # 2. If embedded returns TRUST_E_NOSIGNATURE, check if a corrupt WIN_CERTIFICATE table was stapled
        if emb_status == TRUST_E_NOSIGNATURE:
            if has_embedded_cert_table:
                return SignatureResult(
                    is_trusted=False,
                    signature_type="INVALID_OR_TAMPERED",
                    status_code=emb_status,
                    status_label="Malformed or tampered WIN_CERTIFICATE table rejected by WinVerifyTrust",
                    signer_subject="",
                    issuer_subject="",
                    catalog_path="",
                    is_microsoft_signed=False,
                )

            cat_trusted, cat_path = self._verify_catalog(abs_path)
            if cat_trusted:
                signer, issuer = self._extract_cert_names(cat_path) if cat_path else ("", "")
                if not signer:
                    signer = "Microsoft Windows (OS Security Catalog)"
                is_ms = self._check_microsoft_name(signer, issuer) or (
                    "\\catroot\\" in cat_path.lower()
                )
                return SignatureResult(
                    is_trusted=True,
                    signature_type="OS_CATALOG",
                    status_code=0,
                    status_label="Valid Windows Security Catalog Signature",
                    signer_subject=signer,
                    issuer_subject=issuer or "Microsoft Root Certificate Authority",
                    catalog_path=cat_path,
                    is_microsoft_signed=is_ms,
                )

            return SignatureResult(
                is_trusted=False,
                signature_type="UNSIGNED",
                status_code=emb_status,
                status_label="No embedded or catalog digital signature present",
                signer_subject="",
                issuer_subject="",
                catalog_path="",
                is_microsoft_signed=False,
            )

        # 3. Embedded signature exists, but failed cryptographic validation!
        signer, issuer = self._extract_cert_names(abs_path)
        return SignatureResult(
            is_trusted=False,
            signature_type="INVALID_OR_TAMPERED",
            status_code=emb_status,
            status_label=self._format_error_code(emb_status),
            signer_subject=signer,
            issuer_subject=issuer,
            catalog_path="",
            is_microsoft_signed=False,
        )

    def _verify_embedded(self, file_path: str) -> int:
        """Calls WinVerifyTrust with WTD_CHOICE_FILE."""
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        wtd = WINTRUST_DATA()
        wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wtd.dwUIChoice = WTD_UI_NONE
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE
        wtd.dwUnionChoice = WTD_CHOICE_FILE
        wtd.u.pFile = ctypes.pointer(file_info)
        wtd.dwStateAction = WTD_STATEACTION_VERIFY
        wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL

        action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2
        status = self._wintrust.WinVerifyTrust(
            None, ctypes.byref(action_guid), ctypes.byref(wtd)
        )

        wtd.dwStateAction = WTD_STATEACTION_CLOSE
        self._wintrust.WinVerifyTrust(
            None, ctypes.byref(action_guid), ctypes.byref(wtd)
        )

        return status & 0xFFFFFFFF

    def _verify_catalog(self, file_path: str) -> Tuple[bool, str]:
        """
        Looks up the file's Authenticode digest in the Windows CatRoot database.
        Checks both SHA-256 (CryptCATAdminAcquireContext2) and SHA-1 catalogs.
        """
        h_file = self._kernel32.CreateFileW(
            file_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if h_file == INVALID_HANDLE_VALUE or not h_file:
            return False, ""

        try:
            # Try modern SHA-256 catalog context first, then legacy SHA-1
            for alg in ("SHA256", None):
                if alg == "SHA256" and not self._has_cat_v2:
                    continue
                trusted, cat_path = self._query_catalog_context(h_file, alg)
                if trusted:
                    return True, cat_path
            return False, ""
        finally:
            self._kernel32.CloseHandle(h_file)

    def _query_catalog_context(
        self, h_file: wintypes.HANDLE, algorithm: Optional[str]
    ) -> Tuple[bool, str]:
        h_cat_admin = ctypes.c_void_p()
        if algorithm is not None:
            ok = self._wintrust.CryptCATAdminAcquireContext2(
                ctypes.byref(h_cat_admin), None, algorithm, None, 0
            )
        else:
            ok = self._wintrust.CryptCATAdminAcquireContext(
                ctypes.byref(h_cat_admin), None, 0
            )
        if not ok or not h_cat_admin:
            return False, ""

        try:
            hash_len = wintypes.DWORD(0)
            if algorithm is not None:
                self._wintrust.CryptCATAdminCalcHashFromFileHandle2(
                    h_cat_admin, h_file, ctypes.byref(hash_len), None, 0
                )
            else:
                self._wintrust.CryptCATAdminCalcHashFromFileHandle(
                    h_file, ctypes.byref(hash_len), None, 0
                )
            if hash_len.value == 0:
                return False, ""

            hash_buf = (ctypes.c_ubyte * hash_len.value)()
            if algorithm is not None:
                calc_ok = self._wintrust.CryptCATAdminCalcHashFromFileHandle2(
                    h_cat_admin, h_file, ctypes.byref(hash_len), hash_buf, 0
                )
            else:
                calc_ok = self._wintrust.CryptCATAdminCalcHashFromFileHandle(
                    h_file, ctypes.byref(hash_len), hash_buf, 0
                )
            if not calc_ok:
                return False, ""

            prev_cat = ctypes.c_void_p(None)
            while True:
                h_cat_info = self._wintrust.CryptCATAdminEnumCatalogFromHash(
                    h_cat_admin,
                    hash_buf,
                    hash_len.value,
                    0,
                    ctypes.byref(prev_cat) if prev_cat.value else None,
                )
                if not h_cat_info:
                    break

                prev_cat = ctypes.c_void_p(h_cat_info)
                cat_info = CATALOG_INFO()
                cat_info.cbStruct = ctypes.sizeof(CATALOG_INFO)
                if self._wintrust.CryptCATCatalogInfoFromContext(
                    h_cat_info, ctypes.byref(cat_info), 0
                ):
                    cat_file_path = cat_info.wszCatalogFile
                    if self._verify_embedded(cat_file_path) == 0:
                        self._wintrust.CryptCATAdminReleaseCatalogContext(
                            h_cat_admin, h_cat_info, 0
                        )
                        return True, cat_file_path
            return False, ""
        finally:
            self._wintrust.CryptCATAdminReleaseContext(h_cat_admin, 0)

    def _extract_cert_names(self, signed_file_path: str) -> Tuple[str, str]:
        """
        Enumerates all certificates in the PKCS#7 store and selects the leaf
        code-signing certificate (excluding intermediate/root CA issuers).
        """
        encoding = wintypes.DWORD(0)
        content_type = wintypes.DWORD(0)
        format_type = wintypes.DWORD(0)
        h_store = ctypes.c_void_p()
        h_msg = ctypes.c_void_p()

        path_buf = ctypes.create_unicode_buffer(signed_file_path)
        ok = self._crypt32.CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            ctypes.cast(path_buf, ctypes.c_void_p),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            ctypes.byref(encoding),
            ctypes.byref(content_type),
            ctypes.byref(format_type),
            ctypes.byref(h_store),
            ctypes.byref(h_msg),
            None,
        )
        if not ok or not h_store:
            return "", ""

        pairs: List[Tuple[str, str]] = []
        try:
            p_cert = None
            while True:
                p_cert = self._crypt32.CertEnumCertificatesInStore(h_store, p_cert)
                if not p_cert:
                    break
                subj = ""
                iss = ""
                name_buf = ctypes.create_unicode_buffer(256)
                if (
                    self._crypt32.CertGetNameStringW(
                        p_cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, name_buf, 256
                    )
                    > 1
                ):
                    subj = name_buf.value

                issuer_buf = ctypes.create_unicode_buffer(256)
                if (
                    self._crypt32.CertGetNameStringW(
                        p_cert,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        CERT_NAME_ISSUER_FLAG,
                        None,
                        issuer_buf,
                        256,
                    )
                    > 1
                ):
                    iss = issuer_buf.value
                if subj:
                    pairs.append((subj, iss))
        finally:
            if h_store:
                self._crypt32.CertCloseStore(h_store, 0)
            if h_msg:
                self._crypt32.CryptMsgClose(h_msg)

        if not pairs:
            return "", ""

        # Leaf certificate is the subject that is NOT an issuer for another cert in the store
        all_issuers = {iss for _, iss in pairs if iss}
        for subj, iss in pairs:
            if subj not in all_issuers and subj != iss:
                return subj, iss

        return pairs[0]

    @staticmethod
    def _check_microsoft_name(signer: str, issuer: str) -> bool:
        combined = f"{signer} {issuer}".lower()
        return "microsoft" in combined or "windows" in combined

    @staticmethod
    def _format_error_code(code: int) -> str:
        mapping = {
            TRUST_E_NOSIGNATURE: "Unsigned binary (TRUST_E_NOSIGNATURE)",
            TRUST_E_BAD_DIGEST: "Cryptographic hash mismatch / Tampered binary (TRUST_E_BAD_DIGEST)",
            TRUST_E_EXPLICIT_DISTRUST: "Certificate explicitly revoked/distrusted (TRUST_E_EXPLICIT_DISTRUST)",
            TRUST_E_SUBJECT_NOT_TRUSTED: "Subject not trusted (TRUST_E_SUBJECT_NOT_TRUSTED)",
            CERT_E_EXPIRED: "Signing certificate expired (CERT_E_EXPIRED)",
            CERT_E_UNTRUSTEDROOT: "Self-signed or untrusted root CA (CERT_E_UNTRUSTEDROOT)",
            CRYPT_E_SECURITY_SETTINGS: "Blocked by local crypto policy (CRYPT_E_SECURITY_SETTINGS)",
        }
        return mapping.get(code, f"Untrusted signature status (0x{code:08X})")
