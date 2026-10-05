"""Authenticode signature verification.

Fully in-process (ctypes WinVerifyTrust + CryptQueryObject), read-only,
offline. No revocation/network lookups: we do NOT hold signatures to CRL
checks (the tool is offline-first; an unavailable CRL would turn every
valid signature into an error).

Status vocabulary: Signed / Unsigned / Invalid / Unknown / Unavailable.

All lookups are cached per (path, size, mtime) for the scan session.
"""

from __future__ import annotations

import ctypes
import os
import threading
from ctypes import byref, c_byte, c_void_p, pointer, sizeof, wintypes

from app.models.enums import SignerStatus

wintypes.LPCWSTR  # noqa - referenced to silence linters

_ACTION_GUID = (0x00AAC56B, 0xCD44, 0x11D0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


def _make_guid(data1, data2, data3, data4) -> _GUID:
    guid = _GUID()
    guid.Data1 = data1
    guid.Data2 = data2
    guid.Data3 = data3
    guid.Data4 = (wintypes.BYTE * 8)(*data4)
    return guid


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_GUID)),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", c_void_p),
        ("pSIPClientData", c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", c_void_p),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", c_void_p),
    ]


class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(c_byte))]


class _CERT_INFO(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("SerialNumber", _BLOB),
        ("SignatureAlgorithm", c_void_p),
        ("Issuer", _BLOB),
        ("NotBefore", wintypes.DWORD * 2),
        ("NotAfter", wintypes.DWORD * 2),
        ("Subject", _BLOB),
        ("SubjectPublicKeyInfo", c_void_p),
        ("IssuerUniqueId", _BLOB),
        ("SubjectUniqueId", _BLOB),
        ("cExtension", wintypes.DWORD),
        ("rgExtension", c_void_p),
    ]


class _CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", c_void_p),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.POINTER(_CERT_INFO)),
        ("hCertStore", c_void_p),
    ]


class _CMSG_SIGNER_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("Issuer", _BLOB),
        ("SerialNumber", _BLOB),
        ("HashAlgorithm", c_void_p),
        ("HashEncryptionAlgorithm", c_void_p),
        ("EncryptedHash", _BLOB),
        ("AuthAttrs", c_void_p),
        ("UnauthAttrs", c_void_p),
        ("SignerCertId", c_void_p),
        ("Reserved", c_void_p),
    ]


# trust result codes
_S_OK = 0
_TRUST_E_NOSIGNATURE = 0x800B0100
_CERT_E_UNTRUSTEDROOT = 0x800B0109
_CERT_E_UNTRUSTEDTESTROOT = 0x800B010D
_TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0104
_CERT_E_EXPIRED = 0x800B0101
_CERT_E_REVOKED = 0x800B010C
_TRUST_E_NO_SIGNER_CERT = 0x800B0110
_TRUST_E_CERT_SIGNATURE = 0x80096004
_TRUST_E_ENTRYPOINT_NOT_FOUND = 0x80096002
_TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003

_NO_SIGNATURE_CODES = {_TRUST_E_NOSIGNATURE, _TRUST_E_NO_SIGNER_CERT,
                       _TRUST_E_SUBJECT_FORM_UNKNOWN, _TRUST_E_ENTRYPOINT_NOT_FOUND}


class SignatureResult:
    __slots__ = ("status", "publisher", "subject", "issuer", "detail")

    def __init__(self, status: str, publisher: str = "", subject: str = "",
                 issuer: str = "", detail: str = "") -> None:
        self.status = status
        self.publisher = publisher
        self.subject = subject
        self.issuer = issuer
        self.detail = detail

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "publisher": self.publisher,
            "subject": self.subject,
            "issuer": self.issuer,
            "detail": self.detail,
        }


class SignatureEvaluator:
    """Session-wide authenticode evaluator with caching."""

    def __init__(self) -> None:
        self._cache: dict[tuple, SignatureResult] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(path: str) -> tuple | None:
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (os.path.normcase(path), st.st_size, int(st.st_mtime))

    def evaluate(self, path: str) -> SignatureResult:
        """Determine signature status of a file without executing it."""
        if not path:
            return SignatureResult(SignerStatus.UNAVAILABLE.value, detail="no file path")

        norm = path
        key = self._key(path)
        if key is None:
            return SignatureResult(SignerStatus.UNAVAILABLE.value,
                                   detail="file missing / unreadable")
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached

        result = self._evaluate(path)
        with self._lock:
            self._cache[key] = result
        return result

    # ------------------------------------------------------------------
    def _evaluate(self, path: str) -> SignatureResult:
        code = self._verify_trust(path)
        if code == _S_OK:
            publisher, subject, issuer = self._extract_publisher(path)
            return SignatureResult(SignerStatus.SIGNED.value, publisher=publisher,
                                   subject=subject, issuer=issuer,
                                   detail="signature verified")
        if code in _NO_SIGNATURE_CODES or (code & 0x80000000 and code == _TRUST_E_NOSIGNATURE):
            return SignatureResult(SignerStatus.UNSIGNED.value,
                                   detail="no authenticode signature present")
        detail = f"trust result 0x{code & 0xFFFFFFFF:08X}"
        if code == _CERT_E_EXPIRED:
            detail = "certificate expired"
        elif code == _CERT_E_UNTRUSTEDROOT or code == _CERT_E_UNTRUSTEDTESTROOT:
            detail = "untrusted root"
        elif code == _TRUST_E_SUBJECT_NOT_TRUSTED:
            detail = "trust subject not trusted"
        elif code == _TRUST_E_CERT_SIGNATURE:
            detail = "certificate signature invalid"
        elif code == _CERT_E_REVOKED:
            detail = "certificate revoked (offline engine)"
        return SignatureResult(SignerStatus.INVALID.value, detail=detail)

    # ------------------------------------------------------------------
    @staticmethod
    def _verify_trust(path: str) -> int:
        try:
            wintrust = ctypes.windll.Wintrust.WinVerifyTrust
        except (AttributeError, OSError):
            return _TRUST_E_CERT_SIGNATURE

        action = _make_guid(*_ACTION_GUID)
        file_info = _WINTRUST_FILE_INFO(sizeof(_WINTRUST_FILE_INFO), path, None, None)
        data = _WINTRUST_DATA(
            cbStruct=sizeof(_WINTRUST_DATA),
            pPolicyCallbackData=None,
            pSIPClientData=None,
            dwUIChoice=2,            # WTD_UI_NONE
            fdwRevocationChecks=0,   # WTD_REVOKE_NONE (offline friendly)
            dwUnionChoice=1,         # WTD_CHOICE_FILE
            pFile=pointer(file_info),
            dwStateAction=0,         # WTD_STATEACTION_IGNORE
            hWVTStateData=None,
            pwszURLReference=None,
            dwProvFlags=0x0,         # no special provider flags
            dwUIContext=0,
            pSignatureSettings=None,
        )
        try:
            result = wintrust(None, byref(action), byref(data))
            return int(result)
        except Exception:
            return _TRUST_E_CERT_SIGNATURE

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_publisher(path: str) -> tuple[str, str, str]:
        """Return (publisher, subject, issuer) using CryptQueryObject."""
        try:
            crypt32 = ctypes.windll.crypt32
        except (AttributeError, OSError):
            return "", "", ""

        h_store = c_void_p()
        h_msg = c_void_p()
        h_context = c_void_p()
        dw_encoding, dw_content, dw_format = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()

        # CERT_QUERY_OBJECT_FILE=1, CONTENT_FLAG_ALL=0x0000FFFE, FORMAT_FLAG_ALL=0x0000FFFF
        query_ok = crypt32.CryptQueryObject(
            1, path, 0x0000FFFE, 0x0000FFFF, 0,
            byref(dw_encoding), byref(dw_content), byref(dw_format),
            byref(h_store), byref(h_msg), byref(h_context))
        if not query_ok:
            return "", "", ""

        try:
            # CMSG_SIGNER_INFO_PARAM=6
            signer = self._read_signer(crypt32, h_msg)
            if signer is None:
                # fall back to first store certificate
                cert = self._first_cert(crypt32, h_store)
                if cert is None:
                    return "", "", ""
                subject = self._name_string(crypt32, cert, 0)
                issuer = self._name_string(crypt32, cert, 0x1)
                return subject, subject, issuer

            cert = self._find_cert_by_issuer_serial(crypt32, h_store, signer)
            if cert is None:
                cert = self._first_cert(crypt32, h_store)
            if cert is None:
                return "", "", ""
            subject = self._name_string(crypt32, cert, 0)
            issuer = self._name_string(crypt32, cert, 0x1)
            return subject, subject, issuer
        finally:
            if h_msg.value:
                crypt32.CryptMsgClose(h_msg)
            if h_store.value:
                crypt32.CertCloseStore(h_store, 0)

    @staticmethod
    def _read_signer(crypt32, h_msg) -> "_CMSG_SIGNER_INFO | None":
        """Parse the raw CMSG_SIGNER_INFO out of the signed message."""
        cb = wintypes.DWORD()
        ok = crypt32.CryptMsgGetParam(h_msg, 6, 0, None, None, byref(cb))
        if not ok or not cb.value or cb.value > 1 << 20:
            return None
        buf = ctypes.create_string_buffer(cb.value)
        ok = crypt32.CryptMsgGetParam(h_msg, 6, 0, buf, cb, None)
        if not ok:
            return None
        # Note: signer.IsIssuer is only populated when the cert itself
        # carries a distinct issuer; here we rely on the signer's own
        # Issuer + SerialNumber fields.
        raw = ctypes.string_at(ctypes.addressof(buf), cb.value)
        info = ctypes.cast(ctypes.create_string_buffer(raw), ctypes.POINTER(_CMSG_SIGNER_INFO))
        try:
            return info.contents
        except Exception:
            return None

    @staticmethod
    def _first_cert(crypt32, h_store) -> _CERT_CONTEXT | None:
        ctx = crypt32.CertEnumCertificatesInStore(h_store, None)
        if not ctx:
            return None
        return ctypes.cast(ctx, ctypes.POINTER(_CERT_CONTEXT)).contents

    @staticmethod
    def _find_cert_by_issuer_serial(crypt32, h_store, signer: "_CMSG_SIGNER_INFO") -> _CERT_CONTEXT | None:
        issuer_bytes = ctypes.string_at(signer.Issuer.pbData, signer.Issuer.cbData)
        serial_bytes = ctypes.string_at(signer.SerialNumber.pbData, signer.SerialNumber.cbData)
        ctx = ctypes.c_void_p(None)
        while True:
            ctx = crypt32.CertEnumCertificatesInStore(h_store, ctx)
            if not ctx:
                break
            cert = ctypes.cast(ctx, ctypes.POINTER(_CERT_CONTEXT)).contents
            info = cert.pCertInfo.contents
            cand_issuer = ctypes.string_at(info.Issuer.pbData, info.Issuer.cbData)
            cand_serial = ctypes.string_at(info.SerialNumber.pbData, info.SerialNumber.cbData)
            if cand_serial == serial_bytes and cand_issuer == issuer_bytes:
                return cert
        return None

    @staticmethod
    def _name_string(crypt32, cert: _CERT_CONTEXT, flags: int) -> str:
        # CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
        buf = ctypes.create_unicode_buffer(512)
        n = crypt32.CertGetNameStringW(cert, 4, flags, None, buf, len(buf))
        if n <= 1:
            return ""
        return buf.value or ""

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()