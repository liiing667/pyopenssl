"""
Centralized handling of differences between OpenSSL and cryptography
versions.

Not every build of the OpenSSL bindings exposes the same symbols.  Every
optional symbol that pyOpenSSL can live without is probed exactly once in
this module, with a safe fallback, so the rest of the package never needs
to guess whether an attribute exists on the bindings and can degrade
gracefully when it does not.
"""

from __future__ import annotations

from OpenSSL._util import lib

__all__ = [
    "CFFI_VERSION",
    "DTLS1_COOKIE_LENGTH",
    "HAS_DTLS_GET_DATA_MTU",
    "HAS_KEYLOG",
    "HAS_SSL_COOKIE",
    "HAS_SSL_GET0_GROUP_NAME",
    "HAS_UNEXPECTED_EOF_WHILE_READING",
    "SSL_R_UNEXPECTED_EOF_WHILE_READING",
]


def _has_symbol(name: str) -> bool:
    return getattr(lib, name, None) is not None


def _cffi_version() -> str:
    try:
        import cffi
    except ImportError:
        # cryptography only needs the compiled ``_cffi_backend`` at
        # runtime; the ``cffi`` Python package itself is not guaranteed
        # to be installed.
        return "n/a"
    return cffi.__version__  # type: ignore[no-any-return]


#: Version of the installed ``cffi`` package, or ``"n/a"`` when only the
#: compiled ``_cffi_backend`` is available.
CFFI_VERSION: str = _cffi_version()

#: Maximum DTLS cookie length; falls back to the historical default when
#: the constant is not exposed by the linked OpenSSL.
DTLS1_COOKIE_LENGTH: int = getattr(lib, "DTLS1_COOKIE_LENGTH", 255)

#: Whether ``DTLS_get_data_mtu`` is available (OpenSSL 1.1.1+).
HAS_DTLS_GET_DATA_MTU: bool = _has_symbol("DTLS_get_data_mtu")

#: Feature flags published by cryptography's OpenSSL bindings.
HAS_KEYLOG: bool = bool(getattr(lib, "Cryptography_HAS_KEYLOG", 0))
HAS_SSL_GET0_GROUP_NAME: bool = bool(
    getattr(lib, "Cryptography_HAS_SSL_GET0_GROUP_NAME", 0)
)
HAS_SSL_COOKIE: bool = bool(getattr(lib, "Cryptography_HAS_SSL_COOKIE", 0))
HAS_UNEXPECTED_EOF_WHILE_READING: bool = bool(
    getattr(lib, "Cryptography_HAS_UNEXPECTED_EOF_WHILE_READING", 0)
)

#: The ``SSL_R_UNEXPECTED_EOF_WHILE_READING`` reason code, when the
#: linked OpenSSL defines it (OpenSSL 3.0+).
SSL_R_UNEXPECTED_EOF_WHILE_READING: int | None = getattr(
    lib, "SSL_R_UNEXPECTED_EOF_WHILE_READING", None
)
