"""
Tests for `OpenSSL._compat`, the central place where differences between
OpenSSL and cryptography versions are detected and absorbed.
"""

from socket import SHUT_RDWR

import pytest
from tests.test_ssl import loopback

from OpenSSL import SSL, _compat
from OpenSSL._util import lib


class TestFeatureDetection:
    """
    The probed constants reflect the actual bindings and always have
    safe, well-typed values.
    """

    def test_cffi_version_is_a_string(self) -> None:
        """
        ``CFFI_VERSION`` is always a string, even when only the compiled
        ``_cffi_backend`` (and not the ``cffi`` package) is installed.
        """
        assert isinstance(_compat.CFFI_VERSION, str)
        assert _compat.CFFI_VERSION

    def test_flags_are_booleans(self) -> None:
        for flag in (
            _compat.HAS_KEYLOG,
            _compat.HAS_SSL_GET0_GROUP_NAME,
            _compat.HAS_SSL_COOKIE,
            _compat.HAS_UNEXPECTED_EOF_WHILE_READING,
            _compat.HAS_DTLS_GET_DATA_MTU,
        ):
            assert isinstance(flag, bool)

    def test_flags_match_bindings(self) -> None:
        assert _compat.HAS_KEYLOG == bool(
            getattr(lib, "Cryptography_HAS_KEYLOG", 0)
        )
        assert _compat.HAS_SSL_COOKIE == bool(
            getattr(lib, "Cryptography_HAS_SSL_COOKIE", 0)
        )
        assert _compat.HAS_DTLS_GET_DATA_MTU == (
            getattr(lib, "DTLS_get_data_mtu", None) is not None
        )

    def test_dtls1_cookie_length_fallback(self) -> None:
        assert _compat.DTLS1_COOKIE_LENGTH == getattr(
            lib, "DTLS1_COOKIE_LENGTH", 255
        )

    def test_unexpected_eof_reason_matches_flag(self) -> None:
        if _compat.HAS_UNEXPECTED_EOF_WHILE_READING:
            assert _compat.SSL_R_UNEXPECTED_EOF_WHILE_READING is not None
        else:
            assert _compat.SSL_R_UNEXPECTED_EOF_WHILE_READING is None


class TestGracefulDegradation:
    """
    Callers of `OpenSSL._compat` degrade to ``NotImplementedError`` rather
    than ``AttributeError`` when a feature is absent.
    """

    def test_get_cleartext_mtu_without_support(self, monkeypatch) -> None:
        monkeypatch.setattr(_compat, "HAS_DTLS_GET_DATA_MTU", False)
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        connection = SSL.Connection(context, None)
        with pytest.raises(NotImplementedError):
            connection.get_cleartext_mtu()

    @pytest.mark.skipif(
        not _compat.HAS_UNEXPECTED_EOF_WHILE_READING,
        reason="requires OpenSSL 3.0+",
    )
    def test_unexpected_eof_without_constant(self, monkeypatch) -> None:
        """
        The unexpected-EOF handling falls back to raising a generic
        ``SSL.Error`` when the OpenSSL 3 constant is unavailable.
        """
        monkeypatch.setattr(
            _compat, "HAS_UNEXPECTED_EOF_WHILE_READING", False
        )
        server_conn, client_conn = loopback()
        client_conn.sock_shutdown(SHUT_RDWR)
        with pytest.raises(SSL.Error) as err:
            server_conn.recv(1024)
        # The specific SysCallError mapping is unavailable, so the
        # generic error is raised instead.
        assert type(err.value) is SSL.Error
