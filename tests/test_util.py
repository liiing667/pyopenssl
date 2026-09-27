import pytest

from OpenSSL._util import (
    OpenSSLErrorInfo,
    _error_lib_code,
    _error_reason_code,
    exception_from_error_queue,
    lib,
)


class TestErrors:
    """
    Tests for handling of certain OpenSSL error cases.
    """

    def test_exception_from_error_queue_nonexistent_reason(self) -> None:
        """
        :func:`exception_from_error_queue` raises ``ValueError`` when it
        encounters an OpenSSL error code which does not have a reason string.
        """
        lib.ERR_put_error(lib.ERR_LIB_EVP, 0, 1112, b"", 10)
        with pytest.raises(ValueError) as exc:
            exception_from_error_queue(ValueError)
        assert exc.value.args[0][0][2] in ("", "unknown error")

    def test_exception_carries_structured_error_info(self) -> None:
        """
        Exceptions raised by :func:`exception_from_error_queue` carry an
        ``openssl_errors`` attribute with :class:`OpenSSLErrorInfo` entries
        that preserve the numeric OpenSSL error codes, so specific failure
        causes can be told apart programmatically.
        """
        lib.ERR_put_error(lib.ERR_LIB_EVP, 0, 1112, b"", 10)
        with pytest.raises(ValueError) as exc:
            exception_from_error_queue(ValueError)

        (info,) = exc.value.openssl_errors
        assert isinstance(info, OpenSSLErrorInfo)
        # The text components mirror the historical argument tuples.
        assert (info.library, info.function, info.reason) == (
            exc.value.args[0][0]
        )
        # The numeric components identify the error precisely.
        assert isinstance(info.code, int)
        assert info.code != 0
        assert info.library_code == lib.ERR_LIB_EVP
        assert info.reason_code == 1112

    def test_exception_from_empty_error_queue(self) -> None:
        """
        :func:`exception_from_error_queue` attaches an empty
        ``openssl_errors`` list when the error queue is empty.
        """
        with pytest.raises(ValueError) as exc:
            exception_from_error_queue(ValueError)
        assert exc.value.args[0] == []
        assert exc.value.openssl_errors == []

    def test_error_code_decoding_matches_openssl(self) -> None:
        """
        The fallback decoding of packed OpenSSL error codes agrees with
        OpenSSL's own ``ERR_GET_*`` macros when those are available.
        """
        lib.ERR_put_error(lib.ERR_LIB_EVP, 0, 1112, b"", 10)
        error = lib.ERR_get_error()
        assert _error_lib_code(error) == lib.ERR_LIB_EVP
        assert _error_reason_code(error) == 1112

    def test_missing_func_error_string_degrades(self, monkeypatch) -> None:
        """
        When the bindings do not expose ``ERR_func_error_string`` (it is
        deprecated since OpenSSL 3.0), the function component degrades to
        an empty string instead of raising ``AttributeError``.
        """
        import OpenSSL._util

        monkeypatch.setattr(OpenSSL._util, "_ERR_func_error_string", None)
        lib.ERR_put_error(lib.ERR_LIB_EVP, 0, 1112, b"", 10)
        with pytest.raises(ValueError) as exc:
            exception_from_error_queue(ValueError)
        assert exc.value.args[0][0][1] == ""
        assert exc.value.openssl_errors[0].function == ""
