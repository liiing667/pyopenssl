from __future__ import annotations

import os
import sys
import warnings
from typing import Any, Callable, NamedTuple, NoReturn, Union

from cryptography.hazmat.bindings.openssl.binding import Binding

StrOrBytesPath = Union[str, bytes, os.PathLike[str], os.PathLike[bytes]]

binding = Binding()
ffi = binding.ffi
lib: Any = binding.lib


# This is a special CFFI allocator that does not bother to zero its memory
# after allocation. This has vastly better performance on large allocations and
# so should be used whenever we don't need the memory zeroed out.
no_zero_allocator = ffi.new_allocator(should_clear_after_alloc=False)


# Optional error-queue helpers.  Not every cryptography/OpenSSL build
# exposes all of them (for example ``ERR_func_error_string`` is deprecated
# since OpenSSL 3.0 and ``ERR_GET_LIB`` is not bound by cryptography at
# all), so probe them once here and degrade gracefully.
_ERR_func_error_string = getattr(lib, "ERR_func_error_string", None)
_ERR_GET_LIB = getattr(lib, "ERR_GET_LIB", None)
_ERR_GET_REASON = getattr(lib, "ERR_GET_REASON", None)


def _func_error_string(error: int) -> str:
    """
    Return the function string for *error*, or ``""`` when the running
    OpenSSL no longer supports function codes.
    """
    if _ERR_func_error_string is None:
        return ""
    return text(_ERR_func_error_string(error))


def _error_lib_code(error: int) -> int:
    if _ERR_GET_LIB is not None:
        return _ERR_GET_LIB(error)  # type: ignore[no-any-return]
    # OpenSSL 3.x packs the library code into bits 23-30 of the error code.
    return (error >> 23) & 0xFF


def _error_reason_code(error: int) -> int:
    if _ERR_GET_REASON is not None:
        return _ERR_GET_REASON(error)  # type: ignore[no-any-return]
    # OpenSSL 3.x packs the reason code into bits 0-22 of the error code.
    return error & 0x7FFFFF


def text(charp: Any) -> str:
    """
    Get a native string type representing of the given CFFI ``char*`` object.

    :param charp: A C-style string represented using CFFI.

    :return: :class:`str`
    """
    if not charp:
        return ""
    return ffi.string(charp).decode("utf-8")


class OpenSSLErrorInfo(NamedTuple):
    """
    Structured details about a single error from OpenSSL's error queue.

    ``library``, ``function``, and ``reason`` are the human-readable
    strings, mirroring the tuples historically passed to the exception.
    ``code`` is the raw packed OpenSSL error code, while ``library_code``
    and ``reason_code`` are its numeric components (comparable against
    OpenSSL's ``*_LIB_*`` and ``*_R_*`` constants), allowing errors to be
    told apart programmatically - for example an expired certificate
    versus a handshake failure.
    """

    library: str
    function: str
    reason: str
    code: int
    library_code: int
    reason_code: int


def exception_from_error_queue(exception_type: type[Exception]) -> NoReturn:
    """
    Convert an OpenSSL library failure into a Python exception.

    When a call to the native OpenSSL library fails, this is usually signalled
    by the return value, and an error code is stored in an error queue
    associated with the current thread. The err library provides functions to
    obtain these error codes and textual error messages.

    The raised exception's first argument is a list of ``(library,
    function, reason)`` text tuples, as it has always been.  Additionally,
    the exception carries an ``openssl_errors`` attribute: a list of
    :class:`OpenSSLErrorInfo` with the numeric error codes preserved, so
    callers can distinguish specific failure causes.
    """
    errors = []
    error_info = []

    while True:
        error = lib.ERR_get_error()
        if error == 0:
            break
        library = text(lib.ERR_lib_error_string(error))
        function = _func_error_string(error)
        reason = text(lib.ERR_reason_error_string(error))
        errors.append((library, function, reason))
        error_info.append(
            OpenSSLErrorInfo(
                library=library,
                function=function,
                reason=reason,
                code=error,
                library_code=_error_lib_code(error),
                reason_code=_error_reason_code(error),
            )
        )

    exception = exception_type(errors)
    exception.openssl_errors = error_info  # type: ignore[attr-defined]
    raise exception


def make_assert(error: type[Exception]) -> Callable[[bool], Any]:
    """
    Create an assert function that uses :func:`exception_from_error_queue` to
    raise an exception wrapped by *error*.
    """

    def openssl_assert(ok: bool) -> None:
        """
        If *ok* is not True, retrieve the error from OpenSSL and raise it.
        """
        if ok is not True:
            exception_from_error_queue(error)

    return openssl_assert


def path_bytes(s: StrOrBytesPath) -> bytes:
    """
    Convert a Python path to a :py:class:`bytes` for the path which can be
    passed into an OpenSSL API accepting a filename.

    :param s: A path (valid for os.fspath).

    :return: An instance of :py:class:`bytes`.
    """
    b = os.fspath(s)

    if isinstance(b, str):
        return b.encode(sys.getfilesystemencoding())
    else:
        return b


def byte_string(s: str) -> bytes:
    return s.encode("charmap")


# A marker object to observe whether some optional arguments are passed any
# value or not.
UNSPECIFIED = object()

_TEXT_WARNING = "str for {0} is no longer accepted, use bytes"


def text_to_bytes_and_warn(label: str, obj: Any) -> Any:
    """
    If ``obj`` is text, emit a warning that it should be bytes instead and try
    to convert it to bytes automatically.

    :param str label: The name of the parameter from which ``obj`` was taken
        (so a developer can easily find the source of the problem and correct
        it).

    :return: If ``obj`` is the text string type, a ``bytes`` object giving the
        UTF-8 encoding of that text is returned.  Otherwise, ``obj`` itself is
        returned.
    """
    if isinstance(obj, str):
        warnings.warn(
            _TEXT_WARNING.format(label),
            category=DeprecationWarning,
            stacklevel=3,
        )
        return obj.encode("utf-8")
    return obj
