"""
Security
---------------

This module contains general functions for security objects and
events.  The functions provided in this module are parts of the ``shell32``
library.

.. seealso::

    :mod:`pywincffi.shell32.security`
"""

from six import integer_types

from pywincffi.core import dist
from pywincffi.core.checks import Enums, input_check, error_check
from pywincffi.exceptions import WindowsAPIError, PyWinCFFINotImplementedError
from pywincffi.kernel32.handle import CloseHandle
from pywincffi.kernel32.synchronization import WaitForSingleObject
from pywincffi.wintypes import HANDLE, wintype_to_cdata


def CheckTokenMembership(TokenHandle, SidToCheck, IsMember):
    """
    The CheckTokenMembership function determines whether a specified
    security identifier (SID) is enabled in an access token.

    .. see also::

        https://msdn.microsoft.com/en-us/aa376389

    :param int TokenHandle:
        A handle to an access token.

    :param int SidToCheck:
        A pointer to a SID structure.

    :param int IsMember:
        A pointer to a variable that receives the results of the check.

    :return:
        If the function succeeds,
        the return value is nonzero.
    """

    input_check("TokenHandle", TokenHandle, integer_types)
    input_check("SidToCheck", SidToCheck, integer_types)
    input_check("IsMember", IsMember, integer_types)
    ffi, library = dist.load()
    sid = library.CreateToolhelp32Snapshot(
        ffi.cast("HANDLE", TokenHandle),
        ffi.cast("PSID", SidToCheck),
        ffi.cast("DWORD", IsMember)
    )
    error_check("CheckTokenMembership")
    return sid