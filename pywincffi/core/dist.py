"""
Distribution
============

Module responsible for building the pywincffi distribution
in ``setup.py``.  This module is meant to serve two
purposes.  The first is to serve as the main means of loading
the pywincffi library:

>>> from pywincffi.core import dist
>>> ffi, lib = dist.load()

The second is to facilitate a means of building a static
library.  This is used by the setup.py during the install
process to build and install pywincffi as well as a wheel
for distribution.
"""

from __future__ import print_function

import shutil
import os
import sys
import tempfile
import warnings
from contextlib import contextmanager
from errno import ENOENT
from os.path import join, isfile
from pkg_resources import resource_filename

from cffi import FFI

from pywincffi.core.logger import get_logger
from pywincffi.exceptions import ResourceNotFoundError

imp = None
ExtensionFileLoader = None
try:
    # pylint: disable=wrong-import-order
    from importlib.machinery import ExtensionFileLoader
except ImportError:
    import imp

try:
    WindowsError
except NameError:
    WindowsError = OSError

__all__ = ("load", )

logger = get_logger("core.dist")

MODULE_NAME = "_pywincffi"
HEADER_FILES = [
    resource_filename(
        "pywincffi", join("core", "cdefs", "headers", "constants.h")),
    resource_filename(
        "pywincffi", join("core", "cdefs", "headers", "structs.h")),
    resource_filename(
        "pywincffi", join("core", "cdefs", "headers", "functions.h"))]
SOURCE_FILES = [
    resource_filename(
        "pywincffi", join("core", "cdefs", "sources", "main.c"))]


class Module(object):
    """
    Used and returned by :func:`load`.  This class stores information
    about a loaded module and is
    """
    cache = None

    def __init__(self, module, mode):
        if self.cache is not None:
            warnings.warn(
                "Module() was instanced multiple times", RuntimeWarning)

        self.module = module
        self.mode = mode
        self.ffi = module.ffi
        self.lib = module.lib

    def __repr__(self):
        return "%r (%s)" % (self.module, self.mode)

    def __iter__(self):
        """
        Override the original __iter__ so tuple unpacking can be
        used to pull out ffi and lib.  This will allow
        """
        yield self.ffi
        yield self.lib


@contextmanager
def _silence(silence):  # pragma: no cover
    """
    The compile step tends to be noisy so this context manager will silent
    the output.  It shouldn't be used to silence ``sys.stderr`` and should
    be used to display data from ``sys.stdout`` if there are problems:

    >>> import sys, os
    >>> with _silence(sys.stdout) as out_path:
    ...     try:
    ...         print("Foobar", file=sys.stdout)
    ...         raise Exception("Some failure")
    ...     except Exception:
    ...         with open(out_path) as file_:
    ...             print(file_.read(), file=sys.stderr)
    ...         raise
    ...     finally:
    ...         os.remove(out_path)
    """
    silence_fd = silence.fileno()

    with os.fdopen(os.dup(silence_fd), "wb") as copied:
        silence.flush()  # Flush library buffers that dup2 knows nothing about

        fd, path = tempfile.mkstemp()
        os.dup2(fd, silence_fd)

        try:
            yield path
        finally:
            silence.flush()
            os.dup2(copied.fileno(), silence_fd)
            os.fsync(fd)
            os.close(fd)


def _import_path(path, module_name=None):
    """
    Function which imports ``path`` and returns it as a module.  This is
    meant to import pyd files produced by :meth:`Distribution._build` in
    a Python 2/3 agnostic fashion.

    :param str path:
        The path to the file to import

    :keyword str module_name:
        Optional name of the module being imported.  By default
        this will use ``Module.name`` if no value is provided.

    :raises ResourceNotFoundError:
        Raised if ``path`` does not exist.
    """
    if module_name is None:  # pragma: no cover
        module_name = MODULE_NAME

    logger.debug("_import_path(%r, module_name=%r)", path, module_name)

    if not isfile(path):
        raise ResourceNotFoundError("Module path %r does not exist" % path)

    elif ExtensionFileLoader is not None:
        loader = ExtensionFileLoader(module_name, path)
        return loader.load_module(module_name)

    elif imp is not None:
        return imp.load_dynamic(module_name, path)

    else:
        raise NotImplementedError(
            "Neither `imp` or `ExtensionFileLoader` were imported")


def _read(*paths):
    """
    Iterates over ``files`` and produces string which combines all inputs
    into a single string.

    :raises ResourceNotFoundError:
        Raised if one of the files in ``files`` is missing.
    """
    logger.debug("_read(%r)", paths)

    output = ""
    for path in paths:
        try:
            with open(path, "r") as file_:
                output += file_.read()
        except (OSError, IOError, WindowsError) as error:
            if error.errno == ENOENT:
                raise ResourceNotFoundError("Failed to locate %s" % path)
            raise

    return output


def _ffi():
    """
    Returns an instance of :class:`FFI` without compiling
    the module.  This function is used internally but also
    as an entrypoint in the setup.py for `cffi_modules`.
    """
    logger.debug("_ffi()")
    header = _read(*HEADER_FILES)
    source = _read(*SOURCE_FILES)

    ffi = FFI()
    ffi.set_unicode(True)
    ffi.set_source(MODULE_NAME, source)
    ffi.cdef(header)

    return ffi


def _compile(ffi, tmpdir=None):
    """
    Performs the compile step, loads the resulting module and then
    return it.

    :param cffi.FFI ffi:
        An instance of :class:`FFI` which you wish to compile and load
        the resulting module for.

    :keyword str tmpdir:
        The path to compile the module to.  By default this will be
        constructed using ``tempfile.mkdtemp(prefix="pywincffi-")``.

    :returns:
        Returns the module built by compiling the ``ffi`` object.
    """
    if tmpdir is None:
        tmpdir = tempfile.mkdtemp(prefix="pywincffi-")

    logger.debug("_compile(%r, tmpdir=%r)", ffi, tmpdir)

    with _silence(sys.stdout) as out_path:
        try:
            pyd_path = ffi.compile(tmpdir=tmpdir)

        except Exception:  # pragma: no cover
            with open(out_path) as file_:
                print(file_.read(), file=sys.stderr)
            raise

    os.remove(out_path)
    module = _import_path(pyd_path)

    # Try to cleanup the temp directory that was created
    # for compiling the module.  In most cases this will
    # remove everything but the built .pyd file.
    shutil.rmtree(tmpdir, ignore_errors=True)

    return module


def load():
    """
    The main function used by pywincffi to load an instance of
    :class:`FFI` and the underlying build library.
    """
    if Module.cache is not None:
        return Module.cache

    logger.debug("load()")
    try:
        import _pywincffi
        Module.cache = Module(_pywincffi, "prebuilt")

    except ImportError:
        Module.cache = Module(_compile(_ffi()), "compiled")

    return Module.cache
