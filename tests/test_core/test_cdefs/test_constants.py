import re
from os.path import isfile, join

from pywincffi.core.ffi import Library
from pywincffi.core.testutil import TestCase


class TestConstantsHeader(TestCase):
    def test_file_exists(self):
        for path in Library.HEADERS:
            if path.endswith("constants.h"):
                self.assertTrue(isfile(path))

    def get_constants(self):
        with open(join(Library.HEADERS_ROOT, "constants.h"), "r") as header:
            for line in header:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue

                match = re.match("^#define ([A-Z_]*) \.\.\..*$", line)
                if match is not None:
                    yield match.group(1)

    def test_library_has_attributes_defined_in_header(self):
        ffi, library = Library.load()
        for constant_name in self.get_constants():
            self.assertTrue(hasattr(library, constant_name))


