"""Run the project's full test suite on the package's own Python (packaging session 3, phageo).

    <package>\\python\\python.exe tools\\package_suite.py [--project <folder>]

The embeddable Python of the package ignores the current folder and ``PYTHONPATH``
(``python313._pth``), so the project folder is put on ``sys.path`` here; the ``__main__`` guard
keeps the worker processes a benchmark test starts from running the suite a second time (seen in
packaging session 2).

**Left out: the tests of the malicious-sample runner** (``tools/positive_benchmark.py``) - the
``PositiveBenchmarkTests`` class and the one test that runs its ``--diagnose`` mode. Why: the
runner is a developer's tool and is never shipped. Its guard decides "code of the project called
exec / compile" by the caller's file path; the embeddable Python's library inside
``python313.zip`` carries bare relative file names (``ast.py``), which the guard joins to the folder
it was started in - the project - so it stops runs that are fine (packaging session 2: three
failures, none in the package's code). On the project's own Python these tests run in the full suite.
"""
from __future__ import annotations

import argparse
import os
import sys
import unittest

LEFT_OUT_CLASSES = ("PositiveBenchmarkTests",)
LEFT_OUT_TESTS = ("FixSessionThreeTests.test_the_diagnosis_says_where_in_numbers_only",)


def left_out(test_id: str) -> bool:
    """Is this test (``tests.test_gamescan.Class.method``) one of the runner's?"""
    parts = test_id.split(".")
    return (len(parts) >= 2 and parts[-2] in LEFT_OUT_CLASSES) or ".".join(parts[-2:]) in LEFT_OUT_TESTS


def _flat(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flat(item)
        else:
            yield item


def suite(module: str = "tests.test_gamescan") -> tuple:
    """``(the suite without the runner's tests, the ids left out)``."""
    loaded = unittest.defaultTestLoader.loadTestsFromName(module)
    kept, dropped = unittest.TestSuite(), []
    for test in _flat(loaded):
        (dropped.append(test.id()) if left_out(test.id()) else kept.addTest(test))
    return kept, dropped


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = ap.parse_args(argv)
    os.chdir(args.project)
    sys.path.insert(0, args.project)
    tests, dropped = suite()
    sys.stderr.write("python %s %s\nleft out (the malicious-sample runner's tests): %d\n"
                     % (sys.version.split()[0], sys.executable, len(dropped)))
    result = unittest.TextTestRunner(verbosity=1).run(tests)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":                 # worker processes of a test import this file again
    sys.exit(main())
