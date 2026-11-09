#!/usr/bin/env python
"""
Run the test suite: `python runtests.py [test labels]`.
"""

import os
import sys

import django
from django.conf import settings
from django.test.utils import get_runner


if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')
    django.setup()

    TestRunner = get_runner(settings)
    failures = TestRunner(verbosity=1).run_tests(sys.argv[1:] or ['tests'])
    sys.exit(bool(failures))
