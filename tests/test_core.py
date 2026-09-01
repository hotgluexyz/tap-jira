"""Tests standard tap features using the built-in SDK tests library."""

import datetime

import pytest
from hotglue_singer_sdk.testing import get_standard_tap_tests

from tap_jira.tap import TapJira

SAMPLE_CONFIG = {
    "start_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
    # TODO: Initialize minimal tap config
    "client_id": "placeholder",
    "client_secret": "placeholder",
}

# _test_stream_connections makes live HTTP calls; excluded by default.
# Replace SAMPLE_CONFIG placeholders with real credentials and call it directly.
_STANDARD_TESTS = [
    t
    for t in get_standard_tap_tests(TapJira, config=SAMPLE_CONFIG)
    if getattr(t, "__name__", "") != "_test_stream_connections"
]


@pytest.mark.parametrize("test_func", _STANDARD_TESTS)
def test_standard(test_func):
    """Run built-in SDK tap tests (CLI output and catalog discovery)."""
    test_func()


# TODO: Create additional tests as appropriate for your tap.
