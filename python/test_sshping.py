#!/usr/bin/env python3
"""Unit tests for the parts of sshping.py that need no ssh server."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sshping  # noqa: E402
from sshping import SSHPingError, fmtnum, latency_stats, parse_target  # noqa: E402


class TestFmtnum(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(fmtnum(1234567, -9, "s"), "1234567 ns")
        self.assertEqual(fmtnum(1000, 0, "B"), "1000 B")

    def test_delimited(self):
        self.assertEqual(fmtnum(1234567, -9, "s", delimited=True),
                         "1,234,567 ns")
        self.assertEqual(fmtnum(123, 0, "B", delimited=True), "123 B")

    def test_human(self):
        h = dict(human=True)
        self.assertEqual(fmtnum(0, -9, "s", **h), "0.00 ns")
        self.assertEqual(fmtnum(1234567, -9, "s", **h), "1.23 ms")
        self.assertEqual(fmtnum(12345678, -9, "s", **h), "12.3 ms")
        self.assertEqual(fmtnum(123456789, -9, "s", **h), "123 ms")
        self.assertEqual(fmtnum(1537191418, -9, "s", **h), "1.54 s")
        self.assertEqual(fmtnum(8000000, 0, "B", **h), "8.00 MB")
        self.assertEqual(fmtnum(50, 0, "B", **h), "50.0 B")

    def test_human_rounding_moves_to_next_digit_or_prefix(self):
        h = dict(human=True)
        self.assertEqual(fmtnum(9996, -9, "s", **h), "10.0 us")
        self.assertEqual(fmtnum(99960, -9, "s", **h), "100 us")
        self.assertEqual(fmtnum(999600, -9, "s", **h), "1.00 ms")

    def test_rounds_floats(self):
        self.assertEqual(fmtnum(2.6, 0, "B"), "3 B")


class TestLatencyStats(unittest.TestCase):
    def test_even_count_median(self):
        # The C++ version averaged the lower middle element with itself
        self.assertEqual(latency_stats([4, 1, 3, 2])["median"], 2.5)

    def test_odd_count(self):
        s = latency_stats([5, 1, 3])
        self.assertEqual((s["min"], s["median"], s["mean"], s["max"]),
                         (1, 3, 3, 5))
        self.assertEqual(s["stdev"], 2)

    def test_single(self):
        self.assertEqual(latency_stats([7])["stdev"], 0)


class TestParseTarget(unittest.TestCase):
    def test_forms(self):
        cases = {
            "host":                 (None, "host", None),
            "host:2222":            (None, "host", 2222),
            "me@host":              ("me", "host", None),
            "me@host:22":           ("me", "host", 22),
            "a@b@host":             ("a@b", "host", None),
            "@host":                (None, "host", None),
            "[::1]":                (None, "::1", None),
            "[::1]:2222":           (None, "::1", 2222),
            "me@[fe80::1]:22":      ("me", "fe80::1", 22),
            "::1":                  (None, "::1", None),
            "host:":                (None, "host", None),
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                self.assertEqual(parse_target(target), expected)

    def test_errors(self):
        for target in ("", "me@", ":22", "host:0", "host:65536", "host:x",
                       "[::1", "[::1]x"):
            with self.subTest(target=target):
                with self.assertRaises(SSHPingError) as cm:
                    parse_target(target)
                self.assertEqual(cm.exception.exit_code, sshping.EXIT_USAGE)


class TestArgs(unittest.TestCase):
    def test_defaults(self):
        a = sshping.parse_args(["host"])
        self.assertEqual(a.count, sshping.DEFAULT_COUNT)
        self.assertEqual(a.echocmd, "stty raw -echo; cat")
        self.assertEqual(a.runtests, "es")

    def test_time_limit_alone_means_no_count_limit(self):
        self.assertIsNone(sshping.parse_args(["-t", "5", "host"]).count)

    def test_bad_values(self):
        for argv in (["-s", "0", "h"], ["-c", "-3", "h"], ["-r", "x", "h"],
                     ["-T", "-1", "h"]):
            with self.subTest(argv=argv):
                with self.assertRaises(SystemExit):
                    sshping.parse_args(argv)


if __name__ == "__main__":
    unittest.main()
