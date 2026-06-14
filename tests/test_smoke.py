"""Smoke tests for EMAILRECON. No network is used (all DNS disabled)."""
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from emailrecon import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    analyze_email,
    analyze_domain,
    build_report,
)
from emailrecon.cli import main  # noqa: E402
from emailrecon.core import Severity, breach_hints, load_breach_corpus  # noqa: E402


class TestEmailAnalysis(unittest.TestCase):
    def test_valid_simple(self):
        e = analyze_email("Alice@Example.com")
        self.assertTrue(e.valid_syntax)
        self.assertEqual(e.normalized, "alice@example.com")
        self.assertEqual(e.domain, "example.com")
        self.assertFalse(e.is_role_account)

    def test_invalid(self):
        for bad in ("", "nope", "a@", "@b.com", "a@b", "a b@c.com"):
            self.assertFalse(analyze_email(bad).valid_syntax, bad)

    def test_role_disposable_freemail(self):
        e = analyze_email("admin@mailinator.com")
        self.assertTrue(e.is_role_account)
        self.assertTrue(e.is_disposable)
        self.assertFalse(e.is_freemail)

        g = analyze_email("someone@gmail.com")
        self.assertTrue(g.is_freemail)

    def test_plus_tag(self):
        e = analyze_email("user+newsletter@example.com")
        self.assertTrue(e.has_plus_tag)
        self.assertEqual(e.plus_tag, "newsletter")
        # role detection uses the base local-part
        r = analyze_email("admin+abc@example.com")
        self.assertTrue(r.is_role_account)


class TestDomainPosture(unittest.TestCase):
    def test_no_lookups(self):
        d = analyze_domain("example.com", do_lookups=False)
        self.assertFalse(d.lookups_performed)
        self.assertEqual(d.mx_records, [])


class TestBreachCorpus(unittest.TestCase):
    def test_load_and_match(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("# comment\nmailinator.com\njoe@leak.example\n")
            path = fh.name
        try:
            corpus = load_breach_corpus(path)
            self.assertIn("mailinator.com", corpus)
            e = analyze_email("admin@mailinator.com")
            hints = breach_hints(e, corpus)
            self.assertTrue(any("mailinator.com" in h for h in hints))
        finally:
            os.unlink(path)

    def test_missing_corpus(self):
        self.assertEqual(load_breach_corpus("/no/such/file.txt"), set())
        self.assertEqual(load_breach_corpus(None), set())


class TestReport(unittest.TestCase):
    def test_build_report_offline(self):
        report = build_report("admin@mailinator.com", do_lookups=False)
        self.assertEqual(report.tool, TOOL_NAME)
        codes = {f.code for f in report.findings}
        self.assertIn("DISPOSABLE_DOMAIN", codes)
        self.assertIn("ROLE_ACCOUNT", codes)
        self.assertIn("DNS_NOT_CHECKED", codes)
        self.assertGreaterEqual(report.max_severity.rank, Severity.MEDIUM.rank)

    def test_invalid_report(self):
        report = build_report("not-an-email", do_lookups=False)
        self.assertFalse(report.email.valid_syntax)
        self.assertEqual(report.findings[0].code, "EMAIL_INVALID")

    def test_report_json_roundtrip(self):
        report = build_report("user@gmail.com", do_lookups=False)
        data = json.loads(json.dumps(report.to_dict()))
        self.assertEqual(data["email"]["domain"], "gmail.com")
        self.assertIn("findings", data)


class TestCli(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def test_scan_json_findings_exit(self):
        code, out, _ = self._run(
            ["scan", "admin@mailinator.com", "--no-dns", "--format", "json"]
        )
        self.assertEqual(code, 3)  # findings present -> non-zero
        payload = json.loads(out)
        self.assertEqual(payload["tool"], TOOL_NAME)
        self.assertEqual(payload["version"], TOOL_VERSION)

    def test_scan_table_clean_freemail(self):
        # gmail address: only INFO-level finding (FREEMAIL) -> exit 0
        code, out, _ = self._run(["scan", "jane@gmail.com", "--no-dns"])
        self.assertEqual(code, 0)
        self.assertIn("emailrecon", out)

    def test_scan_invalid_exit(self):
        code, _, _ = self._run(["scan", "garbage", "--no-dns"])
        self.assertEqual(code, 3)  # EMAIL_INVALID is HIGH


class TestHardenedEdgeCases(unittest.TestCase):
    """Tests for hardening: input validation, error handling, and edge cases."""

    # ------------------------------------------------------------------
    # CLI: --timeout validation
    # ------------------------------------------------------------------

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def test_cli_negative_timeout_returns_2(self):
        code, _out, err = self._run(["scan", "user@example.com", "--no-dns", "--timeout", "-1"])
        self.assertEqual(code, 2)
        self.assertIn("timeout", err.lower())

    def test_cli_zero_timeout_returns_2(self):
        code, _out, err = self._run(["scan", "user@example.com", "--no-dns", "--timeout", "0"])
        self.assertEqual(code, 2)
        self.assertIn("timeout", err.lower())

    # ------------------------------------------------------------------
    # CLI: --breach-corpus path validation
    # ------------------------------------------------------------------

    def test_cli_missing_breach_corpus_returns_2(self):
        code, _out, err = self._run(
            ["scan", "user@example.com", "--no-dns", "--breach-corpus", "/nonexistent/corpus.txt"]
        )
        self.assertEqual(code, 2)
        self.assertIn("breach corpus", err.lower())

    def test_cli_valid_breach_corpus_works(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("example.com\n")
            path = fh.name
        try:
            code, _out, err = self._run(
                ["scan", "user@example.com", "--no-dns", "--breach-corpus", path]
            )
            # findings present (BREACH_HINT + DNS_NOT_CHECKED) -> exit 3
            self.assertEqual(code, 3)
        finally:
            os.unlink(path)

    # ------------------------------------------------------------------
    # core: build_report timeout validation
    # ------------------------------------------------------------------

    def test_build_report_negative_timeout_raises(self):
        with self.assertRaises(ValueError):
            build_report("user@example.com", do_lookups=False, timeout=-5.0)

    def test_build_report_zero_timeout_raises(self):
        with self.assertRaises(ValueError):
            build_report("user@example.com", do_lookups=False, timeout=0)

    # ------------------------------------------------------------------
    # core: empty / whitespace-only email
    # ------------------------------------------------------------------

    def test_empty_email_is_invalid(self):
        e = analyze_email("")
        self.assertFalse(e.valid_syntax)

    def test_whitespace_email_is_invalid(self):
        e = analyze_email("   ")
        self.assertFalse(e.valid_syntax)

    def test_none_like_string_is_invalid(self):
        # Passing None-ish strings — must not raise
        for bad in ("None", "null", "undefined"):
            self.assertFalse(analyze_email(bad).valid_syntax)

    # ------------------------------------------------------------------
    # core: breach corpus edge cases
    # ------------------------------------------------------------------

    def test_empty_breach_corpus_file_yields_empty_set(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("")  # empty file
            path = fh.name
        try:
            corpus = load_breach_corpus(path)
            self.assertEqual(corpus, set())
        finally:
            os.unlink(path)

    def test_breach_corpus_comments_only_yields_empty_set(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("# all lines are comments\n# another comment\n")
            path = fh.name
        try:
            corpus = load_breach_corpus(path)
            self.assertEqual(corpus, set())
        finally:
            os.unlink(path)

    # ------------------------------------------------------------------
    # mcp_server: module imports cleanly (broken imports were a real bug)
    # ------------------------------------------------------------------

    def test_mcp_server_importable(self):
        import importlib
        mod = importlib.import_module("emailrecon.mcp_server")
        self.assertTrue(callable(getattr(mod, "serve", None)))


if __name__ == "__main__":
    unittest.main()
