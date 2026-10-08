import unittest

from frecon.scanner import Target, build_findings, parse_target


class ParseTargetTests(unittest.TestCase):
    def test_hostname_defaults_to_https(self):
        target = parse_target("example.com")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.web_url, "https://example.com/")

    def test_url_uses_host_and_explicit_port(self):
        target = parse_target("http://Example.com:8080/a/path")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.web_url, "http://example.com:8080/")

    def test_ipv6_literal_is_normalized(self):
        target = parse_target("https://[2001:db8::1]")
        self.assertEqual(target.host, "2001:db8::1")
        self.assertEqual(target.web_url, "https://[2001:db8::1]/")

    def test_bare_ipv6_literal_is_supported(self):
        target = parse_target("2001:db8::1")
        self.assertEqual(target.host, "2001:db8::1")
        self.assertEqual(target.scheme, "https")

    def test_rejects_unsupported_scheme_and_credentials(self):
        with self.assertRaises(ValueError):
            parse_target("ftp://example.com")
        with self.assertRaises(ValueError):
            parse_target("https://user:pass@example.com")

    def test_risky_port_is_reported_as_indicator(self):
        findings = build_findings(
            [{"port": 3389, "service": "ms-wbt-server"}],
            {"url": "https://example.com", "http": None, "tls": None},
        )
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("Remote Desktop", findings[0]["title"])

    def test_missing_web_headers_are_reported(self):
        findings = build_findings(
            [],
            {"url": "https://example.com/", "http": {"headers": {}}, "tls": None},
        )
        titles = {finding["title"] for finding in findings}
        self.assertIn("HSTS header missing", titles)
        self.assertIn("Content Security Policy header missing", titles)

    def test_invalid_tls_certificate_is_reported(self):
        findings = build_findings(
            [],
            {
                "url": "https://example.com/",
                "http": None,
                "tls": {"verified": False, "certificate_error": True, "error": "hostname mismatch"},
            },
        )
        self.assertEqual(findings[0]["title"], "TLS certificate validation failed")


if __name__ == "__main__":
    unittest.main()