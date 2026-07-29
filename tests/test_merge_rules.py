import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "merge-rules.py"
SPEC = importlib.util.spec_from_file_location("merge_rules", SCRIPT)
assert SPEC and SPEC.loader
merge_rules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(merge_rules)


class MergeRulesTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def write(self, name, content):
        path = self.directory / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_translates_supported_singbox_fields(self):
        path = self.write(
            "rules.json",
            json.dumps(
                {
                    "version": 2,
                    "rules": [
                        {
                            "domain": ["EXAMPLE.COM", "exact.example"],
                            "domain_suffix": ["Ads.Example", ".child.example"],
                            "domain_keyword": ["track.er*"],
                            "domain_regex": [r"^ad[0-9]+\.example$"],
                        }
                    ],
                }
            ),
        )

        lines = merge_rules.parse_singbox_json(path)

        self.assertEqual(
            lines,
            {
                "|example.com^",
                "|exact.example^",
                "||ads.example^",
                "||*.child.example^",
                r"/track\.er\*/",
                r"/^ad[0-9]+\.example$/",
            },
        )

    def test_re2_literal_escaping_preserves_keyword_characters(self):
        self.assertEqual(
            merge_rules.escape_re2_literal(r"a.b*[c](d){e}?^$|\z-"),
            r"a\.b\*\[c\]\(d\)\{e\}\?\^\$\|\\z-",
        )

    def test_rejects_ip_cidr_instead_of_silently_losing_it(self):
        path = self.write(
            "rules.json",
            json.dumps({"version": 2, "rules": [{"ip_cidr": "192.0.2.0/24"}]}),
        )

        with self.assertRaisesRegex(ValueError, "cannot be represented"):
            merge_rules.parse_singbox_json(path)

    def test_rejects_fields_with_and_semantics(self):
        path = self.write(
            "rules.json",
            json.dumps(
                {
                    "version": 2,
                    "rules": [{"domain": "example.com", "port": 443}],
                }
            ),
        )

        with self.assertRaisesRegex(ValueError, "AND semantics"):
            merge_rules.parse_singbox_json(path)

    def test_rejects_logical_and_inverted_rules(self):
        logical = self.write(
            "logical.json",
            json.dumps(
                {
                    "version": 2,
                    "rules": [{"type": "logical", "mode": "and", "rules": []}],
                }
            ),
        )
        inverted = self.write(
            "inverted.json",
            json.dumps(
                {"version": 2, "rules": [{"domain": "example.com", "invert": True}]}
            ),
        )

        with self.assertRaisesRegex(ValueError, "logical"):
            merge_rules.parse_singbox_json(logical)
        with self.assertRaisesRegex(ValueError, "invert"):
            merge_rules.parse_singbox_json(inverted)

    def test_preserves_officially_supported_adguard_syntax(self):
        path = self.write(
            "rules.txt",
            "[Adblock Plus 2.0]\n! comment\n||Example.COM^\n"
            "@@||allowed.example^\n||wild*.example^\n"
            "/^ad[0-9]+\\.example$/\n||important.example^$important\n"
            "0.0.0.0 hosts.example\nplain.example\n",
        )

        lines = merge_rules.parse_adguard_source(path)

        self.assertEqual(
            lines,
            {
                "||Example.COM^",
                "@@||allowed.example^",
                "||wild*.example^",
                r"/^ad[0-9]+\.example$/",
                "||important.example^$important",
                "0.0.0.0 hosts.example",
                "plain.example",
            },
        )

    def test_missing_configured_source_fails_by_default(self):
        with mock.patch.object(
            merge_rules, "SOURCES", (("missing.txt", "Missing", "adguard"),)
        ):
            with self.assertRaisesRegex(FileNotFoundError, "Required source"):
                merge_rules.merge_sources(self.directory)

    def test_merge_deduplicates_exact_lines_across_formats(self):
        self.write(
            "one.json",
            json.dumps(
                {"version": 2, "rules": [{"domain_suffix": "ads.example"}]}
            ),
        )
        self.write(
            "two.txt",
            "! metadata\n||ads.example^\n@@||allowed.example^\n",
        )

        with mock.patch.object(
            merge_rules,
            "SOURCES",
            (
                ("one.json", "One", "sing-box"),
                ("two.txt", "Two", "adguard"),
            ),
        ):
            with redirect_stdout(io.StringIO()):
                merged = merge_rules.merge_sources(self.directory)

        self.assertEqual(merged, {"||ads.example^", "@@||allowed.example^"})

    def test_output_is_sorted_and_deterministic(self):
        output = self.directory / "combined.txt"

        merge_rules.write_adguard_source(
            {"||z.example^", "||a.example^"}, output
        )
        first = output.read_bytes()
        merge_rules.write_adguard_source(
            {"||a.example^", "||z.example^"}, output
        )

        self.assertEqual(first, output.read_bytes())
        self.assertEqual(
            output.read_text(encoding="utf-8").splitlines()[-2:],
            ["||a.example^", "||z.example^"],
        )
        self.assertTrue(first.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
