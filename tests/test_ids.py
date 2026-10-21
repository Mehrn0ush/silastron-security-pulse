from __future__ import annotations

import unittest

from silastron_pulse.errors import ValidationError
from silastron_pulse.ids import cvelist_v5_relpath, parse_cve_id, same_cve_id


class CveIdTests(unittest.TestCase):
    def test_valid_ids(self) -> None:
        self.assertEqual(parse_cve_id("cve-2099-0001"), "CVE-2099-0001")
        self.assertEqual(parse_cve_id("CVE-2021-44228"), "CVE-2021-44228")

    def test_rejects_padding_lookalikes_as_different(self) -> None:
        self.assertFalse(same_cve_id("CVE-2099-0001", "CVE-2099-00001"))

    def test_rejects_malformed(self) -> None:
        for value in ["CVE-99-1", "CVE-2099-1", "not-a-cve", "", None, 123]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    parse_cve_id(value)  # type: ignore[arg-type]

    def test_cvelist_path(self) -> None:
        self.assertEqual(
            cvelist_v5_relpath("CVE-2099-0001"),
            "cves/2099/0xxx/CVE-2099-0001.json",
        )
        self.assertEqual(
            cvelist_v5_relpath("CVE-2021-44228"),
            "cves/2021/44xxx/CVE-2021-44228.json",
        )


if __name__ == "__main__":
    unittest.main()
