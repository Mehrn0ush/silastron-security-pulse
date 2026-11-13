"""Validate generated feeds against RFC 4287 and sitemaps against the sitemaps.org XSD.

Needs lxml and rnc2rng (requirements-feed-check.lock); the schemas are vendored under vendor/.

    python .github/scripts/validate_site_files.py SITE_DIR

Validates SITE_DIR/sitemap.xml, SITE_DIR/feed.xml, SITE_DIR/kev/feed.xml (and /malware/feed.xml when
present), plus a populated feed made from hostile fixture rows, because a real feed may be empty.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import rnc2rng
from lxml import etree

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from silastron_pulse.feeds import build_feed, kev_entries  # noqa: E402


def atom_schema() -> etree.RelaxNG:
    xml = rnc2rng.dumps(rnc2rng.loads((ROOT / "vendor" / "rfc4287" / "atom.rnc").read_text(encoding="utf-8")))
    # `namespace local = ""` becomes xmlns:local="", which XML forbids; the schema's `local:*` is already ns="".
    xml = re.sub(r'\s+xmlns:local=""', "", xml)
    return etree.RelaxNG(etree.fromstring(xml.encode("utf-8")))


def hostile_feed() -> bytes:
    rows = [
        {"cve_id": "CVE-2026-0001", "kev_date_added": "2026-11-01", "vendor_project": "<script>x</script> & Co",
         "product": "‮evil" + "x" * 5000, "vulnerability_name": "a & b < c > d \"q\" 'r' \u0000 skipped"},
        {"cve_id": "CVE-2026-0002", "kev_date_added": "2026-10-31", "vendor_project": None, "product": None,
         "vulnerability_name": None},
    ]
    entries = kev_entries(rows, "https://pulse.silastron.com")
    return build_feed(title="t & <u>", feed_id="tag:pulse.silastron.com,2026:feed:test",
                      self_href="https://pulse.silastron.com/f.xml", alternate_href="https://pulse.silastron.com/",
                      entries=entries, empty_updated="2026-11-01T00:00:00Z", rights="r")


def check_feed(schema: etree.RelaxNG, name: str, data: bytes) -> bool:
    doc = etree.fromstring(data)
    ok = schema.validate(doc)
    entries = len(doc.findall("{http://www.w3.org/2005/Atom}entry"))
    ids = [e.findtext("{http://www.w3.org/2005/Atom}id") for e in doc.findall("{http://www.w3.org/2005/Atom}entry")]
    unique = len(ids) == len(set(ids))
    print(f"{'PASS' if ok and unique else 'FAIL'}: {name} ({entries} entries{'' if unique else ', DUPLICATE IDS'})")
    for err in schema.error_log:
        print(f"  line {err.line}: {err.message}")
    return ok and unique


def check_sitemap(path: Path) -> bool:
    schema = etree.XMLSchema(etree.parse(str(ROOT / "vendor" / "sitemaps" / "sitemap.xsd")))
    doc = etree.parse(str(path))
    ok = schema.validate(doc)
    urls = doc.getroot().findall("{http://www.sitemaps.org/schemas/sitemap/0.9}url")
    missing = [u.findtext("{http://www.sitemaps.org/schemas/sitemap/0.9}loc") for u in urls
               if u.find("{http://www.sitemaps.org/schemas/sitemap/0.9}lastmod") is None]
    print(f"{'PASS' if ok and not missing else 'FAIL'}: {path} ({len(urls)} URLs, {len(missing)} without lastmod)")
    for err in schema.error_log:
        print(f"  line {err.line}: {err.message}")
    return ok and not missing


def main(site_dir: str) -> int:
    site = Path(site_dir)
    schema = atom_schema()
    results = [check_feed(schema, "populated hostile fixture feed", hostile_feed())]
    for rel in ("feed.xml", "kev/feed.xml", "malware/feed.xml"):
        if (site / rel).is_file():
            results.append(check_feed(schema, rel, (site / rel).read_bytes()))
        elif rel != "malware/feed.xml":
            print(f"FAIL: {rel} is missing")
            results.append(False)
    results.append(check_sitemap(site / "sitemap.xml"))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
