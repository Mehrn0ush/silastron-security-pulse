"""Regression tests for release-audit findings F5–F14."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from silastron_pulse.adapters.cve import _fetch_one, parse_cve_record
from silastron_pulse.adapters.kev import parse_kev_catalog
from silastron_pulse.constants import CVE_DELTA_JSON_URL, CVE_DELTA_LOG_URL, KEV_JSON_URL
from silastron_pulse.diff import detect_changes
from silastron_pulse.errors import ArtifactVerifyError, FetchError, PublishGuardError, ValidationError
from silastron_pulse.freshness import freshness
from silastron_pulse.http import FetchResult, RetryingFetcher, ScriptedFetcher
from silastron_pulse.ids import cvelist_v5_raw_url
from silastron_pulse.jsonutil import sha256_bytes
from silastron_pulse.links import authoritative_href
from silastron_pulse.pipeline import collect, _entries_from_snapshot
from silastron_pulse.store import promote_snapshot, rollback_snapshot
from silastron_pulse.verify_run import verify_collect_run
from tests.support import fetch_result, fixture_bytes, frozen_clock, test_config, valid_fetcher

ROOT = Path(__file__).resolve().parents[1]


class KevRemovalTests(unittest.TestCase):
    def test_kev_removals_are_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config(Path(tmp))
            first = collect(config=config, fetcher=valid_fetcher(), clock=frozen_clock())
            assert first.snapshot is not None
            previous = _entries_from_snapshot(first.snapshot)
            second = collect(
                config=test_config(Path(tmp) / "second"),
                fetcher=valid_fetcher(**{KEV_JSON_URL: fetch_result(KEV_JSON_URL, "kev_one.json")}),
                clock=frozen_clock(),
                previous_snapshot_path=Path(tmp) / "candidate.json",
            )
            assert second.snapshot is not None
            current = _entries_from_snapshot(second.snapshot)
            changes = detect_changes(previous, current)
            self.assertEqual(changes.removed_kev_entries, ["CVE-2099-0002"])
            self.assertIn("CVE-2099-0002", second.snapshot["changes"]["removed_kev_entries"])

    def test_detect_changes_fails_closed_if_removals_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config(Path(tmp))
            result = collect(config=config, fetcher=valid_fetcher(), clock=frozen_clock())
            entries = _entries_from_snapshot(result.snapshot)
            reduced = dict(entries)
            reduced.pop("CVE-2099-0002")
            changes = detect_changes(entries, reduced)
            self.assertTrue(changes.removed_kev_entries)
            self.assertIn("removed_kev_entries", changes.to_dict())


class PreviousSnapshotTests(unittest.TestCase):
    def test_missing_previous_snapshot_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config(Path(tmp))
            result = collect(
                config=config,
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                previous_snapshot_path=Path(tmp) / "missing.json",
            )
            self.assertEqual(result.status, "failed")
            self.assertIn("unavailable", result.error or "")

    def test_source_state_without_snapshot_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            (state / "source").mkdir(parents=True)
            (state / "source" / "manifest.json").write_text("{}", encoding="utf-8")
            result = collect(
                config=test_config(root / "out"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=state,
            )
            self.assertEqual(result.status, "failed")
            self.assertIn("Previous snapshot is required", result.error or "")


class CveRevisionTests(unittest.TestCase):
    def test_delta_forces_cve_refetch_independent_of_kev(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = collect(
                config=test_config(root / "one"),
                fetcher=valid_fetcher(),
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            self.assertEqual(first.status, "ok")
            updated_url = cvelist_v5_raw_url("CVE-2099-0001")
            fetcher = valid_fetcher(
                **{
                    CVE_DELTA_JSON_URL: fetch_result(CVE_DELTA_JSON_URL, "delta.json"),
                    CVE_DELTA_LOG_URL: fetch_result(CVE_DELTA_LOG_URL, "delta_log.json"),
                    updated_url: fetch_result(updated_url, "cve_2099_0001_updated.json"),
                }
            )
            second = collect(
                config=test_config(root / "two"),
                fetcher=fetcher,
                clock=frozen_clock(),
                state_dir=root / "state",
            )
            assert second.snapshot is not None
            self.assertEqual(second.snapshot["summary"]["cve_strategy"], "delta")
            self.assertIn("CVE-2099-0001", second.snapshot["changes"]["changed_cve_information"])
            record = next(item for item in second.snapshot["records"] if item["cve_id"] == "CVE-2099-0001")
            self.assertEqual(record["cve"]["date_updated"], "2099-01-11T00:00:00.000Z")


class ReplayAndArtifactTests(unittest.TestCase):
    def _published(self, root: Path) -> tuple[dict, Path]:
        config = test_config(root)
        result = collect(config=config, fetcher=valid_fetcher(), clock=frozen_clock())
        assert result.snapshot is not None
        published = root / "published"
        promote_snapshot(
            result.snapshot,
            published,
            now=datetime(2099, 1, 10, 12, tzinfo=timezone.utc),
            stale_after_hours=36,
            max_bytes=config.max_kev_bytes,
            max_depth=config.max_json_depth,
        )
        return result.snapshot, published

    def test_stale_candidate_replay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, published = self._published(root)
            older = dict(snapshot)
            older["generated_at"] = "2099-01-01T00:00:00Z"
            older["snapshot_id"] = "stale-replay"
            with self.assertRaises(PublishGuardError):
                promote_snapshot(
                    older,
                    published,
                    now=datetime(2099, 1, 10, 13, tzinfo=timezone.utc),
                    stale_after_hours=36,
                    max_bytes=test_config(root).max_kev_bytes,
                    max_depth=test_config(root).max_json_depth,
                )

    def test_superseded_snapshot_id_cannot_be_replayed_without_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, published = self._published(root)
            second = dict(first)
            second["generated_at"] = "2099-01-10T13:00:00Z"
            second["snapshot_id"] = "newer-snapshot"
            promote_snapshot(
                second,
                published,
                now=datetime(2099, 1, 10, 13, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=test_config(root).max_kev_bytes,
                max_depth=test_config(root).max_json_depth,
            )
            with self.assertRaises(PublishGuardError):
                promote_snapshot(
                    first,
                    published,
                    now=datetime(2099, 1, 10, 14, tzinfo=timezone.utc),
                    stale_after_hours=36,
                    max_bytes=test_config(root).max_kev_bytes,
                    max_depth=test_config(root).max_json_depth,
                )
            rollback_snapshot(
                published,
                first["snapshot_id"],
                now=datetime(2099, 1, 10, 15, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=test_config(root).max_kev_bytes,
                max_depth=test_config(root).max_json_depth,
                confirm="ROLLBACK",
            )
            latest = json.loads((published / "latest.json").read_text())
            self.assertEqual(latest["snapshot_id"], first["snapshot_id"])
            manifest = json.loads((published / "manifest.json").read_text())
            self.assertEqual(manifest["publication_state"], "rolled_back")

    def _run(self, **overrides: object) -> dict:
        payload = {
            "id": 39739385294,
            "repository_full_name": "Mehrn0ush/silastron-security-pulse",
            "path": ".github/workflows/collect.yml",
            "name": "Collect",
            "head_branch": "main",
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_sha": "abc",
        }
        payload.update(overrides)
        return payload

    def _candidate(self, *, head_sha: str = "abc", revision: str = "kev:cve") -> tuple[bytes, str, dict, str]:
        snapshot = {
            "snapshot_id": "20261022T071919Z_113d2177d767",
            "binding": {
                "collector_commit_sha": head_sha,
                "source_state_revision": revision,
            },
        }
        payload = json.dumps(snapshot, separators=(",", ":")).encode("utf-8")
        digest = sha256_bytes(payload)
        metadata = {"content_sha256": digest, "source_state_revision": revision}
        sha256sums = f"{digest}  candidate.json\n"
        return payload, digest, metadata, sha256sums

    def test_unrelated_collection_artifact_is_rejected(self) -> None:
        payload, digest, metadata, sha256sums = self._candidate()
        with self.assertRaises(ArtifactVerifyError):
            verify_collect_run(
                self._run(path=".github/workflows/ci.yml", name="CI"),
                expected_repository="Mehrn0ush/silastron-security-pulse",
                expected_branch="main",
                expected_head_sha="abc",
                artifact={"name": "pulse-candidate", "digest": "sha256:" + ("0" * 64)},
                candidate_bytes=payload,
                expected_digest=digest,
                metadata=metadata,
                sha256sums_text=sha256sums,
            )

    def test_github_archive_digest_may_differ_from_candidate_content(self) -> None:
        payload, digest, metadata, sha256sums = self._candidate()
        result = verify_collect_run(
            self._run(),
            expected_repository="Mehrn0ush/silastron-security-pulse",
            expected_branch="main",
            expected_head_sha="abc",
            artifact={
                "name": "pulse-candidate",
                "digest": "sha256:" + ("4" * 64),
                "expired": False,
            },
            candidate_bytes=payload,
            expected_digest=digest,
            metadata=metadata,
            sha256sums_text=sha256sums,
        )
        self.assertEqual(result["digest"], digest)
        self.assertNotEqual(result["digest"], "4" * 64)
        self.assertEqual(result["snapshot_id"], "20261022T071919Z_113d2177d767")
        self.assertEqual(result["run_id"], 39739385294)

    def test_incorrect_candidate_content_digest_is_rejected(self) -> None:
        payload, digest, metadata, sha256sums = self._candidate()
        with self.assertRaises(ArtifactVerifyError):
            verify_collect_run(
                self._run(),
                expected_repository="Mehrn0ush/silastron-security-pulse",
                expected_branch="main",
                expected_head_sha="abc",
                artifact={"name": "pulse-candidate", "digest": "sha256:" + ("4" * 64)},
                candidate_bytes=payload,
                expected_digest="0" * 64,
                metadata=metadata,
                sha256sums_text=sha256sums,
            )
        wrong_meta = dict(metadata)
        wrong_meta["content_sha256"] = "0" * 64
        with self.assertRaises(ArtifactVerifyError):
            verify_collect_run(
                self._run(),
                expected_repository="Mehrn0ush/silastron-security-pulse",
                expected_branch="main",
                expected_head_sha="abc",
                artifact={"name": "pulse-candidate"},
                candidate_bytes=payload,
                expected_digest=digest,
                metadata=wrong_meta,
                sha256sums_text=sha256sums,
            )
        with self.assertRaises(ArtifactVerifyError):
            verify_collect_run(
                self._run(),
                expected_repository="Mehrn0ush/silastron-security-pulse",
                expected_branch="main",
                expected_head_sha="abc",
                artifact={"name": "pulse-candidate"},
                candidate_bytes=payload,
                expected_digest=digest,
                metadata=metadata,
                sha256sums_text=f"{'0' * 64}  candidate.json\n",
            )

    def test_incorrect_metadata_binding_is_rejected(self) -> None:
        payload, digest, metadata, sha256sums = self._candidate(head_sha="abc")
        with self.assertRaises(ArtifactVerifyError):
            verify_collect_run(
                self._run(head_sha="def"),
                expected_repository="Mehrn0ush/silastron-security-pulse",
                expected_branch="main",
                expected_head_sha="def",
                artifact={"name": "pulse-candidate"},
                candidate_bytes=payload,
                expected_digest=digest,
                metadata=metadata,
                sha256sums_text=sha256sums,
            )
        wrong_meta = dict(metadata)
        wrong_meta["source_state_revision"] = "other-revision"
        with self.assertRaises(ArtifactVerifyError):
            verify_collect_run(
                self._run(),
                expected_repository="Mehrn0ush/silastron-security-pulse",
                expected_branch="main",
                expected_head_sha="abc",
                artifact={"name": "pulse-candidate"},
                candidate_bytes=payload,
                expected_digest=digest,
                metadata=wrong_meta,
                sha256sums_text=sha256sums,
            )

    def test_missing_digest_is_rejected(self) -> None:
        payload, _digest, metadata, sha256sums = self._candidate()
        with self.assertRaises(ArtifactVerifyError):
            verify_collect_run(
                self._run(),
                expected_repository="Mehrn0ush/silastron-security-pulse",
                expected_branch="main",
                expected_head_sha="abc",
                artifact={"name": "pulse-candidate"},
                candidate_bytes=payload,
                expected_digest=None,
                metadata=metadata,
                sha256sums_text=sha256sums,
            )

    def test_identical_snapshot_id_promote_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, published = self._published(root)
            first = json.loads((published / "manifest.json").read_text())
            again = promote_snapshot(
                snapshot,
                published,
                now=datetime(2099, 1, 10, 13, tzinfo=timezone.utc),
                stale_after_hours=36,
                max_bytes=test_config(root).max_kev_bytes,
                max_depth=test_config(root).max_json_depth,
            )
            latest = json.loads((published / "latest.json").read_text())
            self.assertEqual(latest["snapshot_id"], snapshot["snapshot_id"])
            self.assertEqual(again["snapshot_id"], first["snapshot_id"])


class PublishWorkflowTests(unittest.TestCase):
    def _job(self, job_id: str) -> str:
        text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        lines = text.splitlines()
        start = None
        for index, line in enumerate(lines):
            if line == f"  {job_id}:":
                start = index
                break
        self.assertIsNotNone(start, f"job {job_id} missing")
        end = len(lines)
        assert start is not None
        for index in range(start + 1, len(lines)):
            line = lines[index]
            if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
                end = index
                break
        return "\n".join(lines[start:end])

    def test_persist_published_needs_build_outputs_snapshot_id(self) -> None:
        build = self._job("build")
        persist = self._job("persist-published")
        self.assertIn("snapshot_id: ${{ steps.digest.outputs.snapshot_id }}", build)
        self.assertIn("needs: [build, deploy]", persist)
        self.assertIn(
            'git commit -m "publish ${{ needs.build.outputs.snapshot_id }}"',
            persist,
        )
        self.assertIn("sha256sums_text=sha256sums", build)
        self.assertIn("metadata=meta", build)
        self.assertIn("artifact.digest is the GitHub zip-archive SHA-256", build)


class TimestampAndFreshnessTests(unittest.TestCase):
    def test_retrieval_timestamps_are_required_and_preserved_on_304(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config(Path(tmp))
            first = collect(config=config, fetcher=valid_fetcher(), clock=frozen_clock())
            assert first.snapshot is not None
            self.assertTrue(first.snapshot["sources"]["kev"]["retrieved_at"])
            self.assertTrue(first.snapshot["sources"]["cve"]["retrieved_at"])
            record = first.snapshot["records"][0]["cve"]
            self.assertTrue(record["retrieved_at"])
            cached = record
            url = cvelist_v5_raw_url(record["cve_id"])
            fetcher = ScriptedFetcher(
                {
                    url: [
                        FetchResult(
                            requested_url=url,
                            final_url=url,
                            status_code=304,
                            content_type="",
                            body=b"",
                            retrieved_at="2099-01-10T13:00:00Z",
                            etag='"abc"',
                            not_modified=True,
                        )
                    ]
                }
            )
            reused = _fetch_one(
                record["cve_id"],
                fetcher,
                config,
                etag='"abc"',
                cached=cached,
            )
            self.assertEqual(reused.retrieved_at, record["retrieved_at"])
            self.assertEqual(reused.last_checked_at, "2099-01-10T13:00:00Z")

    def test_preview_computes_freshness_at_viewing_time(self) -> None:
        viewed = datetime(2099, 1, 12, 1, tzinfo=timezone.utc)
        result = freshness(
            generated_at="2099-01-10T12:00:00Z",
            now=viewed,
            stale_after_hours=36,
        )
        self.assertTrue(result["stale"])
        self.assertFalse(result["fresh"])
        source = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        self.assertIn("function evaluateFreshness", source)
        self.assertIn("Date.now()", source)
        self.assertNotIn("if (manifest.stale)", source)
        self.assertNotIn("manifest.fresh ? \"yes\"", source.replace("Fresh at viewing time", ""))
        self.assertIn("Freshness is evaluated at viewing time", source)
        self.assertIn("independent of record completeness", source)


class TruncationAndRetryTests(unittest.TestCase):
    def test_product_truncation_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(test_config(Path(tmp)), max_products=8)
            raw = fixture_bytes("cve_many_products.json")
            record = parse_cve_record(
                json.loads(raw),
                expected_cve_id="CVE-2099-0001",
                raw=raw,
                source_url=cvelist_v5_raw_url("CVE-2099-0001"),
                config=config,
            )
            self.assertEqual(len(record.products), 8)
            self.assertEqual(record.omitted_product_count, 4)
            self.assertIn("products", record.truncated_fields)

    def test_cwe_truncation_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config(Path(tmp))
            raw = fixture_bytes("kev_truncated_cwes.json")
            catalog = parse_kev_catalog(
                json.loads(raw),
                raw=raw,
                retrieved_at="2099-01-10T12:00:00Z",
                config=config,
            )
            record = catalog.records[0]
            self.assertEqual(len(record.cwes), config.max_cwes)
            self.assertTrue(record.cwes_incomplete)
            self.assertIn("cwes", record.truncated_fields)
            self.assertIn("cwes_unparsed", record.truncated_fields)

    def test_rate_limit_and_transient_errors_retry(self) -> None:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        delays: list[float] = []
        inner = ScriptedFetcher(
            {
                url: [
                    FetchError("HTTP 429", retryable=True, retry_after=0.01, status_code=429),
                    FetchError("HTTP 503", retryable=True, status_code=503),
                    fetch_result(url, "kev_valid.json"),
                ]
            }
        )
        fetcher = RetryingFetcher(inner, max_attempts=3, backoff_seconds=0.5, sleep=delays.append)
        result = fetcher.get(url, max_bytes=1_000_000)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(inner.calls), 3)
        self.assertEqual(delays[0], 0.01)
        self.assertEqual(delays[1], 1.0)

    def test_path_restricted_links(self) -> None:
        self.assertIsNotNone(
            authoritative_href("https://www.cve.org/CVERecord?id=CVE-2021-44228")
        )
        self.assertIsNone(authoritative_href("https://github.com/octocat/Hello-World"))
        self.assertIsNone(authoritative_href("https://www.cisa.gov/news"))
        source = (ROOT / "preview" / "app.js").read_text(encoding="utf-8")
        self.assertIn("CVELIST_BLOB", source)
        self.assertIn("known-exploited-vulnerabilities-catalog", source)


class UpstreamSampleTests(unittest.TestCase):
    def test_real_kev_and_cve_samples_parse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config(Path(tmp))
            kev_raw = fixture_bytes("upstream/kev_cve_2021_44228.json")
            catalog = parse_kev_catalog(
                json.loads(kev_raw),
                raw=kev_raw,
                retrieved_at="2026-10-21T12:00:00Z",
                config=config,
            )
            self.assertEqual(catalog.records[0].cve_id, "CVE-2021-44228")
            cve_raw = fixture_bytes("upstream/CVE-2021-44228.json")
            record = parse_cve_record(
                json.loads(cve_raw),
                expected_cve_id="CVE-2021-44228",
                raw=cve_raw,
                source_url=cvelist_v5_raw_url("CVE-2021-44228"),
                config=config,
                retrieved_at="2026-10-21T12:00:00Z",
            )
            self.assertEqual(record.status, "ok")
            self.assertEqual(record.cve_id, "CVE-2021-44228")


if __name__ == "__main__":
    unittest.main()
