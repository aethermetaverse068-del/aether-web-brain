#!/usr/bin/env python3
"""Stdlib tests for the brain-map leak guard and the publish plan."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tempfile
import unittest
import zlib
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import publish_brain_map as pub

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER = ROOT / "brain-map" / "index.html"
ALLOW = ROOT / "tools" / "publish-allow.txt"
DENY = ROOT / "tools" / "deny.example.txt"
MIN_PNG = bytes.fromhex(
    "89504e470d0a1a0a"
    "0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c63000100000500010d0a2db4"
    "0000000049454e44ae426082"
)

CLEAN_HTML = """<!DOCTYPE html>
<html lang="zh-Hant">
<head><meta charset="utf-8"><title>示範腦圖</title></head>
<body>
  <p class="banner">示範資料</p>
  <p>晨星市立圖書館有一場春季閱讀會。技能分享、homepage、case study、md5 abcdef。</p>
</body>
</html>
"""

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def _rules(html: str, deny: list[str] | None = None) -> set[str]:
    return {hit.rule for hit in pub.scan_html(html, deny)}


class LeakGuardTests(unittest.TestCase):
    def test_clean_page_passes(self) -> None:
        self.assertEqual(pub.scan_html(CLEAN_HTML), [])

    def test_near_misses_pass(self) -> None:
        text = " ".join(
            [
                "skill building",
                "ask later",
                "homepage",
                "case study",
                "aeth",
                "reik",
                "md5 d41d8cd98f00b204e9800998ecf8427e",
                "photo@2x.png",
                "ordinary.example",
                "workspace ideas",
                "ABCDEFGHIJ012345678",
                "abcdefghij01234567890",
                "sha-256",
                "utf-8",
                "us-east",
                "europewest1",
            ]
        )
        self.assertEqual(pub.scan_html(f"<p>{text}</p>"), [])

    def test_word_aether(self) -> None:
        self.assertIn("word:aether", _rules("<p>The AeThEr notes</p>"))

    def test_word_reiki(self) -> None:
        self.assertIn("word:reiki", _rules("<p>REIKI session</p>"))

    def test_word_case_prefix(self) -> None:
        hits = _rules("<p>Ticket CASE-4401 is closed.</p>")
        self.assertIn("word:CASE-", hits)
        self.assertNotIn("path:case-local", hits)

    def test_reviewer_substrings(self) -> None:
        samples = {
            "word:claude": "Claude",
            "word:fleet": "FLEET",
            "word:cases": "Cases",
            "word:spiritual": "Spiritual",
            "word:internal": "Internal",
            "word:艦隊": "艦隊",
            "word:老闆": "老闆",
        }
        for rule, token in samples.items():
            with self.subTest(rule=rule):
                found = _rules(f"<p>x {token} y</p>")
                self.assertIn(rule, found)

    def test_jd_is_whole_word_only(self) -> None:
        self.assertIn("word:jd", _rules("<p>owner JD said</p>"))
        self.assertNotIn("word:jd", _rules("<p>jdk and ajd</p>"))

    def test_md_filename(self) -> None:
        self.assertIn("filename:.md", _rules("<p>See docs/README.md for notes.</p>"))
        self.assertEqual(pub.scan_html("<p>checksum.md5 only</p>"), [])

    def test_path_workspace(self) -> None:
        self.assertIn("path:/workspace", _rules("<p>cached at /workspace/cache</p>"))

    def test_path_home(self) -> None:
        self.assertIn("path:/home/", _rules("<p>file /home/demo/map</p>"))
        self.assertEqual(pub.scan_html("<p>visit /homepage later</p>"), [])

    def test_path_case_local(self) -> None:
        self.assertIn("path:case-local", _rules("<p>root case-local/data</p>"))

    def test_path_windows_drive(self) -> None:
        self.assertIn("path:C:\\", _rules(r"<p>open C:\Users\demo\map</p>"))

    def test_path_tilde(self) -> None:
        self.assertIn("path:~/", _rules("<p>config ~/.ssh/id</p>"))

    def test_secret_sk(self) -> None:
        self.assertIn("secret:sk-", _rules("<p>sk-proj-abc123456789</p>"))
        self.assertEqual(pub.scan_html("<p>ask-later please</p>"), [])

    def test_secret_ghp(self) -> None:
        self.assertIn("secret:ghp_", _rules("<p>ghp_abcdefghijklmnopqrstuvwxyz</p>"))

    def test_secret_github_pat(self) -> None:
        self.assertIn(
            "secret:github_pat_",
            _rules("<p>github_pat_11AAAAAAAAzzzz</p>"),
        )

    def test_secret_xox(self) -> None:
        self.assertIn("secret:xox", _rules("<p>xoxb-1234567890-abcdefghij</p>"))

    def test_secret_jwt(self) -> None:
        self.assertIn("secret:jwt", _rules(f"<p>{JWT}</p>"))

    def test_secret_sb_secret(self) -> None:
        self.assertIn("secret:sb_secret", _rules("<p>sb_secret_abc123</p>"))

    def test_secret_service_role(self) -> None:
        self.assertIn("secret:service_role", _rules("<p>key service_role</p>"))

    def test_secret_akia(self) -> None:
        self.assertIn("secret:AKIA", _rules("<p>AKIAIOSFODNN7EXAMPLE</p>"))

    def test_secret_private_key(self) -> None:
        html = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA7secretkeymaterial\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertIn("secret:private-key", _rules(html))

    def test_email(self) -> None:
        self.assertIn("email", _rules("<p>Write person@example.com today.</p>"))

    def test_entity_encoded_email_trips(self) -> None:
        self.assertIn("email", _rules("<p>person&#64;example.com</p>"))

    def test_supabase(self) -> None:
        html = "<p>https://db.abcdproject.supabase.co/rest/v1/</p>"
        self.assertIn("supabase", _rules(html))

    def test_deny_file_token_trips_and_absent_token_passes(self) -> None:
        blocked = pub.scan_html(CLEAN_HTML, ["orders_table_alpha"])
        self.assertEqual([hit.rule for hit in blocked], [])
        page = CLEAN_HTML.replace("春季閱讀會", "orders_table_alpha")
        hits = pub.scan_html(page, ["orders_table_alpha"])
        self.assertEqual([hit.rule for hit in hits], ["deny-list"])
        self.assertNotIn("orders_table_alpha", hits[0].excerpt)

    def test_deny_token_is_literal_and_case_insensitive(self) -> None:
        html = "<p>userXemail versus User.Email</p>"
        hits = pub.scan_html(html, ["user.email"])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].rule, "deny-list")
        self.assertEqual(pub.scan_html("<p>userXemail only</p>", ["user.email"]), [])

    def test_excerpt_masks_secret(self) -> None:
        secret = "sk-liveSecretValue123456"
        hits = pub.scan_html(f"<p>{secret}</p>")
        self.assertEqual(len(hits), 1)
        self.assertNotIn(secret, hits[0].excerpt)
        self.assertNotIn("liveSecret", hits[0].excerpt)
        self.assertLessEqual(len(hits[0].excerpt), 12)

    def test_private_key_body_is_not_in_excerpt(self) -> None:
        body = "MIIEowIBAAKCAQEA7secretkeymaterial"
        html = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{body}\n"
            "-----END RSA PRIVATE KEY-----"
        )
        hits = pub.scan_html(html)
        joined = " ".join(hit.excerpt for hit in hits)
        self.assertNotIn(body, joined)
        self.assertNotIn("PRIVATE KEY", joined)

    def test_load_deny_file_skips_blanks_and_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deny.txt"
            path.write_text(
                "# local names\n\n  orders_table  \n# again\norders_table\n",
                encoding="utf-8",
            )
            self.assertEqual(pub.load_deny_file(path), ["orders_table"])

    def test_placeholder_is_demo_and_passes_guard(self) -> None:
        text = PLACEHOLDER.read_text(encoding="utf-8")
        self.assertIn("示範資料", text)
        self.assertNotIn("http://", text)
        self.assertNotIn("https://", text)
        self.assertNotRegex(text, r"<script[^>]+src=")
        self.assertNotRegex(text, r"<link[^>]+href=")
        self.assertEqual(pub.scan_html(text), [])


class PublishPlanTests(unittest.TestCase):
    def test_git_blob_sha_matches_git(self) -> None:
        self.assertEqual(
            pub.git_blob_sha1(b"hello"),
            "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
        )

    def test_published_json_shape(self) -> None:
        raw = b"<p>hi</p>"
        body = pub.build_published_json(
            raw,
            datetime(2026, 9, 29, 8, 22, 0, tzinfo=timezone.utc),
        )
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(
            data,
            {
                "published_at": "2026-09-29T08:22:00Z",
                "sha256": hashlib.sha256(raw).hexdigest(),
            },
        )

    def test_content_unchanged_compares_blob_sha(self) -> None:
        raw = b"<p>same</p>"
        self.assertTrue(pub.content_unchanged(raw, pub.git_blob_sha1(raw)))
        self.assertFalse(pub.content_unchanged(raw, None))
        self.assertFalse(pub.content_unchanged(raw, pub.git_blob_sha1(b"<p>other</p>")))

    def _run(self, args: list[str], env: dict[str, str] | None = None) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=False):
            with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                code = pub.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_dry_run_placeholder_makes_no_network_call(self) -> None:
        token = "github_pat_should_not_leave"
        with mock.patch("urllib.request.urlopen") as urlopen:
            code, stdout, stderr = self._run(
                [str(PLACEHOLDER), "--allow-file", str(ALLOW), "--deny-file", str(DENY), "--dry-run"],
                {pub.TOKEN_ENV: token},
            )
        urlopen.assert_not_called()
        self.assertEqual(code, 0, stderr)
        self.assertIn("leak guard: ok", stdout)
        self.assertIn("no network calls made", stdout)
        self.assertIn(pub.PAGES_URL, stdout)
        self.assertIn(pub.HTML_PATH, stdout)
        self.assertIn(pub.JSON_PATH, stdout)
        self.assertIn("sha256", stdout)
        self.assertNotIn(token, stdout)
        self.assertNotIn(token, stderr)
        self.assertNotIn("<html", stdout.lower())

    def test_deny_file_flag_blocks_before_network(self) -> None:
        secret_name = "zz_private_column_name"
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "index.html"
            page.write_text(CLEAN_HTML + f"<p>{secret_name}</p>", encoding="utf-8")
            deny = Path(tmp) / "deny.txt"
            deny.write_text(f"# keep local\n{secret_name}\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [str(page), "--allow-file", str(ALLOW), "--dry-run", "--deny-file", str(deny)],
                    {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("rule: deny-list", stderr)
        self.assertIn("nothing was published", stderr)
        self.assertNotIn(secret_name, stderr)
        self.assertNotIn(secret_name, stdout)
        self.assertEqual(stdout, "")

    def test_guard_blocks_real_publish_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "index.html"
            page.write_text("<p>aether</p>", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [str(page), "--allow-file", str(ALLOW), "--deny-file", str(DENY)],
                    {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("rule: word:aether", stderr)
        self.assertIn("excerpt: a***", stderr)
        self.assertNotIn("<p>", stderr)
        self.assertIn("nothing was published", stderr)
        self.assertEqual(stdout, "")

    def test_missing_token_does_not_call_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "index.html"
            page.write_text(CLEAN_HTML, encoding="utf-8")
            env = os.environ.copy()
            env.pop(pub.TOKEN_ENV, None)
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch("urllib.request.urlopen") as urlopen:
                    code, _stdout, stderr = self._run(
                        [str(page), "--allow-file", str(ALLOW), "--deny-file", str(DENY)],
                        env={},
                    )
        urlopen.assert_not_called()
        self.assertEqual(code, 2)
        self.assertIn(pub.TOKEN_ENV, stderr)

    def test_publish_writes_only_brain_map_files(self) -> None:
        token = "github_pat_testtokenvalue"
        html = b"<p>fresh fictional page</p>"
        calls: list[tuple[str, str, dict | None, str]] = []

        def urlopen(req: urllib.request.Request, timeout: int = 60) -> object:
            del timeout
            method = req.get_method()
            url = req.full_url
            auth = req.get_header("Authorization")
            raw = req.data
            payload = json.loads(raw.decode("utf-8")) if raw else None
            calls.append((method, url, payload, auth))
            self.assertEqual(auth, "Bearer " + token)
            self.assertNotIn(token, url)
            if raw:
                self.assertNotIn(token.encode("utf-8"), raw)
            if method == "GET" and url.endswith(f"/contents/{pub.HTML_PATH}?ref=main"):
                err = urllib.error.HTTPError(
                    url,
                    404,
                    "Not Found",
                    hdrs=None,
                    fp=io.BytesIO(b'{"message":"Not Found"}'),
                )
                raise err
            if method == "GET" and url.endswith("/git/ref/heads/main"):
                return _Resp({"object": {"sha": "a" * 40, "type": "commit"}})
            if method == "GET" and f"/git/commits/{'a' * 40}" in url:
                return _Resp({"sha": "a" * 40, "tree": {"sha": "b" * 40}})
            if method == "POST" and url.endswith("/git/blobs"):
                assert payload is not None
                self.assertEqual(payload["encoding"], "base64")
                decoded = base64.b64decode(payload["content"])
                return _Resp({"sha": pub.git_blob_sha1(decoded)})
            if method == "POST" and url.endswith("/git/trees"):
                assert payload is not None
                self.assertEqual(payload["base_tree"], "b" * 40)
                paths = [item["path"] for item in payload["tree"]]
                self.assertEqual(
                    paths,
                    ["brain-map/index.html", "brain-map/published.json"],
                )
                for item in payload["tree"]:
                    self.assertEqual(item["mode"], "100644")
                    self.assertEqual(item["type"], "blob")
                return _Resp({"sha": "c" * 40})
            if method == "POST" and url.endswith("/git/commits"):
                assert payload is not None
                self.assertEqual(payload["tree"], "c" * 40)
                self.assertEqual(payload["parents"], ["a" * 40])
                self.assertNotIn("<p>", payload["message"])
                return _Resp({"sha": "d" * 40})
            if method == "PATCH":
                raise AssertionError("publish must not update main")
            if method == "POST" and url.endswith("/git/refs"):
                assert payload is not None
                self.assertNotIn("force", payload)
                self.assertTrue(str(payload["ref"]).startswith("refs/heads/brain-map-publish/"))
                self.assertNotEqual(payload["ref"], "refs/heads/main")
                self.assertEqual(payload["sha"], "d" * 40)
                return _Resp({"ref": payload["ref"], "object": {"sha": "d" * 40}})
            if method == "POST" and url.endswith("/pulls"):
                assert payload is not None
                self.assertEqual(payload["base"], "main")
                self.assertTrue(str(payload["head"]).startswith("brain-map-publish/"))
                self.assertTrue(str(payload["title"]).startswith("Publish brain map "))
                self.assertNotIn("<p>", payload.get("body", ""))
                return _Resp(
                    {
                        "html_url": "https://github.com/aethermetaverse068-del/aether-web-brain/pull/99",
                        "number": 99,
                    }
                )
            raise AssertionError(f"unexpected {method} {url}")

        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "index.html"
            page.write_bytes(html)
            with mock.patch("urllib.request.urlopen", urlopen):
                code, stdout, stderr = self._run(
                    [str(page), "--allow-file", str(ALLOW), "--deny-file", str(DENY)],
                    {pub.TOKEN_ENV: token},
                )
        self.assertEqual(code, 0, stderr)
        self.assertIn(
            "pull request: https://github.com/aethermetaverse068-del/aether-web-brain/pull/99",
            stdout,
        )
        self.assertIn("branch: brain-map-publish/", stdout)
        self.assertIn(pub.PAGES_URL, stdout)
        self.assertFalse(any(method == "PATCH" for method, _url, _payload, _auth in calls))
        self.assertNotIn(token, stdout)
        self.assertNotIn(token, stderr)
        blob_payloads = [
            base64.b64decode(payload["content"])
            for method, url, payload, _auth in calls
            if method == "POST" and url.endswith("/git/blobs") and payload is not None
        ]
        self.assertEqual(blob_payloads[0], html)
        meta = json.loads(blob_payloads[1].decode("utf-8"))
        self.assertEqual(meta["sha256"], hashlib.sha256(html).hexdigest())
        methods = [(method, url.split("/repos/", 1)[-1]) for method, url, _p, _a in calls]
        self.assertEqual(
            [item[0] for item in methods],
            ["GET", "GET", "GET", "POST", "POST", "POST", "POST", "POST", "POST"],
        )

    def test_unchanged_remote_skips_commit(self) -> None:
        token = "github_pat_testtokenvalue"
        html = b"<p>already there</p>"
        remote_sha = pub.git_blob_sha1(html)
        calls: list[str] = []

        def urlopen(req: urllib.request.Request, timeout: int = 60) -> object:
            del timeout
            calls.append(req.get_method() + " " + req.full_url)
            self.assertNotIn(token, req.full_url)
            if req.get_method() == "GET" and f"/contents/{pub.HTML_PATH}" in req.full_url:
                return _Resp({"sha": remote_sha, "path": pub.HTML_PATH})
            raise AssertionError("commit path should not run when content matches")

        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "index.html"
            page.write_bytes(html)
            with mock.patch("urllib.request.urlopen", urlopen):
                code, stdout, stderr = self._run(
                    [str(page), "--allow-file", str(ALLOW), "--deny-file", str(DENY)],
                    {pub.TOKEN_ENV: token},
                )
        self.assertEqual(code, 0, stderr)
        self.assertIn("unchanged:", stdout)
        self.assertIn(pub.PAGES_URL, stdout)
        self.assertEqual(len(calls), 1)
        self.assertNotIn(token, stdout)

    def test_api_error_scrubs_token(self) -> None:
        token = "github_pat_SUPERSECRETVALUE"
        html = b"<p>needs publish</p>"

        def urlopen(req: urllib.request.Request, timeout: int = 60) -> object:
            del timeout
            err = urllib.error.HTTPError(
                req.full_url,
                401,
                "Unauthorized",
                hdrs=None,
                fp=io.BytesIO(
                    json.dumps({"message": f"bad credentials {token}"}).encode("utf-8")
                ),
            )
            raise err

        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "index.html"
            page.write_bytes(html)
            with mock.patch("urllib.request.urlopen", urlopen):
                code, stdout, stderr = self._run(
                    [str(page), "--allow-file", str(ALLOW), "--deny-file", str(DENY)],
                    {pub.TOKEN_ENV: token},
                )
        self.assertEqual(code, 2)
        self.assertNotIn(token, stderr)
        self.assertNotIn(token, stdout)
        self.assertIn("[redacted]", stderr)
        self.assertIn("HTTP 401", stderr)


class AllowlistTests(unittest.TestCase):
    def _run(self, args: list[str], env: dict[str, str] | None = None) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=False):
            with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                code = pub.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_load_allow_file_skips_blanks_and_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "publish-allow.txt"
            path.write_text(
                "# names\n\nindex.html\n\n# png\noverview.png\nindex.html\n",
                encoding="utf-8",
            )
            self.assertEqual(pub.load_allow_file(path), ["index.html", "overview.png"])

    def test_hard_refuse_wins_over_allowlist(self) -> None:
        listed = [
            "index.html",
            "notes.md",
            "run.py",
            "run.sh",
            "Notes.MD",
            "internal-map.png",
            "MyInternal.json",
            "brain-map.json",
            "brain-map.prev.json",
            "supabase-snapshot.json",
            "Brain-Map.JSON",
        ]
        expected = {
            "notes.md": "filename:hard-refuse:.md",
            "run.py": "filename:hard-refuse:.py",
            "run.sh": "filename:hard-refuse:.sh",
            "Notes.MD": "filename:hard-refuse:.md",
            "internal-map.png": "filename:hard-refuse:internal",
            "MyInternal.json": "filename:hard-refuse:internal",
            "brain-map.json": "filename:hard-refuse:brain-map.json",
            "brain-map.prev.json": "filename:hard-refuse:brain-map.prev.json",
            "supabase-snapshot.json": "filename:hard-refuse:supabase-snapshot.json",
            "Brain-Map.JSON": "filename:hard-refuse:brain-map.json",
        }
        for name, rule in expected.items():
            with self.subTest(name=name):
                self.assertEqual(pub.filename_refusal(name, listed), rule)

    def test_unlisted_and_outside_allowed_set_are_refused(self) -> None:
        allow = ["index.html", "readme.txt"]
        self.assertEqual(
            pub.filename_refusal("overview.png", allow),
            "filename:not-listed",
        )
        self.assertEqual(
            pub.filename_refusal("readme.txt", allow),
            "filename:not-allowed-set",
        )
        self.assertIsNone(pub.filename_refusal("index.html", allow))
        self.assertIsNone(
            pub.filename_refusal("brain-map.demo.json", ["brain-map.demo.json"])
        )
        self.assertIsNone(pub.filename_refusal("overview.png", ["overview.png"]))

    def test_publish_refuses_unlisted_file_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.html"
            page.write_text(CLEAN_HTML, encoding="utf-8")
            extra = root / "overview.png"
            extra.write_bytes(MIN_PNG)
            allow = root / "publish-allow.txt"
            allow.write_text("index.html\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [str(page), str(extra), "--allow-file", str(allow), "--deny-file", str(DENY)],
                    {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("rule: filename:not-listed", stderr)
        self.assertIn("file: overview.png", stderr)
        self.assertIn("nothing was published", stderr)
        self.assertEqual(stdout, "")

    def test_publish_hard_refuses_listed_source_files_before_network(self) -> None:
        names = [
            "notes.md",
            "run.py",
            "run.sh",
            "internal-shot.png",
            "brain-map.json",
            "brain-map.prev.json",
            "supabase-snapshot.json",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.html"
            page.write_text(CLEAN_HTML, encoding="utf-8")
            allow_lines = ["index.html", *names]
            allow = root / "publish-allow.txt"
            allow.write_text("\n".join(allow_lines) + "\n", encoding="utf-8")
            for name in names:
                (root / name).write_text("clean fictional text\n", encoding="utf-8")
                with mock.patch("urllib.request.urlopen") as urlopen:
                    code, stdout, stderr = self._run(
                        [
                            str(page),
                            str(root / name),
                            "--allow-file",
                            str(allow),
                            "--deny-file",
                            str(DENY),
                            "--dry-run",
                        ],
                        {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                    )
                urlopen.assert_not_called()
                self.assertEqual(code, 1, name)
                self.assertIn("rule: filename:hard-refuse:", stderr)
                self.assertIn(f"file: {name}", stderr)
                self.assertIn("nothing was published", stderr)
                self.assertNotIn("clean fictional text", stderr)
                self.assertEqual(stdout, "")

    def test_dry_run_allows_demo_json_and_png(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.html"
            page.write_text(CLEAN_HTML, encoding="utf-8")
            demo = root / "brain-map.demo.json"
            demo.write_text('{"label":"示範資料"}\n', encoding="utf-8")
            shot = root / "overview.png"
            shot.write_bytes(MIN_PNG)
            allow = root / "publish-allow.txt"
            allow.write_text(
                "# publish set\nindex.html\nbrain-map.demo.json\noverview.png\n",
                encoding="utf-8",
            )
            sha_file = root / "png-sha.txt"
            sha_file.write_text(hashlib.sha256(MIN_PNG).hexdigest() + "\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [
                        str(page),
                        str(demo),
                        str(shot),
                        "--allow-file",
                        str(allow),
                        "--deny-file",
                        str(DENY),
                        "--png-sha-file",
                        str(sha_file),
                        "--dry-run",
                    ]
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 0, stderr)
        self.assertIn("brain-map/index.html", stdout)
        self.assertIn("brain-map/brain-map.demo.json", stdout)
        self.assertIn("brain-map/overview.png", stdout)
        self.assertIn("no network calls made", stdout)

    def test_demo_json_leak_blocks_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.html"
            page.write_text(CLEAN_HTML, encoding="utf-8")
            demo = root / "brain-map.demo.json"
            demo.write_text('{"note":"claude"}\n', encoding="utf-8")
            allow = root / "publish-allow.txt"
            allow.write_text("index.html\nbrain-map.demo.json\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, _stdout, stderr = self._run(
                    [
                        str(page),
                        str(demo),
                        "--allow-file",
                        str(allow),
                        "--deny-file",
                        str(DENY),
                        "--dry-run",
                    ],
                    {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("rule: word:claude", stderr)
        self.assertNotIn("claude", stderr.replace("rule: word:claude", ""))


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return len(data).to_bytes(4, "big") + tag + data + crc.to_bytes(4, "big")


def _png_with_chunk(tag: bytes, data: bytes) -> bytes:
    marker = b"IEND"
    index = MIN_PNG.rfind(marker) - 4
    return MIN_PNG[:index] + _png_chunk(tag, data) + MIN_PNG[index:]


class SecurityReviewTests(unittest.TestCase):
    def _run(self, args: list[str], env: dict[str, str] | None = None) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=False):
            with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                code = pub.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def _page(self, root: Path, body: str) -> tuple[Path, Path, Path]:
        page = root / "index.html"
        page.write_text(f"<p>{body}</p>", encoding="utf-8")
        allow = root / "publish-allow.txt"
        allow.write_text("index.html\n", encoding="utf-8")
        deny = root / "deny-local.txt"
        deny.write_text("# fictional\nfictional_table_alpha\n", encoding="utf-8")
        return page, allow, deny

    def test_deny_file_is_required_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page, allow, _deny = self._page(root, "clean fictional page")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [str(page), "--allow-file", str(allow), "--dry-run"],
                    {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 2)
        self.assertIn("rule: deny-file:required", stderr)
        self.assertIn("nothing was published", stderr)
        self.assertEqual(stdout, "")

    def test_deny_file_without_usable_lines_exits_before_network(self) -> None:
        cases = {
            "empty": "",
            "comments-only": "# local names\n\n  # another\n",
        }
        for label, contents in cases.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    page, allow, deny = self._page(root, "clean fictional page")
                    deny.write_text(contents, encoding="utf-8")
                    with mock.patch("urllib.request.urlopen") as urlopen:
                        code, stdout, stderr = self._run(
                            [
                                str(page),
                                "--allow-file",
                                str(allow),
                                "--deny-file",
                                str(deny),
                                "--dry-run",
                            ],
                            {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                        )
                urlopen.assert_not_called()
                self.assertEqual(code, 2, stderr)
                self.assertIn("rule: deny-file:empty", stderr)
                self.assertIn("nothing was published", stderr)
                self.assertEqual(stdout, "")

    def test_builtin_rules_block_before_network(self) -> None:
        samples = [
            ("http://example.test/a", "url"),
            ("https://example.test/a", "url"),
            ("see supabase here", "word:supabase"),
            ("abcdefghij0123456789", "supabase-ref"),
            ("ABCDEFGHIJ0123456789", "supabase-ref"),
            ("ap-northeast-1", "cloud-region"),
            ("us-east-1", "cloud-region"),
            ("AP-NORTHEAST-2", "cloud-region"),
            ("europe-west1", "cloud-region"),
        ]
        for body, rule in samples:
            with self.subTest(body=body):
                with tempfile.TemporaryDirectory() as tmp:
                    page, allow, deny = self._page(Path(tmp), body)
                    with mock.patch("urllib.request.urlopen") as urlopen:
                        code, stdout, stderr = self._run(
                            [
                                str(page),
                                "--allow-file",
                                str(allow),
                                "--deny-file",
                                str(deny),
                                "--dry-run",
                            ],
                            {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                        )
                urlopen.assert_not_called()
                self.assertEqual(code, 1, stderr)
                self.assertIn(f"rule: {rule}", stderr)
                self.assertIn("nothing was published", stderr)
                self.assertNotIn(body, stderr)
                self.assertEqual(stdout, "")

    def test_symlink_input_and_allow_file_are_refused(self) -> None:
        secret = "claude-hidden-token"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real-index.html"
            real.write_text(f"<p>{secret}</p>", encoding="utf-8")
            link = root / "index.html"
            os.symlink(real, link)
            allow = root / "publish-allow.txt"
            allow.write_text("index.html\n", encoding="utf-8")
            deny = root / "deny-local.txt"
            deny.write_text("# none\n", encoding="utf-8")
            self.assertTrue(os.path.islink(link))
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [str(link), "--allow-file", str(allow), "--deny-file", str(deny)],
                    {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("rule: symlink", stderr)
        self.assertIn("file: index.html", stderr)
        self.assertNotIn(secret, stderr)
        self.assertEqual(stdout, "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.html"
            page.write_text(CLEAN_HTML, encoding="utf-8")
            real_allow = root / "allow-real.txt"
            real_allow.write_text("index.html\n", encoding="utf-8")
            allow = root / "publish-allow.txt"
            os.symlink(real_allow, allow)
            deny = root / "deny-local.txt"
            deny.write_text("# none\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [str(page), "--allow-file", str(allow), "--deny-file", str(deny), "--dry-run"],
                    {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("rule: symlink", stderr)
        self.assertIn("file: publish-allow.txt", stderr)
        self.assertEqual(stdout, "")

    def test_symlink_parent_directory_is_refused(self) -> None:
        for kind in ("html", "allow", "deny", "png-sha"):
            with self.subTest(kind=kind):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    real = root / "real"
                    real.mkdir()
                    linkdir = root / "linkdir"
                    os.symlink(real, linkdir, target_is_directory=True)
                    page = root / "index.html"
                    page.write_text(CLEAN_HTML, encoding="utf-8")
                    allow = root / "publish-allow.txt"
                    allow.write_text("index.html\n", encoding="utf-8")
                    deny = root / "deny-local.txt"
                    deny.write_text("# fictional\nfictional_table_alpha\n", encoding="utf-8")
                    extra: list[str] = []
                    if kind == "html":
                        (real / "index.html").write_text(CLEAN_HTML, encoding="utf-8")
                        page = linkdir / "index.html"
                        self.assertFalse(os.path.islink(page))
                        self.assertTrue(os.path.islink(linkdir))
                    elif kind == "allow":
                        (real / "publish-allow.txt").write_text("index.html\n", encoding="utf-8")
                        allow = linkdir / "publish-allow.txt"
                    elif kind == "deny":
                        (real / "deny-local.txt").write_text(
                            "# fictional\nfictional_table_alpha\n",
                            encoding="utf-8",
                        )
                        deny = linkdir / "deny-local.txt"
                    else:
                        (real / "png-sha.txt").write_text(("ab" * 32) + "\n", encoding="utf-8")
                        extra = ["--png-sha-file", str(linkdir / "png-sha.txt")]
                    with mock.patch("urllib.request.urlopen") as urlopen:
                        code, stdout, stderr = self._run(
                            [
                                str(page),
                                "--allow-file",
                                str(allow),
                                "--deny-file",
                                str(deny),
                                "--dry-run",
                                *extra,
                            ],
                            {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                        )
                urlopen.assert_not_called()
                self.assertEqual(code, 1, stderr)
                self.assertIn("rule: symlink", stderr)
                self.assertEqual(stdout, "")

    def test_inline_svg_namespace_passes_and_other_urls_fail(self) -> None:
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" '
            'xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">'
            '<circle cx="2" cy="2" r="1"></circle>'
            "</svg>"
        )
        page_html = CLEAN_HTML.replace("</body>", svg + "\n</body>")
        self.assertEqual(pub.scan_html(page_html), [])
        blocked = [
            "<p>http://example.test/a</p>",
            "<p>https://example.test/a</p>",
            "<p>http://www.w3.org/2000/svg/extra</p>",
            "<p>https://www.w3.org/2000/svg</p>",
            '<svg xmlns="http://www.w3.org/2000/svg?x=1"></svg>',
        ]
        for html in blocked:
            with self.subTest(html=html):
                hits = pub.scan_html(html)
                self.assertIn("url", {hit.rule for hit in hits})
                joined = " ".join(hit.excerpt for hit in hits)
                self.assertNotIn("example.test", joined)
                self.assertNotIn("w3.org", joined)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.html"
            page.write_text(page_html, encoding="utf-8")
            allow = root / "publish-allow.txt"
            allow.write_text("index.html\n", encoding="utf-8")
            deny = root / "deny-local.txt"
            deny.write_text("# fictional\nfictional_table_alpha\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [
                        str(page),
                        "--allow-file",
                        str(allow),
                        "--deny-file",
                        str(deny),
                        "--dry-run",
                    ],
                    {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                )
            urlopen.assert_not_called()
            self.assertEqual(code, 0, stderr)
            self.assertIn("leak guard: ok", stdout)
            page.write_text(
                CLEAN_HTML.replace("</body>", "<p>https://example.test/a</p></body>"),
                encoding="utf-8",
            )
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [
                        str(page),
                        "--allow-file",
                        str(allow),
                        "--deny-file",
                        str(deny),
                        "--dry-run",
                    ],
                    {pub.TOKEN_ENV: "github_pat_should_not_leave"},
                )
            urlopen.assert_not_called()
            self.assertEqual(code, 1, stderr)
            self.assertIn("rule: url", stderr)
            self.assertNotIn("https://example.test/a", stderr)
            self.assertEqual(stdout, "")

    def test_png_text_chunks_and_sha_allowlist(self) -> None:
        self.assertEqual(pub.png_text_fragments(MIN_PNG), [])
        text_png = _png_with_chunk(b"tEXt", b"Note\x00claude-hidden-token")
        ztxt_png = _png_with_chunk(
            b"zTXt",
            b"Note\x00\x00" + zlib.compress(b"supabase-hidden"),
        )
        itxt_png = _png_with_chunk(
            b"iTXt",
            b"Note\x00\x01\x00en\x00\x00" + zlib.compress(b"https://example.test/hidden-path"),
        )
        bad_png = _png_with_chunk(b"zTXt", b"Note\x00\x00this-is-not-zlib")
        cases = [
            (text_png, "word:claude", "claude-hidden-token"),
            (ztxt_png, "word:supabase", "supabase-hidden"),
            (itxt_png, "url", "https://example.test/hidden-path"),
        ]
        for png_bytes, rule, secret in cases:
            with self.subTest(rule=rule):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    page = root / "index.html"
                    page.write_text(CLEAN_HTML, encoding="utf-8")
                    shot = root / "overview.png"
                    shot.write_bytes(png_bytes)
                    allow = root / "publish-allow.txt"
                    allow.write_text("index.html\noverview.png\n", encoding="utf-8")
                    deny = root / "deny-local.txt"
                    deny.write_text("# none\nfictional_table_alpha\n", encoding="utf-8")
                    sha_file = root / "png-sha.txt"
                    sha_file.write_text(hashlib.sha256(png_bytes).hexdigest() + "\n", encoding="utf-8")
                    with mock.patch("urllib.request.urlopen") as urlopen:
                        code, stdout, stderr = self._run(
                            [
                                str(page),
                                str(shot),
                                "--allow-file",
                                str(allow),
                                "--deny-file",
                                str(deny),
                                "--png-sha-file",
                                str(sha_file),
                                "--dry-run",
                            ]
                        )
                urlopen.assert_not_called()
                self.assertEqual(code, 1, stderr)
                self.assertIn(f"rule: {rule}", stderr)
                self.assertNotIn(secret, stderr)
                self.assertEqual(stdout, "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.html"
            page.write_text(CLEAN_HTML, encoding="utf-8")
            shot = root / "overview.png"
            shot.write_bytes(bad_png)
            allow = root / "publish-allow.txt"
            allow.write_text("index.html\noverview.png\n", encoding="utf-8")
            deny = root / "deny-local.txt"
            deny.write_text("# none\nfictional_table_alpha\n", encoding="utf-8")
            sha_file = root / "png-sha.txt"
            sha_file.write_text(hashlib.sha256(bad_png).hexdigest() + "\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, stdout, stderr = self._run(
                    [
                        str(page),
                        str(shot),
                        "--allow-file",
                        str(allow),
                        "--deny-file",
                        str(deny),
                        "--png-sha-file",
                        str(sha_file),
                        "--dry-run",
                    ]
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 1, stderr)
        self.assertIn("rule: png:text-chunk-parse", stderr)
        self.assertNotIn("this-is-not-zlib", stderr)
        self.assertEqual(stdout, "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.html"
            page.write_text(CLEAN_HTML, encoding="utf-8")
            shot = root / "overview.png"
            shot.write_bytes(MIN_PNG)
            allow = root / "publish-allow.txt"
            allow.write_text("index.html\noverview.png\n", encoding="utf-8")
            deny = root / "deny-local.txt"
            deny.write_text("# none\nfictional_table_alpha\n", encoding="utf-8")
            sha_file = root / "png-sha.txt"
            sha_file.write_text(("ab" * 32) + "\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, _stdout, stderr = self._run(
                    [
                        str(page),
                        str(shot),
                        "--allow-file",
                        str(allow),
                        "--deny-file",
                        str(deny),
                        "--png-sha-file",
                        str(sha_file),
                        "--dry-run",
                    ]
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("rule: png:sha-not-listed", stderr)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = root / "index.html"
            page.write_text(CLEAN_HTML, encoding="utf-8")
            shot = root / "overview.png"
            shot.write_bytes(MIN_PNG)
            allow = root / "publish-allow.txt"
            allow.write_text("index.html\noverview.png\n", encoding="utf-8")
            deny = root / "deny-local.txt"
            deny.write_text("# none\nfictional_table_alpha\n", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                code, _stdout, stderr = self._run(
                    [
                        str(page),
                        str(shot),
                        "--allow-file",
                        str(allow),
                        "--deny-file",
                        str(deny),
                        "--dry-run",
                    ]
                )
        urlopen.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("rule: png:sha-file-required", stderr)


class _Resp:
    def __init__(self, payload: dict) -> None:
        self.status = 201
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


if __name__ == "__main__":
    unittest.main()
