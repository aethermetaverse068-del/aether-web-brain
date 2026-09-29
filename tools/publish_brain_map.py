#!/usr/bin/env python3
"""Publish allowlisted brain-map files to this repo's GitHub Pages site.

The script reads only the files you pass in. It does not read a data cache.
A leak guard and a filename allowlist run before any network call. Publishing
uses the GitHub REST API with the fine-grained token in BRAIN_MAP_GH_TOKEN.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html as html_lib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

OWNER = "aethermetaverse068-del"
REPO = "aether-web-brain"
BRANCH = "main"
HTML_PATH = "brain-map/index.html"
JSON_PATH = "brain-map/published.json"
PAGES_URL = "https://aethermetaverse068-del.github.io/aether-web-brain/brain-map/"
API_ROOT = "https://api.github.com"
TOKEN_ENV = "BRAIN_MAP_GH_TOKEN"
COMMIT_MESSAGE = (
    "Publish brain map\n\n"
    "Update brain-map/index.html and brain-map/published.json."
)
MAX_HITS = 30

# Extensions that show up in asset names like photo@2x.png. They are not inboxes.
_EMAIL_SKIP_TLDS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "svg",
    "ico",
    "css",
    "js",
    "map",
    "woff",
    "woff2",
    "ttf",
    "otf",
}


@dataclass(frozen=True)
class GuardHit:
    rule: str
    excerpt: str


class PublishError(Exception):
    """A publish failed before or during the GitHub API call."""


def _email_accept(match: re.Match[str]) -> bool:
    tld = match.group(0).rsplit(".", 1)[-1].lower()
    return tld not in _EMAIL_SKIP_TLDS


# Case-insensitive. Patterns consume the whole suspicious token so the
# printed excerpt can be masked without leaving the rest of the secret beside it.
_RULES: list[tuple[str, re.Pattern[str], object]] = [
    ("word:aether", re.compile(r"aether", re.I), None),
    ("word:reiki", re.compile(r"reiki", re.I), None),
    ("word:CASE-", re.compile(r"(?<![A-Za-z])case-", re.I), None),
    ("word:claude", re.compile(r"claude", re.I), None),
    ("word:fleet", re.compile(r"fleet", re.I), None),
    ("word:cases", re.compile(r"cases", re.I), None),
    ("word:spiritual", re.compile(r"spiritual", re.I), None),
    ("word:internal", re.compile(r"internal", re.I), None),
    (
        "word:jd",
        re.compile(r"(?<![A-Za-z0-9_])jd(?![A-Za-z0-9_])", re.I),
        None,
    ),
    ("word:艦隊", re.compile(r"艦隊"), None),
    ("word:老闆", re.compile(r"老闆"), None),
    (
        "filename:.md",
        re.compile(
            r"(?<![A-Za-z0-9_])[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.md\b",
            re.I,
        ),
        None,
    ),
    ("path:/workspace", re.compile(r"/workspace", re.I), None),
    ("path:/home/", re.compile(r"/home/", re.I), None),
    ("path:case-local", re.compile(r"case-local", re.I), None),
    ("path:C:\\", re.compile(r"c:\\", re.I), None),
    ("path:~/", re.compile(r"~/"), None),
    (
        "secret:sk-",
        re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{4,}", re.I),
        None,
    ),
    (
        "secret:ghp_",
        re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{4,}", re.I),
        None,
    ),
    (
        "secret:github_pat_",
        re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{4,}", re.I),
        None,
    ),
    (
        "secret:xox",
        re.compile(r"(?<![A-Za-z0-9])xox[A-Za-z0-9_\-]{3,}", re.I),
        None,
    ),
    (
        "secret:jwt",
        re.compile(
            r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            re.I,
        ),
        None,
    ),
    ("secret:sb_secret", re.compile(r"sb_secret[A-Za-z0-9_\-]*", re.I), None),
    ("secret:service_role", re.compile(r"service_role", re.I), None),
    (
        "secret:AKIA",
        re.compile(r"(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}\b", re.I),
        None,
    ),
    (
        "secret:private-key",
        re.compile(r"BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY", re.I),
        None,
    ),
    (
        "email",
        re.compile(
            r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@"
            r"[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}(?![A-Za-z0-9])",
            re.I,
        ),
        _email_accept,
    ),
    (
        "supabase",
        re.compile(
            r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)*supabase\.co\b",
            re.I,
        ),
        None,
    ),
]


def mask_secret(value: str) -> str:
    """Return a short excerpt that does not contain the matched secret."""
    compact = re.sub(r"\s+", " ", value).strip()
    if not compact:
        return "***"
    if len(compact) <= 8:
        return compact[0] + "***"
    return compact[:2] + "***" + compact[-1]


def _variants(html: str) -> list[str]:
    """Raw HTML plus an entity-decoded copy, so &#64; cannot hide an address."""
    variants = [html]
    decoded = html_lib.unescape(html)
    if decoded != html:
        variants.append(decoded)
    return variants


def _first_match(
    pattern: re.Pattern[str],
    variants: list[str],
    accept: object,
) -> re.Match[str] | None:
    for text in variants:
        for match in pattern.finditer(text):
            if accept is not None and not accept(match):
                continue
            return match
    return None


def _load_token_lines(path: Path) -> list[str]:
    """Load one token per line. Blank lines and # comments are ignored."""
    text = path.read_text(encoding="utf-8-sig")
    tokens: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        key = token.casefold()
        if key in seen:
            continue
        seen.add(key)
        tokens.append(token)
    return tokens


def load_deny_file(path: Path) -> list[str]:
    """Load deny tokens, one per line. Blank lines and # comments are ignored."""
    return _load_token_lines(path)


def load_allow_file(path: Path) -> list[str]:
    """Load allowlisted filenames, one per line. Blank lines and # comments are ignored."""
    return _load_token_lines(path)


# Names the publisher may copy. Anything else is refused even if allowlisted.
ALLOWED_BASENAMES = {"index.html", "brain-map.demo.json"}
HARD_REFUSE_BASENAMES = {
    "brain-map.json",
    "brain-map.prev.json",
    "supabase-snapshot.json",
}
HARD_REFUSE_EXTENSIONS = (".py", ".sh", ".md")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def filename_refusal(basename: str, allow_names: list[str]) -> str | None:
    """Return a refusal rule, or None when this basename may be published.

    Hard refusals win over the allowlist. A name must also be listed and be
    index.html, brain-map.demo.json, or a PNG screenshot.
    """
    if basename in {"", ".", ".."} or "/" in basename or "\\" in basename:
        return "filename:hard-refuse:path"
    folded = basename.casefold()
    if "internal" in folded:
        return "filename:hard-refuse:internal"
    for ext in HARD_REFUSE_EXTENSIONS:
        if folded.endswith(ext):
            return f"filename:hard-refuse:{ext}"
    if folded in HARD_REFUSE_BASENAMES:
        return f"filename:hard-refuse:{folded}"
    allowed = {name.casefold() for name in allow_names}
    if folded not in allowed:
        return "filename:not-listed"
    if folded not in ALLOWED_BASENAMES and not folded.endswith(".png"):
        return "filename:not-allowed-set"
    return None


def review_filenames(
    basenames: list[str], allow_names: list[str]
) -> list[tuple[str, str]]:
    """Return (rule, filename) for every basename that must not be published."""
    refusals: list[tuple[str, str]] = []
    seen: set[str] = set()
    for basename in basenames:
        folded = basename.casefold()
        if folded in seen:
            refusals.append(("filename:duplicate", basename))
            continue
        seen.add(folded)
        rule = filename_refusal(basename, allow_names)
        if rule is not None:
            refusals.append((rule, basename))
    return refusals


def report_filename_refusals(refusals: list[tuple[str, str]]) -> None:
    print("publish refused", file=sys.stderr)
    for rule, filename in refusals:
        print(f"rule: {rule}", file=sys.stderr)
        print(f"file: {filename}", file=sys.stderr)
    print("nothing was published", file=sys.stderr)


def scan_html(html: str, deny_tokens: list[str] | None = None) -> list[GuardHit]:
    """Return leak-guard hits. An empty list means the page may be published."""
    variants = _variants(html)
    hits: list[GuardHit] = []
    seen_rules: set[str] = set()
    for name, pattern, accept in _RULES:
        match = _first_match(pattern, variants, accept)
        if match is None:
            continue
        hits.append(GuardHit(name, mask_secret(match.group(0))))
        seen_rules.add(name)
    for token in deny_tokens or []:
        key = "deny:" + token.casefold()
        if key in seen_rules:
            continue
        match = _first_match(re.compile(re.escape(token), re.I), variants, None)
        if match is None:
            continue
        hits.append(GuardHit("deny-list", mask_secret(match.group(0))))
        seen_rules.add(key)
    if len(hits) > MAX_HITS:
        extra = len(hits) - MAX_HITS
        hits = hits[:MAX_HITS]
        hits.append(GuardHit("additional-hits", f"{extra} more"))
    return hits


def report_hits(hits: list[GuardHit]) -> None:
    print("leak guard: blocked", file=sys.stderr)
    for hit in hits:
        print(f"rule: {hit.rule}", file=sys.stderr)
        print(f"excerpt: {hit.excerpt}", file=sys.stderr)
    print("nothing was published", file=sys.stderr)


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def content_unchanged(local: bytes, remote_blob_sha: str | None) -> bool:
    if not remote_blob_sha:
        return False
    return git_blob_sha1(local) == remote_blob_sha


def build_published_json(html_bytes: bytes, now: datetime | None = None) -> bytes:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    payload = {
        "published_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sha256": hashlib.sha256(html_bytes).hexdigest(),
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _scrub(text: str, token: str) -> str:
    if token and text and token in text:
        text = text.replace(token, "[redacted]")
    return text


def _api_message(raw: bytes, token: str) -> str:
    text = raw.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict) and parsed.get("message"):
        text = str(parsed["message"])
    text = _scrub(text, token).strip()
    if len(text) > 180:
        text = text[:180] + "..."
    return text


def _expect_sha(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise PublishError("GitHub API returned an unexpected sha")
    return value


class GitHubClient:
    """Minimal REST client. The token is sent only on the Authorization header."""

    def __init__(self, token: str) -> None:
        self._token = token

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        missing_ok: bool = False,
    ) -> dict | None:
        url = f"{API_ROOT}/repos/{OWNER}/{REPO}{path}"
        data = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self._token,
            "User-Agent": "brain-map-publisher",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            resp_ctx = urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as err:
            raw = err.read() if err.fp is not None else b""
            status = err.code
            if status == 404 and missing_ok:
                return None
            message = _api_message(raw, self._token)
            raise PublishError(
                f"GitHub API {method} {path} failed with HTTP {status}: {message}"
            ) from None
        except urllib.error.URLError as err:
            reason = _scrub(str(getattr(err, "reason", err)), self._token)
            raise PublishError(f"GitHub API connection failed: {reason}") from None
        except Exception as err:
            # Do not chain the original error: urllib can attach the request,
            # and that request carries the Authorization header.
            raise PublishError(
                f"GitHub API request failed ({type(err).__name__})"
            ) from None
        with resp_ctx as resp:
            raw = resp.read()
            status = resp.status
        if status not in (200, 201):
            message = _api_message(raw, self._token)
            raise PublishError(
                f"GitHub API {method} {path} failed with HTTP {status}: {message}"
            )
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise PublishError(
                f"GitHub API {method} {path} returned a non-JSON response"
            ) from None
        if not isinstance(parsed, dict):
            raise PublishError(
                f"GitHub API {method} {path} returned an unexpected response"
            )
        return parsed

    def remote_blob_sha(self, repo_path: str) -> str | None:
        quoted = urllib.parse.quote(repo_path, safe="/")
        body = self._request(
            "GET",
            f"/contents/{quoted}?ref={BRANCH}",
            missing_ok=True,
        )
        if body is None:
            return None
        return _expect_sha(body.get("sha"))

    def branch_head(self) -> tuple[str, str]:
        ref = self._request("GET", f"/git/ref/heads/{BRANCH}")
        if ref is None:
            raise PublishError("GitHub API returned an empty ref")
        obj = ref.get("object")
        if not isinstance(obj, dict):
            raise PublishError("GitHub API returned an unexpected ref")
        commit_sha = _expect_sha(obj.get("sha"))
        commit = self._request("GET", f"/git/commits/{commit_sha}")
        if commit is None:
            raise PublishError("GitHub API returned an empty commit")
        tree = commit.get("tree")
        if not isinstance(tree, dict):
            raise PublishError("GitHub API returned an unexpected commit")
        tree_sha = _expect_sha(tree.get("sha"))
        return commit_sha, tree_sha

    def create_blob(self, data: bytes) -> str:
        body = self._request(
            "POST",
            "/git/blobs",
            {
                "content": base64.b64encode(data).decode("ascii"),
                "encoding": "base64",
            },
        )
        if body is None:
            raise PublishError("GitHub API returned an empty blob")
        return _expect_sha(body.get("sha"))

    def create_tree(self, base_tree: str, entries: list[tuple[str, str]]) -> str:
        body = self._request(
            "POST",
            "/git/trees",
            {
                "base_tree": base_tree,
                "tree": [
                    {
                        "path": path,
                        "mode": "100644",
                        "type": "blob",
                        "sha": sha,
                    }
                    for path, sha in entries
                ],
            },
        )
        if body is None:
            raise PublishError("GitHub API returned an empty tree")
        return _expect_sha(body.get("sha"))

    def create_commit(self, tree_sha: str, parent_sha: str) -> str:
        body = self._request(
            "POST",
            "/git/commits",
            {
                "message": COMMIT_MESSAGE,
                "tree": tree_sha,
                "parents": [parent_sha],
            },
        )
        if body is None:
            raise PublishError("GitHub API returned an empty commit")
        return _expect_sha(body.get("sha"))

    def update_branch(self, commit_sha: str) -> None:
        self._request(
            "PATCH",
            f"/git/refs/heads/{BRANCH}",
            {"sha": commit_sha, "force": False},
        )


def publish_files(
    token: str,
    files: list[tuple[str, bytes]],
    published_bytes: bytes,
) -> str:
    """Push allowlisted brain-map files. Return 'unchanged' or the new commit sha.

    The tree is based on the current branch tip, so every other path stays.
    ``files`` is a list of (repo path, bytes). published.json is added here.
    """
    client = GitHubClient(token)
    changed = False
    for repo_path, data in files:
        remote_sha = client.remote_blob_sha(repo_path)
        if not content_unchanged(data, remote_sha):
            changed = True
            break
    if not changed:
        return "unchanged"
    parent_sha, tree_sha = client.branch_head()
    entries = [(repo_path, client.create_blob(data)) for repo_path, data in files]
    entries.append((JSON_PATH, client.create_blob(published_bytes)))
    new_tree = client.create_tree(tree_sha, entries)
    commit_sha = client.create_commit(new_tree, parent_sha)
    client.update_branch(commit_sha)
    return commit_sha


def _read_text_file(path: Path, label: str) -> tuple[bytes, str] | None:
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return None
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        print(f"{label} must be UTF-8", file=sys.stderr)
        return None
    return data, text


def _read_png(path: Path) -> bytes | None:
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return None
    data = path.read_bytes()
    if not data.startswith(PNG_MAGIC):
        print(f"not a png: {path.name}", file=sys.stderr)
        return None
    return data


def _repo_path(basename: str) -> str:
    return f"brain-map/{basename}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="publish_brain_map.py",
        description=(
            "Leak-check allowlisted brain-map files and publish them under "
            "brain-map/ on GitHub Pages."
        ),
    )
    parser.add_argument("html_path", help="Path to the generated index.html")
    parser.add_argument(
        "extra_paths",
        nargs="*",
        help="Optional brain-map.demo.json and PNG screenshots",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the leak guard and print the publish plan without network calls",
    )
    parser.add_argument(
        "--deny-file",
        help="Extra deny list, one token per line (not committed; applied locally)",
    )
    parser.add_argument(
        "--allow-file",
        required=True,
        help=(
            "Allowlist of basenames, one per line. "
            "Only index.html, brain-map.demo.json, and PNG screenshots may be listed."
        ),
    )
    args = parser.parse_args(argv)

    allow_path = Path(args.allow_file)
    if not allow_path.is_file():
        print(f"allow file not found: {allow_path}", file=sys.stderr)
        return 2
    allow_names = load_allow_file(allow_path)

    input_paths = [Path(args.html_path), *[Path(item) for item in args.extra_paths]]
    basenames = [path.name for path in input_paths]
    refusals = review_filenames(basenames, allow_names)
    if basenames[0].casefold() != "index.html":
        refusals.insert(0, ("filename:expected-index-html", basenames[0]))
    if refusals:
        report_filename_refusals(refusals)
        return 1

    loaded_files: list[tuple[str, bytes]] = []
    texts: list[str] = []
    for path in input_paths:
        name = path.name
        if name.casefold().endswith(".png"):
            png = _read_png(path)
            if png is None:
                return 2
            loaded_files.append((_repo_path(name), png))
            continue
        loaded = _read_text_file(path, name)
        if loaded is None:
            return 2
        data, text = loaded
        loaded_files.append((_repo_path(name), data))
        texts.append(text)

    deny_tokens: list[str] = []
    if args.deny_file:
        deny_path = Path(args.deny_file)
        if not deny_path.is_file():
            print(f"deny file not found: {deny_path}", file=sys.stderr)
            return 2
        deny_tokens = load_deny_file(deny_path)

    hits: list[GuardHit] = []
    for text in texts:
        hits.extend(scan_html(text, deny_tokens))
    if hits:
        report_hits(hits[:MAX_HITS] if len(hits) > MAX_HITS else hits)
        return 1

    html_bytes = loaded_files[0][1]
    published = build_published_json(html_bytes)
    digest = hashlib.sha256(html_bytes).hexdigest()
    if args.dry_run:
        print("leak guard: ok")
        print("dry-run: would publish")
        print(f"  {HTML_PATH} ({len(html_bytes)} bytes, sha256 {digest})")
        for repo_path, data in loaded_files[1:]:
            print(f"  {repo_path} ({len(data)} bytes)")
        print(f"  {JSON_PATH}")
        sys.stdout.write(published.decode("utf-8"))
        print(f"pages url: {PAGES_URL}")
        print("no network calls made")
        return 0

    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        print(f"{TOKEN_ENV} is not set", file=sys.stderr)
        return 2
    try:
        result = publish_files(token, loaded_files, published)
    except PublishError as err:
        print(_scrub(str(err), token), file=sys.stderr)
        return 2
    print("leak guard: ok")
    if result == "unchanged":
        for repo_path, _data in loaded_files:
            print(f"unchanged: {repo_path}")
    else:
        for repo_path, _data in loaded_files:
            print(f"published: {repo_path}")
        print(f"published: {JSON_PATH}")
        print(f"commit: {result}")
    print(f"pages url: {PAGES_URL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
