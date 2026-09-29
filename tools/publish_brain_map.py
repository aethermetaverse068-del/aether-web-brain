#!/usr/bin/env python3
"""Publish allowlisted brain-map files to this repo's GitHub Pages site.

The script reads only the files you pass in. It does not read a data cache.
A leak guard and a filename allowlist run before any network call. Publishing
uses the GitHub REST API with the fine-grained token in BRAIN_MAP_GH_TOKEN.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import html as html_lib
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
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
    ("word:supabase", re.compile(r"supabase", re.I), None),
    ("url", re.compile(r"https?://", re.I), None),
    (
        "supabase-ref",
        re.compile(r"(?<![a-z0-9])[a-z0-9]{20}(?![a-z0-9])"),
        None,
    ),
    ("cloud-region", re.compile(r"\b[a-z]{2}-[a-z]+-\d\b"), None),
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
    text = _read_bytes_nofollow(path).decode("utf-8-sig")
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


def load_sha_file(path: Path) -> set[str]:
    """Load PNG sha256 hex digests, one per line. Blank lines and # comments are ignored."""
    shas: set[str] = set()
    for token in _load_token_lines(path):
        if re.fullmatch(r"[0-9a-fA-F]{64}", token) is None:
            raise ValueError("sha line")
        shas.add(token.casefold())
    return shas


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

    def create_branch(self, branch: str, commit_sha: str) -> None:
        """Create a new branch ref. This never updates or force-pushes main."""
        self._request(
            "POST",
            "/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": commit_sha},
        )

    def open_pull_request(self, branch: str, stamp: str) -> str:
        body = self._request(
            "POST",
            "/pulls",
            {
                "title": f"Publish brain map {stamp}",
                "head": branch,
                "base": BRANCH,
                "body": (
                    "Automated brain-map publish. "
                    "Review the diff before merging into main."
                ),
            },
        )
        if body is None:
            raise PublishError("GitHub API returned an empty pull request")
        url = body.get("html_url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise PublishError("GitHub API returned an unexpected pull request URL")
        return url


def publish_stamp(moment: datetime) -> str:
    """UTC timestamp safe to use in a git branch name (no colons)."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def publish_files(
    token: str,
    files: list[tuple[str, bytes]],
    published_bytes: bytes,
    now: datetime,
) -> str:
    """Open a pull request for the allowlisted files.

    Return 'unchanged' or the pull request URL. main is only read. The new
    commit is attached to brain-map-publish/<timestamp> and is not force-pushed.
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
    stamp = publish_stamp(now)
    branch = f"brain-map-publish/{stamp}"
    client.create_branch(branch, commit_sha)
    return client.open_pull_request(branch, stamp)


def _is_symlink(path: Path) -> bool:
    """True when path is a symlink. Uses islink and lstat, never is_file."""
    raw = os.fspath(path)
    if os.path.islink(raw):
        return True
    try:
        mode = os.lstat(raw).st_mode
    except OSError:
        return False
    return stat.S_ISLNK(mode)


def _read_bytes_nofollow(path: Path) -> bytes:
    """Read a regular file. O_NOFOLLOW refuses a symlink that appears after the check."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.fspath(path), flags)
    except OSError as err:
        if err.errno == errno.ELOOP:
            raise OSError(errno.ELOOP, "symlink") from None
        raise
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


def _report_symlinks(paths: list[Path]) -> None:
    print("publish refused", file=sys.stderr)
    for path in paths:
        print("rule: symlink", file=sys.stderr)
        print(f"file: {path.name}", file=sys.stderr)
    print("nothing was published", file=sys.stderr)


class PngParseError(Exception):
    """A PNG text chunk could not be parsed. The message never includes chunk bytes."""


def _decode_text_chunk(chunk: bytes) -> str:
    sep = chunk.find(b"\x00")
    if sep <= 0 or sep > 79:
        raise PngParseError("tEXt")
    keyword = chunk[:sep].decode("latin-1")
    text = chunk[sep + 1 :].decode("latin-1")
    return keyword + "\n" + text


def _decode_ztxt_chunk(chunk: bytes) -> str:
    sep = chunk.find(b"\x00")
    if sep <= 0 or sep > 79:
        raise PngParseError("zTXt")
    keyword = chunk[:sep].decode("latin-1")
    rest = chunk[sep + 1 :]
    if len(rest) < 2 or rest[0] != 0:
        raise PngParseError("zTXt")
    try:
        raw = zlib.decompress(rest[1:])
    except zlib.error:
        raise PngParseError("zTXt") from None
    return keyword + "\n" + raw.decode("latin-1")


def _decode_itxt_chunk(chunk: bytes) -> str:
    sep = chunk.find(b"\x00")
    if sep <= 0 or sep > 79:
        raise PngParseError("iTXt")
    keyword = chunk[:sep]
    rest = chunk[sep + 1 :]
    if len(rest) < 2:
        raise PngParseError("iTXt")
    flag = rest[0]
    method = rest[1]
    rest = rest[2:]
    lang_sep = rest.find(b"\x00")
    if lang_sep < 0:
        raise PngParseError("iTXt")
    language = rest[:lang_sep]
    rest = rest[lang_sep + 1 :]
    trans_sep = rest.find(b"\x00")
    if trans_sep < 0:
        raise PngParseError("iTXt")
    translated = rest[:trans_sep]
    text = rest[trans_sep + 1 :]
    if flag not in (0, 1) or method != 0:
        raise PngParseError("iTXt")
    if flag == 1:
        try:
            text = zlib.decompress(text)
        except zlib.error:
            raise PngParseError("iTXt") from None
    try:
        parts = [
            keyword.decode("latin-1"),
            language.decode("latin-1"),
            translated.decode("utf-8"),
            text.decode("utf-8"),
        ]
    except UnicodeDecodeError:
        raise PngParseError("iTXt") from None
    return "\n".join(parts)


def png_text_fragments(data: bytes) -> list[str]:
    """Return the text of every tEXt, zTXt, and iTXt chunk.

    A text chunk that cannot be parsed, including a failed inflate, raises
    PngParseError. The PNG signature is required.
    """
    if not data.startswith(PNG_MAGIC):
        raise PngParseError("signature")
    pos = 8
    texts: list[str] = []
    saw_iend = False
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos : pos + 4], "big")
        ctype = data[pos + 4 : pos + 8]
        pos += 8
        if pos + length + 4 > len(data):
            raise PngParseError("truncated")
        chunk = data[pos : pos + length]
        crc = int.from_bytes(data[pos + length : pos + length + 4], "big")
        pos += length + 4
        if ctype in (b"tEXt", b"zTXt", b"iTXt"):
            actual = zlib.crc32(ctype + chunk) & 0xFFFFFFFF
            if actual != crc:
                raise PngParseError("crc")
            if ctype == b"tEXt":
                texts.append(_decode_text_chunk(chunk))
            elif ctype == b"zTXt":
                texts.append(_decode_ztxt_chunk(chunk))
            else:
                texts.append(_decode_itxt_chunk(chunk))
        if ctype == b"IEND":
            saw_iend = True
            break
    if not saw_iend:
        raise PngParseError("iend")
    return texts


def _read_regular_bytes(path: Path) -> bytes | None:
    """Read path after rejecting symlinks via islink and lstat, before any is_file use."""
    if _is_symlink(path):
        _report_symlinks([path])
        return None
    try:
        info = os.lstat(path)
    except OSError:
        print(f"not a file: {path}", file=sys.stderr)
        return None
    if not stat.S_ISREG(info.st_mode):
        print(f"not a file: {path}", file=sys.stderr)
        return None
    try:
        return _read_bytes_nofollow(path)
    except OSError as err:
        if err.errno == errno.ELOOP:
            _report_symlinks([path])
            return None
        print(f"not a file: {path}", file=sys.stderr)
        return None


def _read_text_file(path: Path, label: str) -> tuple[bytes, str] | None:
    data = _read_regular_bytes(path)
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        print(f"{label} must be UTF-8", file=sys.stderr)
        return None
    return data, text


def _read_png(path: Path) -> bytes | None:
    data = _read_regular_bytes(path)
    if data is None:
        return None
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
        help="Required local deny list, one token per line. Never commit the real file.",
    )
    parser.add_argument(
        "--allow-file",
        required=True,
        help=(
            "Allowlist of basenames, one per line. "
            "Only index.html, brain-map.demo.json, and PNG screenshots may be listed."
        ),
    )
    parser.add_argument(
        "--png-sha-file",
        help="Required when publishing PNGs. One sha256 hex digest per line.",
    )
    args = parser.parse_args(argv)

    if not args.deny_file:
        print("publish refused", file=sys.stderr)
        print("rule: deny-file:required", file=sys.stderr)
        print("nothing was published", file=sys.stderr)
        return 2

    allow_path = Path(args.allow_file)
    deny_path = Path(args.deny_file)
    sha_path = Path(args.png_sha_file) if args.png_sha_file else None
    input_paths = [Path(args.html_path), *[Path(item) for item in args.extra_paths]]
    watched = [*input_paths, allow_path, deny_path]
    if sha_path is not None:
        watched.append(sha_path)
    symlinks = [path for path in watched if _is_symlink(path)]
    if symlinks:
        _report_symlinks(symlinks)
        return 1

    if _classify_missing(allow_path):
        print(f"allow file not found: {allow_path}", file=sys.stderr)
        return 2
    if _classify_missing(deny_path):
        print("publish refused", file=sys.stderr)
        print("rule: deny-file:required", file=sys.stderr)
        print("nothing was published", file=sys.stderr)
        return 2
    try:
        allow_names = load_allow_file(allow_path)
        deny_tokens = load_deny_file(deny_path)
    except OSError as err:
        if err.errno == errno.ELOOP:
            _report_symlinks([allow_path, deny_path])
            return 1
        print(f"not a file: {allow_path}", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        print("deny file must be UTF-8", file=sys.stderr)
        return 2
    if not deny_tokens:
        print("publish refused", file=sys.stderr)
        print("rule: deny-file:empty", file=sys.stderr)
        print("nothing was published", file=sys.stderr)
        return 2

    basenames = [path.name for path in input_paths]
    refusals = review_filenames(basenames, allow_names)
    if basenames[0].casefold() != "index.html":
        refusals.insert(0, ("filename:expected-index-html", basenames[0]))
    if refusals:
        report_filename_refusals(refusals)
        return 1

    publishing_png = any(name.casefold().endswith(".png") for name in basenames)
    sha_allow: set[str] = set()
    if publishing_png:
        if sha_path is None:
            print("publish refused", file=sys.stderr)
            print("rule: png:sha-file-required", file=sys.stderr)
            print("nothing was published", file=sys.stderr)
            return 1
        if _classify_missing(sha_path):
            print("publish refused", file=sys.stderr)
            print("rule: png:sha-file-required", file=sys.stderr)
            print("nothing was published", file=sys.stderr)
            return 1
        try:
            sha_allow = load_sha_file(sha_path)
        except ValueError:
            print("publish refused", file=sys.stderr)
            print("rule: png:sha-file", file=sys.stderr)
            print("nothing was published", file=sys.stderr)
            return 1
        except OSError as err:
            if err.errno == errno.ELOOP:
                _report_symlinks([sha_path])
                return 1
            print("publish refused", file=sys.stderr)
            print("rule: png:sha-file-required", file=sys.stderr)
            print("nothing was published", file=sys.stderr)
            return 1

    loaded_files: list[tuple[str, bytes]] = []
    texts: list[str] = []
    for path in input_paths:
        name = path.name
        if name.casefold().endswith(".png"):
            png = _read_png(path)
            if png is None:
                return 1 if _is_symlink(path) else 2
            try:
                fragments = png_text_fragments(png)
            except PngParseError:
                print("publish refused", file=sys.stderr)
                print("rule: png:text-chunk-parse", file=sys.stderr)
                print(f"file: {name}", file=sys.stderr)
                print("nothing was published", file=sys.stderr)
                return 1
            texts.extend(fragments)
            digest = hashlib.sha256(png).hexdigest()
            if digest not in sha_allow:
                print("publish refused", file=sys.stderr)
                print("rule: png:sha-not-listed", file=sys.stderr)
                print(f"file: {name}", file=sys.stderr)
                print(f"sha256: {digest}", file=sys.stderr)
                print("nothing was published", file=sys.stderr)
                return 1
            loaded_files.append((_repo_path(name), png))
            continue
        loaded = _read_text_file(path, name)
        if loaded is None:
            return 1 if _is_symlink(path) else 2
        data, text = loaded
        loaded_files.append((_repo_path(name), data))
        texts.append(text)

    hits: list[GuardHit] = []
    for text in texts:
        hits.extend(scan_html(text, deny_tokens))
    if hits:
        report_hits(hits[:MAX_HITS] if len(hits) > MAX_HITS else hits)
        return 1

    html_bytes = loaded_files[0][1]
    now = datetime.now(timezone.utc)
    published = build_published_json(html_bytes, now)
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
        result = publish_files(token, loaded_files, published, now)
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
        print(f"branch: brain-map-publish/{publish_stamp(now)}")
        print(f"pull request: {result}")
    print(f"pages url: {PAGES_URL}")
    return 0


def _classify_missing(path: Path) -> bool:
    """True when path is not a regular file. Caller has already rejected symlinks."""
    try:
        info = os.lstat(path)
    except OSError:
        return True
    return not stat.S_ISREG(info.st_mode)


if __name__ == "__main__":
    sys.exit(main())
