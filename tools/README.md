# Publishing the brain map

`tools/publish_brain_map.py` copies allowlisted finished files to this repo's GitHub Pages site. It runs on the machine that already generated the page. It does not read the data cache, and it does not add a workflow that pulls data from anywhere else.

## How Pages serves `brain-map/`

GitHub Pages for this repo is the built-in (legacy) source, not a GitHub Actions workflow:

- Branch: `main`
- Folder: `/` (repository root)
- Site: https://aethermetaverse068-del.github.io/aether-web-brain/

A file committed at `brain-map/index.html` is therefore served at:

https://aethermetaverse068-del.github.io/aether-web-brain/brain-map/

The publish script does not change that Pages configuration. It never commits to `main` and never force-pushes. It reads `main`, writes the allowlisted files onto a new branch `brain-map-publish/YYYY-MM-DDTHHMMSSZ`, and opens a pull request into `main` titled `Publish brain map <timestamp>`. A person reviews that pull request before it is merged. After merge, Pages serves:

- `brain-map/index.html` — the HTML file, byte for byte
- `brain-map/brain-map.demo.json` — optional demo JSON, when you pass that file
- `brain-map/<name>.png` — optional PNG screenshots, when each filename is allowlisted
- `brain-map/published.json` — UTC timestamp and the sha256 of the HTML page (written by the script, not taken from the allowlist)

`README.md` and `web-brain-showcase.html` are left as they are. If every allowlisted file already matches the remote bytes, the script does not create a commit.

The `brain-map/index.html` committed in git is fictional demo content. It shows a `示範資料` banner so merging this change does not publish real data.

## Token

Create a fine-grained personal access token limited to this one repository:

- Repository access: only `aethermetaverse068-del/aether-web-brain`
- Permissions: Contents — Read and write; Pull requests — Read and write

Put it in the environment on the generating machine. Do not commit it, pass it as a command-line argument, or print it. The script reads `BRAIN_MAP_GH_TOKEN` and sends it only as an `Authorization` header.

```sh
export BRAIN_MAP_GH_TOKEN='<fine-grained token>'
```

The generating machine does not need git credentials. The script talks to the GitHub REST API over HTTPS.

## Command

From a checkout of this repo, or from a copy of `tools/publish_brain_map.py` (stdlib only; no pip packages):

```sh
cp tools/deny.example.txt /path/to/deny.internal.txt   # keep this copy off the repo; add real tokens locally
python3 tools/publish_brain_map.py /path/to/index.html \
  --allow-file tools/publish-allow.txt \
  --deny-file /path/to/deny.internal.txt
```

`--deny-file` is required, and the file must contain at least one usable token. If the flag is missing, or the file is empty or only comments and blank lines, the script exits 2 and does not call the network. Name the real local file so that it contains `internal` (for example `deny.internal.txt`). The allowlist hard-refuses any filename containing `internal`, so that file cannot be published even if it is passed in by mistake. `deny*.txt` and any path containing `internal` are gitignored. `tools/deny.example.txt` is the only tracked deny list, and it contains fictional lines.

Optional companions (demo JSON and PNG screenshots) are extra arguments. Each basename must be listed in the allow file. A PNG also needs `--png-sha-file` (one sha256 per line); a screenshot whose digest is not listed is refused. A symlink anywhere in an input path, or in the allow, deny, or sha path (including a parent directory), is refused.

```sh
python3 tools/publish_brain_map.py /path/to/index.html /path/to/brain-map.demo.json /path/to/overview.png \
  --allow-file /path/to/publish-allow.txt \
  --deny-file /path/to/deny.internal.txt \
  --png-sha-file /path/to/png-sha.txt
```

Check the leak guard and the publish plan with no network call:

```sh
python3 tools/publish_brain_map.py /path/to/index.html \
  --allow-file tools/publish-allow.txt \
  --deny-file /path/to/deny.internal.txt \
  --dry-run
```

## Allowlist

`--allow-file` is required. The file is one basename per line; blank lines and `#` comments are ignored. A file is published only when its basename is listed there.

These names are still refused when they are listed:

- any filename containing `internal`
- any filename ending in `.py`, `.sh`, or `.md`
- `brain-map.json`, `brain-map.prev.json`, and `supabase-snapshot.json`

The only names that can pass are `index.html`, `brain-map.demo.json`, and PNG screenshots (`.png`). `tools/publish-allow.txt` lists the first two. Add each screenshot filename on its own line before publishing it. A refusal exits nonzero, prints the rule and the filename, and does not call the network.

On success the script prints the pull request URL and the Pages URL above. A guard hit exits nonzero, prints the rule name and a short masked excerpt, and does not call the network. The pull request is the only write; `main` is not updated.

## Guard

Before anything leaves the machine the script scans the HTML, any JSON companion, and the text of every PNG `tEXt`, `iTXt` (including compressed), and `zTXt` chunk. A text chunk that cannot be parsed is refused. The scan is case-insensitive except where noted:

- the words `aether`, `reiki`, `CASE-`, `claude`, `fleet`, `cases`, `spiritual`, `internal`, the whole word `jd`, and the Chinese words `艦隊` and `老闆`
- any `.md` filename
- absolute or internal paths: `/workspace`, `/home/`, `case-local`, `C:\`, `~/`
- secret-looking strings: `sk-`, `ghp_`, `github_pat_`, `xox`, JWTs starting with `eyJ`, `sb_secret`, `service_role`, AWS keys starting with `AKIA`, and PEM `BEGIN … PRIVATE KEY` headers
- email addresses
- any `http://` or `https://` URL, and any protocol-relative `//...` value in `src`, `href`, `srcset`, `action`, `poster`, or CSS `url(...)` / `@import`. The only exceptions are the exact SVG namespace values `http://www.w3.org/2000/svg` and `http://www.w3.org/1999/xlink`
- the substring `supabase`, `*.supabase.co`, and a standalone 20-character project ref (any case). The only skip is a contiguous `data:image/...;base64,` payload, with no whitespace, inside a real `src`, `href`, `srcset`, or `poster` attribute, or inside `url()` in a `style` attribute or a `<style>` element, and only in the original raw HTML. An entity-decoded copy is scanned with no skip. Text, scripts, comments, JSON, and the raw elements `textarea`, `title`, `xmp`, `plaintext`, `iframe`, `noembed`, `noframes`, and `noscript` are not skipped
- cloud regions in any case whose first label is a known location prefix, including a single trailing zone letter. Fictional examples: `af-south-9`, `af-south-9b`, `AP-SOUTHEAST-9`, and `europe-north9`
- each token in `--deny-file`

The guard does not scan this README.

A CSS class whose first label is a location prefix can still match the region rule. `col-md-6` does not. A 20-character token outside a real `data:image/...;base64,` payload in `src`, `href`, `srcset`, `poster`, or style `url()` still matches the project-ref rule. `alt`, `title`, `data-*`, `text/plain`, and text that merely looks like `x=` or `url(` do not qualify.

## First real publish

Review the generated page and the `--dry-run` output yourself before the first publish without `--dry-run`. That command opens a pull request. Merging the pull request is what replaces the demo page.

## Tests

```sh
python3 -m unittest discover -s tools -p 'test_*.py' -v
```

Python 3.12 or newer is required. The same command runs in GitHub Actions on Python 3.12, 3.13, and 3.14 for pull requests and pushes (`.github/workflows/tests.yml`). That workflow only runs the tests. It does not publish.
