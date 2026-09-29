# Publishing the brain map

`tools/publish_brain_map.py` copies one finished HTML file to this repo's GitHub Pages site. It runs on the machine that already generated the page. It does not read the data cache, and it does not add a workflow that pulls data from anywhere else.

## How Pages serves `brain-map/`

GitHub Pages for this repo is the built-in (legacy) source, not a GitHub Actions workflow:

- Branch: `main`
- Folder: `/` (repository root)
- Site: https://aethermetaverse068-del.github.io/aether-web-brain/

A file committed at `brain-map/index.html` is therefore served at:

https://aethermetaverse068-del.github.io/aether-web-brain/brain-map/

The publish script does not change that Pages configuration. It adds or updates only these two paths, on top of the current `main` tree:

- `brain-map/index.html` — the HTML file, byte for byte
- `brain-map/published.json` — UTC timestamp and the sha256 of that file

`README.md` and `web-brain-showcase.html` are left as they are. If the remote HTML bytes are already identical, the script does not create a commit.

The `brain-map/index.html` committed in git is fictional demo content. It shows a `示範資料` banner so merging this change does not publish real data.

## Token

Create a fine-grained personal access token limited to this one repository:

- Repository access: only `aethermetaverse068-del/aether-web-brain`
- Permissions: Contents — Read and write

Put it in the environment on the generating machine. Do not commit it, pass it as a command-line argument, or print it. The script reads `BRAIN_MAP_GH_TOKEN` and sends it only as an `Authorization` header.

```sh
export BRAIN_MAP_GH_TOKEN='<fine-grained token>'
```

The generating machine does not need git credentials. The script talks to the GitHub REST API over HTTPS.

## Command

From a checkout of this repo, or from a copy of `tools/publish_brain_map.py` (stdlib only; no pip packages):

```sh
python3 tools/publish_brain_map.py /path/to/index.html
```

Check the leak guard and the publish plan with no network call:

```sh
python3 tools/publish_brain_map.py /path/to/index.html --dry-run
```

Add local database table or column names at publish time. That file stays on the generating machine and is not committed. One token per line; blank lines and `#` comments are ignored:

```sh
python3 tools/publish_brain_map.py /path/to/index.html --deny-file /path/to/deny.txt
```

On success the script prints the Pages URL above. A guard hit exits nonzero, prints the rule name and a short masked excerpt, and does not call the network.

## Guard

Before anything leaves the machine the script scans the HTML (and an HTML-entity-decoded copy) case-insensitively for:

- the words `aether`, `reiki`, and `CASE-`
- any `.md` filename
- absolute or internal paths: `/workspace`, `/home/`, `case-local`, `C:\`, `~/`
- secret-looking strings: `sk-`, `ghp_`, `github_pat_`, `xox`, JWTs starting with `eyJ`, `sb_secret`, `service_role`, AWS keys starting with `AKIA`, and PEM `BEGIN … PRIVATE KEY` headers
- email addresses
- `*.supabase.co`
- each token in `--deny-file`

The guard scans the HTML you pass in. It does not scan this README.

## First real publish

Review the generated page and the `--dry-run` output yourself before the first publish without `--dry-run`. That command is what replaces the demo page with the real one.

## Tests

```sh
python3 -m unittest discover -s tools -p 'test_*.py' -v
```
