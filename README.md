# skill-xray

A static security scanner for AI skill packages: the folders (a `SKILL.md` file
plus bundled `scripts/`, `references/`, `hooks.json`, `.mcp.json`) that agents
load and act on. A skill's instructions enter the agent's context and its
scripts run with the agent's privileges, so a skill can read data or run code on
the machine it is installed on. skill-xray reads the package before install and
does not execute it.

It is the counterpart of `mcp-xray`, which does the same for MCP servers.

## Status

This version does ingest only: it walks a package into a file inventory and a
coverage ledger. It does not yet parse file contents, run checks, or emit SARIF.

The walker reads a package it does not trust, so:

- it caps per-file size, file count, and total bytes read, so a crafted package
  cannot make it hang or run out of memory;
- it does not follow a symlink or an NTFS junction out of the package directory;
- it does not open a FIFO, device, or socket (a `read()` on a FIFO never
  returns);
- it inventories shipped compiled code (`.pyc`/`.pyo`/`.pyd`) instead of dropping
  it with its `__pycache__` directory, and lists it under `shippedBytecode`, so a
  full text-coverage number can never hide unreviewable executable code;
- it records every file it does not read, with a reason, and a skipped file
  lowers the reported coverage unless it is a binary asset, a compiled artifact,
  or an excluded cache directory.

## Use

```bash
pip install -e .
skill-xray <package-dir>            # a directory
skill-xray <path>/SKILL.md          # a single file
skill-xray <path>/skill.zip         # a .zip archive
skill-xray https://host/skill.zip   # an http(s) URL
skill-xray https://github.com/u/r.git   # a git repository
skill-xray --scan-known-skills      # find and scan every skill under the known agent roots
skill-xray <target> --json          # JSON output
```

Directory, file and zip are fully offline. URL and git are the only inputs that
use the network; each enforces size, count and SSRF limits and fails closed.

## Develop

Requires Python 3.12 or newer (the junction check uses `os.path.isjunction`,
added in 3.12).

```bash
python -m ruff check .        # lint
python dev/deadcode.py src    # unused top-level symbols
python -m pytest tests        # tests
```

CI runs on Linux, macOS, and Windows. Each OS runs a different part: the symlink
tests run on Linux and macOS, the NTFS junction test runs on Windows, and macOS
is where filenames arrive in a different Unicode form (NFD vs NFC).

## Layout

```
src/skill_xray/
  ingest.py   walk, decode, classify, and build the ledger (stdlib only, no parsing)
  resolve.py  turn a directory/file/zip/URL/git target into a local dir, with caps
  cli.py      inventory a target and print the ledger
tests/
  test_ingest.py   walker tests, including the symlink, junction, and FIFO cases
  test_resolve.py  input-resolver tests: zip-slip, zip-bomb, SSRF, git guard
  test_cli.py      CLI tests
dev/
  deadcode.py      unused-symbol check, also run in CI
```
