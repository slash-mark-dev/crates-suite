#!/usr/bin/env python3
"""Build README.md from the CLI's own help output, so every documented
example is a command the binary actually accepts.

Usage: python3 scripts/gen_readme.py target/release/sm-crates > README.md
"""
import os
import re
import subprocess
import sys

BIN = sys.argv[1]
ENV = dict(os.environ, NO_COLOR="1")


def run(*args):
    return subprocess.run([BIN, *args], capture_output=True, text=True, env=ENV).stdout


def section(text, name):
    """Lines under an ALL-CAPS header, up to the next header."""
    out, on = [], False
    for line in text.splitlines():
        if re.fullmatch(r"[A-Z][A-Z &/-]+", line.strip()) and not line.startswith(" "):
            if on:
                break
            on = line.strip() == name
            continue
        if on:
            out.append(line)
    return out


top = run("help")
groups, order = {}, []
current = None
for line in top.splitlines():
    s = line.rstrip()
    if re.fullmatch(r"[A-Z][A-Z &/-]+", s) and s not in ("USAGE", "GLOBAL OPTIONS", "EXIT CODES"):
        current = s
        groups[current] = []
        order.append(current)
        continue
    if s in ("USAGE", "GLOBAL OPTIONS", "EXIT CODES"):
        current = None
        continue
    m = re.match(r"^  ([a-z]+)\s{2,}(.+)$", s)
    if current and m:
        groups[current].append((m.group(1), m.group(2)))

tools = [t for g in order for t in groups[g]]
assert len(tools) == 25, f"expected 25 tools, found {len(tools)}"

details = {}
for name, _ in tools:
    h = run("help", name)
    title = h.splitlines()[0].split("—", 1)[1].strip()
    ex = [l.strip() for l in section(h, "EXAMPLES") if l.strip()]
    req = " ".join(l.strip() for l in section(h, "REQUIRES") if l.strip())
    details[name] = (title, ex, req)

global_opts = "\n".join(section(top, "GLOBAL OPTIONS"))
exit_codes = [l.strip() for l in section(top, "EXIT CODES") if l.strip()]

o = []
w = o.append
w("# Crates.io Suite\n")
w("**Rust Package Intelligence Suite by [Slash Mark](https://slashmark.in).** 25 advanced tools that explore, analyze and manage Rust crates, all in one binary called `sm-crates`.\n")
w("[![CI](https://github.com/slash-mark-dev/crates-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/slash-mark-dev/crates-suite/actions/workflows/ci.yml)")
w("[![crates.io](https://img.shields.io/crates/v/sm-crates.svg)](https://crates.io/crates/sm-crates)")
w("[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)\n")
w("Every tool is built on something only the Rust ecosystem has: Miri, `build.rs` and proc macros, `-sys` crates, cargo features and resolver v2, `no_std`, auto traits, rustdoc JSON, editions, cargo-vet and cargo-crev, and crates.io Trusted Publishing. The suite has no basic lookups. Every tool analyzes, audits, measures or explains something.\n")
w("- **Live data.** The crates.io API, the sparse index, the published `.crate` files, docs.rs, the RustSec advisory database, NVD, cargo-vet audit sets, cargo-crev proofs, OSS-Fuzz and GitHub.")
w("- **Runs your real toolchain where it matters.** `miri`, `buildtrace`, `featmatrix`, `timings`, `mono`, `profile`, `futurecompat` and `edition` drive `cargo` on your machine instead of guessing.")
w("- **Built for CI.** Every tool supports `--json` and `--markdown`, uses the same exit codes and offers `--fail-on` thresholds.\n")
w("## Install\n")
w("```bash\ncargo install sm-crates\n```\n")
w("This needs Rust 1.85 or newer. You can also download a prebuilt binary for Linux, macOS or Windows from the [releases page](https://github.com/slash-mark-dev/crates-suite/releases). Then run `sm-crates help`.\n")
w("## The 25 tools\n")
n = 0
for g in order:
    w(f"### {g.title().replace('&', '&')}\n")
    w("| # | Tool | Command | What it does |")
    w("|---|---|---|---|")
    for name, summary in groups[g]:
        n += 1
        w(f"| {n} | {details[name][0]} | `{name}` | {summary} |")
    w("")
w("## Examples\n")
for g in order:
    for name, _ in groups[g]:
        title, ex, req = details[name]
        w(f"### `{name}`: {title}\n")
        w("```bash\n" + "\n".join(ex) + "\n```\n")
        if req:
            w(f"Needs: {req}\n")
w("## Options for every tool\n")
w("```text\n" + global_opts.strip("\n") + "\n```\n")
w("Run `sm-crates help <tool>` for each tool's own options and a full description of how it works.\n")
w("## Exit codes\n")
w("| Code | Meaning |\n|---|---|")
for l in exit_codes:
    code, meaning = l.split(None, 1)
    w(f"| `{code}` | {meaning} |")
w("")
w("## Use in GitHub Actions\n")
w("""```yaml
- uses: dtolnay/rust-toolchain@stable
- run: cargo install sm-crates --locked
- run: sm-crates unsafe --fail-on high
- run: sm-crates vet --markdown >> "$GITHUB_STEP_SUMMARY"
- run: sm-crates trustpub --fail-on medium
```
""")
w("## Configuration\n")
w("| Variable | Purpose |\n|---|---|")
w("| `GITHUB_TOKEN` or `GH_TOKEN` | Raises GitHub API limits for `srcverify`, `assurance`, `crev` and `successor` |")
w("| `NVD_API_KEY` | Raises NVD limits for `csys` |")
w("| `NO_COLOR` | Disables colored output |")
w("")
w("Responses are cached in your user cache directory, so repeated runs are fast. Use `--refresh` to bypass the cache and `--offline` to use only cached data.\n")
w("## Notes\n")
w("- `sm-crates` follows the [crates.io data access policy](https://crates.io/data-access): it sends an identifying User-Agent, keeps API calls to one per second, and reads the sparse index and static.crates.io wherever it can.")
w("- `miri` needs the nightly toolchain with the Miri component (`rustup +nightly component add miri`). `autotraits` reads rustdoc JSON from docs.rs, or builds it locally with nightly (`--local`). `pubdeps` and `docscov` use nightly rustdoc JSON when available and fall back to docs.rs or a source scan.")
w("- `buildtrace` gives a full trace only on Linux with `strace`. On macOS and Windows it runs in portable mode, which sees programs started through PATH, file changes and credential-file reads but not network access, and says which mode ran. It is an observation harness, not a sandbox: run untrusted crates in a VM.")
w("- Findings are leads for review, not verdicts. Each finding says where it was found and how to fix it.\n")
w("## License\n")
w("MIT © Slash Mark IT Solutions. See [LICENSE](LICENSE).")
print("\n".join(o))
