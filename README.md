# Crates.io Suite

**Rust Package Intelligence Suite by [Slash Mark](https://slashmark.in).** 25 advanced tools that explore, analyze and manage Rust crates, all in one binary called `sm-crates`.

[![CI](https://github.com/slash-mark-dev/crates-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/slash-mark-dev/crates-suite/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sm-crates.svg)](https://crates.io/crates/sm-crates)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Every tool is built on something only the Rust ecosystem has: Miri, `build.rs` and proc macros, `-sys` crates, cargo features and resolver v2, `no_std`, auto traits, rustdoc JSON, editions, cargo-vet and cargo-crev, and crates.io Trusted Publishing. The suite has no basic lookups. Every tool analyzes, audits, measures or explains something.

- **Live data.** The crates.io API, the sparse index, the published `.crate` files, docs.rs, the RustSec advisory database, NVD, cargo-vet audit sets, cargo-crev proofs, OSS-Fuzz and GitHub.
- **Runs your real toolchain where it matters.** `miri`, `buildtrace`, `featmatrix`, `timings`, `mono`, `profile`, `futurecompat` and `edition` drive `cargo` on your machine instead of guessing.
- **Built for CI.** Every tool supports `--json` and `--markdown`, uses the same exit codes and offers `--fail-on` thresholds.

## Install

```bash
cargo install sm-crates
```

This needs Rust 1.85 or newer. You can also download a prebuilt binary for Linux, macOS or Windows from the [releases page](https://github.com/slash-mark-dev/crates-suite/releases). Then run `sm-crates help`.

## The 25 tools

### Soundness & Safety

| # | Tool | Command | What it does |
|---|---|---|---|
| 1 | Unsafe Soundness Hotspots | `unsafe` | Known-unsound unsafe patterns and unsafe blocks without SAFETY comments, per dependency |
| 2 | Miri UB Runner | `miri` | Run dependency test suites under Miri to catch undefined behaviour and data races |
| 3 | Panic Surface Map | `panics` | Every unwrap, expect, index and panic! reachable from a crate's public API |
| 4 | Auto-Trait Leak Detector | `autotraits` | Catch a new version silently dropping Send, Sync, Unpin or UnwindSafe on a public type |
| 5 | Verification Coverage | `assurance` | Which dependencies are fuzzed, Kani-proven, Miri-tested, loom-tested or property-tested |

### Compile-Time Supply Chain

| # | Tool | Command | What it does |
|---|---|---|---|
| 6 | Build Script Sandbox Trace | `buildtrace` | Run build scripts and proc macros under a tracer and record every file, network and process access |
| 7 | Bundled C Library Scanner | `csys` | Find C libraries vendored in -sys/-src crates, match their versions to CVEs, and flag links conflicts |
| 8 | Published-vs-Repo Verifier | `srcverify` | Diff the published .crate against the exact git commit it claims to come from |
| 9 | cargo-vet Audit Coverage | `vet` | Import public cargo-vet audit sets and find the smallest audit that covers each dependency |
| 10 | crev Trust Graph | `crev` | Score dependencies by signed cargo-crev reviews from a web of trust |

### Features & Targets

| # | Tool | Command | What it does |
|---|---|---|---|
| 11 | Feature Matrix Tester | `featmatrix` | Compile feature combinations to find broken ones, and features that remove API instead of adding it |
| 12 | Feature Bleed Explainer | `features` | Explain who enables each feature, and when dev, build or other-target dependencies change your release build |
| 13 | no_std Readiness | `nostd` | Which dependencies pull in std or alloc, and the Cargo.toml changes that get you to no_std |
| 14 | Async Runtime Conflict Detector | `runtimes` | Mixed async runtimes, duplicate Tokio majors, and blocking calls inside async dependencies |
| 15 | Target Compatibility Matrix | `targets` | Which dependencies build for wasm32, WASI, embedded, Android and iOS targets |

### Build Performance

| # | Tool | Command | What it does |
|---|---|---|---|
| 16 | Compile Critical Path | `timings` | The chain of crates that sets your build time, from cargo --timings data |
| 17 | Monomorphization & Macro Bloat | `mono` | Generic instantiations and LLVM IR lines generated per crate and per function |
| 18 | Release Profile Advisor | `profile` | Measure LTO, codegen-units, panic=abort and opt-level on your project and report the trade-offs |

### Api & Evolution

| # | Tool | Command | What it does |
|---|---|---|---|
| 19 | Public Dependency Leak | `pubdeps` | Dependency types exposed in your public API, so their breaking release becomes yours |
| 20 | Doc Coverage & Link Check | `docscov` | Undocumented public items, missing # Safety/# Errors/# Panics sections and broken intra-doc links |
| 21 | Future-Breakage Forecast | `futurecompat` | Future-incompatibility warnings and upcoming-toolchain errors in your dependency tree |
| 22 | Edition Migration Planner | `edition` | Edition-2024 readiness of every workspace member and the migration lints each will hit |

### Ecosystem Intelligence

| # | Tool | Command | What it does |
|---|---|---|---|
| 23 | Download Anomaly Detector | `anomaly` | Sudden download spikes per version, an early signal of bot inflation or compromise |
| 24 | Successor Finder | `successor` | Detect crates the ecosystem is leaving and what dependents replace them with |
| 25 | Publisher Provenance | `trustpub` | Whether each release came from Trusted Publishing or a personal token, and who published it |

## Examples

### `unsafe`: Unsafe Soundness Hotspots

```bash
sm-crates unsafe
sm-crates unsafe smallvec@1.13.2 bytes hashbrown
sm-crates unsafe smallvec@1.15.1 --diff 1.11.0
sm-crates unsafe --members --only mycrate --fail-on medium
```

Needs: network (crate downloads)

### `miri`: Miri UB Runner

```bash
sm-crates miri --plan
sm-crates miri smallvec@1.13.2 --lib
sm-crates miri --max 3 --timeout 1200
sm-crates miri bytes --many-seeds --miriflags=-Zmiri-strict-provenance
```

Needs: network, nightly toolchain with the miri component

### `panics`: Panic Surface Map

```bash
sm-crates panics
sm-crates panics itoa@1.0.11 smallvec
sm-crates panics --deps --only serde_json,url
sm-crates panics semver --max-findings 20 --json
```

Needs: network for published crates; none for your own project

### `autotraits`: Auto-Trait Leak Detector

```bash
sm-crates autotraits tokio 1.44.0 1.45.0
sm-crates autotraits bytes
sm-crates autotraits smallvec@1.13.2 1.15.1 --local
sm-crates autotraits regex 1.10.6 1.11.1 --local --all-features --json
```

Needs: network (docs.rs rustdoc JSON), or nightly with --local

### `assurance`: Verification Coverage

```bash
sm-crates assurance
sm-crates assurance smallvec bytes crossbeam-channel itoa
sm-crates assurance --only hashbrown,memchr --json
sm-crates assurance regex --no-repo
```

Needs: network (crates.io, GitHub, OSS-Fuzz)

### `buildtrace`: Build Script Sandbox Trace

```bash
sm-crates buildtrace
sm-crates buildtrace --no-network --json
sm-crates buildtrace openssl-sys@0.9.103 --features vendored
sm-crates buildtrace libz-sys --portable --fail-on medium
```

Needs: cargo; strace on Linux for the full trace (portable observer elsewhere); network unless dependencies are cached

### `csys`: Bundled C Library Scanner

```bash
sm-crates csys
sm-crates csys openssl-src@300.0.1+3.0.1 libsqlite3-sys@0.28.0
sm-crates csys libz-sys zstd-sys curl-sys --no-cve
sm-crates csys --no-scan --json
```

Needs: network (crate downloads, NVD CVE API; NVD_API_KEY optional)

### `srcverify`: Published-vs-Repo Verifier

```bash
sm-crates srcverify itoa@1.0.11
sm-crates srcverify cfg-if@1.0.0 hex@0.4.3 --json
sm-crates srcverify --limit 10
sm-crates srcverify libgit2-sys@0.17.0+1.8.1
```

Needs: network (crate downloads, git access to the repository hosts), git

### `vet`: cargo-vet Audit Coverage

```bash
sm-crates vet
sm-crates vet serde@1.0.210 libc@0.2.158 --import mozilla,google
sm-crates vet --criteria safe-to-run --json
sm-crates vet smallvec@1.13.2 --no-suggest
```

Needs: network (cargo-vet audit sets on raw.githubusercontent.com, crate downloads; crates.io API for trusted publishers)

### `crev`: crev Trust Graph

```bash
sm-crates crev
sm-crates crev once_cell@1.0.1 log@0.4.8 --depth 1
sm-crates crev --root https://github.com/dpc/crev-proofs --max-repos 10 --json
```

Needs: network (git access to proof repositories), git

### `featmatrix`: Feature Matrix Tester

```bash
sm-crates featmatrix
sm-crates featmatrix itoa@1.0.15
sm-crates featmatrix semver@1.0.26 --strategy powerset --depth 2
sm-crates featmatrix memchr@2.7.4 --static
```

Needs: cargo (network for named crates)

### `features`: Feature Bleed Explainer

```bash
sm-crates features
sm-crates features --why serde/std
sm-crates features --why syn --json
sm-crates features --all --markdown
```

Needs: cargo

### `nostd`: no_std Readiness

```bash
sm-crates nostd
sm-crates nostd serde_json@1.0.140
sm-crates nostd semver@1.0.26 --no-default-features --target thumbv7em-none-eabihf
sm-crates nostd hashbrown@0.15.2 --all
```

Needs: cargo, network (index lookups; named crates); rustup target for real cross-checks

### `runtimes`: Async Runtime Conflict Detector

```bash
sm-crates runtimes
sm-crates runtimes --deps
sm-crates runtimes --json --fail-on medium
```

Needs: cargo, network (sources of dependencies with --deps)

### `targets`: Target Compatibility Matrix

```bash
sm-crates targets
sm-crates targets --target wasm32-unknown-unknown,thumbv7em-none-eabihf
sm-crates targets --target x86_64-unknown-linux-gnu --all
sm-crates targets --no-docsrs --json
```

Needs: cargo; rustup targets for real cross-checks

### `timings`: Compile Critical Path

```bash
sm-crates timings --clean
sm-crates timings --file target/cargo-timings/cargo-timing.html
sm-crates timings --clean --release --top 5 --json
```

Needs: cargo (no network unless dependencies must be downloaded)

### `mono`: Monomorphization & Macro Bloat

```bash
sm-crates mono
sm-crates mono --release --top 15
sm-crates mono --copies 10 --json
sm-crates mono --macros
```

Needs: cargo (no network unless dependencies must be downloaded)

### `profile`: Release Profile Advisor

```bash
sm-crates profile --quick
sm-crates profile --variants baseline,opt-z,min-size --bench-cmd "{bin} --version" --runs 3
sm-crates profile --variants strip,line-tables --json
```

Needs: cargo (no network unless dependencies must be downloaded)

### `pubdeps`: Public Dependency Leak

```bash
sm-crates pubdeps
sm-crates pubdeps reqwest@0.12.9
sm-crates pubdeps tower-http --only http,bytes --json
sm-crates pubdeps axum --max-items 10
```

Needs: network (crates.io sparse index; downloads named crates); cargo for local projects

### `docscov`: Doc Coverage & Link Check

```bash
sm-crates docscov
sm-crates docscov semver --min-coverage 90
sm-crates docscov itoa --source docsrs
sm-crates docscov itoa --rustdoc
sm-crates docscov --rustdoc-json target/doc/my_lib.json
sm-crates docscov --package core-lib --json
```

Needs: network (crates.io; docs.rs for named crates); cargo for local projects; nightly toolchain optional

### `futurecompat`: Future-Breakage Forecast

```bash
sm-crates futurecompat
sm-crates futurecompat --verify --all-targets
sm-crates futurecompat --crater beta-1.98-1 --json
sm-crates futurecompat --beta --no-crater
```

Needs: cargo; network for the crates.io index, crater reports and Rust release data; beta/nightly toolchains for --beta/--nightly

### `edition`: Edition Migration Planner

```bash
sm-crates edition
sm-crates edition --to 2024 --dry-run-fix
sm-crates edition --all-features --json
```

Needs: cargo (no network unless dependencies must be downloaded)

### `anomaly`: Download Anomaly Detector

```bash
sm-crates anomaly
sm-crates anomaly serde tokio --days 60
sm-crates anomaly --all --limit 20 --json
sm-crates anomaly some-new-crate --threshold 4 --min-daily 50
```

Needs: network (crates.io API)

### `successor`: Successor Finder

```bash
sm-crates successor atty
sm-crates successor atty --compare clap,env_logger,colored,criterion,pretty_env_logger --scan-top 0
sm-crates successor
sm-crates successor lazy_static --dependents 100 --json
```

Needs: network (crates.io API and sparse index, RustSec via git)

### `trustpub`: Publisher Provenance

```bash
sm-crates trustpub
sm-crates trustpub cc pyo3 zerocopy
sm-crates trustpub tokio@1.40.0 --history 15
sm-crates trustpub --all --since 90 --json
sm-crates trustpub --only serde,libc --fail-on medium
```

Needs: network (crates.io API); cargo for local projects

## Options for every tool

```text
      --json                  Print machine-readable JSON instead of text
      --markdown              Print a Markdown report (for PR comments and job summaries)
      --fail-on LEVEL         Exit 1 when a finding is at or above LEVEL: info, low, medium, high (default), critical, none
  -p, --project DIR           Project directory containing Cargo.toml (default: current directory)
      --offline               Use only cached data; never touch the network
      --refresh               Ignore cached responses and fetch fresh data
      --no-color              Disable colored output (also honors NO_COLOR)
  -q, --quiet                 Only print findings, no tables or notes
  -h, --help                  Show help for this tool
```

Run `sm-crates help <tool>` for each tool's own options and a full description of how it works.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | no findings at or above --fail-on |
| `1` | findings at or above --fail-on (default: high) |
| `2` | invalid command line |
| `3` | could not complete (network, toolchain, project) |

## Use in GitHub Actions

```yaml
- uses: dtolnay/rust-toolchain@stable
- run: cargo install sm-crates --locked
- run: sm-crates unsafe --fail-on high
- run: sm-crates vet --markdown >> "$GITHUB_STEP_SUMMARY"
- run: sm-crates trustpub --fail-on medium
```

## Configuration

| Variable | Purpose |
|---|---|
| `GITHUB_TOKEN` or `GH_TOKEN` | Raises GitHub API limits for `srcverify`, `assurance`, `crev` and `successor` |
| `NVD_API_KEY` | Raises NVD limits for `csys` |
| `NO_COLOR` | Disables colored output |

Responses are cached in your user cache directory, so repeated runs are fast. Use `--refresh` to bypass the cache and `--offline` to use only cached data.

## Notes

- `sm-crates` follows the [crates.io data access policy](https://crates.io/data-access): it sends an identifying User-Agent, keeps API calls to one per second, and reads the sparse index and static.crates.io wherever it can.
- `miri` needs the nightly toolchain with the Miri component (`rustup +nightly component add miri`). `autotraits` reads rustdoc JSON from docs.rs, or builds it locally with nightly (`--local`). `pubdeps` and `docscov` use nightly rustdoc JSON when available and fall back to docs.rs or a source scan.
- `buildtrace` gives a full trace only on Linux with `strace`. On macOS and Windows it runs in portable mode, which sees programs started through PATH, file changes and credential-file reads but not network access, and says which mode ran. It is an observation harness, not a sandbox: run untrusted crates in a VM.
- Findings are leads for review, not verdicts. Each finding says where it was found and how to fix it.

## License

MIT © Slash Mark IT Solutions. See [LICENSE](LICENSE).
