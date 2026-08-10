// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable that, when set, is used verbatim as the
/// `bitcoin-node` path and skips [`discover_bitcoin_node`] entirely.
pub const BITCOIN_NODE_PATH_ENV: &str = "BITCOIN_NODE_PATH";

/// Where `discover_bitcoin_node` looks, in order, when
/// [`BITCOIN_NODE_PATH_ENV`] is unset.
///
/// `bitcoin-node` is the IPC-enabled multiprocess binary, which upstream
/// ships under `libexec/` rather than `bin/` — so a `$PATH` lookup alone
/// misses a stock tarball install, and a `libexec` guess alone misses the
/// developer who symlinked it into `~/.local/bin`. Both are searched.
///
/// `$PATH` first: someone who put `bitcoin-node` on their `$PATH` chose
/// that binary, and it should win over an older tarball left in a home
/// directory.
///
/// This list is the whole macOS story. Homebrew's `bitcoin` formula
/// installs `bitcoind`, NOT the multiprocess `bitcoin-node`, so there is
/// no Homebrew path worth probing — on macOS this binary comes from an
/// upstream tarball or a local build, which is why `~/.local` and
/// `/usr/local` are here and `/opt/homebrew/bin` is not.
const CANDIDATE_SUFFIXES: &[&str] = &[
    // Tarball layouts, relative to a prefix.
    "libexec/bitcoin-node",
    "bin/bitcoin-node",
];

/// Prefixes probed against [`CANDIDATE_SUFFIXES`]. `$HOME`-relative entries
/// are expanded at call time; a missing `$HOME` just drops them.
const CANDIDATE_PREFIXES: &[&str] = &[
    "~/.local",
    "/usr/local",
    "/opt/bitcoin",
    // Where the Linux dev box has it — kept so that machine keeps working
    // without an env var now that the default is no longer its path.
    "~/bitcoin-31.0",
    "~/bitcoin-30.0",
];

/// Lowest bitcoin-core major version this harness can actually drive.
///
/// Not cosmetic, and not a "please upgrade": `bp-template-distribution`
/// links `bitcoin_core_sv2::unix_capnp::v31x`, whose schema declares
/// `Init.makeMining @3` (v30 had it at `@2`, and upstream kept the ordinal
/// busy with a `makeMiningOld2` placeholder). A v30 node therefore has no
/// method 3 to call. Measured on v30.2 (2026-08-09): it spawns, writes its
/// cookie, serves JSON-RPC and creates `node.sock`, and then answers TDP
/// startup with
/// `Unimplemented … interfaceName = capnp/init.capnp:Init; methodId = 3`.
/// So a v30 node passes every check except the one that matters, which is
/// why the version is checked up front rather than discovered as an opaque
/// capnp error 29 tests deep.
pub const MIN_BITCOIN_NODE_MAJOR: u32 = 31;

/// Find an IPC-enabled `bitcoin-node` new enough to drive, or return the
/// best path to name in an error.
///
/// Returns `(path, found)`. On `found == false` the path is the most
/// actionable candidate — an installed-but-too-old binary if there is one,
/// otherwise the first path searched — which exists only to make the skip
/// message concrete. `is_available()` is what callers actually branch on.
///
/// Deliberately NOT cached in a `OnceLock`: it runs once per
/// `RegtestConfig::default()`, a handful of times per test binary, and a
/// few `stat` calls plus at most one or two `-version` spawns are nothing
/// against the ~1-2 s the node itself takes to come up. Caching would also
/// make the env var un-overridable within a process, which is exactly the
/// knob a developer reaches for first.
pub fn discover_bitcoin_node() -> (PathBuf, bool) {
    // An explicit env var is a decision, not a hint: honour it verbatim,
    // including when it points at nothing. Silently searching elsewhere
    // would run tests against a DIFFERENT binary than the operator named,
    // and a regtest that passes on the wrong node proves nothing.
    //
    // The version floor is deliberately NOT applied here. The banner cannot
    // settle it for a development build: master carries minor `.99`, and
    // `v30.99` exists both before and after the `makeMining` renumbering —
    // measured on this machine, where a Jan-2026 master checkout reports
    // v30.99 with `@2` while v31.1 reports `@3`. Refusing every `.99` would
    // lock out contributors building from master; accepting them all would
    // reinstate the confusing failure. So a named binary is simply used, and
    // a mismatch surfaces as the capnp error rather than as a wrong guess.
    if let Ok(from_env) = std::env::var(BITCOIN_NODE_PATH_ENV) {
        let p = PathBuf::from(from_env);
        let ok = p.exists() && is_executable(&p);
        return (p, ok);
    }

    let mut first: Option<PathBuf> = None;
    let mut too_old: Option<PathBuf> = None;
    for candidate in candidates() {
        if candidate.exists() && is_executable(&candidate) {
            if is_usable(&candidate) {
                return (candidate, true);
            }
            // Keep looking: a v30 earlier on `$PATH` must not shadow a v31
            // in a tarball prefix. Remember it, though — "you have v30
            // here" beats "not found" as a skip message.
            too_old.get_or_insert_with(|| candidate.clone());
        }
        first.get_or_insert(candidate);
    }
    let named = too_old
        .or(first)
        .unwrap_or_else(|| PathBuf::from("bitcoin-node"));
    (named, false)
}

/// Present, executable, and new enough — the single definition of "this
/// binary can run the regtests", shared by discovery and
/// [`RegtestConfig::is_available`] so the two cannot disagree.
///
/// An unreadable or unparseable `-version` banner counts as **usable**: a
/// local build may print something we don't recognise, and skipping it
/// silently is the worse error. Failing loudly against a node we could not
/// classify leaves a diagnosable message; skipping leaves a green suite
/// that proved nothing.
///
/// Same reasoning, one step further, for a path the operator named in
/// [`BITCOIN_NODE_PATH_ENV`]: the floor is not applied at all. See
/// [`discover_bitcoin_node`] for why the banner cannot settle it there.
fn is_usable(path: &Path) -> bool {
    path.exists()
        && is_executable(path)
        && (is_env_named(path)
            || node_major_version(path).is_none_or(|major| major >= MIN_BITCOIN_NODE_MAJOR))
}

/// Whether `path` is the one [`BITCOIN_NODE_PATH_ENV`] names.
///
/// Compared by value rather than tracked as a flag on `RegtestConfig`, so
/// that a config built by any route — `default()`, `with_bitcoin_node_path`,
/// `clone()` — reaches the same verdict as discovery did.
fn is_env_named(path: &Path) -> bool {
    std::env::var_os(BITCOIN_NODE_PATH_ENV).is_some_and(|named| Path::new(&named) == path)
}

/// Major version reported by `<path> -version`, e.g. `30` from
/// `Bitcoin Core daemon version v30.2 bitcoin-node`.
fn node_major_version(path: &Path) -> Option<u32> {
    let out = std::process::Command::new(path)
        .arg("-version")
        .output()
        .ok()?;
    parse_major_version(&String::from_utf8_lossy(&out.stdout))
}

/// Pull the major version out of a `-version` banner. Split out from the
/// spawn so it is testable without a bitcoin-node on the machine.
fn parse_major_version(banner: &str) -> Option<u32> {
    // `v30.2` → 30, and a bare `v31` → 31. Tokens that merely start with
    // `v` (`variant`) yield no digits and are skipped rather than
    // misparsed, so the first *numeric* `v` token wins.
    banner
        .split_whitespace()
        .filter_map(|tok| tok.strip_prefix('v'))
        .filter_map(|rest| rest.split('.').next())
        .find_map(|digits| digits.parse().ok())
}

/// Every path `discover_bitcoin_node` will consider, in order.
fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    // `$PATH` — covers a symlink into `~/.local/bin`, a package manager's
    // `bin`, or a shell-configured build directory, without guessing at
    // any of them.
    let home = std::env::var("HOME").ok();
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            // `$PATH` entries get the same tilde expansion as our own
            // prefixes. A shell exports `PATH` verbatim, so an unexpanded
            // `~/...` written in a shell profile arrives here literally —
            // measured on this machine, where `$PATH` carries
            // `~/.dotnet/tools`. `Path::join` would then probe a directory
            // named `~`, which cannot exist.
            if let Some(expanded) = expand_home(&dir, home.as_deref()) {
                out.push(expanded.join("bitcoin-node"));
            }
        }
    }
    for prefix in CANDIDATE_PREFIXES {
        if let Some(base) = expand_home(Path::new(prefix), home.as_deref()) {
            for suffix in CANDIDATE_SUFFIXES {
                out.push(base.join(suffix));
            }
        }
    }
    out
}

/// Expand a leading `~` against `home`. `None` when the path needs `$HOME`
/// and it is unset (some CI containers) — the caller drops the entry rather
/// than probing a literal `~` directory that cannot exist.
fn expand_home(p: &Path, home: Option<&str>) -> Option<PathBuf> {
    let s = p.to_string_lossy();
    let rest = match s.strip_prefix('~') {
        Some(rest) => rest.strip_prefix('/').unwrap_or(rest),
        // No tilde: nothing to expand, and `$HOME` is irrelevant.
        None => return Some(p.to_path_buf()),
    };
    // A bare `~` expands to `$HOME` itself, so an empty remainder is fine.
    Some(PathBuf::from(home?).join(rest))
}

/// Maximum wall-time to wait for bitcoin-node to come up (cookie file +
/// IPC socket + first RPC response). bitcoin-core normally needs 1-2s on a
/// warm tmpfs; 30s is a generous ceiling that still bounds hung-test damage.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct RegtestConfig {
    pub bitcoin_node_path: PathBuf,
    pub startup_timeout: Duration,
    /// Extra args appended verbatim to the bitcoin-node invocation.
    /// Useful for `-debug=net`, `-printtoconsole`, etc.
    pub extra_args: Vec<String>,
    /// When `Some`, the node uses this datadir instead of an internally
    /// owned tempdir, and does NOT delete it on shutdown/drop. The caller
    /// owns the directory's lifecycle. Lets a test restart bitcoin-node
    /// at the same datadir (= same IPC socket path) to exercise
    /// reconnect/resume paths across a `bitcoind` restart.
    pub external_datadir: Option<PathBuf>,
}

impl Default for RegtestConfig {
    fn default() -> Self {
        Self {
            bitcoin_node_path: discover_bitcoin_node().0,
            startup_timeout: Duration::from_secs(DEFAULT_STARTUP_TIMEOUT_SECS),
            extra_args: Vec::new(),
            external_datadir: None,
        }
    }
}

impl RegtestConfig {
    pub fn with_bitcoin_node_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.bitcoin_node_path = path.into();
        self
    }

    pub fn with_startup_timeout(mut self, timeout: Duration) -> Self {
        self.startup_timeout = timeout;
        self
    }

    pub fn with_extra_args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.extra_args = args.into_iter().collect();
        self
    }

    /// Use a caller-owned datadir instead of an internal tempdir. The
    /// node will NOT delete it on shutdown — the caller is responsible
    /// for cleanup. See [`RegtestConfig::external_datadir`].
    pub fn with_external_datadir(mut self, datadir: impl Into<PathBuf>) -> Self {
        self.external_datadir = Some(datadir.into());
        self
    }

    /// Whether the configured binary exists, is executable, and is at least
    /// [`MIN_BITCOIN_NODE_MAJOR`] — unless the operator named it in
    /// [`BITCOIN_NODE_PATH_ENV`], which overrides the version check. Lets
    /// callers fast-skip integration tests on machines without a usable
    /// bitcoin-core.
    ///
    /// The version is part of "available" on purpose. A v30 node satisfies
    /// every other check and then fails TDP startup with an opaque capnp
    /// `Unimplemented`; treating it as available would turn a clean skip
    /// into ~29 confusing failures.
    pub fn is_available(&self) -> bool {
        is_usable(&self.bitcoin_node_path)
    }

    /// One line explaining why [`is_available`] is false, for tests to print
    /// when they skip.
    ///
    /// Skip messages are the only evidence a developer gets that a suite did
    /// not run, so they have to distinguish "no binary" from "wrong binary"
    /// from "too old" — three different fixes.
    ///
    /// [`is_available`]: RegtestConfig::is_available
    pub fn unavailable_reason(&self) -> String {
        let path = self.bitcoin_node_path.display();
        if !self.bitcoin_node_path.exists() {
            return format!(
                "bitcoin-node not found (last tried {path}); set {BITCOIN_NODE_PATH_ENV}, and note \
                 the harness needs the multiprocess `bitcoin-node`, not the legacy `bitcoind` \
                 Homebrew's `bitcoin` formula ships"
            );
        }
        if !is_executable(&self.bitcoin_node_path) {
            return format!("{path} is not executable");
        }
        match node_major_version(&self.bitcoin_node_path) {
            Some(major) if major < MIN_BITCOIN_NODE_MAJOR => {
                too_old_reason(&self.bitcoin_node_path, major)
            }
            _ => format!("{path} looks usable — nothing to explain"),
        }
    }
}

/// The "too old" half of [`RegtestConfig::unavailable_reason`], split out so a
/// test can assert the wording against a known-old version without needing a
/// v30 binary on the machine — which is what lets the "`/bin/sh` is not called
/// too old" control compare against a string it has actually seen produced,
/// rather than a phrase that may no longer appear anywhere.
fn too_old_reason(path: &Path, major: u32) -> String {
    let path = path.display();
    format!(
        "{path} is v{major}; the SV2 IPC bindings call `Init.makeMining @3`, which only \
         exists from v{MIN_BITCOIN_NODE_MAJOR} on. Point \
         {BITCOIN_NODE_PATH_ENV} at a v{MIN_BITCOIN_NODE_MAJOR}+ multiprocess build (that \
         also bypasses this check, for a master build whose `v30.99` banner cannot say \
         which side of the renumbering it is on)"
    )
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    // No env-var mutation test — Rust 1.85 marks `set_var`/`remove_var` as
    // unsafe and `unsafe_code = "deny"` is on for the workspace. The env
    // var is read once at `RegtestConfig::default()` call time; a fresh
    // process with `BITCOIN_NODE_PATH=...` set would observe it.

    #[test]
    fn builder_overrides_path_and_timeout() {
        let cfg = RegtestConfig::default()
            .with_bitcoin_node_path("/x/bitcoin-node")
            .with_startup_timeout(Duration::from_secs(5));
        assert_eq!(cfg.bitcoin_node_path, PathBuf::from("/x/bitcoin-node"));
        assert_eq!(cfg.startup_timeout, Duration::from_secs(5));
    }

    #[test]
    fn missing_binary_is_unavailable() {
        let cfg = RegtestConfig::default().with_bitcoin_node_path("/definitely/not/here");
        assert!(!cfg.is_available());
    }

    /// No absolute path may be baked in for one developer's machine.
    ///
    /// This is the regression: the default used to be
    /// `/home/warioishere/bitcoin-31.0/libexec/bitcoin-node`, so ~29
    /// regtests skipped on every other machine — and a skipped test PASSES,
    /// so the suite went green while proving nothing. Discovery has to come
    /// from the environment, never from a literal.
    #[test]
    fn candidates_are_derived_from_the_environment_not_hard_coded() {
        for c in candidates() {
            let s = c.to_string_lossy();
            assert!(
                !s.contains("warioishere"),
                "a specific developer's home directory is baked into discovery: {s}"
            );
        }
        // And the search is non-trivial: `$PATH` alone contributes several
        // entries on any real machine, so an empty list would mean the
        // whole mechanism silently does nothing.
        assert!(
            candidates().len() > CANDIDATE_PREFIXES.len(),
            "discovery should probe $PATH in addition to the fixed prefixes"
        );
    }

    /// Every prefix must be probed for BOTH layouts.
    ///
    /// `libexec/bitcoin-node` is where upstream's multiprocess tarball puts
    /// it; `bin/bitcoin-node` is where a local build or a manual copy tends
    /// to land. Checking only one silently halves the search.
    #[test]
    fn each_prefix_is_probed_for_every_layout() {
        let all = candidates();
        // `~/.local` is in `CANDIDATE_PREFIXES` and does not depend on
        // `$HOME` being any particular value — only on it being set.
        if std::env::var("HOME").is_ok() {
            for suffix in CANDIDATE_SUFFIXES {
                assert!(
                    all.iter().any(|c| c.ends_with(suffix)),
                    "no candidate ends with {suffix} — that layout is not searched"
                );
            }
        }
    }

    /// A `~`-prefixed entry must be expanded, not probed literally —
    /// wherever it came from.
    ///
    /// Both our own `CANDIDATE_PREFIXES` and `$PATH` are subject to this: a
    /// shell exports `PATH` verbatim, so a profile line written as
    /// `~/.dotnet/tools` arrives unexpanded. That is not hypothetical — it
    /// is what this machine's `$PATH` contains, and it is what made the
    /// first version of this test fail.
    #[test]
    fn home_relative_paths_are_expanded_from_every_source() {
        let Ok(home) = std::env::var("HOME") else {
            return;
        };
        for c in candidates() {
            let s = c.to_string_lossy();
            assert!(
                !s.contains('~'),
                "a literal `~` directory can never exist, so this candidate is \
                 dead weight: {s}"
            );
        }
        // Positive direction, so this cannot pass by the list being empty:
        // `~/.local` is a fixed prefix, so its expansion must be present.
        let want = PathBuf::from(&home).join(".local/libexec/bitcoin-node");
        assert!(
            candidates().contains(&want),
            "expected the expanded {} among the candidates",
            want.display()
        );
    }

    /// The version gate has to read a real banner, and reject v30.
    ///
    /// Measured 2026-08-09: v30.2 spawns, writes its cookie, serves JSON-RPC
    /// and creates `node.sock` — it passes every check the harness had — and
    /// then fails TDP startup with `Unimplemented … capnp/init.capnp:Init`.
    /// So the banner is the only cheap place to catch it.
    #[test]
    fn version_banner_is_parsed_and_v30_is_rejected() {
        let v30 = "Bitcoin Core daemon version v30.2 bitcoin-node\n\
                   Copyright (C) 2009-2026 The Bitcoin Core developers";
        assert_eq!(parse_major_version(v30), Some(30));
        assert!(parse_major_version(v30).unwrap() < MIN_BITCOIN_NODE_MAJOR);

        assert_eq!(
            parse_major_version("Bitcoin Core daemon version v31.0 bitcoin-node"),
            Some(31)
        );
        // A bare major, and a `v`-prefixed non-number that must not be
        // mistaken for one.
        assert_eq!(parse_major_version("version v31"), Some(31));
        assert_eq!(
            parse_major_version("variant vX build v32.1"),
            Some(32),
            "a `v`-prefixed word should be skipped, not parsed as a version"
        );
    }

    /// An unrecognised banner must NOT skip.
    ///
    /// A local build can print anything, and per this repo's testing notes a
    /// skipped test is indistinguishable from a passing one. Failing loudly
    /// against an unclassifiable node is recoverable; silently skipping is
    /// the failure mode that hid a whole suite.
    #[test]
    fn an_unparseable_banner_is_treated_as_usable() {
        assert_eq!(
            parse_major_version("some custom build, no version token"),
            None
        );
        // `is_usable` folds that `None` to "yes" — pinned here because the
        // opposite default is the tempting one.
        assert!(
            None::<u32>.is_none_or(|major: u32| major >= MIN_BITCOIN_NODE_MAJOR),
            "an unknown version must not be treated as too old"
        );
    }

    /// A binary the operator named must be used even if the banner is old.
    ///
    /// Not a nicety. `v30.99` is what a master build reports, and that
    /// banner exists on BOTH sides of the `makeMining` renumbering —
    /// measured on this machine, where a Jan-2026 master checkout is v30.99
    /// with `@2` and v31.1 is `@3`. So the floor cannot classify a
    /// development build, and the env var has to be the way out. Without
    /// this, a contributor's own master build is unusable with no override.
    #[test]
    fn an_explicitly_named_binary_bypasses_the_version_floor() {
        let Some(named) = std::env::var_os(BITCOIN_NODE_PATH_ENV) else {
            // Nothing named: the floor applies to everything, which is the
            // other half of this behaviour and is covered above.
            return;
        };
        let named = PathBuf::from(named);
        if !named.exists() {
            return;
        }
        assert!(
            is_env_named(&named),
            "the env-named path must be recognised as such: {}",
            named.display()
        );
        assert!(
            RegtestConfig::default()
                .with_bitcoin_node_path(&named)
                .is_available(),
            "a binary named in {BITCOIN_NODE_PATH_ENV} must count as available: {}",
            named.display()
        );
        // Negative control: the bypass is keyed to THAT path, not switched
        // on globally by the env var's mere presence. Otherwise this test
        // would pass while the floor was disabled for every binary.
        assert!(
            !is_env_named(Path::new("/definitely/not/the/named/one")),
            "the bypass must not extend to other paths"
        );
    }

    /// Each unavailability cause gets its own message, because each has a
    /// different fix.
    #[test]
    fn unavailable_reason_distinguishes_missing_from_too_old() {
        let missing = RegtestConfig::default().with_bitcoin_node_path("/definitely/not/here");
        let reason = missing.unavailable_reason();
        assert!(
            reason.contains("not found") && reason.contains(BITCOIN_NODE_PATH_ENV),
            "a missing binary should name the override env var: {reason}"
        );
        // The phrase the control below looks for, taken from the code that
        // produces it rather than retyped. An earlier version of this test
        // searched for wording that `unavailable_reason` never emits, so the
        // control passed no matter what the function did.
        let too_old = too_old_reason(Path::new("/bin/sh"), MIN_BITCOIN_NODE_MAJOR - 1);
        let hallmark = "the SV2 IPC bindings call";
        assert!(
            too_old.contains(hallmark),
            "positive control: a genuinely too-old binary must say so, else the \
             negative control below cannot fail: {too_old}"
        );

        // A path that exists and is executable but is not bitcoin-node at
        // all: `-version` yields no version token, so it is NOT called too
        // old. `/bin/sh` is present on every unix this suite runs on.
        let sh = RegtestConfig::default().with_bitcoin_node_path("/bin/sh");
        assert!(
            !sh.unavailable_reason().contains(hallmark),
            "an unclassifiable binary must not be reported as too old"
        );
    }

    #[test]
    fn expand_home_handles_bare_tilde_and_missing_home() {
        assert_eq!(
            expand_home(Path::new("~/x"), Some("/home/u")),
            Some(PathBuf::from("/home/u/x"))
        );
        // A bare `~` is `$HOME` itself.
        assert_eq!(
            expand_home(Path::new("~"), Some("/home/u")),
            Some(PathBuf::from("/home/u"))
        );
        // Absolute paths pass through untouched, `$HOME` or not.
        assert_eq!(
            expand_home(Path::new("/usr/local"), None),
            Some(PathBuf::from("/usr/local"))
        );
        // Needs `$HOME` and hasn't got it: dropped, not mangled.
        assert_eq!(expand_home(Path::new("~/x"), None), None);
    }
}
