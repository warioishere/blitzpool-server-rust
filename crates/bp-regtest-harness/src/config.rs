// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Names the `bitcoin-node` path and skips the [`discover_bitcoin_node`]
/// search. Used as given except for a leading `~`, which only arrives here
/// quoted; the version floor is not applied.
pub const BITCOIN_NODE_PATH_ENV: &str = "BITCOIN_NODE_PATH";

/// Layouts probed under each prefix after `$PATH`, which wins because it was
/// chosen. Upstream ships the multiprocess `bitcoin-node` under `libexec/`,
/// which `$PATH` misses. No Homebrew path: that formula ships only `bitcoind`.
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
    // Extracted-tarball directories in a home directory.
    "~/bitcoin-31.0",
    "~/bitcoin-30.0",
];

/// Lowest bitcoin-core major version the harness can drive. The v31 IPC
/// schema has `Init.makeMining @3` (`@2` in v30), so a v30 node fails TDP
/// startup with a capnp `Unimplemented`; checked up front to skip cleanly.
pub const MIN_BITCOIN_NODE_MAJOR: u32 = 31;

/// Find a usable `bitcoin-node`. Returns `(path, found)`; when not found the
/// path only makes the skip message concrete (a too-old binary if any).
/// Not cached, so the env var stays overridable within a process.
pub fn discover_bitcoin_node() -> (PathBuf, bool) {
    // An explicit env var is honoured verbatim, even when it points at
    // nothing: a regtest passing on a different binary proves nothing. No
    // version floor: a master build reports `v30.99` on both sides of the
    // `makeMining` renumbering.
    if let Ok(from_env) = std::env::var(BITCOIN_NODE_PATH_ENV) {
        let p = named_node_path(&from_env, std::env::var("HOME").ok().as_deref());
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
            // A v30 earlier on `$PATH` must not shadow a v31 later; keep it
            // for the skip message.
            too_old.get_or_insert_with(|| candidate.clone());
        }
        first.get_or_insert(candidate);
    }
    let named = too_old
        .or(first)
        .unwrap_or_else(|| PathBuf::from("bitcoin-node"));
    (named, false)
}

/// Resolve a [`BITCOIN_NODE_PATH_ENV`] value, split from the env read so it
/// is testable without `set_var`. A quoted leading `~` is expanded, or every
/// regtest would skip; without `$HOME` the literal is kept for the message.
fn named_node_path(value: &str, home: Option<&str>) -> PathBuf {
    let named = PathBuf::from(value);
    expand_home(&named, home).unwrap_or(named)
}

/// The one definition of "can run the regtests", shared by discovery and
/// [`RegtestConfig::is_available`]. An unparseable banner or an env-named
/// path counts as usable: failing loudly is diagnosable, while a skip leaves
/// a green suite that proved nothing.
fn is_usable(path: &Path) -> bool {
    path.exists()
        && is_executable(path)
        && (is_env_named(path)
            || node_major_version(path).is_none_or(|major| major >= MIN_BITCOIN_NODE_MAJOR))
}

/// Whether `path` is the one [`BITCOIN_NODE_PATH_ENV`] names. Compared by
/// value, not a flag, so a config built by any route reaches the same verdict.
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

/// Major version from a `-version` banner, testable without a node.
fn parse_major_version(banner: &str) -> Option<u32> {
    // The first numeric `v` token wins; words like `variant` are skipped.
    banner
        .split_whitespace()
        .filter_map(|tok| tok.strip_prefix('v'))
        .filter_map(|rest| rest.split('.').next())
        .find_map(|digits| digits.parse().ok())
}

/// Every path `discover_bitcoin_node` will consider, in order.
fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let home = std::env::var("HOME").ok();
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            // A shell exports `PATH` verbatim, so `~/...` can arrive literally.
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

/// Expand a leading `~` against `home`; `None` when `$HOME` is needed but
/// unset, so the caller drops the entry.
fn expand_home(p: &Path, home: Option<&str>) -> Option<PathBuf> {
    let s = p.to_string_lossy();
    let rest = match s.strip_prefix('~') {
        Some(rest) => rest.strip_prefix('/').unwrap_or(rest),
        None => return Some(p.to_path_buf()),
    };
    Some(PathBuf::from(home?).join(rest))
}

/// Maximum wait for bitcoin-node to come up (cookie, IPC socket, first RPC);
/// generous, but still bounds a hung test.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct RegtestConfig {
    pub bitcoin_node_path: PathBuf,
    pub startup_timeout: Duration,
    /// Extra args appended verbatim to the bitcoin-node invocation.
    pub extra_args: Vec<String>,
    /// Caller-owned datadir, never deleted by the node, so a test can restart
    /// bitcoin-node on the same IPC socket path to exercise reconnects.
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

    /// See [`RegtestConfig::external_datadir`]; the caller cleans it up.
    pub fn with_external_datadir(mut self, datadir: impl Into<PathBuf>) -> Self {
        self.external_datadir = Some(datadir.into());
        self
    }

    /// Whether the binary exists, is executable and is at least
    /// [`MIN_BITCOIN_NODE_MAJOR`] (unless named in [`BITCOIN_NODE_PATH_ENV`]).
    /// The version counts because a v30 node passes everything else and then
    /// fails TDP startup with an opaque capnp error.
    pub fn is_available(&self) -> bool {
        is_usable(&self.bitcoin_node_path)
    }

    /// Why [`is_available`] is false, for a skipping test to print. Missing,
    /// not executable and too old are told apart: three different fixes.
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

/// The "too old" half of [`RegtestConfig::unavailable_reason`].
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

    // No env-var mutation test: `set_var` is unsafe and the workspace denies
    // `unsafe_code`.

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

    /// Pins that no user's home directory is hard-coded into discovery and
    /// that `$PATH` really contributes candidates.
    #[test]
    fn candidates_are_derived_from_the_environment_not_hard_coded() {
        for prefix in CANDIDATE_PREFIXES {
            assert!(
                !prefix.starts_with("/home/") && !prefix.starts_with("/Users/"),
                "{prefix} hard-codes one user's home directory — use a `~` prefix, \
                 which expands per user"
            );
        }
        // Only a `$PATH` directory no prefix can produce proves the `$PATH`
        // search is alive.
        let home = std::env::var("HOME").ok();
        let prefix_derived: Vec<PathBuf> = CANDIDATE_PREFIXES
            .iter()
            .filter_map(|p| expand_home(Path::new(p), home.as_deref()))
            .flat_map(|base| CANDIDATE_SUFFIXES.iter().map(move |s| base.join(s)))
            .collect();
        if let Some(path_var) = std::env::var_os("PATH") {
            let all = candidates();
            let only_from_path = std::env::split_paths(&path_var)
                .filter_map(|d| expand_home(&d, home.as_deref()))
                .map(|d| d.join("bitcoin-node"))
                .filter(|c| !prefix_derived.contains(c));
            let mut checked = 0usize;
            let mut found = false;
            for c in only_from_path {
                checked += 1;
                if all.contains(&c) {
                    found = true;
                    break;
                }
            }
            // `checked == 0`: every `$PATH` entry coincides with a prefix.
            assert!(
                found || checked == 0,
                "none of the {checked} $PATH-only directories reached the candidate \
                 list — the $PATH search is dead"
            );
        }
    }

    /// Pins that both `libexec/` and `bin/` layouts are searched.
    #[test]
    fn each_prefix_is_probed_for_every_layout() {
        let all = candidates();
        if std::env::var("HOME").is_ok() {
            for suffix in CANDIDATE_SUFFIXES {
                assert!(
                    all.iter().any(|c| c.ends_with(suffix)),
                    "no candidate ends with {suffix} — that layout is not searched"
                );
            }
        }
    }

    /// Pins that a leading `~` is expanded for prefixes and `$PATH` alike.
    #[test]
    fn home_relative_paths_are_expanded_from_every_source() {
        let Ok(home) = std::env::var("HOME") else {
            return;
        };
        // Only a leading `~` is unexpanded; one inside a name is ordinary.
        for c in candidates() {
            let s = c.to_string_lossy();
            assert!(
                !s.starts_with('~'),
                "a literal `~` directory can never exist, so this candidate is \
                 dead weight: {s}"
            );
        }
        // Positive control, so an empty list cannot pass.
        let want = PathBuf::from(&home).join(".local/libexec/bitcoin-node");
        assert!(
            candidates().contains(&want),
            "expected the expanded {} among the candidates",
            want.display()
        );
    }

    /// Pins that a real banner is parsed and v30 is rejected.
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
        assert_eq!(parse_major_version("version v31"), Some(31));
        assert_eq!(
            parse_major_version("variant vX build v32.1"),
            Some(32),
            "a `v`-prefixed word should be skipped, not parsed as a version"
        );
    }

    /// Pins that an unrecognised banner counts as usable rather than skipping.
    #[test]
    fn an_unparseable_banner_is_treated_as_usable() {
        assert_eq!(
            parse_major_version("some custom build, no version token"),
            None
        );
        // `/bin/sh` is a real executable that prints no version token.
        let sh = Path::new("/bin/sh");
        assert_eq!(
            node_major_version(sh),
            None,
            "precondition: /bin/sh must be unclassifiable for this test to mean anything"
        );
        assert!(
            is_usable(sh),
            "an unclassifiable banner must count as usable — silently skipping is the \
             worse failure, because a skipped test passes"
        );
    }

    /// Pins that an env-named binary bypasses the version floor, and only that one.
    #[test]
    fn an_explicitly_named_binary_bypasses_the_version_floor() {
        let Some(named) = std::env::var_os(BITCOIN_NODE_PATH_ENV) else {
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
        // Negative control: the bypass is keyed to that path, not global.
        assert!(
            !is_env_named(Path::new("/definitely/not/the/named/one")),
            "the bypass must not extend to other paths"
        );
    }

    /// Pins a distinct message per unavailability cause.
    #[test]
    fn unavailable_reason_distinguishes_missing_from_too_old() {
        let missing = RegtestConfig::default().with_bitcoin_node_path("/definitely/not/here");
        let reason = missing.unavailable_reason();
        assert!(
            reason.contains("not found") && reason.contains(BITCOIN_NODE_PATH_ENV),
            "a missing binary should name the override env var: {reason}"
        );
        // A stub that really answers with a v30 banner reaches the too-old arm.
        let hallmark = "the SV2 IPC bindings call";
        let stub = v30_banner_stub();
        let old = RegtestConfig::default().with_bitcoin_node_path(&stub);
        assert!(
            !old.is_available(),
            "a v30 banner must fail the floor: {}",
            stub.display()
        );
        let reason = old.unavailable_reason();
        assert!(
            reason.contains(hallmark) && reason.contains("is v30"),
            "a too-old binary must name its version and why it cannot work: {reason}"
        );
        std::fs::remove_file(&stub).ok();

        // An executable with no version token is not called too old.
        let sh = RegtestConfig::default().with_bitcoin_node_path("/bin/sh");
        assert!(
            !sh.unavailable_reason().contains(hallmark),
            "an unclassifiable binary must not be reported as too old"
        );
    }

    /// An executable that answers `-version` with a v30 banner, so no v30
    /// install is needed.
    fn v30_banner_stub() -> PathBuf {
        let path = std::env::temp_dir().join(format!("bp-v30-stub-{}", stub_suffix()));
        std::fs::write(
            &path,
            "#!/bin/sh\necho 'Bitcoin Core daemon version v30.2 bitcoin-node'\n",
        )
        .expect("write stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod stub");
        }
        path
    }

    /// Unique per call; a timestamp could collide between parallel tests.
    fn stub_suffix() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        format!(
            "{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        )
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

    /// Pins that the override path itself expands a quoted `~`.
    #[test]
    fn a_quoted_tilde_in_the_override_is_expanded() {
        assert_eq!(
            named_node_path("~/b/bitcoin-node", Some("/home/u")),
            PathBuf::from("/home/u/b/bitcoin-node"),
            "a quoted `~` must expand, or the named binary can never exist"
        );
        // Negative control: an absolute path is untouched.
        assert_eq!(
            named_node_path("/opt/bitcoin-31.1/bin/bitcoin-node", Some("/home/u")),
            PathBuf::from("/opt/bitcoin-31.1/bin/bitcoin-node"),
            "an absolute path is the operator's decision — pass it through"
        );
        // No `$HOME`: keep the literal for the skip message.
        assert_eq!(
            named_node_path("~/b/bitcoin-node", None),
            PathBuf::from("~/b/bitcoin-node")
        );
    }
}
