// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one way to build an HTTP client. reqwest is built without a bundled
//! crypto provider, and building a client before one is installed panics, so
//! every client goes through [`client_builder`]. The workspace `clippy.toml`
//! forbids the reqwest constructors that would bypass it.

/// A `reqwest` builder with the process's TLS crypto provider installed:
/// `ring`, the provider the rest of the dependency tree already uses.
#[allow(clippy::disallowed_methods)]
pub fn client_builder() -> reqwest::ClientBuilder {
    // Err only when a provider is already installed, which is all this needs.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
}

#[cfg(test)]
mod tests {
    /// Without the provider install, `build` panics with "No rustls crypto
    /// provider is configured".
    #[test]
    fn a_client_builds() {
        super::client_builder().build().expect("client");
    }
}
