// SPDX-License-Identifier: AGPL-3.0-or-later

//! Links into the pool UI that the API hands out or mails: invite and join
//! links, verify and access links, admin pages.

/// `path` on the pool UI at `base` (the `pool_base_url` setting), as the web
/// build routes it: a plain path, no `#`.
pub fn pool_ui_link(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::pool_ui_link;

    #[test]
    fn joins_base_and_path_with_one_slash() {
        assert_eq!(
            pool_ui_link("https://pool.example", "invite/open/t"),
            "https://pool.example/invite/open/t"
        );
        assert_eq!(
            pool_ui_link("https://pool.example/", "/blockparty/join/t"),
            "https://pool.example/blockparty/join/t"
        );
    }
}
