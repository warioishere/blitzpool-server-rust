// SPDX-License-Identifier: AGPL-3.0-or-later

//! A localhost HTTP stand-in's request reader, for the adapter tests that
//! answer one request per connection.

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Read one request off `socket`: its path and its body (by `content-length`).
pub(crate) async fn read_request(socket: &mut TcpStream) -> (String, Vec<u8>) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0, "connection closed before the request was read");
        raw.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&raw).to_string();
        if let Some(end) = text.find("\r\n\r\n") {
            let len: usize = text[..end]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            if raw.len() >= end + 4 + len {
                let path = text.split_whitespace().nth(1).unwrap_or("").to_string();
                return (path, raw[end + 4..end + 4 + len].to_vec());
            }
        }
    }
}
