// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire helpers shared by the SV2 regtests: one frame out, one frame in,
//! and the polling wait, in one place so a dependency bump lands once.
//!
//! Cargo compiles this module into every test binary that declares it, so
//! a helper one binary does not use is dead code there; the allow is for
//! that, not for anything unused in the crate.
#![allow(dead_code)]

use std::time::Duration;

use stratum_core::codec_sv2::MessageFrame;
use stratum_core::parsers_sv2::{parse_message_frame_with_tlvs, AnyMessageOwned};

use stratum_apps::network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf};

/// The regtest miner address every SV2 regtest mines to.
pub(crate) const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// A fresh SV2 extranonce allocator, as the binary builds one for all ports.
pub(crate) fn sv2_extranonce() -> bp_stratum_v2::extranonce::SharedExtranonceAllocator {
    bp_stratum_v2::extranonce::SharedExtranonceAllocator::new_default_on_worker(
        bp_stratum_v2::extranonce::SV2_WORKER_ID,
    )
}

/// Put `msg` into its SV2 frame and write it over the Noise stream.
pub(crate) async fn write_any_message(writer: &mut NoiseTcpWriteHalf, msg: AnyMessageOwned) {
    let sv2_frame: MessageFrame<AnyMessageOwned> =
        msg.try_into().expect("AnyMessageOwned to MessageFrame");
    writer.write_frame(sv2_frame).await.expect("write_frame");
}

/// Read one frame and parse it as a base-protocol message (no negotiated
/// extensions, so any TLV tail is dropped).
pub(crate) async fn read_any_message(reader: &mut NoiseTcpReadHalf) -> AnyMessageOwned {
    let mut sv2_frame = reader.read_frame().await.expect("read_frame");
    let header = sv2_frame.header();
    let (msg, _tlvs) = parse_message_frame_with_tlvs(header, sv2_frame.payload(), &[])
        .expect("parse_message_frame_with_tlvs");
    msg.into_owned()
}

/// Sub-protocol name of a message, for assertion messages.
pub(crate) fn decode_label(m: &AnyMessageOwned) -> &'static str {
    match m {
        AnyMessageOwned::Common(_) => "Common",
        AnyMessageOwned::Mining(_) => "Mining",
        AnyMessageOwned::JobDeclaration(_) => "JobDeclaration",
        AnyMessageOwned::TemplateDistribution(_) => "TemplateDistribution",
        AnyMessageOwned::Extensions(_) => "Extensions",
    }
}

/// Poll `cond` every 50 ms until it holds or `timeout` passes.
pub(crate) async fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut cond: F) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
