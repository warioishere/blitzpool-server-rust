// SPDX-License-Identifier: AGPL-3.0-or-later

//! Keeps every log event on one line. Worker names, user identities and
//! other peer-controlled strings reach the log verbatim, and the formatter
//! escapes terminal control sequences but not `\n` or `\r`: a worker named
//! `rig\n<forged line>` would otherwise write a second, fake log line. The
//! fmt layer writes each event with one `write_all`, ending in its own
//! newline, so this writer escapes every line break before that one.

use std::io;

use tracing_subscriber::fmt::MakeWriter;

/// Wraps a [`MakeWriter`] so that each event it writes stays one line.
pub(crate) struct OneLinePerEvent<M>(pub(crate) M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for OneLinePerEvent<M> {
    type Writer = OneLineWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        OneLineWriter(self.0.make_writer())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        OneLineWriter(self.0.make_writer_for(meta))
    }
}

pub(crate) struct OneLineWriter<W>(W);

impl<W: io::Write> io::Write for OneLineWriter<W> {
    /// Takes the whole buffer, so `write_all` hands over one event per call.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (body, end): (&[u8], &[u8]) = match buf.split_last() {
            Some((b'\n', body)) => (body, b"\n"),
            _ => (buf, b""),
        };
        if !body.iter().any(|b| matches!(b, b'\n' | b'\r')) {
            self.0.write_all(buf)?;
            return Ok(buf.len());
        }
        let mut line = Vec::with_capacity(buf.len() + 8);
        for &byte in body {
            match byte {
                b'\n' => line.extend_from_slice(b"\\n"),
                b'\r' => line.extend_from_slice(b"\\r"),
                _ => line.push(byte),
            }
        }
        line.extend_from_slice(end);
        self.0.write_all(&line)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    use super::*;

    /// Collects everything written, for reading back after the event.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// What one warning naming `worker` writes, through `make_writer`.
    fn logged<M>(make_writer: M, captured: &Captured, worker: &str) -> String
    where
        M: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    {
        let subscriber = tracing_subscriber::registry()
            .with(fmt::layer().with_ansi(false).with_writer(make_writer));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(worker = %worker, "share rejected");
        });
        String::from_utf8(captured.0.lock().unwrap().clone()).unwrap()
    }

    /// A worker name carrying line breaks cannot forge a second log line;
    /// the plain fmt writer is the control that it otherwise would.
    #[test]
    fn a_peer_string_with_line_breaks_stays_on_its_event_line() {
        let worker = "rig1\nERROR forged line\r";

        let plain = Captured::default();
        let out = logged(plain.clone(), &plain, worker);
        assert_eq!(out.lines().count(), 2, "control: unescaped, got {out:?}");

        let guarded = Captured::default();
        let out = logged(OneLinePerEvent(guarded.clone()), &guarded, worker);
        assert_eq!(out.matches('\n').count(), 1, "one line, got {out:?}");
        assert!(out.ends_with('\n'));
        assert!(out.contains(r"rig1\nERROR forged line\r"), "got {out:?}");
    }
}
