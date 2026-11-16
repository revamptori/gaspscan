//! Small shared helpers: JSON string escaping, ephemeral port selection and
//! a monotonic deadline type. Kept dependency-free on purpose.

use std::time::{Duration, Instant};

/// Escape a string for inclusion inside a JSON string literal.
pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// A simple wall-clock deadline wrapper.
#[derive(Clone, Copy)]
pub struct Deadline {
    start: Instant,
    limit: Duration,
}

impl Deadline {
    pub fn new(limit: Duration) -> Deadline {
        Deadline {
            start: Instant::now(),
            limit,
        }
    }

    /// Milliseconds remaining until the deadline (0 when expired).
    pub fn remaining_ms(&self) -> u64 {
        let elapsed = self.start.elapsed();
        if elapsed >= self.limit {
            0
        } else {
            (self.limit - elapsed).as_millis() as u64
        }
    }

    pub fn is_expired(&self) -> bool {
        self.start.elapsed() >= self.limit
    }
}

/// Pick an ephemeral-ish source port for crafting probe packets.
///
/// Uses a cheap mixing of process id and a counter so repeated probes from
/// one process do not collide, without pulling in an RNG crate.
pub fn ephemeral_port(counter: u32) -> u16 {
    let pid = std::process::id() as u32;
    let mixed = pid
        .wrapping_mul(2654435761)
        .wrapping_add(counter.wrapping_mul(2246822519))
        .wrapping_add(0x9e3779b9);
    16384 + (mixed % 49151) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_handles_quotes_and_controls() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("line\nbreak"), "line\\nbreak");
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("ctrl\u{0007}bell"), "ctrl\\u0007bell");
    }

    #[test]
    fn deadline_expires() {
        let d = Deadline::new(Duration::from_millis(50));
        assert!(!d.is_expired());
        std::thread::sleep(Duration::from_millis(80));
        assert!(d.is_expired());
        assert_eq!(d.remaining_ms(), 0);
    }

    #[test]
    fn ephemeral_ports_are_in_range() {
        for i in 0..100 {
            let p = ephemeral_port(i);
            assert!(p >= 16384);
            assert!(p <= 65535);
        }
    }
}
