//! Scan result model and rendering (human table and JSON).

use crate::ports::service_name;
use crate::util::json_escape;

/// Outcome of probing a single port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    /// The port accepted a connection / answered the probe as open.
    Open,
    /// The port actively refused the connection (RST / ECONNREFUSED).
    Closed,
    /// No usable answer within the timeout (could be filtered).
    OpenFiltered,
    /// For UDP we cannot distinguish open from filtered.
    OpenOrFiltered,
    /// The SYN probe was sent, but spoofing means replies cannot return.
    Sent,
    /// An error occurred probing the port (e.g. unreachable network).
    Error(String),
}

impl PortState {
    pub fn as_str(&self) -> &str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::OpenFiltered => "filtered|open",
            PortState::OpenOrFiltered => "open|filtered",
            PortState::Sent => "sent",
            PortState::Error(_) => "error",
        }
    }
}

/// A single probe result.
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub banner: Option<String>,
}

impl PortResult {
    pub fn service(&self) -> &str {
        service_name(self.port).unwrap_or("-")
    }
}

/// How to render the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

/// Render the full report. `target` is the scanned host as the user typed it.
pub fn render_report(
    target: &str,
    scan_type: &str,
    results: &[PortResult],
    duration_ms: u128,
    format: OutputFormat,
    include_closed: bool,
) -> String {
    match format {
        OutputFormat::Human => {
            render_human(target, scan_type, results, duration_ms, include_closed)
        }
        OutputFormat::Json => render_json(target, scan_type, results, duration_ms),
    }
}

fn visible(results: &[PortResult], include_closed: bool) -> Vec<&PortResult> {
    results
        .iter()
        .filter(|r| is_visible(&r.state, include_closed))
        .collect()
}

fn is_visible(state: &PortState, include_closed: bool) -> bool {
    include_closed
        || matches!(
            state,
            PortState::Open
                | PortState::Sent
                | PortState::OpenFiltered
                | PortState::OpenOrFiltered
                | PortState::Error(_)
        )
}

fn render_human(
    target: &str,
    scan_type: &str,
    results: &[PortResult],
    duration_ms: u128,
    include_closed: bool,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "gaspscan {} scan of {} ({} ports probed in {} ms)\n",
        scan_type,
        target,
        results.len(),
        duration_ms
    ));
    out.push_str(&format!(
        "{:<8}{:<12}{:<16}{}\n",
        "PORT", "STATE", "SERVICE", "BANNER"
    ));
    for r in visible(results, include_closed) {
        let banner = r.banner.clone().unwrap_or_else(|| "-".to_string());
        let banner_clean: String = banner
            .chars()
            .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '.' })
            .take(60)
            .collect();
        out.push_str(&format!(
            "{:<8}{:<12}{:<16}{}\n",
            r.port,
            r.state.as_str(),
            r.service(),
            banner_clean
        ));
    }
    let open_count = results
        .iter()
        .filter(|r| matches!(r.state, PortState::Open))
        .count();
    out.push_str(&format!(
        "summary: {} open, {} closed/filtered of {} probed\n",
        open_count,
        results.len() - open_count,
        results.len()
    ));
    out
}

fn render_json(
    target: &str,
    scan_type: &str,
    results: &[PortResult],
    duration_ms: u128,
) -> String {
    let mut out = String::new();
    out.push_str("{\n  \"target\": \"");
    out.push_str(&json_escape(target));
    out.push_str("\",\n  \"scan_type\": \"");
    out.push_str(&json_escape(scan_type));
    out.push_str("\",\n  \"duration_ms\": ");
    out.push_str(&duration_ms.to_string());
    out.push_str(",\n  \"results\": [\n");
    for (i, r) in results.iter().enumerate() {
        out.push_str("    {\"port\": ");
        out.push_str(&r.port.to_string());
        out.push_str(", \"state\": \"");
        out.push_str(&json_escape(r.state.as_str()));
        out.push_str("\", \"service\": \"");
        out.push_str(&json_escape(r.service()));
        out.push_str("\", \"banner\": ");
        match &r.banner {
            Some(b) => {
                out.push('"');
                out.push_str(&json_escape(b));
                out.push('"');
            }
            None => out.push_str("null"),
        }
        out.push('}');
        if i + 1 != results.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_results() -> Vec<PortResult> {
        vec![
            PortResult { port: 22, state: PortState::Open, banner: Some("SSH-2.0".to_string()) },
            PortResult { port: 23, state: PortState::Closed, banner: None },
        ]
    }

    #[test]
    fn human_report_lists_open_ports() {
        let out = render_report(
            "127.0.0.1",
            "connect",
            &sample_results(),
            12,
            OutputFormat::Human,
            false,
        );
        assert!(out.contains("22"));
        assert!(out.contains("open"));
        assert!(out.contains("ssh"));
        assert!(!out.contains("\n23 ")); // closed port hidden by default
    }

    #[test]
    fn human_report_can_include_closed() {
        let out = render_report(
            "127.0.0.1",
            "connect",
            &sample_results(),
            12,
            OutputFormat::Human,
            true,
        );
        assert!(out.contains("23"));
        assert!(out.contains("closed"));
    }

    #[test]
    fn json_report_is_well_formed() {
        let out = render_report(
            "host\"name",
            "connect",
            &sample_results(),
            7,
            OutputFormat::Json,
            false,
        );
        assert!(out.contains("\"target\": \"host\\\"name\""));
        assert!(out.contains("\"port\": 22"));
        assert!(out.contains("\"state\": \"open\""));
        assert!(out.contains("\"banner\": \"SSH-2.0\""));
        // balancing braces
        let open = out.matches('{').count();
        let close = out.matches('}').count();
        assert_eq!(open, close);
    }
}
