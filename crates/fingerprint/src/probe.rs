//! Pure parser for the diagnostic strings PHP emits on request-startup
//! failures. This module performs no network requests and sends no payloads.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProbeInfo {
    pub memory_limit_mb: Option<u64>,
    pub post_max_size_bytes: Option<u64>,
    pub diagnostics: bool,
    pub rejected: bool,
}

/// Mirrors the upstream `parse_probe_response` decisions exactly.
pub fn parse_probe_response(data: &[u8]) -> ProbeInfo {
    let mut info = ProbeInfo::default();

    if let Some(bytes) = value_between(data, b"Allowed memory size of ", b" bytes") {
        info.memory_limit_mb = bytes
            .parse::<u64>()
            .ok()
            .map(|n| (n / (1024 * 1024)).max(1));
        info.diagnostics = true;
        return info;
    }
    if let Some(bytes) = value_between(data, b"exceeds the limit of ", b" bytes") {
        info.post_max_size_bytes = bytes.parse::<u64>().ok();
        info.diagnostics = true;
        return info;
    }
    let status_line = data.split(|b| *b == b'\n').next().unwrap_or_default();
    if contains(status_line, b"413") || contains(data, b"Request Entity Too Large") {
        info.rejected = true;
        return info;
    }
    if contains(data, b"Fatal error:")
        || contains(data, b"Warning:")
        || contains(data, b"Deprecated:")
    {
        info.diagnostics = true;
    }
    info
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn value_between<'a>(data: &'a [u8], prefix: &[u8], suffix: &[u8]) -> Option<&'a str> {
    let start = find(data, prefix)? + prefix.len();
    let tail = &data[start..];
    let end = find(tail, suffix)?;
    let digits = &tail[..end];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_memory_limit_and_post_max_size() {
        let parsed =
            parse_probe_response(b"Fatal error: Allowed memory size of 8388608 bytes exhausted");
        assert_eq!(parsed.memory_limit_mb, Some(8));
        assert!(parsed.diagnostics);

        let parsed = parse_probe_response(
            b"Warning: POST Content-Length exceeds the limit of 8388608 bytes",
        );
        assert_eq!(parsed.post_max_size_bytes, Some(8388608));
        assert!(parsed.diagnostics);
    }

    #[test]
    fn distinguishes_413_from_diagnostics() {
        let parsed = parse_probe_response(b"HTTP/1.1 413 Request Entity Too Large\r\n\r\n");
        assert!(parsed.rejected);
        assert!(!parsed.diagnostics);

        let parsed = parse_probe_response(b"<html>just a page</html>");
        assert_eq!(parsed, ProbeInfo::default());
    }
}
