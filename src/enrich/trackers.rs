//! Advertisement / tracker domain heuristics.

const TRACKER_SUFFIXES: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "scorecardresearch.com",
    "adservice.google.com",
    "facebook.net",
    "fbcdn.net",
    "advertising.com",
    "adnxs.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "hotjar.com",
    "mixpanel.com",
    "segment.io",
    "sentry.io",
];

const TRACKER_LABELS: &[&str] = &["ads", "adserver", "tracker", "pixel", "beacon", "analytics"];

pub fn is_tracker_or_ad(name: &str) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    for s in TRACKER_SUFFIXES {
        if n == *s || n.ends_with(&format!(".{s}")) {
            return true;
        }
    }
    for label in n.split('.') {
        if TRACKER_LABELS.contains(&label) {
            return true;
        }
    }
    false
}
