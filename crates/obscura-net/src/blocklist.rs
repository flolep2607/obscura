
use std::collections::HashSet;
use std::sync::OnceLock;

const PGL_LIST: &str = include_str!("pgl_domains.txt");

fn blocklist() -> &'static HashSet<&'static str> {
    static BLOCKLIST: OnceLock<HashSet<&str>> = OnceLock::new();
    BLOCKLIST.get_or_init(|| {
        let mut set = HashSet::with_capacity(4000);
        for line in PGL_LIST.lines() {
            let domain = line.trim();
            if !domain.is_empty() && !domain.starts_with('#') {
                set.insert(domain);
            }
        }
        for domain in EXTRA_DOMAINS {
            set.insert(*domain);
        }
        set
    })
}

pub fn is_blocked(host: &str) -> bool {
    let bl = blocklist();

    if bl.contains(host) {
        return true;
    }

    let mut domain = host;
    while let Some(pos) = domain.find('.') {
        domain = &domain[pos + 1..];
        if bl.contains(domain) {
            return true;
        }
    }

    false
}

/// Telemetry and beacon endpoints the Peter Lowe list misses, seen on retail product pages (2026-11). They
/// only receive events: a page's content never depends on them, and each one cost a TCP+TLS connection per page, up
/// to 46 at once for the Bazaarvoice beacon. Review and widget hosts (apps.bazaarvoice.com, yotpo) are not here:
/// they put text in the page. Dynatrace is not here either: blocking its RUM agent made several retail
/// pages run twice the requests and take twice as long (bisected 2026-11-05), so a "beacon" is not always
/// safe to drop. Check each addition against a before/after page load.
static EXTRA_DOMAINS: &[&str] = &[
    "network-a.bazaarvoice.com",
    "monorail-edge.shopifysvc.com",
    "otlp-http-production.shopifysvc.com",
    "riskified.com",
    "analytics.org.coveo.com",
    "cquotient.com",
    "attraqt.io",
    "pixels.spotify.com",
    "c360a.salesforce.com",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(is_blocked("google-analytics.com"));
        assert!(is_blocked("doubleclick.net"));
    }

    #[test]
    fn test_subdomain_match() {
        assert!(is_blocked("www.google-analytics.com"));
        assert!(is_blocked("ssl.google-analytics.com"));
    }

    #[test]
    fn test_not_blocked() {
        assert!(!is_blocked("google.com"));
        assert!(!is_blocked("example.com"));
        assert!(!is_blocked("github.com"));
    }

    #[test]
    fn test_pgl_domains() {
        assert!(is_blocked("adnxs.com"));
        assert!(is_blocked("criteo.com"));
    }

    #[test]
    fn test_extra_telemetry_domains_are_blocked_but_widgets_are_not() {
        assert!(is_blocked("network-a.bazaarvoice.com"));
        assert!(is_blocked("beacon.riskified.com"));
        assert!(is_blocked("examplestoreprod1.analytics.org.coveo.com"));
        assert!(!is_blocked("apps.bazaarvoice.com"));
        assert!(!is_blocked("cdn.shopify.com"));
    }

    #[test]
    fn test_blocklist_size() {
        assert!(blocklist().len() > 3500);
    }
}
