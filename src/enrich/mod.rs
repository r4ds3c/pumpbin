//! GeoIP, ASN, DNS whitelist, OSINT adapters (Phase 4 stubs).

/// Offline IP→country lookup stub.
pub fn country_for_ip(_ip: std::net::IpAddr) -> Option<String> {
    None
}
