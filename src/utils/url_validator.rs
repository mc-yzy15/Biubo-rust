use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub enum UrlValidationResult {
    PrivateIp,
    Localhost,
    LinkLocal,
    Reserved,
    DnsResolvesToPrivate,
    InvalidUrl,
}

/// Resolve and validate a proxy target without creating a nested Tokio runtime.
/// Returns the checked DNS addresses so the caller can pin the outbound client
/// to this exact address set and avoid DNS rebinding between validation/connect.
pub async fn resolve_safe_target(url: &str) -> Result<Vec<SocketAddr>, UrlValidationResult> {
    let parsed = parse_http_url(url).map_err(|()| UrlValidationResult::InvalidUrl)?;
    let host = parsed.host_str().ok_or(UrlValidationResult::InvalidUrl)?;

    if is_localhost(host) {
        return Err(UrlValidationResult::Localhost);
    }
    if let Some(ip) = parse_host_ip(host) {
        if matches!(ip, IpAddr::V6(ipv6) if ipv6.is_loopback()) {
            return Err(UrlValidationResult::Localhost);
        }
        if let Some(result) = classify_ip(&ip, false) {
            return Err(result);
        }
        return Ok(Vec::new());
    }

    let port = parsed
        .port_or_known_default()
        .ok_or(UrlValidationResult::InvalidUrl)?;
    let addresses = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    {
        Ok(Ok(addresses)) => addresses,
        Ok(Err(_)) | Err(_) => return Err(UrlValidationResult::InvalidUrl),
    };

    let mut checked_addresses = Vec::new();
    for address in addresses {
        if let Some(result) = classify_ip(&address.ip(), true) {
            return Err(result);
        }
        checked_addresses.push(address);
    }

    if checked_addresses.is_empty() {
        Err(UrlValidationResult::InvalidUrl)
    } else {
        Ok(checked_addresses)
    }
}

fn parse_http_url(url: &str) -> Result<url::Url, ()> {
    let parsed = url::Url::parse(url).map_err(|_| ())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
        return Err(());
    }
    Ok(parsed)
}

fn parse_host_ip(host: &str) -> Option<IpAddr> {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    IpAddr::from_str(host).ok()
}

fn classify_ip(ip: &IpAddr, from_dns: bool) -> Option<UrlValidationResult> {
    if is_private_ip(ip) {
        return Some(if from_dns {
            UrlValidationResult::DnsResolvesToPrivate
        } else {
            UrlValidationResult::PrivateIp
        });
    }
    if is_link_local(ip) {
        return Some(UrlValidationResult::LinkLocal);
    }
    if is_reserved(ip) {
        return Some(UrlValidationResult::Reserved);
    }
    None
}

fn is_localhost(host: &str) -> bool {
    let lower = host.to_lowercase();
    lower == "localhost"
        || lower == "localhost.localdomain"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower == "0.0.0.0"
        || lower == "::"
        || lower == "::1"
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    (octets[0] == 10)
        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 127)
        || (octets[0] == 169 && octets[1] == 254)
}

fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    if let Some(mapped_ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&mapped_ipv4);
    }

    let segments = ip.segments();
    segments[0] == 0xfc00 || segments[0] == 0xfd00 || ip.is_loopback()
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 169 && octets[1] == 254
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            segments[0] == 0xfe80
        }
    }
}

fn is_reserved(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 0
                || (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 18)
                || (octets[0] == 198 && octets[1] == 19)
                || (octets[0] >= 224 && octets[0] <= 239)
                || (octets[0] >= 240)
        }
        IpAddr::V6(ipv6) => ipv6.is_multicast() || *ipv6 == Ipv6Addr::UNSPECIFIED,
    }
}

pub fn is_ip_in_range(ip: &str, cidr: &str) -> bool {
    let target_ip = match IpAddr::from_str(ip) {
        Ok(i) => i,
        Err(_) => return false,
    };

    if cidr.contains('/') {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let network_ip = match IpAddr::from_str(parts[0]) {
            Ok(i) => i,
            Err(_) => return false,
        };

        let prefix_len: u32 = match parts[1].parse() {
            Ok(p) => p,
            Err(_) => return false,
        };

        match (target_ip, network_ip) {
            (IpAddr::V4(target), IpAddr::V4(network)) => {
                is_ipv4_in_subnet(target, network, prefix_len)
            }
            (IpAddr::V6(target), IpAddr::V6(network)) => {
                is_ipv6_in_subnet(target, network, prefix_len)
            }
            _ => false,
        }
    } else {
        match (IpAddr::from_str(cidr), IpAddr::from_str(ip)) {
            (Ok(cidr_ip), Ok(target_ip)) => cidr_ip == target_ip,
            _ => false,
        }
    }
}

fn is_ipv4_in_subnet(target: Ipv4Addr, network: Ipv4Addr, prefix_len: u32) -> bool {
    if prefix_len > 32 {
        return false;
    }

    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };

    let target_bits = u32::from(target);
    let network_bits = u32::from(network);

    (target_bits & mask) == (network_bits & mask)
}

fn is_ipv6_in_subnet(target: Ipv6Addr, network: Ipv6Addr, prefix_len: u32) -> bool {
    if prefix_len > 128 {
        return false;
    }

    let target_bytes = target.octets();
    let network_bytes = network.octets();

    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;

    for i in 0..full_bytes {
        if target_bytes[i] != network_bytes[i] {
            return false;
        }
    }

    if remaining_bits > 0 && full_bytes < 16 {
        let mask = 0xFFu8 << (8 - remaining_bits);
        if (target_bytes[full_bytes] & mask) != (network_bytes[full_bytes] & mask) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validate_private_ip() {
        for url in [
            "http://192.168.1.1/test",
            "http://10.0.0.1/test",
            "http://172.16.0.1/test",
        ] {
            assert_eq!(
                resolve_safe_target(url).await,
                Err(UrlValidationResult::PrivateIp)
            );
        }
    }

    #[tokio::test]
    async fn test_validate_localhost() {
        assert_eq!(
            resolve_safe_target("http://localhost/test").await,
            Err(UrlValidationResult::Localhost)
        );
        assert_eq!(
            resolve_safe_target("http://127.0.0.1/test").await,
            Err(UrlValidationResult::PrivateIp)
        );
        assert_eq!(
            resolve_safe_target("http://0.0.0.0/test").await,
            Err(UrlValidationResult::Localhost)
        );
    }

    #[tokio::test]
    async fn test_validate_public_ip() {
        assert_eq!(
            resolve_safe_target("http://8.8.8.8/test").await,
            Ok(Vec::new())
        );
        assert_eq!(
            resolve_safe_target("https://1.1.1.1/test").await,
            Ok(Vec::new())
        );
    }

    #[tokio::test]
    async fn test_safe_target_classification() {
        assert_eq!(
            resolve_safe_target("https://8.8.8.8/v1").await,
            Ok(Vec::new())
        );
        assert_ne!(
            resolve_safe_target("http://localhost/admin").await,
            Ok(Vec::new())
        );
        assert_ne!(
            resolve_safe_target("http://192.168.1.1/internal").await,
            Ok(Vec::new())
        );
    }

    #[test]
    fn test_validate_rejects_non_http_schemes() {
        assert!(parse_http_url("file:///etc/passwd").is_err());
        assert!(parse_http_url("ftp://8.8.8.8/file").is_err());
    }

    #[tokio::test]
    async fn test_async_validation_runs_inside_existing_runtime() {
        assert_eq!(
            resolve_safe_target("http://127.0.0.1/internal").await,
            Err(UrlValidationResult::PrivateIp)
        );
        assert_eq!(
            resolve_safe_target("http://[::1]/internal").await,
            Err(UrlValidationResult::Localhost)
        );
        assert_eq!(
            resolve_safe_target("http://[::ffff:127.0.0.1]/internal").await,
            Err(UrlValidationResult::PrivateIp)
        );
        assert_eq!(
            resolve_safe_target("file:///etc/passwd").await,
            Err(UrlValidationResult::InvalidUrl)
        );
    }

    #[test]
    fn test_ip_in_range() {
        assert!(is_ip_in_range("192.168.1.100", "192.168.1.0/24"));
        assert!(!is_ip_in_range("192.168.2.100", "192.168.1.0/24"));
        assert!(is_ip_in_range("10.0.0.1", "10.0.0.1"));
        assert!(!is_ip_in_range("10.0.0.5", "10.0.0.1"));
    }
}
