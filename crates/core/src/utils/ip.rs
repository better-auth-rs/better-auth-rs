//! Resolve forwarded addresses without trusting an arbitrary leftmost hop.

use crate::{AuthRequest, config::IpAddressConfig};
use std::net::IpAddr;

fn address(value: &str) -> Option<IpAddr> {
    match value.parse::<IpAddr>().ok()? {
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => ip.to_ipv4_mapped().map(IpAddr::V4),
        IpAddr::V6(_) if value.contains('.') => {
            let mut segments = [0; 8];
            for (target, group) in segments.iter_mut().zip(dotted_groups(value)) {
                *target = group_number(&group);
            }
            Some(IpAddr::V6(segments.into()))
        }
        ip => Some(ip),
    }
}

// The upstream IPv6 utility preserves non-mapped dotted tails as one group.
fn dotted_groups(value: &str) -> Vec<String> {
    let groups: Vec<_> = if let Some((left, right)) = value.split_once("::") {
        let left: Vec<_> = left.split(':').filter(|group| !group.is_empty()).collect();
        let right: Vec<_> = right.split(':').filter(|group| !group.is_empty()).collect();
        let missing = 8 - left.len() - right.len();
        left.into_iter()
            .chain(std::iter::repeat_n("0", missing))
            .chain(right)
            .collect()
    } else {
        value.split(':').collect()
    };
    groups
        .into_iter()
        .map(|group| format!("{group:0>4}"))
        .collect()
}

fn group_number(group: &str) -> u16 {
    let end = group
        .find(|char: char| !char.is_ascii_hexdigit())
        .unwrap_or(group.len());
    u16::from_str_radix(group.get(..end).unwrap_or(""), 16).unwrap_or(0)
}

fn network(value: &str) -> Option<(IpAddr, u32)> {
    let (ip, prefix) = value
        .rsplit_once('/')
        .map_or((value, None), |(ip, bits)| (ip, Some(bits)));
    let ip = address(ip)?;
    let width = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse().ok()?
        }
        Some(_) => return None,
        None => width,
    };
    (prefix <= width).then_some((ip, prefix))
}

fn contains((network, prefix): (IpAddr, u32), candidate: IpAddr) -> bool {
    match (network, candidate) {
        (IpAddr::V4(network), IpAddr::V4(candidate)) => {
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            u32::from(network) & mask == u32::from(candidate) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(candidate)) => {
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            u128::from(network) & mask == u128::from(candidate) & mask
        }
        _ => false,
    }
}

fn normalize(ip: IpAddr, original: &str, subnet: f64) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(_) if original.contains('.') => {
            let mut bits = if subnet < 128.0 {
                subnet.floor().max(0.0) as u32
            } else {
                128
            };
            dotted_groups(original)
                .into_iter()
                .map(|group| {
                    if bits >= 16 {
                        bits -= 16;
                        group
                    } else {
                        let mask = u16::MAX.checked_shl(16 - bits).unwrap_or(0);
                        bits = 0;
                        format!("{:04x}", group_number(&group) & mask)
                    }
                })
                .collect::<Vec<_>>()
                .join(":")
                .to_ascii_lowercase()
        }
        IpAddr::V6(ip) => {
            let bits = if subnet < 128.0 {
                subnet.floor().max(0.0) as u32
            } else {
                128
            };
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            let ip = std::net::Ipv6Addr::from(u128::from(ip) & mask);
            ip.segments()
                .iter()
                .map(|segment| format!("{segment:04x}"))
                .collect::<Vec<_>>()
                .join(":")
        }
    }
}

impl IpAddressConfig {
    /// Log invalid proxy entries. Invalid entries never become trusted networks.
    pub fn warn_invalid_proxies(&self) {
        let invalid: Vec<_> = self
            .trusted_proxies
            .iter()
            .filter(|entry| network(entry).is_none())
            .collect();
        if !invalid.is_empty() {
            crate::observability::logger::current().warn("Ignoring invalid advanced.ipAddress.trustedProxies entries; each entry must be an IP address or CIDR range", &[crate::observability::LogArgument::Value(&serde_json::json!(invalid))]);
        }
    }

    /// Resolve one forwarded header, excluding configured trusted proxies.
    pub fn resolve_header(&self, value: &str) -> Option<String> {
        let mut hops = value
            .split(',')
            .map(str::trim)
            .filter(|hop| !hop.is_empty());
        let trusted: Vec<_> = self
            .trusted_proxies
            .iter()
            .filter_map(|value| network(value))
            .collect();
        let (ip, original) = if trusted.is_empty() {
            let original = hops.next()?;
            let ip = address(original)?;
            if hops.next().is_some() {
                return None;
            }
            (ip, original)
        } else {
            let mut selected = None;
            for hop in hops.rev() {
                let ip = address(hop)?;
                if !trusted.iter().any(|network| contains(*network, ip)) {
                    selected = Some((ip, hop));
                    break;
                }
            }
            selected?
        };
        Some(normalize(ip, original, self.ipv6_subnet))
    }

    /// Resolve configured headers, with the upstream dev/test localhost fallback.
    pub fn resolve(&self, request: &AuthRequest) -> Option<String> {
        if self.disable_ip_tracking() {
            return None;
        }
        for name in self.headers() {
            if let Some((_, value)) = request
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                && let Some(ip) = self.resolve_header(value)
            {
                return Some(ip);
            }
        }
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();
        let test = std::env::var("TEST").is_ok_and(|value| !value.is_empty() && value != "false");
        (test || matches!(node_env.as_str(), "test" | "dev" | "development"))
            .then(|| "127.0.0.1".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_chains_require_trusted_hops_and_normalize_addresses() {
        let mut config = IpAddressConfig::default();
        assert_eq!(config.resolve_header("203.0.113.7, 10.0.0.1"), None);
        assert_eq!(config.resolve_header("unknown"), None);
        config.trusted_proxies = vec!["10.0.0.0/8".into(), "invalid/24".into()];
        assert_eq!(
            config.resolve_header("192.0.2.99, 203.0.113.7, 10.0.0.1"),
            Some("203.0.113.7".into())
        );
        assert_eq!(
            config.resolve_header("203.0.113.7, invalid, 10.0.0.1"),
            None
        );
        assert_eq!(config.resolve_header("10.0.0.1"), None);
        assert_eq!(
            config.resolve_header("::ffff:203.0.113.7, 10.0.0.1"),
            Some("203.0.113.7".into())
        );
        assert_eq!(
            config.resolve_header("2001:DB8:abcd:1234:5678::1"),
            Some("2001:0db8:abcd:1234:0000:0000:0000:0000".into())
        );
        config.ipv6_subnet = 60.9;
        assert_eq!(
            config.resolve_header("2001:db8:abcd:1234::1"),
            Some("2001:0db8:abcd:1230:0000:0000:0000:0000".into())
        );
        config.trusted_proxies = vec!["::ffff:10.0.0.0/8".into(), "::ffff:10.0.0.0/128".into()];
        assert_eq!(
            config.resolve_header("203.0.113.7, ::ffff:a00:1"),
            Some("203.0.113.7".into())
        );
    }
}
