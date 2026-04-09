//! Local `.fips` name resolution for the browser node.
//!
//! For now this supports only direct `<npub>.fips` names. Resolution is pure
//! computation: `npub -> x-only pubkey -> NodeAddr -> FIPS IPv6`.

use crate::identity;
use crate::ipv6;
use serde::Serialize;

/// Resolved `.fips` name information.
#[derive(Serialize)]
pub struct ResolvedFipsName {
    pub name: String,
    pub npub: String,
    pub node_addr_hex: String,
    pub ipv6: String,
}

/// Extract the label before `.fips`, handling trailing dot and case-insensitive suffixes.
fn extract_fips_label(name: &str) -> Option<&str> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    let lower = trimmed.to_ascii_lowercase();
    if !lower.ends_with(".fips") {
        return None;
    }
    let label_len = trimmed.len().checked_sub(5)?;
    if label_len == 0 {
        return None;
    }
    Some(&trimmed[..label_len])
}

/// Resolve a direct `<npub>.fips` name.
pub fn resolve_fips_query(name: &str) -> Result<ResolvedFipsName, String> {
    let npub = extract_fips_label(name)
        .ok_or_else(|| "name must end with .fips".to_string())?
        .to_string();

    let x_only = identity::decode_npub(&npub)?;
    let node_addr = identity::node_addr_from_x_only(&x_only);
    let ipv6_bytes = ipv6::ipv6_from_node_addr(&node_addr);

    Ok(ResolvedFipsName {
        name: name.to_string(),
        npub,
        node_addr_hex: hex::encode(node_addr),
        ipv6: ipv6::format_ipv6(&ipv6_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn resolves_valid_npub() {
        let identity = Identity::generate();
        let query = format!("{}.fips", identity.npub());
        let resolved = resolve_fips_query(&query).unwrap();
        assert_eq!(resolved.npub, identity.npub());
        assert_eq!(resolved.node_addr_hex, identity.node_addr_hex());
        assert_eq!(
            resolved.ipv6,
            ipv6::format_ipv6(&ipv6::ipv6_from_node_addr(identity.node_addr()))
        );
    }

    #[test]
    fn resolves_trailing_dot() {
        let identity = Identity::generate();
        let query = format!("{}.fips.", identity.npub());
        assert!(resolve_fips_query(&query).is_ok());
    }

    #[test]
    fn resolves_case_insensitive_suffix() {
        let identity = Identity::generate();
        let query = format!("{}.Fips", identity.npub());
        assert!(resolve_fips_query(&query).is_ok());
    }

    #[test]
    fn rejects_missing_suffix() {
        let identity = Identity::generate();
        assert!(resolve_fips_query(&identity.npub()).is_err());
    }

    #[test]
    fn rejects_invalid_npub() {
        assert!(resolve_fips_query("not-a-valid-npub.fips").is_err());
    }

    #[test]
    fn rejects_empty_label() {
        assert!(resolve_fips_query(".fips").is_err());
    }
}
