//! Local `.fips` name resolution for the browser node.
//!
//! Supports direct `<npub>.fips` names. Resolution is pure computation:
//! `npub -> x-only pubkey -> NodeAddr -> FIPS IPv6`.
//!
//! Also provides [`handle_dns_packet`] for answering raw DNS wire queries
//! from the VM guest — the browser bridge intercepts UDP port 53 traffic
//! and feeds it here.

use crate::identity;
use crate::ipv6;
use serde::Serialize;
use simple_dns::rdata::{RData, AAAA};
use simple_dns::{Name, Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, CLASS, TYPE};
use std::net::Ipv6Addr;

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

/// Resolve a direct `<npub>.fips` name to structured info.
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

/// Resolve a `.fips` label to an IPv6 address (internal helper).
fn resolve_label_to_ipv6(label: &str) -> Option<Ipv6Addr> {
    let x_only = identity::decode_npub(label).ok()?;
    let node_addr = identity::node_addr_from_x_only(&x_only);
    let ipv6_bytes = ipv6::ipv6_from_node_addr(&node_addr);
    Some(Ipv6Addr::from(ipv6_bytes))
}

/// Handle a raw DNS query packet and produce a raw DNS response.
///
/// Returns `Some(response_bytes)` on success, `None` if the query is
/// unparseable. For `.fips` AAAA queries the response contains the
/// computed IPv6 address. Non-AAAA queries for valid `.fips` names get
/// NOERROR with empty answers; unknown names get NXDOMAIN.
pub fn handle_dns_packet(query_bytes: &[u8]) -> Option<Vec<u8>> {
    let query = Packet::parse(query_bytes).ok()?;
    let question = query.questions.first()?;

    let qname = question.qname.to_string();
    let is_aaaa = matches!(question.qtype, QTYPE::TYPE(TYPE::AAAA));

    let label = extract_fips_label(&qname);

    let mut response = query.into_reply();
    response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);

    if is_aaaa {
        if let Some(label) = label {
            if let Some(ipv6) = resolve_label_to_ipv6(label) {
                let name = Name::new_unchecked(&qname).into_owned();
                let record = ResourceRecord::new(
                    name,
                    CLASS::IN,
                    300, // 5 minute TTL
                    RData::AAAA(AAAA::from(ipv6)),
                );
                response.answers.push(record);
                return response.build_bytes_vec_compressed().ok();
            }
        }
    }

    // Non-AAAA for a resolvable .fips name: NOERROR with empty answers
    if !is_aaaa && label.and_then(|l| resolve_label_to_ipv6(l)).is_some() {
        return response.build_bytes_vec_compressed().ok();
    }

    // Not a .fips name or unresolvable: NXDOMAIN
    *response.rcode_mut() = RCODE::NameError;
    response.build_bytes_vec_compressed().ok()
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

    // --- handle_dns_packet tests ---

    fn build_test_query(name: &str, rtype: TYPE) -> Vec<u8> {
        use simple_dns::Question;

        let mut packet = Packet::new_query(0x1234);
        let question = Question::new(
            Name::new_unchecked(name).into_owned(),
            QTYPE::TYPE(rtype),
            simple_dns::QCLASS::CLASS(CLASS::IN),
            false,
        );
        packet.questions.push(question);
        packet.build_bytes_vec().unwrap()
    }

    #[test]
    fn dns_packet_aaaa_resolves() {
        let identity = Identity::generate();
        let query_name = format!("{}.fips", identity.npub());
        let query_bytes = build_test_query(&query_name, TYPE::AAAA);

        let response_bytes = handle_dns_packet(&query_bytes).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.answers.len(), 1);

        let expected_ipv6_bytes = ipv6::ipv6_from_node_addr(identity.node_addr());
        let expected_ipv6 = Ipv6Addr::from(expected_ipv6_bytes);
        if let RData::AAAA(aaaa) = &response.answers[0].rdata {
            assert_eq!(Ipv6Addr::from(aaaa.address), expected_ipv6);
        } else {
            panic!("expected AAAA record");
        }
    }

    #[test]
    fn dns_packet_nxdomain_for_unknown() {
        let query_bytes = build_test_query("unknown.fips", TYPE::AAAA);
        let response_bytes = handle_dns_packet(&query_bytes).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.rcode(), RCODE::NameError);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn dns_packet_noerror_for_a_query() {
        let identity = Identity::generate();
        let query_name = format!("{}.fips", identity.npub());
        let query_bytes = build_test_query(&query_name, TYPE::A);

        let response_bytes = handle_dns_packet(&query_bytes).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();
        assert_eq!(response.rcode(), RCODE::NoError);
        assert!(response.answers.is_empty());
    }
}
