//! Bounded endpoint-only service metadata. No payloads, application identity or full-path claims.
use crate::{
    config::PeerId,
    packet::{PacketType, ZCPacket},
};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MAX_FLOWS: usize = 4096;
const IDLE: Duration = Duration::from_secs(60);
const MAX_ROWS: usize = 256;

/// One validated interpretation shared with ACL extraction. Missing transport headers never yield ports.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ParsedPacket<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: u8,
    pub transport_payload: &'a [u8],
    pub non_initial_fragment: bool,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u8>,
    pub ip_bytes: usize,
    pub ports_unavailable: Option<&'static str>,
}

pub(crate) fn parse_ip_packet(bytes: &[u8]) -> Option<ParsedPacket<'_>> {
    let (src_ip, dst_ip, mut protocol, mut offset, end, mut non_initial) = match bytes.first()? >> 4
    {
        4 => {
            if bytes.len() < 20 {
                return None;
            }
            let ihl = usize::from(bytes[0] & 15) * 4;
            let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if ihl < 20 || total < ihl || ihl > bytes.len() || total > bytes.len() {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                bytes[9],
                ihl,
                total,
                u16::from_be_bytes([bytes[6], bytes[7]]) & 0x1fff != 0,
            )
        }
        6 => {
            if bytes.len() < 40 {
                return None;
            }
            let len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            // IPv6 jumbograms need Hop-by-Hop Jumbo Payload validation; deliberately unsupported.
            if len == 0 || len + 40 > bytes.len() {
                return None;
            }
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?)),
                bytes[6],
                40,
                len + 40,
                false,
            )
        }
        _ => return None,
    };
    let mut malformed_extension = false;
    let mut fragmented =
        bytes[0] >> 4 == 4 && u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0;
    if bytes[0] >> 4 == 6 {
        let mut fragments = 0;
        for depth in 0..=16 {
            if !matches!(protocol, 0 | 43 | 44 | 51 | 60) || non_initial {
                break;
            }
            if depth == 16 {
                malformed_extension = true;
                break;
            }
            let Some(h) = bytes.get(offset..end) else {
                return None;
            };
            let needed = match protocol {
                44 => {
                    fragments += 1;
                    if fragments > 1 || h.len() < 8 {
                        malformed_extension = true;
                        break;
                    }
                    non_initial = u16::from_be_bytes([h[2], h[3]]) & 0xfff8 != 0;
                    fragmented = true;
                    8
                }
                51 => {
                    if h.len() < 2 {
                        malformed_extension = true;
                        break;
                    }
                    (usize::from(h[1]) + 2) * 4
                }
                _ => {
                    if h.len() < 2 {
                        malformed_extension = true;
                        break;
                    }
                    (usize::from(h[1]) + 1) * 8
                }
            };
            if needed > h.len() {
                malformed_extension = true;
                break;
            }
            protocol = h[0];
            offset += needed;
        }
    }
    let transport = bytes.get(offset..end)?;
    let mut parsed = ParsedPacket {
        src_ip,
        dst_ip,
        protocol,
        transport_payload: transport,
        non_initial_fragment: non_initial,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
        ip_bytes: end,
        ports_unavailable: None,
    };
    if malformed_extension {
        parsed.protocol = 255;
        parsed.transport_payload = &[];
        parsed.ports_unavailable = Some("malformed_or_excessive_ipv6_extensions");
    } else if non_initial {
        parsed.transport_payload = &[];
        parsed.ports_unavailable = Some("non_initial_fragment");
    } else if protocol == 6 {
        if transport.len() < 20 {
            parsed.ports_unavailable = Some("truncated_tcp_header");
        } else {
            let len = usize::from(transport[12] >> 4) * 4;
            if len < 20 || len > transport.len() {
                parsed.ports_unavailable = Some("invalid_tcp_header_length");
            } else {
                parsed.src_port = Some(u16::from_be_bytes([transport[0], transport[1]]));
                parsed.dst_port = Some(u16::from_be_bytes([transport[2], transport[3]]));
                parsed.tcp_flags = Some(transport[13]);
            }
        }
    } else if protocol == 17 {
        if transport.len() < 8 {
            parsed.ports_unavailable = Some("truncated_udp_header");
        } else {
            let len = usize::from(u16::from_be_bytes([transport[4], transport[5]]));
            if len < 8 || (len > transport.len() && !fragmented) {
                parsed.ports_unavailable = Some("invalid_udp_length");
            } else {
                parsed.src_port = Some(u16::from_be_bytes([transport[0], transport[1]]));
                parsed.dst_port = Some(u16::from_be_bytes([transport[2], transport[3]]));
            }
        }
    } else {
        parsed.ports_unavailable = Some("not_tcp_or_udp");
    }
    Some(parsed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
pub struct FlowEndpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct FlowKey {
    a: FlowEndpoint,
    b: FlowEndpoint,
    protocol: u8,
    reason: Option<&'static str>,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Outbound,
    Inbound,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct FlowCounters {
    pub outbound_packets: u64,
    pub outbound_ip_bytes: u64,
    pub inbound_packets: u64,
    pub inbound_ip_bytes: u64,
    pub acl_denied_packets: u64,
    pub acl_denied_ip_bytes: u64,
    pub tcp_flags_observed: u8,
}
#[derive(Clone, Debug, Serialize)]
pub struct ServiceFlow {
    pub flow_id: uuid::Uuid,
    pub endpoint_a: FlowEndpoint,
    pub endpoint_b: FlowEndpoint,
    pub ip_version: u8,
    pub ip_protocol: u8,
    pub ports_unavailable: Option<&'static str>,
    pub first_observed_unix_ms: u64,
    pub last_observed_unix_ms: u64,
    pub elapsed_ms: u64,
    pub a_to_b: FlowCounters,
    pub b_to_a: FlowCounters,
    pub last_direction: FlowDirection,
    pub last_remote_peer_id: Option<PeerId>,
    pub transport_evidence: &'static str,
    pub last_observation_sequence: u64,
    /// An actual drop at the endpoint ACL hook, not an inferred network failure.
    pub acl_drop_observed: bool,
}
struct Entry {
    record: ServiceFlow,
    first: Instant,
    last: Instant,
}
#[derive(Clone, Debug, Serialize)]
pub struct ReceivedAttachment {
    pub peer_id: PeerId,
    pub connection_id: uuid::Uuid,
    pub packets: u64,
    pub overlay_frame_bytes: u64,
    pub first_observed_unix_ms: u64,
    pub last_observed_unix_ms: u64,
    pub evidence: &'static str,
    #[serde(skip)]
    last_seen: Instant,
}
struct State {
    flows: HashMap<FlowKey, Entry>,
    attachments: HashMap<(PeerId, uuid::Uuid), ReceivedAttachment>,
    last_cleanup: Instant,
    sequence: u64,
    evicted: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct ServiceFlowSnapshot {
    pub boot_id: uuid::Uuid,
    pub sequence: u64,
    pub observed_unix_ms: u64,
    pub expires_after_ms: u64,
    pub tracked_flows: usize,
    pub returned_flows: usize,
    pub truncated: bool,
    pub evicted_idle_flows: u64,
    pub dropped_capacity_samples: u64,
    pub dropped_contention_samples: u64,
    pub malformed_packets: u64,
    pub busy: bool,
    pub byte_semantics: &'static str,
    pub full_path_status: &'static str,
    pub received_attachments: Vec<ReceivedAttachment>,
    pub attachment_capacity_drops: u64,
    pub tracked_attachments: usize,
    pub returned_attachments: usize,
    pub attachments_truncated: bool,
    pub flows: Vec<ServiceFlow>,
}
pub struct ServiceFlowCollector {
    boot_id: uuid::Uuid,
    state: Mutex<State>,
    capacity_drops: AtomicU64,
    contention_drops: AtomicU64,
    malformed: AtomicU64,
    attachment_drops: AtomicU64,
}
impl Default for ServiceFlowCollector {
    fn default() -> Self {
        Self::new()
    }
}
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
impl ServiceFlowCollector {
    pub fn new() -> Self {
        Self {
            boot_id: uuid::Uuid::new_v4(),
            state: Mutex::new(State {
                flows: HashMap::new(),
                attachments: HashMap::new(),
                last_cleanup: Instant::now(),
                sequence: 0,
                evicted: 0,
            }),
            capacity_drops: AtomicU64::new(0),
            contention_drops: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            attachment_drops: AtomicU64::new(0),
        }
    }
    /// Actual ingress connection, including encrypted transit. Never interpreted as an end-to-end path.
    pub(crate) fn observe_ingress(
        &self,
        peer_id: PeerId,
        connection_id: uuid::Uuid,
        overlay_frame_bytes: usize,
    ) {
        let Ok(mut state) = self.state.try_lock() else {
            self.contention_drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let key = (peer_id, connection_id);
        if !state.attachments.contains_key(&key) && state.attachments.len() >= 128 {
            self.attachment_drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let stamp = unix_ms();
        let e = state.attachments.entry(key).or_insert(ReceivedAttachment {
            peer_id,
            connection_id,
            packets: 0,
            overlay_frame_bytes: 0,
            first_observed_unix_ms: stamp,
            last_observed_unix_ms: stamp,
            evidence: "actual_local_ingress_connection_full_path_unverified",
            last_seen: Instant::now(),
        });
        e.packets = e.packets.saturating_add(1);
        e.overlay_frame_bytes = e
            .overlay_frame_bytes
            .saturating_add(overlay_frame_bytes as u64);
        e.last_observed_unix_ms = stamp;
        e.last_seen = Instant::now();
    }
    pub(crate) fn observe_packet(
        &self,
        packet: &ZCPacket,
        direction: FlowDirection,
        remote: Option<PeerId>,
        acl_denied: bool,
    ) {
        if packet.peer_manager_header().is_none_or(|h| {
            h.packet_type != PacketType::Data as u8 || h.is_encrypted() || h.is_compressed()
        }) {
            return;
        }
        self.observe_ip(packet.payload(), direction, remote, acl_denied);
    }
    pub fn observe_ip(
        &self,
        bytes: &[u8],
        direction: FlowDirection,
        remote: Option<PeerId>,
        acl_denied: bool,
    ) {
        let Some(p) = parse_ip_packet(bytes) else {
            self.malformed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let src = FlowEndpoint {
            ip: p.src_ip,
            port: p.src_port,
        };
        let dst = FlowEndpoint {
            ip: p.dst_ip,
            port: p.dst_port,
        };
        let forward = src <= dst;
        let key = FlowKey {
            a: if forward { src } else { dst },
            b: if forward { dst } else { src },
            protocol: p.protocol,
            reason: p.ports_unavailable,
        };
        let Ok(mut state) = self.state.try_lock() else {
            self.contention_drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let now = Instant::now();
        Self::cleanup(&mut state, now, false);
        if !state.flows.contains_key(&key) && state.flows.len() >= MAX_FLOWS {
            self.capacity_drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        state.sequence = state.sequence.saturating_add(1);
        let sequence = state.sequence;
        let stamp = unix_ms();
        let e = state.flows.entry(key).or_insert_with(|| Entry {
            record: ServiceFlow {
                flow_id: uuid::Uuid::new_v4(),
                endpoint_a: key.a,
                endpoint_b: key.b,
                ip_version: if p.src_ip.is_ipv4() { 4 } else { 6 },
                ip_protocol: p.protocol,
                ports_unavailable: p.ports_unavailable,
                first_observed_unix_ms: stamp,
                last_observed_unix_ms: stamp,
                elapsed_ms: 0,
                a_to_b: FlowCounters::default(),
                b_to_a: FlowCounters::default(),
                last_direction: direction,
                last_remote_peer_id: remote,
                transport_evidence: "midstream_observed",
                last_observation_sequence: sequence,
                acl_drop_observed: false,
            },
            first: now,
            last: now,
        });
        e.last = now;
        e.record.last_observed_unix_ms = stamp;
        e.record.elapsed_ms = now
            .duration_since(e.first)
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        e.record.last_direction = direction;
        e.record.last_remote_peer_id = remote;
        e.record.last_observation_sequence = sequence;
        let c = if forward {
            &mut e.record.a_to_b
        } else {
            &mut e.record.b_to_a
        };
        let size = p.ip_bytes as u64;
        if acl_denied {
            c.acl_denied_packets = c.acl_denied_packets.saturating_add(1);
            c.acl_denied_ip_bytes = c.acl_denied_ip_bytes.saturating_add(size);
            e.record.acl_drop_observed = true;
        } else {
            match direction {
                FlowDirection::Outbound => {
                    c.outbound_packets = c.outbound_packets.saturating_add(1);
                    c.outbound_ip_bytes = c.outbound_ip_bytes.saturating_add(size)
                }
                FlowDirection::Inbound => {
                    c.inbound_packets = c.inbound_packets.saturating_add(1);
                    c.inbound_ip_bytes = c.inbound_ip_bytes.saturating_add(size)
                }
            };
            c.tcp_flags_observed |= p.tcp_flags.unwrap_or(0);
        }
        let a = e.record.a_to_b;
        let b = e.record.b_to_a;
        let flags = a.tcp_flags_observed | b.tcp_flags_observed;
        e.record.transport_evidence = if p.protocol == 6 {
            if flags & 4 != 0 {
                "reset_observed"
            } else if flags & 1 != 0 {
                "fin_observed"
            } else if flags & 2 != 0 {
                "syn_observed_no_login_claim"
            } else {
                "midstream_observed"
            }
        } else if p.protocol == 17 {
            if (a.outbound_packets + a.inbound_packets) > 0
                && (b.outbound_packets + b.inbound_packets) > 0
            {
                "bidirectional_udp_observed"
            } else {
                "unidirectional_udp_observed"
            }
        } else {
            "ip_packet_observed"
        };
    }
    fn cleanup(state: &mut State, now: Instant, force: bool) {
        if force || now.duration_since(state.last_cleanup) >= Duration::from_secs(1) {
            let before = state.flows.len();
            state.flows.retain(|_, v| now.duration_since(v.last) < IDLE);
            state
                .attachments
                .retain(|_, v| now.duration_since(v.last_seen) < IDLE);
            state.evicted = state
                .evicted
                .saturating_add((before - state.flows.len()) as u64);
            state.last_cleanup = now;
        }
    }
    pub fn snapshot(&self, limit: usize) -> ServiceFlowSnapshot {
        self.snapshot_since(limit, 0)
    }
    pub fn snapshot_since(&self, limit: usize, after_sequence: u64) -> ServiceFlowSnapshot {
        let mut out = ServiceFlowSnapshot {
            boot_id: self.boot_id,
            sequence: 0,
            observed_unix_ms: unix_ms(),
            expires_after_ms: IDLE.as_millis() as u64,
            tracked_flows: 0,
            returned_flows: 0,
            truncated: false,
            evicted_idle_flows: 0,
            dropped_capacity_samples: self.capacity_drops.load(Ordering::Relaxed),
            dropped_contention_samples: self.contention_drops.load(Ordering::Relaxed),
            malformed_packets: self.malformed.load(Ordering::Relaxed),
            busy: false,
            byte_semantics: "inner_ip_bytes_including_headers_and_retransmissions_not_application_payload_or_wire_bytes",
            full_path_status: "unknown_endpoint_observations_only",
            received_attachments: Vec::new(),
            attachment_capacity_drops: self.attachment_drops.load(Ordering::Relaxed),
            tracked_attachments: 0,
            returned_attachments: 0,
            attachments_truncated: false,
            flows: Vec::new(),
        };
        let Ok(mut state) = self.state.try_lock() else {
            out.busy = true;
            return out;
        };
        Self::cleanup(&mut state, Instant::now(), true);
        out.sequence = state.sequence;
        out.evicted_idle_flows = state.evicted;
        out.tracked_flows = state.flows.len();
        out.received_attachments = state
            .attachments
            .values()
            .take(limit.min(16))
            .cloned()
            .collect();
        out.tracked_attachments = state.attachments.len();
        out.returned_attachments = out.received_attachments.len();
        out.attachments_truncated = out.tracked_attachments > out.returned_attachments;
        // Oldest changed observations first: a bounded batch must not move
        // its cursor past unreported rows. Deduplicate by boot_id + sequence.
        let mut entries = state
            .flows
            .values()
            .filter(|v| v.record.last_observation_sequence > after_sequence)
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|v| v.record.last_observation_sequence);
        out.flows = entries
            .into_iter()
            .take(limit.min(MAX_ROWS))
            .map(|v| v.record.clone())
            .collect();
        out.returned_flows = out.flows.len();
        out.truncated = state
            .flows
            .values()
            .filter(|v| v.record.last_observation_sequence > after_sequence)
            .count()
            > out.returned_flows;
        if limit > 0 && out.truncated {
            out.sequence = out
                .flows
                .last()
                .map_or(after_sequence, |v| v.last_observation_sequence);
        }
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn ipv4(protocol: u8, sport: u16, dport: u16) -> Vec<u8> {
        let len = if protocol == 6 { 40 } else { 28 };
        let mut b = vec![0; len];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        b[9] = protocol;
        b[12..16].copy_from_slice(&[10, 0, 0, 1]);
        b[16..20].copy_from_slice(&[10, 0, 0, 2]);
        b[20..22].copy_from_slice(&sport.to_be_bytes());
        b[22..24].copy_from_slice(&dport.to_be_bytes());
        if protocol == 6 {
            b[32] = 0x50;
            b[33] = 2;
        } else {
            b[24..26].copy_from_slice(&8u16.to_be_bytes());
        }
        b
    }
    #[test]
    fn bounded_delta_cursor_does_not_skip_unreported_rows() {
        let c = ServiceFlowCollector::new();
        for port in 1..=9 {
            c.observe_ip(
                &ipv4(6, 45000, port),
                FlowDirection::Outbound,
                Some(2),
                false,
            );
        }
        let mut cursor = 0;
        let mut ids = std::collections::HashSet::new();
        for expected in [4, 4, 1] {
            let batch = c.snapshot_since(4, cursor);
            assert_eq!(batch.flows.len(), expected);
            assert!(batch.sequence > cursor);
            cursor = batch.sequence;
            for flow in batch.flows {
                assert!(ids.insert(flow.flow_id));
            }
        }
        assert_eq!(ids.len(), 9);
        assert!(c.snapshot_since(4, cursor).flows.is_empty());
    }
    #[test]
    fn tcp_udp_and_reverse_counts() {
        for protocol in [6, 17] {
            let c = ServiceFlowCollector::new();
            let mut b = ipv4(protocol, 45000, if protocol == 6 { 22 } else { 3389 });
            c.observe_ip(&b, FlowDirection::Outbound, Some(2), false);
            b[12..16].copy_from_slice(&[10, 0, 0, 2]);
            b[16..20].copy_from_slice(&[10, 0, 0, 1]);
            b[20..22].copy_from_slice(&(if protocol == 6 { 22u16 } else { 3389 }).to_be_bytes());
            b[22..24].copy_from_slice(&45000u16.to_be_bytes());
            c.observe_ip(&b, FlowDirection::Inbound, Some(2), false);
            let s = c.snapshot(256);
            assert_eq!(s.tracked_flows, 1);
            assert_eq!(s.flows[0].a_to_b.outbound_packets, 1);
            assert_eq!(s.flows[0].b_to_a.inbound_packets, 1);
            assert_eq!(s.flows[0].a_to_b.outbound_ip_bytes, b.len() as u64);
            assert!(!s.flows[0].acl_drop_observed);
        }
    }
    #[test]
    fn fragments_do_not_invent_ports() {
        let mut b = ipv4(6, 22, 1234);
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        let p = parse_ip_packet(&b).unwrap();
        assert_eq!(p.src_port, None);
        assert_eq!(p.ports_unavailable, Some("non_initial_fragment"));
    }
    #[test]
    fn malformed_lengths_never_panic_or_invent_ports() {
        let valid = ipv4(6, 1234, 22);
        for len in 0..valid.len() {
            assert!(parse_ip_packet(&valid[..len]).is_none());
        }
        let mut b = valid;
        b[0] = 0x41;
        assert!(parse_ip_packet(&b).is_none());
        b[0] = 0x45;
        b[32] = 0x10;
        assert_eq!(parse_ip_packet(&b).unwrap().src_port, None);
    }
    #[test]
    fn ipv6_extension_and_tail() {
        let mut b = vec![0u8; 68];
        b[0] = 0x60;
        b[4..6].copy_from_slice(&28u16.to_be_bytes());
        b[6] = 44;
        b[23] = 1;
        b[39] = 2;
        b[40] = 6;
        b[48..50].copy_from_slice(&1234u16.to_be_bytes());
        b[50..52].copy_from_slice(&22u16.to_be_bytes());
        b[60] = 0x50;
        assert_eq!(parse_ip_packet(&b).unwrap().dst_port, Some(22));
        b[42..44].copy_from_slice(&8u16.to_be_bytes());
        assert!(parse_ip_packet(&b).unwrap().src_port.is_none());
        b[4..6].copy_from_slice(&29u16.to_be_bytes());
        assert!(parse_ip_packet(&b).is_none());
    }
    #[test]
    fn only_explicit_denial_counts_drop() {
        let c = ServiceFlowCollector::new();
        let b = ipv4(6, 2000, 22);
        c.observe_ip(&b, FlowDirection::Outbound, None, true);
        let s = c.snapshot(1);
        assert_eq!(s.flows[0].a_to_b.acl_denied_packets, 1);
        assert_eq!(s.flows[0].a_to_b.outbound_packets, 0);
        assert!(s.flows[0].acl_drop_observed);
    }
    #[test]
    fn capacity_idle_and_report_bounds() {
        let c = ServiceFlowCollector::new();
        for n in 0..MAX_FLOWS + 10 {
            c.observe_ip(
                &ipv4(17, n as u16, 3389),
                FlowDirection::Outbound,
                None,
                false,
            );
        }
        let s = c.snapshot(1000);
        assert_eq!(s.tracked_flows, MAX_FLOWS);
        assert_eq!(s.returned_flows, MAX_ROWS);
        assert_eq!(s.dropped_capacity_samples, 10);
        assert!(s.truncated);
        {
            let mut state = c.state.lock().unwrap();
            for e in state.flows.values_mut() {
                e.last = Instant::now() - Duration::from_secs(61);
            }
        }
        let s = c.snapshot(1);
        assert_eq!(s.tracked_flows, 0);
        assert_eq!(s.evicted_idle_flows, MAX_FLOWS as u64);
    }
    #[test]
    fn contention_does_not_block_forwarding() {
        let c = ServiceFlowCollector::new();
        let _lock = c.state.lock().unwrap();
        c.observe_ip(&ipv4(6, 123, 22), FlowDirection::Outbound, None, false);
        assert_eq!(c.contention_drops.load(Ordering::Relaxed), 1);
        assert!(c.snapshot(1).busy);
    }
}
