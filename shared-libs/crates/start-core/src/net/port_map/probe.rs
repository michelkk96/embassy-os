//! Active capability probes for a candidate port-map gateway, feeding
//! [`crate::db::model::public::GatewayPortMapCapabilities`]. One connected UDP
//! socket per gateway: a PCP ANNOUNCE answers "is there a PCP server" and
//! "does it carry the Start9 HOSTNAME marker", a NAT-PMP external-address
//! request answers "is there a NAT-PMP server". All best-effort — any error,
//! timeout, or garbled reply is "not supported".

use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::pcp::capability::has_start9_capability;
use super::server::PCP_PORT;

/// Per-request waits: 250ms, then one 1s retry — same fail-fast budget the
/// map attempts use, so a dead gateway costs ~1.25s, not the RFC's minutes.
const PROBE_TIMEOUTS: [Duration; 2] = [Duration::from_millis(250), Duration::from_secs(1)];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GatewayProbe {
    /// A PCP server answered ANNOUNCE with a valid version-2 SUCCESS response.
    pub pcp: bool,
    /// That answer carried the Start9 HOSTNAME capability marker.
    pub pcp_hostname: bool,
    /// A NAT-PMP server answered an external-address request.
    pub nat_pmp: bool,
}

pub async fn probe_gateway(local_ip: IpAddr, gw: IpAddr, scope_id: Option<u32>) -> GatewayProbe {
    let mut res = GatewayProbe::default();
    let Ok(sock) = UdpSocket::bind((local_ip, 0)).await else {
        return res;
    };
    // Bind the gateway-facing source IP (as the map path does) so the probe
    // egresses the right interface — e.g. the WireGuard tunnel to a StartTunnel
    // gateway — and the reply routes back to us. A link-local gateway needs
    // the interface zone/scope id to connect.
    let dst = match gw {
        IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, PCP_PORT)),
        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, PCP_PORT, 0, scope_id.unwrap_or(0))),
    };
    if sock.connect(dst).await.is_err() {
        return res;
    }

    // Bare 24-byte PCP header: version 2, opcode 0 (ANNOUNCE), client IP.
    let mut req = [0u8; 24];
    req[0] = 2;
    let client_octets = match local_ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    req[8..24].copy_from_slice(&client_octets);
    if let Some(resp) = exchange(&sock, &req).await {
        // A valid version-2 SUCCESS response proves PCP; the marker in its
        // option area proves HOSTNAME. Anything else (a version-1
        // UNSUPP_VERSION error, a garbled datagram) only says "something
        // listens" — NAT-PMP is probed separately below.
        if resp.len() >= 24 && resp[0] == 2 && resp[1] == 0x80 && resp[3] == 0 {
            res.pcp = true;
            res.pcp_hostname = has_start9_capability(&resp[24..]);
        }
    }

    // NAT-PMP external-address request: version 0, opcode 0. A PCP-only server
    // answers UNSUPP_VERSION (version != 0) or not at all; a NAT-PMP server
    // answers version 0, response bit set, result code 0.
    if let Some(resp) = exchange(&sock, &[0u8, 0]).await {
        if resp.len() >= 12 && resp[0] == 0 && resp[1] == 0x80 && resp[2..4] == [0, 0] {
            res.nat_pmp = true;
        }
    }

    res
}

/// Send `req` and return the first datagram that arrives, retransmitting once
/// on silence (RFC 6887 §8.3); the caller validates the reply. On a connected
/// socket an ICMP port-unreachable surfaces as an instant recv error, so a
/// refusing gateway fails in milliseconds rather than consuming the budget.
async fn exchange(sock: &UdpSocket, req: &[u8]) -> Option<Vec<u8>> {
    let mut buf = [0u8; 1100];
    for dur in PROBE_TIMEOUTS {
        if sock.send(req).await.is_err() {
            return None;
        }
        if let Ok(Ok(n)) = timeout(dur, sock.recv(&mut buf)).await {
            return Some(buf[..n].to_vec());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_timeouts_fail_fast() {
        assert!(PROBE_TIMEOUTS.iter().sum::<Duration>() <= Duration::from_millis(1300));
    }
}
