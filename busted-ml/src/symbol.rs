use busted_types::NetworkEvent;

/// Compact symbolic representation of a network event.
/// 6 kinds x 6 sizes x 5 ports = 180 possible symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Symbol {
    /// Connect=0, Send=1, Recv=2, Close=3, Dns=4, Unknown=5
    pub kind: u8,
    /// 0=zero, 1=tiny(<128), 2=small(<1K), 3=med(<8K), 4=large(<64K), 5=huge
    pub size_bucket: u8,
    /// 0=443, 1=80, 2=53, 3=other-well-known(<1024), 4=ephemeral
    pub port_class: u8,
}

const NUM_KINDS: u16 = 6;
const NUM_SIZES: u16 = 6;
const NUM_PORTS: u16 = 5;

/// Total number of distinct symbols.
pub const SYMBOL_SPACE: usize = (NUM_KINDS * NUM_SIZES * NUM_PORTS) as usize; // 180

impl Symbol {
    pub fn from_network_event(event: &NetworkEvent) -> Self {
        let kind = match event.event_type {
            1 => 0, // TCP_CONNECT
            2 => 1, // DATA_SENT
            3 => 2, // DATA_RECEIVED
            4 => 3, // CONNECTION_CLOSED
            5 => 4, // DNS_QUERY
            _ => 5, // Unknown
        };

        let size_bucket = match event.bytes {
            0 => 0,
            1..=127 => 1,
            128..=1023 => 2,
            1024..=8191 => 3,
            8192..=65535 => 4,
            _ => 5,
        };

        let port_class = match event.dport {
            443 => 0,
            80 => 1,
            53 => 2,
            0..=1023 => 3,
            _ => 4,
        };

        Symbol {
            kind,
            size_bucket,
            port_class,
        }
    }

    /// Encode symbol as a unique index in [0, 180).
    pub fn encode(&self) -> u16 {
        self.kind as u16 * NUM_SIZES * NUM_PORTS
            + self.size_bucket as u16 * NUM_PORTS
            + self.port_class as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busted_types::NetworkEvent;

    fn make_event(event_type: u8, bytes: u64, dport: u16) -> NetworkEvent {
        let mut e = NetworkEvent::new();
        e.event_type = event_type;
        e.bytes = bytes;
        e.dport = dport;
        e
    }

    // -- Event type → kind mapping --

    #[test]
    fn kind_tcp_connect() {
        let s = Symbol::from_network_event(&make_event(1, 0, 443));
        assert_eq!(s.kind, 0);
    }

    #[test]
    fn kind_data_sent() {
        let s = Symbol::from_network_event(&make_event(2, 0, 443));
        assert_eq!(s.kind, 1);
    }

    #[test]
    fn kind_data_received() {
        let s = Symbol::from_network_event(&make_event(3, 0, 443));
        assert_eq!(s.kind, 2);
    }

    #[test]
    fn kind_connection_closed() {
        let s = Symbol::from_network_event(&make_event(4, 0, 443));
        assert_eq!(s.kind, 3);
    }

    #[test]
    fn kind_dns_query() {
        let s = Symbol::from_network_event(&make_event(5, 0, 53));
        assert_eq!(s.kind, 4);
    }

    #[test]
    fn kind_unknown_event_types() {
        assert_eq!(Symbol::from_network_event(&make_event(0, 0, 0)).kind, 5);
        assert_eq!(Symbol::from_network_event(&make_event(6, 0, 0)).kind, 5);
        assert_eq!(Symbol::from_network_event(&make_event(255, 0, 0)).kind, 5);
    }

    // -- Size bucket boundaries --

    #[test]
    fn size_bucket_zero() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 0, 443)).size_bucket,
            0
        );
    }

    #[test]
    fn size_bucket_tiny_boundaries() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 1, 443)).size_bucket,
            1
        );
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 127, 443)).size_bucket,
            1
        );
    }

    #[test]
    fn size_bucket_small_boundaries() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 128, 443)).size_bucket,
            2
        );
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 1023, 443)).size_bucket,
            2
        );
    }

    #[test]
    fn size_bucket_medium_boundaries() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 1024, 443)).size_bucket,
            3
        );
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 8191, 443)).size_bucket,
            3
        );
    }

    #[test]
    fn size_bucket_large_boundaries() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 8192, 443)).size_bucket,
            4
        );
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 65535, 443)).size_bucket,
            4
        );
    }

    #[test]
    fn size_bucket_huge() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 65536, 443)).size_bucket,
            5
        );
    }

    // -- Port class --

    #[test]
    fn port_class_443() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 0, 443)).port_class,
            0
        );
    }

    #[test]
    fn port_class_80() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 0, 80)).port_class,
            1
        );
    }

    #[test]
    fn port_class_53() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 0, 53)).port_class,
            2
        );
    }

    #[test]
    fn port_class_well_known() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 0, 22)).port_class,
            3
        );
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 0, 0)).port_class,
            3
        );
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 0, 1023)).port_class,
            3
        );
    }

    #[test]
    fn port_class_ephemeral() {
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 0, 1024)).port_class,
            4
        );
        assert_eq!(
            Symbol::from_network_event(&make_event(1, 0, 8080)).port_class,
            4
        );
    }

    // -- Encode --

    #[test]
    fn encode_range_all_in_bounds() {
        let mut seen = std::collections::HashSet::new();
        for kind in 0..6u8 {
            for size in 0..6u8 {
                for port in 0..5u8 {
                    let s = Symbol {
                        kind,
                        size_bucket: size,
                        port_class: port,
                    };
                    let code = s.encode();
                    assert!(code < SYMBOL_SPACE as u16, "code {} out of range", code);
                    seen.insert(code);
                }
            }
        }
        assert_eq!(seen.len(), SYMBOL_SPACE);
    }

    #[test]
    fn encode_formula() {
        let s = Symbol {
            kind: 2,
            size_bucket: 3,
            port_class: 4,
        };
        assert_eq!(s.encode(), 2 * 30 + 3 * 5 + 4);
    }

    #[test]
    fn symbol_space_is_180() {
        assert_eq!(SYMBOL_SPACE, 180);
    }
}
