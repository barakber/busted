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
