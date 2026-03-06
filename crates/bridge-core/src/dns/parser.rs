//! Minimal DNS packet parser.
//!
//! Parses enough of DNS to extract query names, types, and answer records.
//! Not a full DNS implementation — just what the proxy needs.

use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS query type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    PTR,
    SRV,
    Unknown(u16),
}

impl From<u16> for QueryType {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            15 => Self::MX,
            16 => Self::TXT,
            2 => Self::NS,
            6 => Self::SOA,
            12 => Self::PTR,
            33 => Self::SRV,
            v => Self::Unknown(v),
        }
    }
}

/// A DNS question entry.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub qclass: u16,
}

/// A DNS resource record (answer).
#[derive(Debug, Clone)]
pub enum DnsRecord {
    A { name: String, ttl: u32, ip: Ipv4Addr },
    AAAA { name: String, ttl: u32, ip: Ipv6Addr },
    CNAME { name: String, ttl: u32, target: String },
    Other { name: String, ttl: u32, rtype: u16 },
}

impl DnsRecord {
    pub fn ttl(&self) -> u32 {
        match self {
            Self::A { ttl, .. } => *ttl,
            Self::AAAA { ttl, .. } => *ttl,
            Self::CNAME { ttl, .. } => *ttl,
            Self::Other { ttl, .. } => *ttl,
        }
    }
}

/// Parsed DNS packet.
#[derive(Debug)]
pub struct DnsPacket {
    pub id: u16,
    pub is_response: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    /// Byte offset where the question section ends in the raw packet.
    pub question_end_offset: usize,
}

impl DnsPacket {
    /// Parse a DNS packet from raw bytes.
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 12 {
            anyhow::bail!("DNS packet too short");
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_response = (flags & 0x8000) != 0;
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        let mut offset = 12;
        let mut questions = Vec::with_capacity(qdcount);

        // Parse questions
        for _ in 0..qdcount {
            let (name, new_offset) = parse_name(data, offset)?;
            offset = new_offset;

            if offset + 4 > data.len() {
                anyhow::bail!("Truncated question");
            }

            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            questions.push(DnsQuestion {
                name,
                qtype: QueryType::from(qtype),
                qclass,
            });
        }

        let question_end_offset = offset;

        // Parse answers
        let mut answers = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            if offset >= data.len() {
                break;
            }

            let (name, new_offset) = parse_name(data, offset)?;
            offset = new_offset;

            if offset + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                break;
            }

            let record = match rtype {
                1 if rdlength == 4 => {
                    let ip = Ipv4Addr::new(
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    );
                    DnsRecord::A { name, ttl, ip }
                }
                28 if rdlength == 16 => {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&data[offset..offset + 16]);
                    let ip = Ipv6Addr::from(addr);
                    DnsRecord::AAAA { name, ttl, ip }
                }
                5 => {
                    let (target, _) = parse_name(data, offset).unwrap_or_default();
                    DnsRecord::CNAME { name, ttl, target }
                }
                _ => DnsRecord::Other {
                    name,
                    ttl,
                    rtype,
                },
            };

            offset += rdlength;
            answers.push(record);
        }

        Ok(DnsPacket {
            id,
            is_response,
            questions,
            answers,
            question_end_offset,
        })
    }
}

/// Parse a DNS name (with pointer compression support).
fn parse_name(data: &[u8], mut offset: usize) -> anyhow::Result<(String, usize)> {
    let mut parts = Vec::new();
    let mut jumped = false;
    let mut original_offset = 0;
    let mut max_jumps = 10; // Prevent infinite loops

    loop {
        if offset >= data.len() || max_jumps == 0 {
            anyhow::bail!("Invalid DNS name at offset {}", offset);
        }

        let len = data[offset] as usize;

        if len == 0 {
            if !jumped {
                original_offset = offset + 1;
            }
            break;
        }

        // Check for pointer (compression)
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() {
                anyhow::bail!("Truncated pointer");
            }
            if !jumped {
                original_offset = offset + 2;
            }
            let pointer = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            offset = pointer;
            jumped = true;
            max_jumps -= 1;
            continue;
        }

        offset += 1;
        if offset + len > data.len() {
            anyhow::bail!("Label extends past packet");
        }

        let label = std::str::from_utf8(&data[offset..offset + len])
            .unwrap_or("?")
            .to_string();
        parts.push(label);
        offset += len;
    }

    let final_offset = if jumped { original_offset } else { original_offset };

    Ok((parts.join("."), final_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for testing.
    fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&[0xAB, 0xCD]); // ID
        pkt.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        // Question: encode domain name
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // Root label

        // QTYPE and QCLASS
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // IN class

        pkt
    }

    /// Build a DNS response with an A record.
    fn build_dns_response(domain: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&[0xAB, 0xCD]); // ID
        pkt.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        // Question
        let name_offset = pkt.len();
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01]); // A
        pkt.extend_from_slice(&[0x00, 0x01]); // IN

        // Answer (using pointer to question name)
        pkt.extend_from_slice(&[0xC0, name_offset as u8]); // Name pointer
        pkt.extend_from_slice(&[0x00, 0x01]); // A
        pkt.extend_from_slice(&[0x00, 0x01]); // IN
        pkt.extend_from_slice(&ttl.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        pkt.extend_from_slice(&ip.octets());

        pkt
    }

    #[test]
    fn parse_dns_query() {
        let pkt = build_dns_query("example.com", 1);
        let parsed = DnsPacket::parse(&pkt).unwrap();

        assert_eq!(parsed.id, 0xABCD);
        assert!(!parsed.is_response);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "example.com");
        assert_eq!(parsed.questions[0].qtype, QueryType::A);
    }

    #[test]
    fn parse_dns_response_with_a_record() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let pkt = build_dns_response("example.com", ip, 300);
        let parsed = DnsPacket::parse(&pkt).unwrap();

        assert!(parsed.is_response);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.len(), 1);

        match &parsed.answers[0] {
            DnsRecord::A { name, ttl, ip: parsed_ip } => {
                assert_eq!(name, "example.com");
                assert_eq!(*ttl, 300);
                assert_eq!(*parsed_ip, ip);
            }
            other => panic!("Expected A record, got {:?}", other),
        }
    }

    #[test]
    fn parse_aaaa_query() {
        let pkt = build_dns_query("example.com", 28);
        let parsed = DnsPacket::parse(&pkt).unwrap();

        assert_eq!(parsed.questions[0].qtype, QueryType::AAAA);
    }

    #[test]
    fn parse_subdomain() {
        let pkt = build_dns_query("api.staging.example.com", 1);
        let parsed = DnsPacket::parse(&pkt).unwrap();

        assert_eq!(parsed.questions[0].name, "api.staging.example.com");
    }

    #[test]
    fn reject_too_short_packet() {
        assert!(DnsPacket::parse(&[0; 5]).is_err());
    }
}
