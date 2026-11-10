//! Bounded AnyTLS-style padding rules. A planned packet is a TLS plaintext
//! write, not a guarantee about TCP packets or TLS record boundaries.

use md5::{Digest, Md5};
use rand::Rng;
use std::collections::HashMap;

pub const MAX_SEGMENT_SIZE: usize = 16 * 1024;
const MAX_PADDING_PER_WRITE: u32 = 64 * 1024;
const MAX_SCHEME_BYTES: usize = 16 * 1024;
const MAX_STOP: u32 = 1024;
const FRAME_HEADER_LEN: usize = 7;

#[derive(Debug, Clone)]
pub enum Segment { Range(u32, u32), Check }

#[derive(Debug, Clone)]
pub struct PaddingScheme {
    pub stop: u32,
    pub rules: HashMap<u32, Vec<Segment>>,
    pub raw: String,
}

impl PaddingScheme {
    pub fn default_scheme() -> Self {
        let raw = "stop=8\n\
                   0=30-30\n\
                   1=100-400\n\
                   2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
                   3=9-9,500-1000\n\
                   4=500-1000\n\
                   5=500-1000\n\
                   6=500-1000\n\
                   7=500-1000";
        Self::parse(raw).expect("built-in padding scheme")
    }

    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(raw.len() <= MAX_SCHEME_BYTES, "padding scheme too large");
        let mut stop = None;
        let mut rules = HashMap::new();
        for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let (key, value) = line.split_once('=').ok_or_else(|| anyhow::anyhow!("invalid padding rule"))?;
            if key.trim() == "stop" {
                anyhow::ensure!(stop.is_none(), "duplicate padding stop");
                let parsed: u32 = value.trim().parse()?;
                anyhow::ensure!(parsed <= MAX_STOP, "padding stop too large");
                stop = Some(parsed);
                continue;
            }
            let index: u32 = key.trim().parse()?;
            anyhow::ensure!(index < MAX_STOP && !rules.contains_key(&index), "invalid/duplicate padding index");
            let mut segments = Vec::new();
            let mut maximum = 0u32;
            for part in value.split(',').map(str::trim) {
                anyhow::ensure!(segments.len() < 32, "too many padding segments");
                if part == "c" {
                    segments.push(Segment::Check);
                } else {
                    let (lo, hi) = part.split_once('-').ok_or_else(|| anyhow::anyhow!("invalid padding range"))?;
                    let lo: u32 = lo.trim().parse()?;
                    let hi: u32 = hi.trim().parse()?;
                    anyhow::ensure!(lo > 0 && lo <= hi && hi <= MAX_SEGMENT_SIZE as u32, "padding range out of bounds");
                    maximum += hi;
                    anyhow::ensure!(maximum <= MAX_PADDING_PER_WRITE, "padding write budget exceeded");
                    segments.push(Segment::Range(lo, hi));
                }
            }
            rules.insert(index, segments);
        }
        let stop = stop.ok_or_else(|| anyhow::anyhow!("padding stop missing"))?;
        anyhow::ensure!(rules.keys().all(|index| *index < stop), "padding rule after stop");
        Ok(Self { stop, rules, raw: raw.to_owned() })
    }

    pub fn md5_hex(&self) -> String {
        Md5::digest(self.raw.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub fn padding0_len(&self) -> usize {
        self.rules.get(&0).and_then(|segments| segments.iter().find_map(|segment| {
            match segment {
                Segment::Range(lo, hi) => Some(rand::thread_rng().gen_range(*lo..=*hi) as usize),
                Segment::Check => None,
            }
        })).unwrap_or(0)
    }
}

/// Each output buffer is written once: payload and its waste frame are joined.
/// Real frame bytes may span consecutive writes, but a waste frame is appended
/// only after all real frame bytes have been consumed, never inside a frame.
/// A positive gap below seven bytes requires a minimal seven-byte waste frame;
/// truncating that frame would corrupt the stream, and silently skipping the
/// gap would make the planned padding inconsistent.
pub fn plan_write(scheme: &PaddingScheme, index: u32, data: &[u8]) -> Vec<Vec<u8>> {
    if index >= scheme.stop { return vec![data.to_vec()]; }
    let Some(segments) = scheme.rules.get(&index) else { return vec![data.to_vec()] };
    let mut remaining = data;
    let mut output = Vec::new();
    for segment in segments {
        match segment {
            Segment::Check if remaining.is_empty() => break,
            Segment::Check => {}
            Segment::Range(lo, hi) => {
                let target = rand::thread_rng().gen_range(*lo..=*hi) as usize;
                let real_len = remaining.len().min(target);
                let gap = target - real_len;
                let waste = if gap > 0 { gap.max(FRAME_HEADER_LEN) } else { 0 };
                let mut packet = Vec::with_capacity(real_len + waste);
                packet.extend_from_slice(&remaining[..real_len]);
                remaining = &remaining[real_len..];
                if waste > 0 {
                    packet.extend_from_slice(&[0, 0, 0, 0, 0]); // cmdWaste + stream ID
                    packet.extend_from_slice(&((waste - FRAME_HEADER_LEN) as u16).to_be_bytes());
                    packet.resize(real_len + waste, 0);
                }
                output.push(packet);
            }
        }
    }
    if !remaining.is_empty() { output.push(remaining.to_vec()); }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unbounded_and_ambiguous_schemes() {
        for raw in ["stop=2\n1=10-9", "stop=2\n1=0-0", "stop=2\n1=1-999999",
            "stop=2\n1=1-1\n1=2-2", "stop=2\nstop=3", "stop=0\n1=1-1", "1=1-1"] {
            assert!(PaddingScheme::parse(raw).is_err());
        }
    }

    #[test]
    fn payload_and_waste_share_a_write() {
        let scheme = PaddingScheme::parse("stop=2\n1=20-20").unwrap();
        let packets = plan_write(&scheme, 1, &[1, 2, 3]);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].len(), 20);
        assert_eq!(&packets[0][..3], &[1, 2, 3]);
        assert_eq!(u16::from_be_bytes([packets[0][8], packets[0][9]]), 10);
    }

    #[test]
    fn default_and_stop_parse() {
        let scheme = PaddingScheme::default_scheme();
        assert_eq!(scheme.padding0_len(), 30);
        assert_eq!(plan_write(&scheme, 8, &[4, 5]), vec![vec![4, 5]]);
    }
}
