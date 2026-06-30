//! AnyTLS PaddingScheme.
//!
//! This is the mechanism the AnyTLS protocol exists for: it controls the
//! plaintext size of each underlying TLS write ("packet", counted by call
//! order on the session's single writer) according to a per-index rule
//! table, so that the byte-length pattern of a tunnelled "TLS-in-TLS"
//! connection does not stand out from an ordinary single-layer TLS session.
//!
//! Spec: <https://github.com/anytls/anytls-go/blob/main/docs/protocol.md>
//! (section `paddingScheme 具体含义与实现`).

use md5::{Digest, Md5};
use rand::Rng;
use std::collections::HashMap;

/// One segment of a packet's padding rule.
#[derive(Debug, Clone)]
pub enum Segment {
    /// Random size in `[lo, hi]` (inclusive). Filled with real data first;
    /// if real data runs out before reaching this size, the remainder is
    /// padded with a `cmdWaste` frame.
    Range(u32, u32),
    /// Check symbol (`c`): if no real data remains at this point, stop
    /// processing the rest of this packet's segments — i.e. don't emit
    /// further obligatory padding once the caller's data is exhausted.
    Check,
}

#[derive(Debug, Clone)]
pub struct PaddingScheme {
    /// Packet index at which padding stops being applied. From this index
    /// onward, writes pass straight through unmodified.
    pub stop: u32,
    /// rules[i] = segment list for packet index i. Indices with no entry
    /// (but still < stop) pass through unmodified, same as `stop`.
    pub rules: HashMap<u32, Vec<Segment>>,
    /// Raw scheme text, kept so its md5 can be computed / compared against
    /// a peer's `padding-md5`.
    pub raw: String,
}

impl PaddingScheme {
    /// The default scheme shipped with anytls-go (see protocol.md). Used by
    /// both client and server unless a future config option overrides it.
    pub fn default_scheme() -> Self {
        let raw = "stop=8\n\
                    0=30-30\n\
                    1=100-400\n\
                    2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
                    3=9-9,500-1000\n\
                    4=500-1000\n\
                    5=500-1000\n\
                    6=500-1000\n\
                    7=500-1000"
            .to_string();
        Self::parse(&raw).expect("built-in default padding scheme must parse")
    }

    /// Parse the `key=value` textual scheme format described in protocol.md.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let mut stop = 0u32;
        let mut rules = HashMap::new();

        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid padding scheme line: {line}"))?;
            let key = key.trim();
            if key == "stop" {
                stop = value.trim().parse()?;
                continue;
            }
            let idx: u32 = key.parse()?;
            let mut segs = Vec::new();
            for part in value.split(',') {
                let part = part.trim();
                if part == "c" {
                    segs.push(Segment::Check);
                } else if let Some((lo, hi)) = part.split_once('-') {
                    segs.push(Segment::Range(lo.trim().parse()?, hi.trim().parse()?));
                } else {
                    anyhow::bail!("invalid padding segment: {part}");
                }
            }
            rules.insert(idx, segs);
        }

        Ok(Self { stop, rules, raw: raw.to_string() })
    }

    /// Lowercase hex MD5 of the raw scheme text — sent as `padding-md5` in
    /// `cmdSettings` so the peer can detect a scheme mismatch and react
    /// with `cmdUpdatePaddingScheme`.
    pub fn md5_hex(&self) -> String {
        let digest = Md5::digest(self.raw.as_bytes());
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Picks a random padding0 length from the rule at index 0 (the
    /// auth-phase padding, sent alongside `sha256(password)` before the
    /// session layer even starts). Falls back to 0 if no rule is defined.
    pub fn padding0_len(&self) -> usize {
        let Some(segs) = self.rules.get(&0) else { return 0 };
        let mut rng = rand::thread_rng();
        for seg in segs {
            if let Segment::Range(lo, hi) = seg {
                let n = if hi > lo { rng.gen_range(*lo..=*hi) } else { *lo };
                return n as usize;
            }
        }
        0
    }
}

/// One write instruction produced by [`plan_write`]: either real payload
/// bytes to send verbatim, or a `cmdWaste` filler frame of the given total
/// on-wire length (7-byte frame header + zero data).
pub enum Chunk<'a> {
    Real(&'a [u8]),
    Waste(usize),
}

/// Computes how a single logical "packet" (one call to the session's padded
/// writer) should be split into on-wire chunks, given the current packet
/// index. Any data left over after the rule's segments are exhausted is
/// appended as one final unpadded `Real` chunk, per spec: "如果分包发送完
/// 之后，用户数据仍然有剩余，则直接发送剩余数据".
pub fn plan_write<'a>(scheme: &PaddingScheme, packet_index: u32, data: &'a [u8]) -> Vec<Chunk<'a>> {
    if packet_index >= scheme.stop {
        return vec![Chunk::Real(data)];
    }
    let Some(segments) = scheme.rules.get(&packet_index) else {
        return vec![Chunk::Real(data)];
    };

    let mut out = Vec::new();
    let mut remaining = data;
    let mut rng = rand::thread_rng();

    for seg in segments {
        match seg {
            Segment::Check => {
                // Checkpoint: once real data is exhausted, stop emitting
                // further mandatory padding for this packet.
                if remaining.is_empty() {
                    return out;
                }
            }
            Segment::Range(lo, hi) => {
                let target = if hi > lo { rng.gen_range(*lo..=*hi) } else { *lo } as usize;
                if remaining.len() >= target {
                    let (chunk, rest) = remaining.split_at(target);
                    out.push(Chunk::Real(chunk));
                    remaining = rest;
                } else {
                    let real_len = remaining.len();
                    if real_len > 0 {
                        out.push(Chunk::Real(remaining));
                        remaining = &[];
                    }
                    let pad_needed = target.saturating_sub(real_len);
                    if pad_needed > 0 {
                        out.push(Chunk::Waste(pad_needed));
                    }
                }
            }
        }
    }

    if !remaining.is_empty() {
        out.push(Chunk::Real(remaining));
    }

    out
}
