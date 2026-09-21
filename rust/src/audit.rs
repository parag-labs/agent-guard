//! Signed, append-only audit log for every tool-call decision.
//!
//! Each entry is chained (`prev_hash`) and Ed25519-signed, so the audit trail is
//! tamper-evident -- you can prove after the fact exactly what the agent was
//! allowed to do and why.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// One audit line. Fields are public and mutable so tests (and tampering) can
/// mutate them after the fact -- verification is what catches any such edit.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Wall-clock time the entry was recorded, in seconds.
    pub ts: f64,
    /// The tool the decision was about.
    pub tool: String,
    /// The decision, as a wire string ("allow"/"deny"/"approve").
    pub decision: String,
    /// The human-readable reason for the decision.
    pub reason: String,
    /// Hash of the previous entry, chaining this one to it.
    pub prev_hash: String,
    /// SHA-256 hash committing to this entry's fields.
    pub entry_hash: String,
    /// Ed25519 signature over `entry_hash`, hex-encoded.
    pub signature: String,
}

/// A signed, append-only, hash-chained record of tool-call decisions. Each entry
/// commits to the previous entry's hash and is individually Ed25519-signed, making
/// the trail tamper-evident.
pub struct AuditLog {
    signing: SigningKey,
    verifying: VerifyingKey,
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Create an audit log with a freshly generated Ed25519 key.
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS random source");
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        AuditLog {
            signing,
            verifying,
            entries: Vec::new(),
        }
    }

    /// The verifying (public) key for this log's signatures.
    pub fn public_key(&self) -> VerifyingKey {
        self.verifying
    }

    /// Append a signed, chained entry for a tool-call decision and return a clone.
    pub fn record(&mut self, tool: &str, decision: &str, reason: &str) -> AuditEntry {
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_default();
        let ts = now_seconds();
        let entry_hash = sha256_hex(&canonical(ts, tool, decision, reason, &prev_hash));
        let signature = hex_encode(&self.signing.sign(entry_hash.as_bytes()).to_bytes());
        let entry = AuditEntry {
            ts,
            tool: tool.to_string(),
            decision: decision.to_string(),
            reason: reason.to_string(),
            prev_hash,
            entry_hash,
            signature,
        };
        self.entries.push(entry.clone());
        entry
    }

    /// A snapshot clone of the entry list.
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.clone()
    }

    /// Mutable access to the backing entries, for white-box tamper tests.
    pub fn entries_mut(&mut self) -> &mut Vec<AuditEntry> {
        &mut self.entries
    }

    /// Recompute every entry's hash and check its signature and link to the
    /// previous entry; returns false if anything has been altered, reordered,
    /// truncated, or re-signed with the wrong key.
    pub fn verify_chain(&self) -> bool {
        let mut prev = String::new();
        for e in &self.entries {
            let expected = sha256_hex(&canonical(e.ts, &e.tool, &e.decision, &e.reason, &prev));
            if expected != e.entry_hash {
                return false;
            }
            if !self.verify_sig(&e.entry_hash, &e.signature) {
                return false;
            }
            prev = e.entry_hash.clone();
        }
        true
    }

    fn verify_sig(&self, message: &str, signature_hex: &str) -> bool {
        let raw = match hex_decode(signature_hex) {
            Some(r) => r,
            None => return false,
        };
        let arr: [u8; 64] = match raw.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&arr);
        self.verifying.verify(message.as_bytes(), &sig).is_ok()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// Canonical, sorted-key form matching the reference (decision, prev_hash, reason,
// tool, ts). Only needs to be self-consistent between record and verify_chain.
fn canonical(ts: f64, tool: &str, decision: &str, reason: &str, prev_hash: &str) -> String {
    format!(
        "{{\"decision\": {d}, \"prev_hash\": {p}, \"reason\": {r}, \"tool\": {t}, \"ts\": {ts}}}",
        d = json_str(decision),
        p = json_str(prev_hash),
        r = json_str(reason),
        t = json_str(tool),
    )
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn sha256_hex(s: &str) -> String {
    hex_encode(&Sha256::digest(s.as_bytes()))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("writing to a String is infallible");
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
