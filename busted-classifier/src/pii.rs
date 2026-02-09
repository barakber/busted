/// PII detection flags.
#[derive(Debug, Clone, Default)]
pub struct PiiFlags {
    /// Email address detected.
    pub has_email: bool,
    /// Phone number detected.
    pub has_phone: bool,
    /// Credit card number detected.
    pub has_credit_card: bool,
    /// Social Security Number detected.
    pub has_ssn: bool,
    /// API key or bearer token detected.
    pub has_api_key: bool,
    /// Total number of PII matches found.
    pub match_count: u32,
}

impl PiiFlags {
    /// Returns true if any PII was detected.
    pub fn any(&self) -> bool {
        self.has_email || self.has_phone || self.has_credit_card || self.has_ssn || self.has_api_key
    }
}

/// Scan payload for PII patterns.
///
/// When the `pii` feature is disabled, this always returns default (empty) flags.
#[cfg(feature = "pii")]
pub fn scan(payload: &[u8]) -> PiiFlags {
    use once_cell::sync::Lazy;
    use regex::bytes::RegexSet;

    // Single DFA pass via RegexSet
    static PII_PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
        RegexSet::new([
            // 0: Email
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            // 1: US phone (with separators)
            r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
            // 2: Credit card (major formats)
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            // 3: US SSN
            r"\b\d{3}-\d{2}-\d{4}\b",
            // 4: API key patterns (sk-, key-, api_key, etc.)
            r"(?:sk-|api[_-]key[=:]\s*)[a-zA-Z0-9_-]{20,}",
        ])
        .expect("PII regex patterns must compile")
    });

    let text = match std::str::from_utf8(payload) {
        Ok(s) => s.as_bytes(),
        Err(_) => payload,
    };

    let matches: Vec<usize> = PII_PATTERNS.matches(text).into_iter().collect();
    let match_count = matches.len() as u32;

    PiiFlags {
        has_email: matches.contains(&0),
        has_phone: matches.contains(&1),
        has_credit_card: matches.contains(&2),
        has_ssn: matches.contains(&3),
        has_api_key: matches.contains(&4),
        match_count,
    }
}

#[cfg(not(feature = "pii"))]
pub fn scan(_payload: &[u8]) -> PiiFlags {
    PiiFlags::default()
}

#[cfg(all(test, feature = "pii"))]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        let payload = b"Contact me at user@example.com for details";
        let flags = scan(payload);
        assert!(flags.has_email);
        assert!(flags.any());
    }

    #[test]
    fn test_phone_detection() {
        let payload = b"Call me at (555) 123-4567";
        let flags = scan(payload);
        assert!(flags.has_phone);
    }

    #[test]
    fn test_credit_card_detection() {
        let payload = b"Card number: 4111-1111-1111-1111";
        let flags = scan(payload);
        assert!(flags.has_credit_card);
    }

    #[test]
    fn test_ssn_detection() {
        let payload = b"SSN: 123-45-6789";
        let flags = scan(payload);
        assert!(flags.has_ssn);
    }

    #[test]
    fn test_api_key_detection() {
        let payload = b"Authorization: Bearer sk-1234567890abcdef1234567890abcdef";
        let flags = scan(payload);
        assert!(flags.has_api_key);
    }

    #[test]
    fn test_no_pii() {
        let payload = b"Hello, how are you today? The weather is nice.";
        let flags = scan(payload);
        assert!(!flags.any());
        assert_eq!(flags.match_count, 0);
    }

    #[test]
    fn test_multiple_pii() {
        let payload = b"Email: test@example.com, SSN: 123-45-6789, Card: 4111111111111111";
        let flags = scan(payload);
        assert!(flags.has_email);
        assert!(flags.has_ssn);
        assert!(flags.has_credit_card);
        assert!(flags.match_count >= 3);
    }
}
