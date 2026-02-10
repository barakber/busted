use busted_classifier::pii;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Property: scan() never panics on arbitrary bytes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn scan_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = pii::scan(&data);
    }
}

// ---------------------------------------------------------------------------
// Property: match_count consistency — count of true flags <= match_count
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn match_count_consistent(
        data in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let flags = pii::scan(&data);
        let true_count = [
            flags.has_email,
            flags.has_phone,
            flags.has_credit_card,
            flags.has_ssn,
            flags.has_api_key,
        ]
        .iter()
        .filter(|&&b| b)
        .count() as u32;

        // match_count is the number of pattern categories that matched
        prop_assert_eq!(true_count, flags.match_count);
    }
}

// ---------------------------------------------------------------------------
// When pii feature is DISABLED: all flags are false
// These tests run regardless of feature — they test the default state
// ---------------------------------------------------------------------------

#[test]
fn default_pii_flags_are_false() {
    let flags = pii::PiiFlags::default();
    assert!(!flags.any());
    assert!(!flags.has_email);
    assert!(!flags.has_phone);
    assert!(!flags.has_credit_card);
    assert!(!flags.has_ssn);
    assert!(!flags.has_api_key);
    assert_eq!(flags.match_count, 0);
}

// ---------------------------------------------------------------------------
// The following tests are PII-feature-specific
// ---------------------------------------------------------------------------

// When the pii feature is enabled, known patterns should be detected.
// When disabled, scan always returns defaults, so these tests should
// still pass (the assertions check for the correct behavior based on
// whether the feature is enabled).

#[test]
fn email_detected_or_feature_off() {
    let flags = pii::scan(b"Contact me at user@example.com");
    if cfg!(feature = "pii") {
        assert!(flags.has_email);
        assert!(flags.any());
    } else {
        assert!(!flags.any());
    }
}

#[test]
fn phone_detected_or_feature_off() {
    let flags = pii::scan(b"Call (555) 123-4567");
    if cfg!(feature = "pii") {
        assert!(flags.has_phone);
    } else {
        assert!(!flags.any());
    }
}

#[test]
fn credit_card_detected_or_feature_off() {
    let flags = pii::scan(b"Card: 4111-1111-1111-1111");
    if cfg!(feature = "pii") {
        assert!(flags.has_credit_card);
    } else {
        assert!(!flags.any());
    }
}

#[test]
fn ssn_detected_or_feature_off() {
    let flags = pii::scan(b"SSN: 123-45-6789");
    if cfg!(feature = "pii") {
        assert!(flags.has_ssn);
    } else {
        assert!(!flags.any());
    }
}

#[test]
fn api_key_detected_or_feature_off() {
    let flags = pii::scan(b"Token: sk-1234567890abcdef1234567890abcdef");
    if cfg!(feature = "pii") {
        assert!(flags.has_api_key);
    } else {
        assert!(!flags.any());
    }
}

#[test]
fn clean_text_no_pii() {
    let flags = pii::scan(b"The quick brown fox jumps over the lazy dog");
    assert!(!flags.any());
    assert_eq!(flags.match_count, 0);
}

#[test]
fn empty_payload_no_pii() {
    let flags = pii::scan(b"");
    assert!(!flags.any());
    assert_eq!(flags.match_count, 0);
}

#[test]
fn multiple_pii_types_or_feature_off() {
    let flags = pii::scan(
        b"Email: user@example.com, SSN: 123-45-6789, Card: 4111111111111111, Key: sk-abcdefghijklmnopqrstuvwxyz1234567890",
    );
    if cfg!(feature = "pii") {
        assert!(flags.has_email);
        assert!(flags.has_ssn);
        assert!(flags.has_credit_card);
        assert!(flags.has_api_key);
        assert!(flags.match_count >= 4);
    } else {
        assert!(!flags.any());
    }
}

// ---------------------------------------------------------------------------
// Unit: PiiFlags::any() method
// ---------------------------------------------------------------------------

#[test]
fn any_returns_true_when_email_set() {
    let flags = pii::PiiFlags {
        has_email: true,
        ..Default::default()
    };
    assert!(flags.any());
}

#[test]
fn any_returns_true_when_phone_set() {
    let flags = pii::PiiFlags {
        has_phone: true,
        ..Default::default()
    };
    assert!(flags.any());
}

#[test]
fn any_returns_true_when_credit_card_set() {
    let flags = pii::PiiFlags {
        has_credit_card: true,
        ..Default::default()
    };
    assert!(flags.any());
}

#[test]
fn any_returns_true_when_ssn_set() {
    let flags = pii::PiiFlags {
        has_ssn: true,
        ..Default::default()
    };
    assert!(flags.any());
}

#[test]
fn any_returns_true_when_api_key_set() {
    let flags = pii::PiiFlags {
        has_api_key: true,
        ..Default::default()
    };
    assert!(flags.any());
}

// ---------------------------------------------------------------------------
// Additional PII edge-case tests (feature-gated)
// ---------------------------------------------------------------------------

#[test]
fn international_phone_not_matched() {
    // UK phone format should NOT match the US-only regex
    let flags = pii::scan(b"Call +44 20 7946 0958");
    if cfg!(feature = "pii") {
        // The US phone regex requires 3+3+4 digit pattern; UK numbers differ
        // +44 20 7946 0958 doesn't match \(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}
        assert!(!flags.has_phone, "UK phone should not match US phone regex");
    }
}

#[test]
fn valid_luhn_credit_card_detected() {
    // 4532015112830366 is a valid Luhn Visa card
    let flags = pii::scan(b"Card: 4532015112830366");
    if cfg!(feature = "pii") {
        assert!(flags.has_credit_card, "valid Visa card should be detected");
    }
}

#[test]
fn api_key_prefix_variations() {
    if cfg!(feature = "pii") {
        // api_key= variant
        let flags1 = pii::scan(b"api_key=abcdefghijklmnopqrstuvwxyz1234");
        assert!(flags1.has_api_key, "api_key= prefix should match");

        // api-key: variant
        let flags2 = pii::scan(b"api-key: abcdefghijklmnopqrstuvwxyz1234");
        assert!(flags2.has_api_key, "api-key: prefix should match");

        // api_key: variant
        let flags3 = pii::scan(b"api_key: abcdefghijklmnopqrstuvwxyz1234");
        assert!(flags3.has_api_key, "api_key: prefix should match");
    }
}

#[test]
fn pii_in_url_encoded_content_not_matched() {
    // %40 is URL-encoded '@' — email regex expects literal '@'
    let flags = pii::scan(b"user%40example.com");
    if cfg!(feature = "pii") {
        assert!(
            !flags.has_email,
            "URL-encoded @ should not match email regex"
        );
    }
}

#[test]
fn sk_uppercase_not_matched() {
    // The regex has lowercase `sk-`, uppercase `SK-` should NOT match
    let flags = pii::scan(b"Token: SK-1234567890abcdef1234567890abcdef");
    if cfg!(feature = "pii") {
        assert!(
            !flags.has_api_key,
            "uppercase SK- should not match lowercase sk- regex"
        );
    }
}

#[test]
fn email_in_json_string_value() {
    // Email embedded in a JSON payload
    let flags = pii::scan(br#"{"email":"user@example.com","name":"Test"}"#);
    if cfg!(feature = "pii") {
        assert!(flags.has_email, "email in JSON value should be detected");
    } else {
        assert!(!flags.any());
    }
}

#[test]
fn ssn_without_dashes_not_matched() {
    // SSN regex requires dashes: \b\d{3}-\d{2}-\d{4}\b
    let flags = pii::scan(b"SSN: 123456789");
    if cfg!(feature = "pii") {
        assert!(!flags.has_ssn, "SSN without dashes should not match");
    }
}

#[test]
fn credit_card_without_separators() {
    // Regex allows optional separators: [- ]? — no separators should still match
    let flags = pii::scan(b"Card: 4111111111111111");
    if cfg!(feature = "pii") {
        assert!(
            flags.has_credit_card,
            "credit card without separators should match"
        );
    }
}

#[test]
fn phone_with_dot_separators() {
    // Phone regex accepts dots: [-.\s]?
    let flags = pii::scan(b"Phone: 555.123.4567");
    if cfg!(feature = "pii") {
        assert!(flags.has_phone, "phone with dot separators should match");
    }
}

#[test]
fn short_api_key_no_match() {
    // API key regex requires 20+ chars after prefix: [a-zA-Z0-9_-]{20,}
    let flags = pii::scan(b"sk-short");
    if cfg!(feature = "pii") {
        assert!(
            !flags.has_api_key,
            "short API key should not match (< 20 chars)"
        );
    }
}
