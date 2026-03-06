//! Data Loss Prevention (DLP) scanner.
//!
//! Scans flow content for sensitive data patterns:
//! - Credit card numbers (Luhn validation)
//! - Social Security Numbers
//! - API keys / secrets
//! - Custom regex patterns
//!
//! Implements the Inspector trait for use in the inspection pipeline.

use serde::{Deserialize, Serialize};

use super::flow::Flow;
use super::pipeline::Inspector;
use super::Verdict;

/// A DLP pattern to scan for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPattern {
    /// Pattern name for logging/audit.
    pub name: String,
    /// What to do when this pattern is found.
    pub action: DlpAction,
    /// The detection function type.
    pub detector: DetectorType,
}

/// Action when a DLP pattern is matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DlpAction {
    Block,
    ShadowCopy,
    Alert,
}

/// Type of content detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectorType {
    CreditCard,
    Ssn,
    ApiKey,
    CustomKeyword(Vec<String>),
}

/// A DLP match found in content.
#[derive(Debug, Clone)]
pub struct DlpMatch {
    pub pattern_name: String,
    pub matched_text: String,
    pub offset: usize,
}

/// DLP scanner that checks flow content for sensitive data.
pub struct DlpScanner {
    patterns: Vec<DlpPattern>,
}

impl DlpScanner {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Create a scanner with default patterns (credit cards, SSNs, API keys).
    pub fn with_defaults() -> Self {
        Self {
            patterns: vec![
                DlpPattern {
                    name: "credit-card".to_string(),
                    action: DlpAction::Block,
                    detector: DetectorType::CreditCard,
                },
                DlpPattern {
                    name: "ssn".to_string(),
                    action: DlpAction::Alert,
                    detector: DetectorType::Ssn,
                },
                DlpPattern {
                    name: "api-key".to_string(),
                    action: DlpAction::Alert,
                    detector: DetectorType::ApiKey,
                },
            ],
        }
    }

    /// Add a custom pattern.
    pub fn add_pattern(&mut self, pattern: DlpPattern) {
        self.patterns.push(pattern);
    }

    /// Scan content for all configured patterns.
    pub fn scan(&self, content: &[u8]) -> Vec<DlpMatch> {
        let text = String::from_utf8_lossy(content);
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            let detected = match &pattern.detector {
                DetectorType::CreditCard => detect_credit_cards(&text),
                DetectorType::Ssn => detect_ssns(&text),
                DetectorType::ApiKey => detect_api_keys(&text),
                DetectorType::CustomKeyword(keywords) => detect_keywords(&text, keywords),
            };

            for (matched_text, offset) in detected {
                matches.push(DlpMatch {
                    pattern_name: pattern.name.clone(),
                    matched_text,
                    offset,
                });
            }
        }

        matches
    }

    /// Get the most restrictive action from all matched patterns.
    fn worst_action(&self, matches: &[DlpMatch]) -> Option<&DlpAction> {
        let mut worst: Option<&DlpAction> = None;

        for m in matches {
            if let Some(pattern) = self.patterns.iter().find(|p| p.name == m.pattern_name) {
                worst = Some(match (worst, &pattern.action) {
                    (None, action) => action,
                    (Some(DlpAction::Block), _) => &DlpAction::Block,
                    (_, DlpAction::Block) => &DlpAction::Block,
                    (Some(DlpAction::ShadowCopy), _) => &DlpAction::ShadowCopy,
                    (_, DlpAction::ShadowCopy) => &DlpAction::ShadowCopy,
                    (Some(action), _) => action,
                });
            }
        }

        worst
    }
}

impl Default for DlpScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Inspector for DlpScanner {
    fn name(&self) -> &str {
        "dlp-scanner"
    }

    fn inspect(&self, flow: &Flow) -> Verdict {
        if flow.inspect_buffer.is_empty() {
            return Verdict::Allow;
        }

        let matches = self.scan(&flow.inspect_buffer);
        if matches.is_empty() {
            return Verdict::Allow;
        }

        tracing::info!(
            flow_id = %flow.id,
            matches = matches.len(),
            patterns = ?matches.iter().map(|m| &m.pattern_name).collect::<Vec<_>>(),
            "DLP match detected"
        );

        match self.worst_action(&matches) {
            Some(DlpAction::Block) => Verdict::Block {
                reason: format!(
                    "DLP: {} detected",
                    matches[0].pattern_name
                ),
            },
            Some(DlpAction::ShadowCopy) => Verdict::ShadowCopy,
            Some(DlpAction::Alert) => Verdict::Alert {
                severity: super::Severity::High,
                message: format!(
                    "DLP: {} pattern(s) detected",
                    matches.len()
                ),
            },
            None => Verdict::Allow,
        }
    }
}

/// Detect credit card numbers using digit extraction + Luhn validation.
fn detect_credit_cards(text: &str) -> Vec<(String, usize)> {
    let mut results = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Look for sequences of digits (possibly separated by spaces or dashes)
        if chars[i].is_ascii_digit() {
            let start = i;
            let mut digits = String::new();
            let mut raw = String::new();
            let mut j = i;

            while j < len && digits.len() < 19 {
                if chars[j].is_ascii_digit() {
                    digits.push(chars[j]);
                    raw.push(chars[j]);
                    j += 1;
                } else if (chars[j] == ' ' || chars[j] == '-') && !digits.is_empty() {
                    raw.push(chars[j]);
                    j += 1;
                } else {
                    break;
                }
            }

            if (13..=19).contains(&digits.len()) && luhn_check(&digits) {
                // Trim trailing separators (spaces/dashes) from the raw match
                let trimmed = raw.trim_end_matches(|c: char| c == ' ' || c == '-');
                results.push((trimmed.to_string(), start));
            }

            i = j;
        } else {
            i += 1;
        }
    }

    results
}

/// Luhn algorithm for credit card validation.
fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 {
        return false;
    }

    let mut sum = 0;
    let mut double = false;

    for &d in digits.iter().rev() {
        let mut val = d;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }

    sum % 10 == 0
}

/// Detect Social Security Numbers (xxx-xx-xxxx pattern).
fn detect_ssns(text: &str) -> Vec<(String, usize)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();

    for i in 0..bytes.len().saturating_sub(10) {
        // Check for xxx-xx-xxxx pattern
        if bytes.len() >= i + 11
            && bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3] == b'-'
            && bytes[i + 4].is_ascii_digit()
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6] == b'-'
            && bytes[i + 7].is_ascii_digit()
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
            && bytes[i + 10].is_ascii_digit()
        {
            let ssn = &text[i..i + 11];
            // Validate: not all zeros in any group
            let area = &ssn[0..3];
            let group = &ssn[4..6];
            let serial = &ssn[7..11];
            if area != "000" && group != "00" && serial != "0000" && area != "666" {
                results.push((ssn.to_string(), i));
            }
        }
    }

    results
}

/// Detect common API key patterns.
fn detect_api_keys(text: &str) -> Vec<(String, usize)> {
    let mut results = Vec::new();

    let prefixes = [
        "sk-", "pk-", "api_", "apikey_", "AKIA", "ghp_", "gho_",
        "github_pat_", "xox", "Bearer ", "token=",
    ];

    for prefix in &prefixes {
        let mut start = 0;
        while let Some(pos) = text[start..].find(prefix) {
            let abs_pos = start + pos;
            // Start extracting the token value after the prefix
            let value_start = abs_pos + prefix.len();
            let remaining = &text[value_start..];
            let value_end = remaining
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
                .unwrap_or(remaining.len().min(100));

            let value = &text[value_start..value_start + value_end];
            if value.len() >= 8 {
                // Return the full match including prefix
                let full_match = &text[abs_pos..value_start + value_end];
                results.push((full_match.to_string(), abs_pos));
            }

            start = abs_pos + 1;
        }
    }

    results
}

/// Detect custom keywords in text.
fn detect_keywords(text: &str, keywords: &[String]) -> Vec<(String, usize)> {
    let lower_text = text.to_lowercase();
    let mut results = Vec::new();

    for keyword in keywords {
        let lower_keyword = keyword.to_lowercase();
        let mut start = 0;
        while let Some(pos) = lower_text[start..].find(&lower_keyword) {
            let abs_pos = start + pos;
            results.push((keyword.clone(), abs_pos));
            start = abs_pos + 1;
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_valid_credit_card() {
        // Visa test number
        let matches = detect_credit_cards("my card is 4111 1111 1111 1111 thanks");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "4111 1111 1111 1111");
    }

    #[test]
    fn detect_credit_card_with_dashes() {
        let matches = detect_credit_cards("card: 4111-1111-1111-1111");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn reject_invalid_card_number() {
        let matches = detect_credit_cards("not a card: 1234567890123");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn detect_ssn() {
        let matches = detect_ssns("ssn is 123-45-6789 in this text");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "123-45-6789");
    }

    #[test]
    fn reject_invalid_ssn() {
        let matches = detect_ssns("not ssn: 000-00-0000");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn detect_api_key() {
        let matches = detect_api_keys("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assert_eq!(matches.len(), 1);
        assert!(matches[0].0.starts_with("Bearer "));
    }

    #[test]
    fn detect_github_token() {
        let matches = detect_api_keys("token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn detect_aws_key() {
        let matches = detect_api_keys("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn detect_custom_keywords() {
        let matches = detect_keywords(
            "This document is CONFIDENTIAL and contains PROPRIETARY information",
            &["confidential".to_string(), "proprietary".to_string()],
        );
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn dlp_scanner_blocks_credit_card() {
        let scanner = DlpScanner::with_defaults();
        let content = b"Please process payment for card 4111111111111111";
        let matches = scanner.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "credit-card");
    }

    #[test]
    fn dlp_scanner_inspector_blocks() {
        let scanner = DlpScanner::with_defaults();
        let mut flow = Flow::new();
        flow.inspect_buffer = b"card number: 4111111111111111".to_vec();

        let verdict = scanner.inspect(&flow);
        assert!(matches!(verdict, Verdict::Block { .. }));
    }

    #[test]
    fn dlp_scanner_allows_clean_content() {
        let scanner = DlpScanner::with_defaults();
        let mut flow = Flow::new();
        flow.inspect_buffer = b"Hello, this is a normal message".to_vec();

        let verdict = scanner.inspect(&flow);
        assert_eq!(verdict, Verdict::Allow);
    }

    #[test]
    fn luhn_validates_known_numbers() {
        assert!(luhn_check("4111111111111111")); // Visa
        assert!(luhn_check("5500000000000004")); // Mastercard
        assert!(luhn_check("340000000000009"));  // Amex
        assert!(!luhn_check("1234567890123456")); // Invalid
    }
}
