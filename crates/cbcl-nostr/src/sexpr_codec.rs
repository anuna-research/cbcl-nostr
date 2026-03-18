//! S-expression codec for Nostr event content fields.
//!
//! Parses Nostr event `content` strings into [`SExpr`] trees and serializes
//! them back. Uses `cbcl-parser::parse_with_fuel` with configurable fuel bounds
//! to prevent unbounded resource consumption from untrusted Nostr events.
//!
//! Also provides a JSON-safe encoding for CBCL [`Atom`] variants, mapping each
//! typed atom to/from a tagged string representation suitable for JSON transport.

#![forbid(unsafe_code)]

use cbcl_core::serializer::serialize;
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_parser::parser::{parse_with_fuel, ParseError};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default fuel budget for parsing untrusted Nostr event content.
///
/// Set conservatively: 8 KiB of input ≈ 8192 fuel units. This prevents
/// deeply-nested or pathologically-large payloads from consuming unbounded
/// resources while still allowing any realistic CBCL message.
pub const DEFAULT_FUEL: usize = 8192;

// ---------------------------------------------------------------------------
// Codec error
// ---------------------------------------------------------------------------

/// Errors that can occur during S-expression codec operations.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The content string failed to parse as a valid S-expression.
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    /// Content string was empty or whitespace-only.
    #[error("empty content")]
    EmptyContent,

    /// A JSON-safe atom string had an unrecognized type tag prefix.
    #[error("invalid atom tag: {0:?}")]
    InvalidAtomTag(String),

    /// A JSON-safe atom string for a Num could not be parsed as i64.
    #[error("invalid number in atom: {0}")]
    InvalidNumber(String),

    /// A JSON-safe atom string for a Bool was not "true" or "false".
    #[error("invalid bool in atom: {0}")]
    InvalidBool(String),
}

// ---------------------------------------------------------------------------
// Parse / Serialize
// ---------------------------------------------------------------------------

/// Parse a Nostr event `content` string into an S-expression tree.
///
/// Uses the default fuel budget ([`DEFAULT_FUEL`]). Returns [`CodecError::EmptyContent`]
/// for blank input, or [`CodecError::Parse`] for malformed S-expressions.
pub fn decode(content: &str) -> Result<SExpr, CodecError> {
    decode_with_fuel(content, DEFAULT_FUEL)
}

/// Parse with an explicit fuel limit.
pub fn decode_with_fuel(content: &str, fuel: usize) -> Result<SExpr, CodecError> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(CodecError::EmptyContent);
    }
    let expr = parse_with_fuel(trimmed, Some(fuel))?;
    Ok(expr)
}

/// Serialize an S-expression tree back to a Nostr event `content` string.
///
/// Uses the canonical serializer from `cbcl-core` which guarantees
/// `decode(encode(x)) == Ok(x)` for all valid `SExpr`.
pub fn encode(sexpr: &SExpr) -> String {
    serialize(sexpr)
}

// ---------------------------------------------------------------------------
// JSON-safe Atom mapping
// ---------------------------------------------------------------------------

/// Atom type tag prefixes for JSON-safe encoding.
///
/// Each CBCL atom variant maps to a single-character prefix followed by
/// the value, ensuring injectivity (no two distinct atoms produce the
/// same string).
///
/// | Variant        | Tag  | JSON string              |
/// |----------------|------|--------------------------|
/// | `Symbol(s)`    | `S:` | `"S:<symbol>"`           |
/// | `Str(s)`       | `Q:` | `"Q:<string-value>"`     |
/// | `Num(n)`       | `N:` | `"N:<decimal>"`          |
/// | `Bool(b)`      | `B:` | `"B:true"` / `"B:false"` |
/// | `Keyword(k)`   | `K:` | `"K:<keyword>"`          |
const TAG_SYMBOL: &str = "S:";
const TAG_STR: &str = "Q:";
const TAG_NUM: &str = "N:";
const TAG_BOOL: &str = "B:";
const TAG_KEYWORD: &str = "K:";

/// Encode a CBCL [`Atom`] as a JSON-safe tagged string.
///
/// The encoding is injective: distinct atoms always produce distinct strings.
pub fn atom_to_json_string(atom: &Atom) -> String {
    match atom {
        Atom::Symbol(s) => format!("{TAG_SYMBOL}{s}"),
        Atom::Str(s) => format!("{TAG_STR}{s}"),
        Atom::Num(n) => format!("{TAG_NUM}{n}"),
        Atom::Bool(b) => format!("{TAG_BOOL}{b}"),
        Atom::Keyword(k) => format!("{TAG_KEYWORD}{k}"),
    }
}

/// Decode a JSON-safe tagged string back into a CBCL [`Atom`].
pub fn atom_from_json_string(s: &str) -> Result<Atom, CodecError> {
    if let Some(rest) = s.strip_prefix(TAG_SYMBOL) {
        return Ok(Atom::Symbol(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix(TAG_STR) {
        return Ok(Atom::Str(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix(TAG_NUM) {
        let n: i64 = rest
            .parse()
            .map_err(|_| CodecError::InvalidNumber(rest.to_string()))?;
        return Ok(Atom::Num(n));
    }
    if let Some(rest) = s.strip_prefix(TAG_BOOL) {
        return match rest {
            "true" => Ok(Atom::Bool(true)),
            "false" => Ok(Atom::Bool(false)),
            _ => Err(CodecError::InvalidBool(rest.to_string())),
        };
    }
    if let Some(rest) = s.strip_prefix(TAG_KEYWORD) {
        return Ok(Atom::Keyword(rest.to_string()));
    }
    Err(CodecError::InvalidAtomTag(s.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // Parse (decode) tests
    // ====================================================================

    #[test]
    fn decode_simple_tell() {
        let content = r#"(tell @bob "The meeting is at 3pm")"#;
        let expr = decode(content).unwrap();
        assert!(matches!(&expr, SExpr::List(items) if items.len() == 3));
    }

    #[test]
    fn decode_with_keywords() {
        let content = r#"(ask @alice "What is the status?" :thread "conv-17")"#;
        let expr = decode(content).unwrap();
        if let SExpr::List(items) = &expr {
            assert_eq!(items.len(), 5);
            assert!(items[0].is_symbol("ask"));
            assert_eq!(items[3], SExpr::Atom(Atom::Keyword("thread".into())));
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn decode_nested() {
        let content = "(meta (define commerce :extends cbcl-base))";
        let expr = decode(content).unwrap();
        if let SExpr::List(items) = &expr {
            assert!(items[0].is_symbol("meta"));
            assert!(matches!(&items[1], SExpr::List(_)));
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn decode_all_atom_types() {
        let content = r#"(test "hello" 42 -7 #t #f :key symbol)"#;
        let expr = decode(content).unwrap();
        if let SExpr::List(items) = &expr {
            assert_eq!(items.len(), 8);
            assert!(items[0].is_symbol("test"));
            assert_eq!(items[1], SExpr::Atom(Atom::Str("hello".into())));
            assert_eq!(items[2], SExpr::Atom(Atom::Num(42)));
            assert_eq!(items[3], SExpr::Atom(Atom::Num(-7)));
            assert_eq!(items[4], SExpr::Atom(Atom::Bool(true)));
            assert_eq!(items[5], SExpr::Atom(Atom::Bool(false)));
            assert_eq!(items[6], SExpr::Atom(Atom::Keyword("key".into())));
            assert!(items[7].is_symbol("symbol"));
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn decode_empty_content_error() {
        assert!(matches!(decode(""), Err(CodecError::EmptyContent)));
        assert!(matches!(decode("   "), Err(CodecError::EmptyContent)));
    }

    #[test]
    fn decode_malformed_error() {
        assert!(matches!(
            decode("(unclosed"),
            Err(CodecError::Parse(_))
        ));
    }

    #[test]
    fn decode_fuel_exhaustion() {
        let deeply_nested = "(".repeat(100) + &")".repeat(100);
        let result = decode_with_fuel(&deeply_nested, 10);
        assert!(matches!(result, Err(CodecError::Parse(_))));
    }

    // ====================================================================
    // Serialize (encode) tests
    // ====================================================================

    #[test]
    fn encode_simple_list() {
        let expr = SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("tell".into())),
            SExpr::Atom(Atom::Str("hi".into())),
        ]);
        assert_eq!(encode(&expr), r#"(tell "hi")"#);
    }

    #[test]
    fn encode_with_all_atoms() {
        let expr = SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("x".into())),
            SExpr::Atom(Atom::Num(42)),
            SExpr::Atom(Atom::Bool(true)),
            SExpr::Atom(Atom::Keyword("k".into())),
            SExpr::Atom(Atom::Str("s".into())),
        ]);
        assert_eq!(encode(&expr), r#"(x 42 #t :k "s")"#);
    }

    // ====================================================================
    // Round-trip tests (REQ-031)
    // ====================================================================

    #[test]
    fn round_trip_simple() {
        let content = r#"(tell "hello world")"#;
        let expr = decode(content).unwrap();
        let re_encoded = encode(&expr);
        assert_eq!(re_encoded, content);
    }

    #[test]
    fn round_trip_complex() {
        let content = r#"(ask @alice "status?" :thread "conv-17" 42 #t)"#;
        let expr = decode(content).unwrap();
        let re_encoded = encode(&expr);
        let re_decoded = decode(&re_encoded).unwrap();
        assert_eq!(expr, re_decoded);
    }

    #[test]
    fn round_trip_nested() {
        let content = "(meta (define commerce :extends cbcl-base (rules (r1 #t))))";
        let expr = decode(content).unwrap();
        let re_encoded = encode(&expr);
        let re_decoded = decode(&re_encoded).unwrap();
        assert_eq!(expr, re_decoded);
    }

    #[test]
    fn round_trip_empty_list() {
        let content = "()";
        let expr = decode(content).unwrap();
        assert_eq!(encode(&expr), content);
    }

    #[test]
    fn round_trip_string_escapes() {
        let content = r#"(tell "a\"b\\c\n")"#;
        let expr = decode(content).unwrap();
        let re_encoded = encode(&expr);
        let re_decoded = decode(&re_encoded).unwrap();
        assert_eq!(expr, re_decoded);
    }

    // ====================================================================
    // JSON-safe atom mapping tests
    // ====================================================================

    #[test]
    fn atom_json_symbol() {
        let atom = Atom::Symbol("tell".into());
        let s = atom_to_json_string(&atom);
        assert_eq!(s, "S:tell");
        assert_eq!(atom_from_json_string(&s).unwrap(), atom);
    }

    #[test]
    fn atom_json_str() {
        let atom = Atom::Str("hello world".into());
        let s = atom_to_json_string(&atom);
        assert_eq!(s, "Q:hello world");
        assert_eq!(atom_from_json_string(&s).unwrap(), atom);
    }

    #[test]
    fn atom_json_num() {
        let atom = Atom::Num(42);
        let s = atom_to_json_string(&atom);
        assert_eq!(s, "N:42");
        assert_eq!(atom_from_json_string(&s).unwrap(), atom);
    }

    #[test]
    fn atom_json_num_negative() {
        let atom = Atom::Num(-99);
        let s = atom_to_json_string(&atom);
        assert_eq!(s, "N:-99");
        assert_eq!(atom_from_json_string(&s).unwrap(), atom);
    }

    #[test]
    fn atom_json_bool_true() {
        let atom = Atom::Bool(true);
        let s = atom_to_json_string(&atom);
        assert_eq!(s, "B:true");
        assert_eq!(atom_from_json_string(&s).unwrap(), atom);
    }

    #[test]
    fn atom_json_bool_false() {
        let atom = Atom::Bool(false);
        let s = atom_to_json_string(&atom);
        assert_eq!(s, "B:false");
        assert_eq!(atom_from_json_string(&s).unwrap(), atom);
    }

    #[test]
    fn atom_json_keyword() {
        let atom = Atom::Keyword("thread".into());
        let s = atom_to_json_string(&atom);
        assert_eq!(s, "K:thread");
        assert_eq!(atom_from_json_string(&s).unwrap(), atom);
    }

    #[test]
    fn atom_json_invalid_tag() {
        assert!(matches!(
            atom_from_json_string("X:unknown"),
            Err(CodecError::InvalidAtomTag(_))
        ));
    }

    #[test]
    fn atom_json_invalid_number() {
        assert!(matches!(
            atom_from_json_string("N:not_a_number"),
            Err(CodecError::InvalidNumber(_))
        ));
    }

    #[test]
    fn atom_json_invalid_bool() {
        assert!(matches!(
            atom_from_json_string("B:maybe"),
            Err(CodecError::InvalidBool(_))
        ));
    }

    #[test]
    fn atom_json_empty_values() {
        let atom = Atom::Symbol(String::new());
        let s = atom_to_json_string(&atom);
        assert_eq!(s, "S:");
        assert_eq!(atom_from_json_string(&s).unwrap(), atom);

        let atom = Atom::Str(String::new());
        let s = atom_to_json_string(&atom);
        assert_eq!(s, "Q:");
        assert_eq!(atom_from_json_string(&s).unwrap(), atom);
    }

    #[test]
    fn atom_json_injective() {
        // Distinct atoms must produce distinct JSON strings
        let atoms = vec![
            Atom::Symbol("t".into()),
            Atom::Bool(true),
            Atom::Symbol("42".into()),
            Atom::Num(42),
            Atom::Str("key".into()),
            Atom::Keyword("key".into()),
            Atom::Num(0),
            Atom::Symbol("0".into()),
        ];
        let strings: Vec<String> = atoms.iter().map(|a| atom_to_json_string(a)).collect();
        for i in 0..strings.len() {
            for j in (i + 1)..strings.len() {
                if strings[i] == strings[j] {
                    assert_eq!(
                        atoms[i], atoms[j],
                        "injectivity violation: {:?} and {:?} produce same string {:?}",
                        atoms[i], atoms[j], strings[i]
                    );
                }
            }
        }
    }

    // ====================================================================
    // JSON-safe atom round-trip through serde_json
    // ====================================================================

    #[test]
    fn atom_json_serde_round_trip() {
        let atoms = vec![
            Atom::Symbol("tell".into()),
            Atom::Str("hello \"world\"".into()),
            Atom::Num(i64::MAX),
            Atom::Num(i64::MIN),
            Atom::Bool(true),
            Atom::Bool(false),
            Atom::Keyword("thread".into()),
        ];
        for atom in atoms {
            let tagged = atom_to_json_string(&atom);
            let json_value = serde_json::to_string(&tagged).unwrap();
            let json_decoded: String = serde_json::from_str(&json_value).unwrap();
            let recovered = atom_from_json_string(&json_decoded).unwrap();
            assert_eq!(recovered, atom, "serde round-trip failed for: {tagged}");
        }
    }

    // ====================================================================
    // NIP-XX content examples (REQ-030)
    // ====================================================================

    #[test]
    fn nip_xx_tell_example() {
        let content = r#"(tell @d4e5f6 "Deploy to staging" :thread "conv-17")"#;
        let expr = decode(content).unwrap();
        let re = encode(&expr);
        let re_expr = decode(&re).unwrap();
        assert_eq!(expr, re_expr);
    }

    #[test]
    fn nip_xx_dialect_example() {
        let content = "(meta (define commerce :extends cbcl-base))";
        let expr = decode(content).unwrap();
        let re = encode(&expr);
        let re_expr = decode(&re).unwrap();
        assert_eq!(expr, re_expr);
    }

    #[test]
    fn nip_xx_ask_example() {
        let content = r#"(ask @alice "What is the status?" :thread "conv-17")"#;
        let expr = decode(content).unwrap();
        let re = encode(&expr);
        let re_expr = decode(&re).unwrap();
        assert_eq!(expr, re_expr);
    }

    // ====================================================================
    // Property: decode(encode(x)) == x
    // ====================================================================

    #[test]
    fn property_decode_encode_identity() {
        let cases = vec![
            SExpr::Atom(Atom::Symbol("hello".into())),
            SExpr::Atom(Atom::Num(0)),
            SExpr::Atom(Atom::Num(-1)),
            SExpr::Atom(Atom::Bool(true)),
            SExpr::Atom(Atom::Bool(false)),
            SExpr::Atom(Atom::Keyword("k".into())),
            SExpr::Atom(Atom::Str("with spaces".into())),
            SExpr::List(vec![]),
            SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("tell".into())),
                SExpr::Atom(Atom::Str("msg".into())),
                SExpr::Atom(Atom::Num(42)),
                SExpr::Atom(Atom::Bool(true)),
                SExpr::Atom(Atom::Keyword("key".into())),
            ]),
            SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("a".into())),
                SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("b".into())),
                    SExpr::List(vec![SExpr::Atom(Atom::Symbol("c".into()))]),
                ]),
            ]),
        ];
        for expr in cases {
            let encoded = encode(&expr);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, expr, "decode(encode(x)) != x for: {encoded}");
        }
    }
}
