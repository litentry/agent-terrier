//! Per-field formatters + intent interpolator (issue #82).
//!
//! Maps ERC-7730 `display.formats[…].fields[].format` strings to operator-
//! readable text. Implements the v0 subset:
//!
//! - `tokenAmount`: `1000000` with `{decimals: 6, ticker: "USDC"}` → `"1.00 USDC"`
//! - `address`: `0xabc...123` → `"0xabc…123"` (truncated for display) or full hex
//! - `integer`: raw integer rendered with thousands separators
//! - `date`: UNIX seconds → ISO-8601 UTC
//! - `bool`: `true`/`false` → `"true"`/`"false"`
//! - `raw` / unknown: hex-encoded bytes / stringified value
//!
//! Intent interpolation: `"Approve {value} to {spender}"` →
//! `"Approve 1.00 USDC to 0xabc…123"` by looking up `{name}` against the
//! field path map.

use std::collections::BTreeMap;

use super::parser::{Erc7730Field, Erc7730Format};

/// Map of field path → rendered value, built from the message + ERC-7730
/// formats. Indexed by the path AND by the leaf name (the trailing segment),
/// so an intent string `{value}` resolves whether the path is `value` or
/// `permit.value`.
pub struct RenderedFields {
    by_path: BTreeMap<String, String>,
    by_leaf: BTreeMap<String, String>,
}

impl RenderedFields {
    pub fn render(message: &serde_json::Value, format: &Erc7730Format) -> Self {
        let mut by_path = BTreeMap::new();
        let mut by_leaf = BTreeMap::new();
        for field in &format.fields {
            let raw = lookup_path(message, &field.path);
            let rendered = render_field(field, raw);
            by_path.insert(field.path.clone(), rendered.clone());
            if let Some(leaf) = field.path.rsplit('.').next() {
                by_leaf.insert(leaf.to_string(), rendered);
            }
        }
        Self { by_path, by_leaf }
    }

    pub fn lookup(&self, key: &str) -> Option<&str> {
        self.by_path
            .get(key)
            .or_else(|| self.by_leaf.get(key))
            .map(String::as_str)
    }

    /// Iterate (label, rendered) pairs in the order they appear in
    /// `format.fields`. The label falls back to the path when not set.
    pub fn iter_pairs<'a>(
        &'a self,
        format: &'a Erc7730Format,
    ) -> impl Iterator<Item = (&'a str, &'a str)> {
        format.fields.iter().map(|f| {
            let label = f.label.as_deref().unwrap_or(&f.path);
            let rendered = self.by_path.get(&f.path).map(String::as_str).unwrap_or("?");
            (label, rendered)
        })
    }
}

/// Interpolate `"Approve {value} to {spender}"` against a rendered field map.
/// Unknown `{name}` references are left in place so the operator can see
/// when a 7730 file references a field the typed data doesn't carry.
pub fn interpolate_intent(template: &str, fields: &RenderedFields) -> String {
    let mut out = String::with_capacity(template.len() + 64);
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        if let Some(end) = rest.find('}') {
            let name = &rest[1..end];
            match fields.lookup(name) {
                Some(rendered) => out.push_str(rendered),
                None => {
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
            }
            rest = &rest[end + 1..];
        } else {
            out.push_str(rest);
            break;
        }
    }
    out.push_str(rest);
    out
}

fn render_field(field: &Erc7730Field, raw: Option<&serde_json::Value>) -> String {
    let raw = match raw {
        Some(v) => v,
        None => return "?".to_string(),
    };
    match field.format.as_str() {
        "tokenAmount" => render_token_amount(raw, &field.params),
        "address" => render_address(raw, &field.params),
        "integer" => render_integer(raw),
        "date" => render_date(raw),
        "bool" => render_bool(raw),
        _ => render_raw(raw),
    }
}

fn render_token_amount(raw: &serde_json::Value, params: &serde_json::Value) -> String {
    let decimals = params
        .get("decimals")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    let ticker = params
        .get("ticker")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    let raw_str = match raw {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return render_raw(raw),
    };
    let n_str = raw_str.trim_start_matches('-');
    let neg = raw_str.starts_with('-');

    let formatted = if decimals == 0 {
        n_str.to_string()
    } else if n_str.len() <= decimals {
        let padded = format!("{:0>width$}", n_str, width = decimals + 1);
        let split_at = padded.len() - decimals;
        let (int_part, frac_part) = padded.split_at(split_at);
        let frac_trimmed = frac_part.trim_end_matches('0');
        if frac_trimmed.is_empty() {
            int_part.to_string()
        } else {
            format!("{int_part}.{frac_trimmed}")
        }
    } else {
        let split_at = n_str.len() - decimals;
        let (int_part, frac_part) = n_str.split_at(split_at);
        let frac_trimmed = frac_part.trim_end_matches('0');
        if frac_trimmed.is_empty() {
            int_part.to_string()
        } else {
            format!("{int_part}.{frac_trimmed}")
        }
    };

    let with_sign = if neg {
        format!("-{formatted}")
    } else {
        formatted
    };
    if ticker.is_empty() {
        with_sign
    } else {
        format!("{with_sign} {ticker}")
    }
}

fn render_address(raw: &serde_json::Value, params: &serde_json::Value) -> String {
    let s = match raw.as_str() {
        Some(s) => s.to_lowercase(),
        None => return render_raw(raw),
    };
    let truncate = params
        .get("truncate")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    if !truncate || s.len() < 12 {
        return s;
    }
    format!("{}…{}", &s[..6], &s[s.len() - 4..])
}

fn render_integer(raw: &serde_json::Value) -> String {
    match raw {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => render_raw(raw),
    }
}

fn render_date(raw: &serde_json::Value) -> String {
    let secs = match raw {
        serde_json::Value::String(s) => s.parse::<i64>().ok(),
        serde_json::Value::Number(n) => n.as_i64(),
        _ => None,
    };
    match secs {
        Some(s) => format_unix_seconds_utc(s),
        None => render_raw(raw),
    }
}

fn render_bool(raw: &serde_json::Value) -> String {
    match raw {
        serde_json::Value::Bool(b) => b.to_string(),
        _ => render_raw(raw),
    }
}

fn render_raw(raw: &serde_json::Value) -> String {
    match raw {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Format `secs` (Unix epoch seconds) as `YYYY-MM-DDTHH:MM:SSZ` without
/// pulling in a date crate. Algorithm: Howard Hinnant's civil-from-days
/// (see <https://howardhinnant.github.io/date_algorithms.html>).
fn format_unix_seconds_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = sod / 3600;
    let mm = (sod % 3600) / 60;
    let ss = sod % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

fn lookup_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = value;
    for segment in path.split('.') {
        if let Ok(idx) = segment.parse::<usize>() {
            cur = cur.as_array().and_then(|a| a.get(idx))?;
        } else {
            cur = cur.get(segment)?;
        }
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_amount_renders_with_decimals_and_ticker() {
        let r = render_token_amount(&json!("1000000"), &json!({"decimals": 6, "ticker": "USDC"}));
        assert_eq!(r, "1 USDC");

        let r = render_token_amount(
            &json!("1234500000"),
            &json!({"decimals": 6, "ticker": "USDC"}),
        );
        assert_eq!(r, "1234.5 USDC");

        let r = render_token_amount(&json!("500000"), &json!({"decimals": 6, "ticker": "USDC"}));
        assert_eq!(r, "0.5 USDC");

        let r = render_token_amount(&json!("0"), &json!({"decimals": 6, "ticker": "USDC"}));
        assert_eq!(r, "0 USDC");
    }

    #[test]
    fn address_truncates_by_default() {
        let r = render_address(
            &json!("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
            &json!({}),
        );
        assert_eq!(r, "0xcccc…cccc");
    }

    #[test]
    fn address_can_be_full() {
        let r = render_address(
            &json!("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
            &json!({"truncate": false}),
        );
        assert_eq!(r, format!("0x{}", "c".repeat(40)));
    }

    #[test]
    fn interpolate_replaces_known_fields_leaves_unknown() {
        let format = Erc7730Format {
            intent: Some("Approve {value} to {spender}".into()),
            fields: vec![
                Erc7730Field {
                    path: "value".into(),
                    label: None,
                    format: "tokenAmount".into(),
                    params: json!({"decimals": 6, "ticker": "USDC"}),
                },
                Erc7730Field {
                    path: "spender".into(),
                    label: None,
                    format: "address".into(),
                    params: json!({"truncate": true}),
                },
            ],
        };
        let msg =
            json!({"value": "1000000", "spender": "0xaaaabbbbccccddddeeeeffff0000111122223333"});
        let rendered = RenderedFields::render(&msg, &format);
        let s = interpolate_intent("Approve {value} to {spender} maybe {unknown}", &rendered);
        assert_eq!(s, "Approve 1 USDC to 0xaaaa…3333 maybe {unknown}");
    }

    #[test]
    fn date_renders_iso8601_utc() {
        let r = render_date(&json!(1_700_000_000));
        // 2023-11-14T22:13:20 UTC.
        assert_eq!(r, "2023-11-14T22:13:20Z");
    }

    #[test]
    fn lookup_path_walks_nested() {
        let v = json!({"permit": {"value": "42"}});
        assert_eq!(lookup_path(&v, "permit.value"), Some(&json!("42")));
        assert_eq!(lookup_path(&v, "permit.missing"), None);
    }
}
