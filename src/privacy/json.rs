//! Duplicate keys must fail, not silently replace an earlier sensitive field.
use anyhow::Result;
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{collections::HashSet, fmt};

struct UniqueKeys;
impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Check;
        impl<'de> Visitor<'de> for Check {
            type Value = UniqueKeys;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueKeys)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueKeys)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueKeys)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueKeys)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueKeys)
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueKeys)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                while seq.next_element::<UniqueKeys>()?.is_some() {}
                Ok(UniqueKeys)
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut seen = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    map.next_value::<UniqueKeys>()?;
                }
                Ok(UniqueKeys)
            }
        }
        deserializer.deserialize_any(Check)
    }
}
pub(super) fn parse(text: &str) -> Result<Value> {
    // Validate separately so serde_json retains arbitrary-precision numbers using
    // its own representation, not a custom float conversion in our visitor.
    let mut d = serde_json::Deserializer::from_str(text);
    UniqueKeys::deserialize(&mut d)
        .map_err(|_| anyhow::anyhow!("invalid JSON or duplicate object key"))?;
    d.end()
        .map_err(|_| anyhow::anyhow!("invalid JSON or trailing data"))?;
    let raw: &serde_json::value::RawValue =
        serde_json::from_str(text).map_err(|_| anyhow::anyhow!("invalid JSON value"))?;
    raw_value(raw).map_err(|_| anyhow::anyhow!("invalid JSON value"))
}
fn raw_value(raw: &serde_json::value::RawValue) -> serde_json::Result<Value> {
    // Avoid Value's private arbitrary-precision number map protocol: a real
    // object key named "$serde_json::private::Number" must stay an object key.
    let text = raw.get();
    Ok(match text.as_bytes()[0] {
        b'{' => {
            let map: std::collections::BTreeMap<String, &serde_json::value::RawValue> =
                serde_json::from_str(text)?;
            Value::Object(
                map.into_iter()
                    .map(|(k, v)| Ok((k, raw_value(v)?)))
                    .collect::<serde_json::Result<_>>()?,
            )
        }
        b'[' => {
            let values: Vec<&serde_json::value::RawValue> = serde_json::from_str(text)?;
            Value::Array(
                values
                    .into_iter()
                    .map(raw_value)
                    .collect::<serde_json::Result<_>>()?,
            )
        }
        b'"' => Value::String(serde_json::from_str(text)?),
        b'n' => Value::Null,
        b't' => Value::Bool(true),
        b'f' => Value::Bool(false),
        _ => Value::Number(serde_json::from_str(text)?),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_and_escaped_keys_fail_at_any_depth() {
        for text in [
            r#"{"secret":1,"secret":2}"#,
            r#"{"x":[{"a":1,"\u0061":2}]}"#,
        ] {
            assert!(parse(text).is_err());
        }
    }
    #[test]
    fn implementation_marker_keys_remain_ordinary_object_keys() {
        let value=parse(r#"{"$serde_json::private::Number":"Alice","nested":{"$serde_json::private::Number":"123"}}"#).unwrap();
        assert_eq!(value["$serde_json::private::Number"], "Alice");
        assert_eq!(value["nested"]["$serde_json::private::Number"], "123");
    }
    #[test]
    fn numbers_remain_exact_and_trailing_data_fails() {
        let v =
            parse(r#"{"n":123456789012345678901234567890,"d":0.123456789012345678901234567890}"#)
                .unwrap();
        assert_eq!(v["n"].to_string(), "123456789012345678901234567890");
        assert_eq!(v["d"].to_string(), "0.123456789012345678901234567890");
        assert!(parse("{} {}").is_err());
    }
}
