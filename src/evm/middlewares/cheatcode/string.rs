use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_sol_types::SolValue;

pub(super) fn parse(s: &str, ty: &DynSolType) -> Option<Vec<u8>> {
    parse_value(s, ty).map(|v| v.abi_encode())
}

pub(super) fn parse_array<I, S>(values: I, ty: &DynSolType) -> Option<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut values = values.into_iter();
    match values.next() {
        Some(first) if !first.as_ref().is_empty() => std::iter::once(first)
            .chain(values)
            .map(|s| parse_value(s.as_ref(), ty))
            .collect::<Option<Vec<_>>>()
            .map(|vec| DynSolValue::Array(vec).abi_encode()),
        // return the empty encoded Bytes when values is empty or the first element is empty
        _ => Some("".abi_encode()),
    }
}

fn parse_value(s: &str, ty: &DynSolType) -> Option<DynSolValue> {
    match ty.coerce_str(s) {
        Ok(value) => Some(value),
        Err(_) => parse_value_fallback(s, ty),
    }
}

// More lenient parsers than `coerce_str`.
fn parse_value_fallback(s: &str, ty: &DynSolType) -> Option<DynSolValue> {
    if ty == &DynSolType::Bool {
        let b = match s {
            "1" => true,
            "0" => false,
            s if s.eq_ignore_ascii_case("true") => true,
            s if s.eq_ignore_ascii_case("false") => false,
            _ => {
                return None;
            }
        };
        return Some(DynSolValue::Bool(b));
    }

    None
}
