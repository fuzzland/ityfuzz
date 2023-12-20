use std::{
    collections::{BTreeMap, HashMap},
    fmt::{Display, Formatter},
};

use alloy_dyn_abi::{DynSolType, DynSolValue, JsonAbiExt, ResolveSolType};
use alloy_json_abi::Function;
use alloy_primitives::{hex, U256};
use anyhow::Result;
use serde::Serialize;

use crate::evm::utils::prettify_value;

#[derive(Debug, Default)]
pub struct Abi {
    /// map<struct_signature, struct_definition>
    /// e.g. struct SomeStruct { uint256 p0; uint256 p1; }
    pub struct_defs: Option<HashMap<String, StructDef>>,
    /// map<struct_signature, nonce>
    /// `struct_nonces` is used to generate unique struct variable names
    pub struct_nonces: HashMap<String, usize>,
    /// map<var_name, struct_instance>
    /// e.g. SomeStruct memory s1 = SomeStruct(1, 2);
    pub struct_instances: Option<BTreeMap<String, StructInstance>>,
    /// map<var_name, array_info>
    pub arrays: Option<BTreeMap<String, ArrayInfo>>,
    /// `array_nonce` is used to generate unique array variable names
    pub array_nonce: usize,
    /// map<tuple_signature, struct_name>
    pub tuple_struct_names: HashMap<String, String>,
}

#[derive(Debug, Default, Serialize, Clone, PartialEq, Eq)]
pub struct StructDef {
    pub name: String,
    // e.g. uint256 p0
    pub props: Vec<String>,
}

#[derive(Debug, Default)]
pub struct StructInstance {
    pub struct_name: String,
    pub var_name: String,
    pub value: String,
}

impl Display for StructInstance {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} memory {} = {};", self.struct_name, self.var_name, self.value)
    }
}

#[derive(Debug, Default)]
pub struct ArrayInfo {
    /// SomeType[] memory a = new SomeType[](2)
    pub declaration: String,
    /// a[0] = SomeType(...)
    /// a[1] = SomeType(...)
    pub assignments: Vec<String>,
}

#[derive(Debug, Default)]
pub struct DecodedArg {
    pub ty: String,
    pub value: String,
}

impl DecodedArg {
    pub fn new(ty: &str, value: String) -> Self {
        Self {
            ty: ty.to_string(),
            value,
        }
    }
}

impl Abi {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decode_input(&mut self, sig: &str, input: &str) -> Result<Vec<DecodedArg>> {
        let func = Function::parse(sig)?;
        let calldata = hex::decode(input)?;
        let tokens = func.abi_decode_input(&calldata[4..], false)?;
        let mut args = vec![];
        for (i, t) in tokens.iter().enumerate() {
            let token_type = func.inputs[i].resolve()?;
            let arg_type = token_type.sol_type_name().to_string();

            let arg = self.format_token(t, Some(token_type));
            args.push(DecodedArg::new(&arg_type, arg));
        }

        Ok(args)
    }

    pub fn take_struct_defs(&mut self) -> HashMap<String, StructDef> {
        self.struct_defs.take().unwrap_or_default()
    }

    pub fn take_memory_vars(&mut self) -> Vec<String> {
        let mut vars = Vec::new();
        if let Some(arrays) = self.arrays.take() {
            // put all declarations before assignments
            let mut arr_assignments = Vec::new();
            for (_, array_info) in arrays {
                vars.push(array_info.declaration);
                arr_assignments.extend(array_info.assignments);
            }
            vars.extend(arr_assignments);
        }
        if let Some(struct_instances) = self.struct_instances.take() {
            vars.extend(struct_instances.values().map(|s| s.to_string()));
        }
        vars
    }

    fn format_token(&mut self, token: &DynSolValue, token_type: Option<DynSolType>) -> String {
        let token_type = token_type.unwrap_or_else(|| token.as_type().expect("unknown type"));

        match token {
            DynSolValue::FixedArray(tokens) => self.build_array(token_type, tokens, true),
            DynSolValue::Array(tokens) => self.build_array(token_type, tokens, false),
            DynSolValue::Tuple(tokens) => {
                let struct_name = self.build_tuple_struct_name(token_type);
                let prop_names = (0..tokens.len()).map(|i| format!("p{}", i)).collect::<Vec<String>>();
                self.build_struct(&struct_name, &prop_names, tokens)
            }
            DynSolValue::CustomStruct {
                name,
                prop_names,
                tuple,
            } => self.build_struct(name, prop_names, tuple),
            t => format_token_raw(t),
        }
    }

    fn build_struct(&mut self, name: &str, prop_names: &[String], tuple: &[DynSolValue]) -> String {
        // build struct signature
        let types = tuple
            .iter()
            .map(|t| t.as_type().expect("unknown type").to_string())
            .collect::<Vec<String>>()
            .join(",");
        let signature = format!("({})", types);

        // build struct definition
        let props = self.build_struct_props(tuple, prop_names);
        let struct_def = StructDef {
            name: name.to_string(),
            props,
        };
        self.struct_defs
            .get_or_insert_with(HashMap::new)
            .insert(signature.clone(), struct_def);

        // build struct instance
        self.struct_nonces
            .entry(signature.clone())
            .and_modify(|nonce| *nonce += 1)
            .or_insert(0);
        let var_name = format!("{}{}", name.to_lowercase(), self.struct_nonces[&signature]);
        let struct_instance = StructInstance {
            struct_name: name.to_string(),
            var_name: var_name.clone(),
            value: format!("{}({})", name, self.build_struct_args(tuple)),
        };
        self.struct_instances
            .get_or_insert_with(BTreeMap::new)
            .insert(var_name.clone(), struct_instance);

        var_name
    }

    fn build_struct_props(&mut self, tuple: &[DynSolValue], prop_names: &[String]) -> Vec<String> {
        tuple
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let prop_name = prop_names[i].to_string();
                let prop_type = t.as_type().expect("unknown type");
                format!("{} {}", prop_type, prop_name)
            })
            .collect::<Vec<String>>()
    }

    fn build_struct_args(&mut self, tuple: &[DynSolValue]) -> String {
        tuple
            .iter()
            .map(|t| self.format_token(t, None))
            .collect::<Vec<String>>()
            .join(", ")
    }

    fn build_tuple_struct_name(&mut self, tuple: DynSolType) -> String {
        let signature = tuple.sol_type_name().to_string();
        let tuple_len = self.tuple_struct_names.len();
        let struct_name = self
            .tuple_struct_names
            .entry(signature)
            .or_insert(format!("S{}", tuple_len));
        struct_name.to_string()
    }

    fn build_array(&mut self, array_type: DynSolType, tokens: &[DynSolValue], is_fixed: bool) -> String {
        let array_name = self.build_array_name();
        let array_info = self.build_array_info(array_type, &array_name, tokens, is_fixed);
        self.arrays
            .get_or_insert_with(BTreeMap::new)
            .insert(array_name.clone(), array_info);
        array_name
    }

    fn build_array_name(&mut self) -> String {
        let name = format!("arr{}", self.array_nonce);
        self.array_nonce += 1;
        name
    }

    fn build_array_info(
        &mut self,
        array_type: DynSolType,
        array_name: &str,
        tokens: &[DynSolValue],
        is_fixed: bool,
    ) -> ArrayInfo {
        let assignments = tokens
            .iter()
            .enumerate()
            .map(|(i, t)| {
                format!(
                    "{}[{}] = {};",
                    array_name,
                    i,
                    self.format_array_item(t, array_type.clone())
                )
            })
            .collect::<Vec<String>>();

        let ty = self.format_array_type(&array_type);
        let array_len = tokens.len();
        let declaration = if is_fixed {
            format!("{} memory {};", ty, array_name)
        } else {
            format!("{} memory {} = new {}({});", ty, array_name, ty, array_len)
        };

        ArrayInfo {
            declaration,
            assignments,
        }
    }

    fn format_array_type(&self, array_type: &DynSolType) -> String {
        let mut ty = array_type.sol_type_name().to_string();
        // change tuple array type to struct array type
        if ty.starts_with('(') && ty.ends_with("[]") {
            let tuple_sig = ty.trim_end_matches("[]");
            let struct_name = self.struct_defs.as_ref().unwrap()[tuple_sig].name.clone();
            ty = format!("{}[]", struct_name);
        }

        ty
    }

    fn format_array_item(&mut self, token: &DynSolValue, token_type: DynSolType) -> String {
        match token {
            DynSolValue::Tuple(..) | DynSolValue::CustomStruct { .. } => {
                let var_name = self.format_token(token, Some(token_type));
                let struct_instance = self
                    .struct_instances
                    .get_or_insert_with(BTreeMap::new)
                    .remove(&var_name)
                    .expect("struct instance not found");

                struct_instance.value
            }
            _ => self.format_token(token, Some(token_type)),
        }
    }
}

pub fn format_token_raw(token: &DynSolValue) -> String {
    match token {
        DynSolValue::Address(addr) => addr.to_checksum(None),
        DynSolValue::FixedBytes(bytes, _) => {
            if bytes.is_empty() {
                String::from("\"\"")
            } else {
                hex::encode_prefixed(bytes)
            }
        }
        DynSolValue::Bytes(bytes) => {
            if bytes.is_empty() {
                String::from("\"\"")
            } else {
                format!("hex\"{}\"", hex::encode(bytes))
            }
        }
        DynSolValue::Int(num, _) => num.to_string(),
        DynSolValue::Uint(num, _) => {
            if num == &U256::MAX {
                String::from("type(uint256).max")
            } else {
                prettify_value(*num)
            }
        }
        DynSolValue::Bool(b) => b.to_string(),
        DynSolValue::String(s) => format!("\"{s}\""),
        DynSolValue::FixedArray(tokens) => format!("[{}]", format_array(tokens)),
        DynSolValue::Array(tokens) => format!("[{}]", format_array(tokens)),
        DynSolValue::Tuple(tokens) => format!("({})", format_array(tokens)),
        DynSolValue::CustomStruct {
            name: _,
            prop_names: _,
            tuple,
        } => format!("({})", format_array(tuple)),
        DynSolValue::Function(f) => f.to_address_and_selector().1.to_string(),
    }
}

fn format_array(tokens: &[DynSolValue]) -> String {
    tokens.iter().map(format_token_raw).collect::<Vec<String>>().join(", ")
}
