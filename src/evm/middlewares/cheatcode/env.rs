use std::{clone::Clone, env};

use alloy_dyn_abi::DynSolType;
use alloy_sol_types::SolValue;
use foundry_cheatcodes::Vm;
use libafl::schedulers::Scheduler;

use super::{string, Cheatcode};
use crate::evm::types::EVMFuzzState;

/// Cheat VmCalls
impl<SC> Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    #[inline]
    pub fn set_env(&self, args: Vm::setEnvCall) -> Option<Vec<u8>> {
        let Vm::setEnvCall { name, value } = args;
        env::set_var(name, value);
        None
    }

    #[inline]
    pub fn env_bool0(&self, args: Vm::envBool_0Call) -> Option<Vec<u8>> {
        let Vm::envBool_0Call { name } = args;
        get_env(&name, &DynSolType::Bool)
    }

    #[inline]
    pub fn env_uint0(&self, args: Vm::envUint_0Call) -> Option<Vec<u8>> {
        let Vm::envUint_0Call { name } = args;
        get_env(&name, &DynSolType::Uint(256))
    }

    #[inline]
    pub fn env_int0(&self, args: Vm::envInt_0Call) -> Option<Vec<u8>> {
        let Vm::envInt_0Call { name } = args;
        get_env(&name, &DynSolType::Int(256))
    }

    #[inline]
    pub fn env_address0(&self, args: Vm::envAddress_0Call) -> Option<Vec<u8>> {
        let Vm::envAddress_0Call { name } = args;
        get_env(&name, &DynSolType::Address)
    }

    #[inline]
    pub fn env_bytes32_0(&self, args: Vm::envBytes32_0Call) -> Option<Vec<u8>> {
        let Vm::envBytes32_0Call { name } = args;
        get_env(&name, &DynSolType::FixedBytes(32))
    }

    #[inline]
    pub fn env_string(&self, args: Vm::envString_0Call) -> Option<Vec<u8>> {
        let Vm::envString_0Call { name } = args;
        get_env(&name, &DynSolType::String)
    }

    #[inline]
    pub fn env_bytes(&self, args: Vm::envBytes_0Call) -> Option<Vec<u8>> {
        let Vm::envBytes_0Call { name } = args;
        get_env(&name, &DynSolType::Bytes)
    }

    #[inline]
    pub fn env_bool1(&self, args: Vm::envBool_1Call) -> Option<Vec<u8>> {
        let Vm::envBool_1Call { name, delim } = args;
        get_env_array(&name, &delim, &DynSolType::Bool)
    }

    #[inline]
    pub fn env_uint1(&self, args: Vm::envUint_1Call) -> Option<Vec<u8>> {
        let Vm::envUint_1Call { name, delim } = args;
        get_env_array(&name, &delim, &DynSolType::Uint(256))
    }

    #[inline]
    pub fn env_int1(&self, args: Vm::envInt_1Call) -> Option<Vec<u8>> {
        let Vm::envInt_1Call { name, delim } = args;
        get_env_array(&name, &delim, &DynSolType::Int(256))
    }

    #[inline]
    pub fn env_address1(&self, args: Vm::envAddress_1Call) -> Option<Vec<u8>> {
        let Vm::envAddress_1Call { name, delim } = args;
        get_env_array(&name, &delim, &DynSolType::Address)
    }

    #[inline]
    pub fn env_bytes32_1(&self, args: Vm::envBytes32_1Call) -> Option<Vec<u8>> {
        let Vm::envBytes32_1Call { name, delim } = args;
        get_env_array(&name, &delim, &DynSolType::FixedBytes(32))
    }

    #[inline]
    pub fn env_string1(&self, args: Vm::envString_1Call) -> Option<Vec<u8>> {
        let Vm::envString_1Call { name, delim } = args;
        get_env_array(&name, &delim, &DynSolType::String)
    }

    #[inline]
    pub fn env_bytes1(&self, args: Vm::envBytes_1Call) -> Option<Vec<u8>> {
        let Vm::envBytes_1Call { name, delim } = args;
        get_env_array(&name, &delim, &DynSolType::Bytes)
    }

    // bool
    #[inline]
    pub fn env_or0(&self, args: Vm::envOr_0Call) -> Option<Vec<u8>> {
        let Vm::envOr_0Call { name, defaultValue } = args;
        get_env_default(&name, &defaultValue, &DynSolType::Bool)
    }

    // uint256
    #[inline]
    pub fn env_or1(&self, args: Vm::envOr_1Call) -> Option<Vec<u8>> {
        let Vm::envOr_1Call { name, defaultValue } = args;
        get_env_default(&name, &defaultValue, &DynSolType::Uint(256))
    }

    // int256
    #[inline]
    pub fn env_or2(&self, args: Vm::envOr_2Call) -> Option<Vec<u8>> {
        let Vm::envOr_2Call { name, defaultValue } = args;
        get_env_default(&name, &defaultValue, &DynSolType::Int(256))
    }

    // address
    #[inline]
    pub fn env_or3(&self, args: Vm::envOr_3Call) -> Option<Vec<u8>> {
        let Vm::envOr_3Call { name, defaultValue } = args;
        get_env_default(&name, &defaultValue, &DynSolType::Address)
    }

    // bytes32
    #[inline]
    pub fn env_or4(&self, args: Vm::envOr_4Call) -> Option<Vec<u8>> {
        let Vm::envOr_4Call { name, defaultValue } = args;
        get_env_default(&name, &defaultValue, &DynSolType::FixedBytes(32))
    }

    // string
    #[inline]
    pub fn env_or5(&self, args: Vm::envOr_5Call) -> Option<Vec<u8>> {
        let Vm::envOr_5Call { name, defaultValue } = args;
        get_env_default(&name, &defaultValue, &DynSolType::String)
    }

    // bytes
    #[inline]
    pub fn env_or6(&self, args: Vm::envOr_6Call) -> Option<Vec<u8>> {
        let Vm::envOr_6Call { name, defaultValue } = args;
        get_env_default(&name, &defaultValue, &DynSolType::Bytes)
    }

    // bool[]
    #[inline]
    pub fn env_or7(&self, args: Vm::envOr_7Call) -> Option<Vec<u8>> {
        let Vm::envOr_7Call {
            name,
            delim,
            defaultValue,
        } = args;
        get_env_array_default(&name, &delim, &defaultValue, &DynSolType::Bool)
    }

    // uint256[]
    #[inline]
    pub fn env_or8(&self, args: Vm::envOr_8Call) -> Option<Vec<u8>> {
        let Vm::envOr_8Call {
            name,
            delim,
            defaultValue,
        } = args;
        get_env_array_default(&name, &delim, &defaultValue, &DynSolType::Uint(256))
    }

    // int256[]
    #[inline]
    pub fn env_or9(&self, args: Vm::envOr_9Call) -> Option<Vec<u8>> {
        let Vm::envOr_9Call {
            name,
            delim,
            defaultValue,
        } = args;
        get_env_array_default(&name, &delim, &defaultValue, &DynSolType::Int(256))
    }

    // address[]
    #[inline]
    pub fn env_or10(&self, args: Vm::envOr_10Call) -> Option<Vec<u8>> {
        let Vm::envOr_10Call {
            name,
            delim,
            defaultValue,
        } = args;
        get_env_array_default(&name, &delim, &defaultValue, &DynSolType::Address)
    }

    // bytes32[]
    #[inline]
    pub fn env_or11(&self, args: Vm::envOr_11Call) -> Option<Vec<u8>> {
        let Vm::envOr_11Call {
            name,
            delim,
            defaultValue,
        } = args;
        get_env_array_default(&name, &delim, &defaultValue, &DynSolType::FixedBytes(32))
    }

    // string[]
    #[inline]
    pub fn env_or12(&self, args: Vm::envOr_12Call) -> Option<Vec<u8>> {
        let Vm::envOr_12Call {
            name,
            delim,
            defaultValue,
        } = args;
        get_env_array_default(&name, &delim, &defaultValue, &DynSolType::String)
    }

    // bytes[]
    #[inline]
    pub fn env_or13(&self, args: Vm::envOr_13Call) -> Option<Vec<u8>> {
        let Vm::envOr_13Call {
            name,
            delim,
            defaultValue,
        } = args;
        get_env_array_default(&name, &delim, &defaultValue, &DynSolType::Bytes)
    }
}

fn get_env(key: &str, ty: &DynSolType) -> Option<Vec<u8>> {
    env::var(key).ok().and_then(|val| string::parse(&val, ty))
}

fn get_env_default<T: SolValue>(key: &str, default: &T, ty: &DynSolType) -> Option<Vec<u8>> {
    Some(get_env(key, ty).unwrap_or_else(|| default.abi_encode()))
}

fn get_env_array(key: &str, delim: &str, ty: &DynSolType) -> Option<Vec<u8>> {
    env::var(key)
        .ok()
        .and_then(|val| string::parse_array(val.split(delim).map(str::trim), ty))
}

fn get_env_array_default<T: SolValue>(key: &str, delim: &str, default: &T, ty: &DynSolType) -> Option<Vec<u8>> {
    Some(get_env_array(key, delim, ty).unwrap_or_else(|| default.abi_encode()))
}
