/// Analysis passes for EVM bytecode

use crate::mutation_utils::ConstantPoolMetadata;
use libafl::state::{HasMetadata, State};

use revm_primitives::Bytecode;
use std::collections::HashSet;
use revm_interpreter::opcode::JUMPI;
use crate::evm::bytecode_iterator::all_bytecode;

/// Find all constants in the bytecode by observing PUSH instructions.
///
/// Check tests below for usage.
pub fn find_constants(bytecode: &Bytecode) -> HashSet<Vec<u8>> {
    let bytecode_len = bytecode.len();
    let mut constants = HashSet::new();
    let bytes = bytecode.bytes();

    let avail_bytecode = all_bytecode(&bytes.to_vec());
    for (pc, op) in avail_bytecode {
        if op >= 0x60 && op <= 0x7f {
            let next_op = if pc + op as usize - 0x5e < bytecode_len {
                bytes[pc + op as usize - 0x5e]
            } else {
                break;
            };
            if next_op == JUMPI {
                continue;
            }
            let mut data = vec![0u8; op as usize - 0x60 + 1];
            let mut i = 0;
            while i < op - 0x60 + 1 {
                let offset = i as usize;
                data[offset] = bytes[pc + offset + 1];
                i += 1;
            }
            constants.insert(data);
        }
    }
    constants
}

/// Add constants in smart contract to the global state's [`ConstantPoolMetadata`]
/// this can be costly, ensure sampling to be cheap
pub fn add_analysis_result_to_state<S>(bytecode: &Bytecode, state: &mut S)
where
    S: HasMetadata + State,
{
    let constants = find_constants(bytecode);
    match state.metadata_map_mut().get_mut::<ConstantPoolMetadata>() {
        Some(meta) => {
            for constant in constants {
                if !meta.constants.contains(&constant) {
                    meta.constants.push(constant);
                }
            }
        }
        None => {
            state.metadata_map_mut().insert(ConstantPoolMetadata {
                constants: constants.into_iter().collect(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm_primitives::{Bytecode, Bytes};

    #[test]
    fn test_find_constants() {
        let bytecode = Bytecode::new_raw(Bytes::from(
            hex::decode("6080604052600436106101c2576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146101c7578063095ea7b314610257578063179e91f1146102bc5780631801c4081461032b57806318160ddd1461035a57806323b872dd146103855780632e82aaf21461040a5780632f6c493c14610467578063313ce567146104be5780633f4ba83a146104ef5780634028db791461050657806342966c68146105615780634b0ee02a146105a65780634cb5465f146105fd5780635294d0e81461067a5780635c975abb146106df5780635ca48d8c1461070e57806370a082311461077357806371d66f00146107ca57806379ba50971461083357806381fc4d901461084a5780638456cb591461089d57806384aa2602146108b457806395d89b41146108eb5780639b03bea61461097b578063a0712d68146109d2578063a9059cbb14610a17578063a9dab16714610a7c578063ab4a2eb314610acf578063bc677b4614610b26578063cae9ca5114610b7d578063d71be8db14610c28578063dd62ed3e14610c9f578063dff96f8a14610d16578063e724529c14610d6d578063f2fde38b14610dd4575b600080fd5b3480156101d357600080fd5b506101dc610e17565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561021c578082015181840152602081019050610201565b50505050905090810190601f1680156102495780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561026357600080fd5b506102a2600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610eb5565b604051808215151515815260200191505060405180910390f35b3480156102c857600080fd5b50610315600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080356000191690602001909291908035906020019092919050505061109b565b6040518082815260200191505060405180910390f35b34801561033757600080fd5b50610340611166565b604051808215151515815260200191505060405180910390f35b34801561036657600080fd5b5061036f611273565b6040518082815260200191505060405180910390f35b34801561039157600080fd5b506103f0600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919050505061127d565b604051808215151515815260200191505060405180910390f35b34801561041657600080fd5b5061044d60048036038101908080356000191690602001909291908035906020019092919080359060200190929190505050611417565b604051808215151515815260200191505060405180910390f35b34801561047357600080fd5b506104a8600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061180f565b6040518082815260200191505060405180910390f35b3480156104ca57600080fd5b506104d3611b70565b604051808260ff1660ff16815260200191505060405180910390f35b3480156104fb57600080fd5b50610504611b83565b005b34801561051257600080fd5b50610547600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611c42565b604051808215151515815260200191505060405180910390f35b34801561056d57600080fd5b5061058c60048036038101908080359060200190929190505050611cbd565b604051808215151515815260200191505060405180910390f35b3480156105b257600080fd5b506105e7600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611e96565b6040518082815260200191505060405180910390f35b34801561060957600080fd5b50610660600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080356000191690602001909291908035906020019092919080359060200190929190505050611f7a565b604051808215151515815260200191505060405180910390f35b34801561068657600080fd5b506106c9600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035600019169060200190929190505050612373565b6040518082815260200191505060405180910390f35b3480156106eb57600080fd5b506106f46124b0565b604051808215151515815260200191505060405180910390f35b34801561071a57600080fd5b5061075d600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080356000191690602001909291905050506124c3565b6040518082815260200191505060405180910390f35b34801561077f57600080fd5b506107b4600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050612599565b6040518082815260200191505060405180910390f35b3480156107d657600080fd5b50610815600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050612607565b60405180826000191660001916815260200191505060405180910390f35b34801561083f57600080fd5b50610848612637565b005b34801561085657600080fd5b50610883600480360381019080803560001916906020019092919080359060200190929190505050612811565b604051808215151515815260200191505060405180910390f35b3480156108a957600080fd5b506108b2612b0e565b005b3480156108c057600080fd5b506108c9612bcd565b604051808263ffffffff1663ffffffff16815260200191505060405180910390f35b3480156108f757600080fd5b50610900612c42565b6040518080602001828103825283818151815260200191508051906020019080838360005b83811015610940578082015181840152602081019050610925565b50505050905090810190601f16801561096d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561098757600080fd5b506109bc600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050612ce0565b6040518082815260200191505060405180910390f35b3480156109de57600080fd5b506109fd60048036038101908080359060200190929190505050612d4e565b604051808215151515815260200191505060405180910390f35b348015610a2357600080fd5b50610a62600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050612f73565b604051808215151515815260200191505060405180910390f35b348015610a8857600080fd5b50610ab5600480360381019080803560001916906020019092919080359060200190929190505050612fa4565b604051808215151515815260200191505060405180910390f35b348015610adb57600080fd5b50610b10600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050613296565b6040518082815260200191505060405180910390f35b348015610b3257600080fd5b50610b3b61336f565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b348015610b8957600080fd5b50610c0e600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290505050613398565b604051808215151515815260200191505060405180910390f35b348015610c3457600080fd5b50610c77600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803560001916906020019092919050505061356b565b6040518084815260200183815260200182151515158152602001935050505060405180910390f35b348015610cab57600080fd5b50610d00600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506135af565b6040518082815260200191505060405180910390f35b348015610d2257600080fd5b50610d57600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050613681565b6040518082815260200191505060405180910390f35b348015610d7957600080fd5b50610dba600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035151590602001909291905050506136ef565b604051808215151515815260200191505060405180910390f35b348015610de057600080fd5b50610e15600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061381c565b005b60058054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610ead5780601f10610e8257610100808354040283529160200191610ead565b820191906000526020600020905b815481529060010190602001808311610e9057829003601f168201915b505050505081565b6000600160189054906101000a900460ff16151515610ed357600080fd5b60008373ffffffffffffffffffffffffffffffffffffffff1614151515610ef957600080fd5b600c60003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16151515610f5257600080fd5b600c60008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16151515610fab57600080fd5b81600960003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b600081600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000856000191660001916815260200190815260200160002060010154111561115f57600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084600019166000191681526020019081526020016000206000015490505b9392505050565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614806112105750600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16145b151561121b57600080fd5b600073ffffffffffffffffffffffffffffffffffffffff16600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161415905090565b6000600754905090565b6000600160189054906101000a900460ff1615151561129b57600080fd5b600c60003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515156112f457600080fd5b61138382600960008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546138bb90919063ffffffff16565b600960008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555061140e8484846138d7565b90509392505050565b600080600160189054906101000a900460ff1615151561143657600080fd5b6114498342613cc290919063ffffffff16565b9050600061145733876124c3565b146040805190810160405280601581526020017f546f6b656e7320616c7265616479206c6f636b65640000000000000000000000815250901515611536576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b838110156114fb5780820151818401526020810190506114e0565b50505050905090810190601f1680156115285780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b5060008414156040805190810160405280601381526020017f416d6f756e742063616e206e6f7420626520300000000000000000000000000081525090151561161a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b838110156115df5780820151818401526020810190506115c4565b50505050905090810190601f16801561160c5780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b506000600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600087600019166000191681526020019081526020016000206000015414156116ef57600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208590806001815401808255809150509060018203906000526020600020016000909192909190915090600019169055505b6116f93085612f73565b5060606040519081016040528085815260200182815260200160001515815250600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008760001916600019168152602001908152602001600020600082015181600001556020820151816001015560408201518160020160006101000a81548160ff02191690831515021790555090505084600019163373ffffffffffffffffffffffffffffffffffffffff167fea90ef40963535482537f0689e05cb8d259e459ebd21530e826702294d0eafdd8684604051808381526020018281526020019250505060405180910390a360019150509392505050565b6000806000600160189054906101000a900460ff1615151561183057600080fd5b600090505b600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080549050811015611a80576118df84600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020838154811015156118cf57fe5b9060005260206000200154612373565b91506000821115611a73576118fd8284613cc290919063ffffffff16565b92506001600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000600260008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208481548110151561198e57fe5b90600052602060002001546000191660001916815260200190815260200160002060020160006101000a81548160ff021916908315150217905550600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081815481101515611a1557fe5b9060005260206000200154600019168473ffffffffffffffffffffffffffffffffffffffff167f11f87fd5adcd05786919b8b868f59a70d78ae4eb6f305c5927f9c5b1659841a4846040518082815260200191505060405180910390a35b8080600101915050611835565b6000831115611b69573073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb85856040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b158015611b2c57600080fd5b505af1158015611b40573d6000803e3d6000fd5b505050506040513d6020811015611b5657600080fd5b8101908080519060200190929190505050505b5050919050565b600660009054906101000a900460ff1681565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515611bde57600080fd5b600160189054906101000a900460ff161515611bf957600080fd5b6000600160186101000a81548160ff0219169083151502179055507f7805862f689e2f13df9f062ff482ad3ad112aca9e0847911ed832e158c525b3360405160405180910390a1565b6000808273ffffffffffffffffffffffffffffffffffffffff1614151515611c6957600080fd5b600c60008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff169050919050565b6000600160189054906101000a900460ff16151515611cdb57600080fd5b81600860003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410151515611d2957600080fd5b600c60003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16151515611d8257600080fd5b611dd482600860003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546138bb90919063ffffffff16565b600860003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555081600760008282540392505081905550600073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a360019050919050565b600080611ea283612599565b9150600090505b600260008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080549050811015611f7457611f65611f5684600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002084815481101515611f4657fe5b90600052602060002001546124c3565b83613cc290919063ffffffff16565b91508080600101915050611ea9565b50919050565b600080600160189054906101000a900460ff16151515611f9957600080fd5b611fac8342613cc290919063ffffffff16565b90506000611fba87876124c3565b146040805190810160405280601581526020017f546f6b656e7320616c7265616479206c6f636b65640000000000000000000000815250901515612099576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b8381101561205e578082015181840152602081019050612043565b50505050905090810190601f16801561208b5780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b5060008414156040805190810160405280601381526020017f416d6f756e742063616e206e6f7420626520300000000000000000000000000081525090151561217d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b83811015612142578082015181840152602081019050612127565b50505050905090810190601f16801561216f5780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b506000600360008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000876000191660001916815260200190815260200160002060000154141561225257600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208590806001815401808255809150509060018203906000526020600020016000909192909190915090600019169055505b61225c3085612f73565b5060606040519081016040528085815260200182815260200160001515815250600360008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008760001916600019168152602001908152602001600020600082015181600001556020820151816001015560408201518160020160006101000a81548160ff02191690831515021790555090505084600019168673ffffffffffffffffffffffffffffffffffffffff167fea90ef40963535482537f0689e05cb8d259e459ebd21530e826702294d0eafdd8684604051808381526020018281526020019250505060405180910390a36001915050949350505050565b600042600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000846000191660001916815260200190815260200160002060010154111580156124465750600360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000836000191660001916815260200190815260200160002060020160009054906101000a900460ff16155b156124aa57600360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600083600019166000191681526020019081526020016000206000015490505b92915050565b600160189054906101000a900460ff1681565b6000600360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000836000191660001916815260200190815260200160002060020160009054906101000a900460ff16151561259357600360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600083600019166000191681526020019081526020016000206000015490505b92915050565b6000808273ffffffffffffffffffffffffffffffffffffffff16141515156125c057600080fd5b600860008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b60026020528160005260406000208181548110151561262257fe5b90600052602060002001600091509150505481565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561269357600080fd5b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506001601481819054906101000a900463ffffffff168092919060010191906101000a81548163ffffffff021916908363ffffffff16021790555050600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f5c486528ec3e3f0ea91181cff8116f02bfa350e03b8b6f12e00765adbb5af85c60405160405180910390a3565b6000600160189054906101000a900460ff1615151561282f57600080fd5b600061283b33856124c3565b116040805190810160405280601081526020017f4e6f20746f6b656e73206c6f636b65640000000000000000000000000000000081525090151561291a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b838110156128df5780820151818401526020810190506128c4565b50505050905090810190601f16801561290c5780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b506129253083612f73565b5061299482600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000866000191660001916815260200190815260200160002060000154613cc290919063ffffffff16565b600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600085600019166000191681526020019081526020016000206000018190555082600019163373ffffffffffffffffffffffffffffffffffffffff167fea90ef40963535482537f0689e05cb8d259e459ebd21530e826702294d0eafdd600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000876000191660001916815260200190815260200160002060000154600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000886000191660001916815260200190815260200160002060010154604051808381526020018281526020019250505060405180910390a36001905092915050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515612b6957600080fd5b600160189054906101000a900460ff16151515612b8557600080fd5b60018060186101000a81548160ff0219169083151502179055507f6985a02210a168e66602d3235cb6db0e70f92b3ba4d376a33c0f3d9434bff62560405160405180910390a1565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515612c2a57600080fd5b600160149054906101000a900463ffffffff16905090565b60048054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015612cd85780601f10612cad57610100808354040283529160200191612cd8565b820191906000526020600020905b815481529060010190602001808311612cbb57829003601f168201915b505050505081565b6000808273ffffffffffffffffffffffffffffffffffffffff1614151515612d0757600080fd5b600a60008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b6000806000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515612dac57600080fd5b82600754019050600660009054906101000a900460ff1660ff16600a0a6402540be400028111151515612e6d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260228152602001807f45524332303a20657863656564206d6178696d756d20746f74616c207375707081526020017f6c7900000000000000000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b8060078190555082600860008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef856040518082815260200191505060405180910390a36001915050919050565b6000600160189054906101000a900460ff16151515612f9157600080fd5b612f9c3384846138d7565b905092915050565b6000600160189054906101000a900460ff16151515612fc257600080fd5b6000612fce33856124c3565b116040805190810160405280601081526020017f4e6f20746f6b656e73206c6f636b6564000000000000000000000000000000008152509015156130ad576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b83811015613072578082015181840152602081019050613057565b50505050905090810190601f16801561309f5780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b5061311c82600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000866000191660001916815260200190815260200160002060010154613cc290919063ffffffff16565b600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600085600019166000191681526020019081526020016000206001018190555082600019163373ffffffffffffffffffffffffffffffffffffffff167fea90ef40963535482537f0689e05cb8d259e459ebd21530e826702294d0eafdd600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000876000191660001916815260200190815260200160002060000154600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000886000191660001916815260200190815260200160002060010154604051808381526020018281526020019250505060405180910390a36001905092915050565b600080600090505b600260008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805490508110156133695761335a61334b84600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208481548110151561333b57fe5b9060005260206000200154612373565b83613cc290919063ffffffff16565b9150808060010191505061329e565b50919050565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6000600160189054906101000a900460ff161515156133b657600080fd5b6133c08484610eb5565b1561355f57600115158473ffffffffffffffffffffffffffffffffffffffff16638f4ffcb1338630876040518563ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018481526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200180602001828103825283818151815260200191508051906020019080838360005b838110156134be5780820151818401526020810190506134a3565b50505050905090810190601f1680156134eb5780820380516001836020036101000a031916815260200191505b5095505050505050602060405180830381600087803b15801561350d57600080fd5b505af1158015613521573d6000803e3d6000fd5b505050506040513d602081101561353757600080fd5b8101908080519060200190929190505050151514151561355657600080fd5b60019050613564565b600090505b9392505050565b6003602052816000526040600020602052806000526040600020600091509150508060000154908060010154908060020160009054906101000a900460ff16905083565b6000808373ffffffffffffffffffffffffffffffffffffffff16141515156135d657600080fd5b60008273ffffffffffffffffffffffffffffffffffffffff16141515156135fc57600080fd5b600960008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b6000808273ffffffffffffffffffffffffffffffffffffffff16141515156136a857600080fd5b600b60008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561374c57600080fd5b81600c60008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055507fd16a7a4ba83c78a07676c543502e8155f633ecd3c35abb1da51bcbf129758b0f8383604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001821515151581526020019250505060405180910390a16001905092915050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561387757600080fd5b80600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008282111515156138cc57600080fd5b818303905092915050565b6000808373ffffffffffffffffffffffffffffffffffffffff16141515156138fe57600080fd5b81600860008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015151561394c57600080fd5b600c60008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515156139a557600080fd5b600c60008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515156139fe57600080fd5b613a5082600860008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546138bb90919063ffffffff16565b600860008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550613ae582600860008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054613cc290919063ffffffff16565b600860008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550613b7a82600a60008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054613cc290919063ffffffff16565b600a60008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550613c0f82600b60008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054613cc290919063ffffffff16565b600b60008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190509392505050565b60008183019050828110151515613cd857600080fd5b929150505600a165627a7a723058201edb114b8b4f6c578f08521bad50425eefafc0dac7b16bc6952d6112aa8845990029").unwrap()
        ));
        let constants = find_constants(&bytecode);
        println!(
            "{:?}",
            constants
                .iter()
                .map(|x| hex::encode(x))
                .collect::<Vec<String>>()
        );
    }
}
