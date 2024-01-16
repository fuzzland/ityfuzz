use serde::{Deserialize, Serialize};

use crate::evm::types::{EVMAddress, EVMU256};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConstantPairMetadata {
    pub token: EVMAddress,
    pub faucet: EVMAddress,
    pub ratio: EVMU256,
}

impl ConstantPairMetadata {
    pub fn new(token: EVMAddress, faucet: EVMAddress, ratio: EVMU256) -> Self {
        Self { token, faucet, ratio }
    }

    pub fn from_return_data(by: &Vec<u8>) -> Vec<Self> {
        let mut ret = Vec::new();
        let parsed = ethers::abi::decode(
            &[ethers::abi::ParamType::Array(Box::new(ethers::abi::ParamType::Tuple(
                vec![
                    ethers::abi::ParamType::Address,
                    ethers::abi::ParamType::Address,
                    ethers::abi::ParamType::Uint(256),
                ],
            )))],
            by,
        )
        .unwrap();

        for parsed_token in parsed {
            if let ethers::abi::Token::Tuple(tokens) = parsed_token {
                let token_t = tokens[0].clone();
                let faucet_t = tokens[1].clone();
                let ratio_t = tokens[2].clone();

                if let (
                    ethers::abi::Token::Address(token_u),
                    ethers::abi::Token::Address(faucet_u),
                    ethers::abi::Token::Uint(ratio_u),
                ) = (token_t, faucet_t, ratio_t)
                {
                    let token = EVMAddress::from_slice(token_u.as_bytes());
                    let faucet = EVMAddress::from_slice(faucet_u.as_bytes());
                    let ratio = EVMU256::from_limbs(ratio_u.0);
                    ret.push(Self::new(token, faucet, ratio));
                } else {
                    panic!("Invalid ConstantPairMetadata return data");
                }
            } else {
                panic!("Invalid return data: {:?}", parsed_token);
            }
        }
        ret
    }
}
