/// Load contract from file system or remote
use glob::glob;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use crate::evm::types::{EVMAddress, EVMFuzzMutator, EVMFuzzState, fixed_address, generate_random_address};
use std::fs::File;

use std::io::Read;
use std::path::Path;
use itertools::Itertools;
use crate::state::FuzzState;
extern crate crypto;

use crate::evm::abi::get_abi_type_boxed_with_address;
use crate::evm::onchain::endpoints::OnChainConfig;
use crate::evm::srcmap::parser::{decode_instructions, SourceMapLocation};

use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;

// to use this address, call rand_utils::fixed_address(FIX_DEPLOYER)
pub static FIX_DEPLOYER: &str = "8b21e662154b4bbc1ec0754d0238875fe3d22fa6";

#[derive(Debug, Clone)]
pub struct ABIConfig {
    pub abi: String,
    pub function: [u8; 4],
    pub function_name: String,
    pub is_static: bool,
    pub is_payable: bool,
    pub is_constructor: bool,
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub name: String,
    pub abi: Vec<ABIConfig>,
    pub code: Vec<u8>,
    pub is_code_deployed: bool,
    pub constructor_args: Vec<u8>,
    pub deployed_address: EVMAddress,
    pub source_map: Option<HashMap<usize, SourceMapLocation>>,
}

#[derive(Debug, Clone)]
pub struct ContractLoader {
    pub contracts: Vec<ContractInfo>,
}

pub fn set_hash(name: &str, out: &mut [u8]) {
    let mut hasher = Sha3::keccak256();
    hasher.input_str(name);
    hasher.result(out)
}

impl ContractLoader {
    fn parse_abi(path: &Path) -> Vec<ABIConfig> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data)
            .expect("failed to read abi file");
        return Self::parse_abi_str(&data);
    }

    fn process_input(ty: String, input: &Value) -> String {
        if let Some(slot) = input.get("components") {
            if ty == "tuple" {
                let v = slot
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| Self::process_input(v["type"].as_str().unwrap().to_string(), v))
                    .collect::<Vec<String>>()
                    .join(",");
                return format!("({})", v);
            } else if ty.ends_with("[]") {
                return format!(
                    "{}[]",
                    Self::process_input(ty[..ty.len() - 2].to_string(), input)
                );
            }
            panic!("unknown type: {}", ty);
        } else {
            ty
        }
    }

    pub fn parse_abi_str(data: &String) -> Vec<ABIConfig> {
        let json: Vec<Value> = serde_json::from_str(&data).expect("failed to parse abi file");
        json.iter()
            .flat_map(|abi| {
                if abi["type"] == "function" || abi["type"] == "constructor" {
                    let name = if abi["type"] == "function" {
                        abi["name"].as_str().expect("failed to parse abi name")
                    } else {
                        "constructor"
                    };
                    let mut abi_name: Vec<String> = vec![];
                    abi["inputs"]
                        .as_array()
                        .expect("failed to parse abi inputs")
                        .iter()
                        .for_each(|input| {
                            abi_name.push(Self::process_input(
                                input["type"].as_str().unwrap().to_string(),
                                input,
                            ));
                        });
                    let mut abi_config = ABIConfig {
                        abi: format!("({})", abi_name.join(",")),
                        function: [0; 4],
                        function_name: name.to_string(),
                        is_static: abi["stateMutability"].as_str().unwrap() == "view",
                        is_payable: abi["stateMutability"].as_str().unwrap() == "payable",
                        is_constructor: abi["type"] == "constructor",
                    };
                    let function_to_hash = format!("{}({})", name, abi_name.join(","));
                    // print name and abi_name
                    println!("{}({})", name, abi_name.join(","));

                    set_hash(function_to_hash.as_str(), &mut abi_config.function);
                    Some(abi_config)
                } else {
                    None
                }
            })
            .collect()
    }

    fn parse_hex_file(path: &Path) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        hex::decode(data).expect("Failed to parse hex file")
    }

    pub fn from_prefix(prefix: &str, state: &mut EVMFuzzState, source_map_info: Option<ContractsSourceMapInfo>) -> Self {
        let mut result = ContractInfo {
            name: prefix.to_string(),
            abi: vec![],
            code: vec![],
            is_code_deployed: false,
            constructor_args: vec![], // todo: fill this
            deployed_address: generate_random_address(state),
            source_map: source_map_info.map(|info|
                info.get(prefix).expect("combined.json provided but contract not found").clone()
            ),
        };
        println!("Loading contract {}", prefix);
        for i in glob(prefix).expect("not such path for prefix") {
            match i {
                Ok(path) => {
                    if path.to_str().unwrap().ends_with(".abi") {
                        // this is an ABI file
                        result.abi = Self::parse_abi(&path);
                        // println!("ABI: {:?}", result.abi);
                    } else if path.to_str().unwrap().ends_with(".bin") {
                        // this is an BIN file
                        result.code = Self::parse_hex_file(&path);
                    } else if path.to_str().unwrap().ends_with(".address") {
                        // this is deployed address
                        result
                            .deployed_address
                            .0
                            .clone_from_slice(Self::parse_hex_file(&path).as_slice());
                    } else {
                        println!("Found unknown file: {:?}", path.display())
                    }
                }
                Err(e) => println!("{:?}", e),
            }
        }

        if let Some(abi) = result.abi.iter().find(|abi| abi.is_constructor) {
            let mut abi_instance =
                get_abi_type_boxed_with_address(&abi.abi, fixed_address(FIX_DEPLOYER).0.to_vec());
            abi_instance.set_func_with_name(abi.function, abi.function_name.clone());
            // since this is constructor args, we ingore the function hash
            // Note (Shangyin): this may still non-deployable, need futher improvement
            // (The check may fail)

            let mut random_bytes = vec![0u8; abi_instance.get().get_bytes().len()];
            for i in 0..random_bytes.len() {
                random_bytes[i] = rand::random();
            }
            print!("Random bytes {:?}", random_bytes);
            // result.constructor_args = random_bytes;
            result.constructor_args = abi_instance.get().get_bytes();
            // println!("Constructor args: {:?}", result.constructor_args);
            result.code.extend(result.constructor_args.clone());
        }
        return Self {
            contracts: if result.code.len() > 0 {
                vec![result]
            } else {
                vec![]
            },
        };
    }

    // This function loads constructs Contract infos from path p
    // The organization of directory p should be
    // p
    // |- contract1.abi
    // |- contract1.bin
    // |- contract2.abi
    // |- contract2.bin
    pub fn from_glob(p: &str, state: &mut EVMFuzzState) -> Self {
        let mut prefix_file_count: HashMap<String, u8> = HashMap::new();
        let mut contract_combined_json_info = None;
        for i in glob(p).expect("not such folder") {
            match i {
                Ok(path) => {
                    let path_str = path.to_str().unwrap();
                    if path_str.ends_with(".abi") {
                        *prefix_file_count
                            .entry(path_str.replace(".abi", "").clone())
                            .or_insert(0) += 1;
                    } else if path_str.ends_with(".bin") {
                        *prefix_file_count
                            .entry(path_str.replace(".bin", "").clone())
                            .or_insert(0) += 1;
                    } else if path_str.ends_with("combined.json") {
                        contract_combined_json_info = Some(path_str.to_string());
                    } else {
                        println!("Found unknown file in folder: {:?}", path.display())
                    }
                }
                Err(e) => println!("{:?}", e),
            }
        }

        let parsed_contract_info = match contract_combined_json_info {
            None => None,
            Some(file_name) => {
                let mut combined_json = File::open(file_name).unwrap();
                let mut buf = String::new();
                combined_json.read_to_string(&mut buf).unwrap();
                Some(parse_combined_json(buf))
            }
        };

        let mut contracts: Vec<ContractInfo> = vec![];
        for (prefix, count) in prefix_file_count {
            if count == 2 {
                for contract in
                    Self::from_prefix((prefix.to_owned() + &String::from('*')).as_str(),
                                      state,
                                      parsed_contract_info.clone()).contracts
                {
                    contracts.push(contract);
                }
            }
        }

        ContractLoader { contracts }
    }


    pub fn from_address(onchain: &mut OnChainConfig, address: HashSet<EVMAddress>) -> Self {
        let mut contracts: Vec<ContractInfo> = vec![];
        for addr in address {
            let abi = onchain.fetch_abi(addr);
            if abi.is_none() {
                println!("ABI not found for {}", addr);
                continue;
            }
            let contract = ContractInfo {
                name: addr.to_string(),
                abi: Self::parse_abi_str(&abi.unwrap()),
                code: onchain.get_contract_code(addr, false).bytes().to_vec(),
                is_code_deployed: true,
                constructor_args: vec![], // todo: fill this
                deployed_address: addr,
                source_map: None,
            };
            contracts.push(contract);
        }
        Self { contracts }
    }
}

type ContractSourceMap = HashMap<usize, SourceMapLocation>;
type ContractsSourceMapInfo = HashMap<String, HashMap<usize, SourceMapLocation>>;

pub fn parse_combined_json(json: String) -> ContractsSourceMapInfo {
    let map_json = serde_json::from_str::<serde_json::Value>(&json).unwrap();

    let contracts = map_json["contracts"].as_object().expect("contracts not found");
    let file_list = map_json["sourceList"].as_array()
        .expect("sourceList not found")
        .iter()
        .map(|x| x.as_str().expect("sourceList is not string").to_string())
        .collect::<Vec<String>>();

    let mut result = ContractsSourceMapInfo::new();

    for (contract_name, contract_info) in contracts {
        let splitter = contract_name.split(':').collect::<Vec<&str>>();
        let file_name = splitter.iter().take(splitter.len()-1).join(":");
        let contract_name = splitter.last().unwrap().to_string();

        let bin_runtime = contract_info["bin-runtime"].as_str().expect("bin-runtime not found");
        let bin_runtime_bytes = hex::decode(bin_runtime).expect("bin-runtime is not hex");

        let srcmap_runtime = contract_info["srcmap-runtime"].as_str().expect("srcmap-runtime not found");

        result.insert(
            contract_name.clone(),
            decode_instructions(
                bin_runtime_bytes,
                srcmap_runtime.to_string(),
                &file_list
            )
        );
    }
    result
}

mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_load() {
        let loader = ContractLoader::from_glob("demo/*", &mut FuzzState::new(0));
        println!(
            "{:?}",
            loader
                .contracts
                .iter()
                .map(|x| x.name.clone())
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn test_combined_json() {
        let combined_json_file = "{\"contracts\":{\"tests/complex-condition/test.sol:main\":{\"bin-runtime\":\"608060405234801561001057600080fd5b506004361061002b5760003560e01c8063051ee71f14610030575b600080fd5b61004a600480360381019061004591906104b8565b610060565b6040516100579190610595565b60405180910390f35b6060600083836000818110610078576100776105b7565b5b905060200201602081019061008d919061061f565b60ff16036100d0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100c790610698565b60405180910390fd5b6000838360018181106100e6576100e56105b7565b5b90506020020160208101906100fb919061061f565b60ff160361013e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161013590610704565b60405180910390fd5b600083836002818110610154576101536105b7565b5b9050602002016020810190610169919061061f565b60ff16036101ac576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101a390610770565b60405180910390fd5b6004838360038181106101c2576101c16105b7565b5b90506020020160208101906101d7919061061f565b60ff161461021a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610211906107dc565b60405180910390fd5b6005838360048181106102305761022f6105b7565b5b9050602002016020810190610245919061061f565b60ff1614610288576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161027f90610848565b60405180910390fd5b60058383600581811061029e5761029d6105b7565b5b90506020020160208101906102b3919061061f565b60ff16146102f6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102ed906108b4565b60405180910390fd5b60078383600681811061030c5761030b6105b7565b5b9050602002016020810190610321919061061f565b60ff1614610364576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161035b90610920565b60405180910390fd5b60088383600781811061037a576103796105b7565b5b905060200201602081019061038f919061061f565b60ff16146103d2576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103c99061098c565b60405180910390fd5b6103da610418565b6040518060400160405280600f81526020017f48656c6c6f20436f6e7472616374730000000000000000000000000000000000815250905092915050565b60003373ffffffffffffffffffffffffffffffffffffffff1660001b90506020590181815262133337602082a15050565b600080fd5b600080fd5b600080fd5b600080fd5b600080fd5b60008083601f84011261047857610477610453565b5b8235905067ffffffffffffffff81111561049557610494610458565b5b6020830191508360208202830111156104b1576104b061045d565b5b9250929050565b600080602083850312156104cf576104ce610449565b5b600083013567ffffffffffffffff8111156104ed576104ec61044e565b5b6104f985828601610462565b92509250509250929050565b600081519050919050565b600082825260208201905092915050565b60005b8381101561053f578082015181840152602081019050610524565b60008484015250505050565b6000601f19601f8301169050919050565b600061056782610505565b6105718185610510565b9350610581818560208601610521565b61058a8161054b565b840191505092915050565b600060208201905081810360008301526105af818461055c565b905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600060ff82169050919050565b6105fc816105e6565b811461060757600080fd5b50565b600081359050610619816105f3565b92915050565b60006020828403121561063557610634610449565b5b60006106438482850161060a565b91505092915050565b7f615b305d20213d20310000000000000000000000000000000000000000000000600082015250565b6000610682600983610510565b915061068d8261064c565b602082019050919050565b600060208201905081810360008301526106b181610675565b9050919050565b7f615b315d20213d20320000000000000000000000000000000000000000000000600082015250565b60006106ee600983610510565b91506106f9826106b8565b602082019050919050565b6000602082019050818103600083015261071d816106e1565b9050919050565b7f615b325d20213d20330000000000000000000000000000000000000000000000600082015250565b600061075a600983610510565b915061076582610724565b602082019050919050565b600060208201905081810360008301526107898161074d565b9050919050565b7f615b335d20213d20340000000000000000000000000000000000000000000000600082015250565b60006107c6600983610510565b91506107d182610790565b602082019050919050565b600060208201905081810360008301526107f5816107b9565b9050919050565b7f615b345d20213d20350000000000000000000000000000000000000000000000600082015250565b6000610832600983610510565b915061083d826107fc565b602082019050919050565b6000602082019050818103600083015261086181610825565b9050919050565b7f615b355d20213d20360000000000000000000000000000000000000000000000600082015250565b600061089e600983610510565b91506108a982610868565b602082019050919050565b600060208201905081810360008301526108cd81610891565b9050919050565b7f615b365d20213d20370000000000000000000000000000000000000000000000600082015250565b600061090a600983610510565b9150610915826108d4565b602082019050919050565b60006020820190508181036000830152610939816108fd565b9050919050565b7f615b375d20213d20380000000000000000000000000000000000000000000000600082015250565b6000610976600983610510565b915061098182610940565b602082019050919050565b600060208201905081810360008301526109a581610969565b905091905056fea26469706673582212205e7a5ef1ad84c28d4cfbbd0cbe0ca7f0232df5dbf0c8885a9c063e982267597164736f6c63430008130033\",\"srcmap-runtime\":\"105:496:1:-:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;148:451;;;;;;;;;;;;;:::i;:::-;;:::i;:::-;;;;;;;:::i;:::-;;;;;;;;;201:13;241:1;233;;235;233:4;;;;;;;:::i;:::-;;;;;;;;;;;;;;;:::i;:::-;:9;;;225:31;;;;;;;;;;;;:::i;:::-;;;;;;;;;282:1;274;;276;274:4;;;;;;;:::i;:::-;;;;;;;;;;;;;;;:::i;:::-;:9;;;266:31;;;;;;;;;;;;:::i;:::-;;;;;;;;;323:1;315;;317;315:4;;;;;;;:::i;:::-;;;;;;;;;;;;;;;:::i;:::-;:9;;;307:31;;;;;;;;;;;;:::i;:::-;;;;;;;;;364:1;356;;358;356:4;;;;;;;:::i;:::-;;;;;;;;;;;;;;;:::i;:::-;:9;;;348:31;;;;;;;;;;;;:::i;:::-;;;;;;;;;405:1;397;;399;397:4;;;;;;;:::i;:::-;;;;;;;;;;;;;;;:::i;:::-;:9;;;389:31;;;;;;;;;;;;:::i;:::-;;;;;;;;;446:1;438;;440;438:4;;;;;;;:::i;:::-;;;;;;;;;;;;;;;:::i;:::-;:9;;;430:31;;;;;;;;;;;;:::i;:::-;;;;;;;;;487:1;479;;481;479:4;;;;;;;:::i;:::-;;;;;;;;;;;;;;;:::i;:::-;:9;;;471:31;;;;;;;;;;;;:::i;:::-;;;;;;;;;528:1;520;;522;520:4;;;;;;;:::i;:::-;;;;;;;;;;;;;;;:::i;:::-;:9;;;512:31;;;;;;;;;;;;:::i;:::-;;;;;;;;;553:5;:3;:5::i;:::-;568:24;;;;;;;;;;;;;;;;;;;148:451;;;;:::o;25:185:0:-;46:10;83;67:28;;59:37;;46:50;;143:4;134:7;130:18;167:2;164:1;157:13;193:8;187:4;184:1;179:23;111:97;;25:185::o;88:117:2:-;197:1;194;187:12;211:117;320:1;317;310:12;334:117;443:1;440;433:12;457:117;566:1;563;556:12;580:117;689:1;686;679:12;718:566;789:8;799:6;849:3;842:4;834:6;830:17;826:27;816:122;;857:79;;:::i;:::-;816:122;970:6;957:20;947:30;;1000:18;992:6;989:30;986:117;;;1022:79;;:::i;:::-;986:117;1136:4;1128:6;1124:17;1112:29;;1190:3;1182:4;1174:6;1170:17;1160:8;1156:32;1153:41;1150:128;;;1197:79;;:::i;:::-;1150:128;718:566;;;;;:::o;1290:555::-;1374:6;1382;1431:2;1419:9;1410:7;1406:23;1402:32;1399:119;;;1437:79;;:::i;:::-;1399:119;1585:1;1574:9;1570:17;1557:31;1615:18;1607:6;1604:30;1601:117;;;1637:79;;:::i;:::-;1601:117;1750:78;1820:7;1811:6;1800:9;1796:22;1750:78;:::i;:::-;1732:96;;;;1528:310;1290:555;;;;;:::o;1851:99::-;1903:6;1937:5;1931:12;1921:22;;1851:99;;;:::o;1956:169::-;2040:11;2074:6;2069:3;2062:19;2114:4;2109:3;2105:14;2090:29;;1956:169;;;;:::o;2131:246::-;2212:1;2222:113;2236:6;2233:1;2230:13;2222:113;;;2321:1;2316:3;2312:11;2306:18;2302:1;2297:3;2293:11;2286:39;2258:2;2255:1;2251:10;2246:15;;2222:113;;;2369:1;2360:6;2355:3;2351:16;2344:27;2193:184;2131:246;;;:::o;2383:102::-;2424:6;2475:2;2471:7;2466:2;2459:5;2455:14;2451:28;2441:38;;2383:102;;;:::o;2491:377::-;2579:3;2607:39;2640:5;2607:39;:::i;:::-;2662:71;2726:6;2721:3;2662:71;:::i;:::-;2655:78;;2742:65;2800:6;2795:3;2788:4;2781:5;2777:16;2742:65;:::i;:::-;2832:29;2854:6;2832:29;:::i;:::-;2827:3;2823:39;2816:46;;2583:285;2491:377;;;;:::o;2874:313::-;2987:4;3025:2;3014:9;3010:18;3002:26;;3074:9;3068:4;3064:20;3060:1;3049:9;3045:17;3038:47;3102:78;3175:4;3166:6;3102:78;:::i;:::-;3094:86;;2874:313;;;;:::o;3193:180::-;3241:77;3238:1;3231:88;3338:4;3335:1;3328:15;3362:4;3359:1;3352:15;3379:86;3414:7;3454:4;3447:5;3443:16;3432:27;;3379:86;;;:::o;3471:118::-;3542:22;3558:5;3542:22;:::i;:::-;3535:5;3532:33;3522:61;;3579:1;3576;3569:12;3522:61;3471:118;:::o;3595:135::-;3639:5;3677:6;3664:20;3655:29;;3693:31;3718:5;3693:31;:::i;:::-;3595:135;;;;:::o;3736:325::-;3793:6;3842:2;3830:9;3821:7;3817:23;3813:32;3810:119;;;3848:79;;:::i;:::-;3810:119;3968:1;3993:51;4036:7;4027:6;4016:9;4012:22;3993:51;:::i;:::-;3983:61;;3939:115;3736:325;;;;:::o;4067:159::-;4207:11;4203:1;4195:6;4191:14;4184:35;4067:159;:::o;4232:365::-;4374:3;4395:66;4459:1;4454:3;4395:66;:::i;:::-;4388:73;;4470:93;4559:3;4470:93;:::i;:::-;4588:2;4583:3;4579:12;4572:19;;4232:365;;;:::o;4603:419::-;4769:4;4807:2;4796:9;4792:18;4784:26;;4856:9;4850:4;4846:20;4842:1;4831:9;4827:17;4820:47;4884:131;5010:4;4884:131;:::i;:::-;4876:139;;4603:419;;;:::o;5028:159::-;5168:11;5164:1;5156:6;5152:14;5145:35;5028:159;:::o;5193:365::-;5335:3;5356:66;5420:1;5415:3;5356:66;:::i;:::-;5349:73;;5431:93;5520:3;5431:93;:::i;:::-;5549:2;5544:3;5540:12;5533:19;;5193:365;;;:::o;5564:419::-;5730:4;5768:2;5757:9;5753:18;5745:26;;5817:9;5811:4;5807:20;5803:1;5792:9;5788:17;5781:47;5845:131;5971:4;5845:131;:::i;:::-;5837:139;;5564:419;;;:::o;5989:159::-;6129:11;6125:1;6117:6;6113:14;6106:35;5989:159;:::o;6154:365::-;6296:3;6317:66;6381:1;6376:3;6317:66;:::i;:::-;6310:73;;6392:93;6481:3;6392:93;:::i;:::-;6510:2;6505:3;6501:12;6494:19;;6154:365;;;:::o;6525:419::-;6691:4;6729:2;6718:9;6714:18;6706:26;;6778:9;6772:4;6768:20;6764:1;6753:9;6749:17;6742:47;6806:131;6932:4;6806:131;:::i;:::-;6798:139;;6525:419;;;:::o;6950:159::-;7090:11;7086:1;7078:6;7074:14;7067:35;6950:159;:::o;7115:365::-;7257:3;7278:66;7342:1;7337:3;7278:66;:::i;:::-;7271:73;;7353:93;7442:3;7353:93;:::i;:::-;7471:2;7466:3;7462:12;7455:19;;7115:365;;;:::o;7486:419::-;7652:4;7690:2;7679:9;7675:18;7667:26;;7739:9;7733:4;7729:20;7725:1;7714:9;7710:17;7703:47;7767:131;7893:4;7767:131;:::i;:::-;7759:139;;7486:419;;;:::o;7911:159::-;8051:11;8047:1;8039:6;8035:14;8028:35;7911:159;:::o;8076:365::-;8218:3;8239:66;8303:1;8298:3;8239:66;:::i;:::-;8232:73;;8314:93;8403:3;8314:93;:::i;:::-;8432:2;8427:3;8423:12;8416:19;;8076:365;;;:::o;8447:419::-;8613:4;8651:2;8640:9;8636:18;8628:26;;8700:9;8694:4;8690:20;8686:1;8675:9;8671:17;8664:47;8728:131;8854:4;8728:131;:::i;:::-;8720:139;;8447:419;;;:::o;8872:159::-;9012:11;9008:1;9000:6;8996:14;8989:35;8872:159;:::o;9037:365::-;9179:3;9200:66;9264:1;9259:3;9200:66;:::i;:::-;9193:73;;9275:93;9364:3;9275:93;:::i;:::-;9393:2;9388:3;9384:12;9377:19;;9037:365;;;:::o;9408:419::-;9574:4;9612:2;9601:9;9597:18;9589:26;;9661:9;9655:4;9651:20;9647:1;9636:9;9632:17;9625:47;9689:131;9815:4;9689:131;:::i;:::-;9681:139;;9408:419;;;:::o;9833:159::-;9973:11;9969:1;9961:6;9957:14;9950:35;9833:159;:::o;9998:365::-;10140:3;10161:66;10225:1;10220:3;10161:66;:::i;:::-;10154:73;;10236:93;10325:3;10236:93;:::i;:::-;10354:2;10349:3;10345:12;10338:19;;9998:365;;;:::o;10369:419::-;10535:4;10573:2;10562:9;10558:18;10550:26;;10622:9;10616:4;10612:20;10608:1;10597:9;10593:17;10586:47;10650:131;10776:4;10650:131;:::i;:::-;10642:139;;10369:419;;;:::o;10794:159::-;10934:11;10930:1;10922:6;10918:14;10911:35;10794:159;:::o;10959:365::-;11101:3;11122:66;11186:1;11181:3;11122:66;:::i;:::-;11115:73;;11197:93;11286:3;11197:93;:::i;:::-;11315:2;11310:3;11306:12;11299:19;;10959:365;;;:::o;11330:419::-;11496:4;11534:2;11523:9;11519:18;11511:26;;11583:9;11577:4;11573:20;11569:1;11558:9;11554:17;11547:47;11611:131;11737:4;11611:131;:::i;:::-;11603:139;;11330:419;;;:::o\"}},\"sourceList\":[\"solidity_utils/lib.sol\",\"tests/complex-condition/test.sol\"],\"version\":\"0.8.19+commit.7dd6d404.Darwin.appleclang\"}";
        let result = parse_combined_json(combined_json_file.to_string());

        assert!(result.contains_key("main"));
        println!("result: {:?}", result);
    }

    // #[test]
    // fn test_remote_load() {
    //     let onchain = OnChainConfig::new("https://bsc-dataseed1.binance.org/".to_string(), 56, 0);
    //
    //     let loader = ContractLoader::from_address(
    //         &onchain,
    //         vec![EVMAddress::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap()],
    //     );
    //     println!(
    //         "{:?}",
    //         loader
    //             .contracts
    //             .iter()
    //             .map(|x| x.name.clone())
    //             .collect::<Vec<String>>()
    //     );
    // }
}
