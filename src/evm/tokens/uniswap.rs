use std::{
    cell::{Ref, RefCell},
    collections::{HashMap, HashSet},
    rc::Rc,
    str::FromStr,
    sync::{Arc, Mutex},
};

use itertools::Itertools;
use lazy_static::lazy_static;
use revm_interpreter::BytecodeLocked;
use revm_primitives::Bytecode;
use tracing::{info, warn};

use super::{
    get_uniswap_info,
    v2_transformer::UniswapPairContext,
    weth_transformer::WethContext,
    PairContext,
    PathContext,
    TokenContext,
    UniswapProvider,
};
use crate::evm::{
    onchain::endpoints::{Chain, OnChainConfig, PairData},
    types::{EVMAddress, EVMU256},
};

pub struct Info {
    routes: Vec<Vec<PairData>>,
    basic_info: BasicInfo,
}

pub struct BasicInfo {
    weth: String,
    is_weth: bool,
}

const MAX_HOPS: u32 = 2; // Assuming the value of MAX_HOPS

lazy_static! {
    pub static ref CODE_REGISTRY: Mutex<HashMap<EVMAddress, Bytecode>> = Mutex::new(HashMap::new());
}

pub fn fetch_uniswap_path(onchain: &mut OnChainConfig, token_address: EVMAddress) -> TokenContext {
    let token = format!("{:?}", token_address);
    let info: Info = find_path_subgraph(onchain, &token);

    let basic_info = info.basic_info;
    if basic_info.weth.is_empty() {
        warn!("failed to find weth address");
        return TokenContext::default();
    }
    let weth = EVMAddress::from_str(&basic_info.weth).unwrap();
    let is_weth = basic_info.is_weth;

    let routes: Vec<Vec<PairData>> = info.routes;

    macro_rules! register_code {
        ($addr: expr) => {
            CODE_REGISTRY
                .lock()
                .unwrap()
                .insert($addr, onchain.get_contract_code_analyzed($addr, false));
        };
    }

    let paths_parsed = routes
        .iter()
        .map(|pairs| {
            let mut path_parsed: PathContext = Default::default();
            pairs.iter().for_each(|pair| match pair.src.as_str() {
                "v2" => {
                    let inner = Rc::new(RefCell::new(UniswapPairContext {
                        pair_address: EVMAddress::from_str(pair.pair.as_str()).expect("failed to parse pair"),
                        next_hop: EVMAddress::from_str(pair.next.as_str()).expect("failed to parse pair"),
                        side: pair.in_ as u8,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::from_str(pair.src_exact.as_str()).unwrap(),
                            &Chain::from_str(&onchain.chain_name).unwrap(),
                        )),
                        initial_reserves: (
                            EVMU256::try_from_be_slice(&hex::decode(&pair.initial_reserves_0).unwrap()).unwrap(),
                            EVMU256::try_from_be_slice(&hex::decode(&pair.initial_reserves_1).unwrap()).unwrap(),
                        ),
                        in_token_address: EVMAddress::from_str(pair.in_token.as_str()).unwrap(),
                    }));
                    register_code!(inner.borrow().next_hop);
                    path_parsed.route.push(super::PairContextTy::Uniswap(inner));
                }
                "pegged" => {
                    let inner_pair = Rc::new(RefCell::new(UniswapPairContext {
                        pair_address: EVMAddress::from_str(pair.pair.as_str()).expect("failed to parse pair"),
                        next_hop: EVMAddress::from_str(pair.next.as_str()).expect("failed to parse pair"),
                        side: pair.in_ as u8,
                        uniswap_info: Arc::new(get_uniswap_info(
                            &UniswapProvider::from_str(pair.src_exact.as_str()).unwrap(),
                            &Chain::from_str(&onchain.chain_name).unwrap(),
                        )),
                        initial_reserves: (
                            EVMU256::try_from_be_slice(&hex::decode(&pair.initial_reserves_0).unwrap()).unwrap(),
                            EVMU256::try_from_be_slice(&hex::decode(&pair.initial_reserves_1).unwrap()).unwrap(),
                        ),
                        in_token_address: EVMAddress::from_str(pair.in_token.as_str()).unwrap(),
                    }));
                    register_code!(inner_pair.borrow().next_hop);
                    path_parsed.route.push(super::PairContextTy::Uniswap(inner_pair));
                    assert_eq!(pair.next, basic_info.weth);
                    let inner = Rc::new(RefCell::new(WethContext {
                        weth_address: EVMAddress::from_str(&pair.next.as_str()).expect("failed to parse pair"),
                    }));
                    path_parsed.route.push(super::PairContextTy::Weth(inner));
                }
                "pegged_weth" => {
                    let weth_address = EVMAddress::from_str(pair.in_token.as_str()).expect("failed to parse pair");
                    register_code!(weth_address);
                    let inner = Rc::new(RefCell::new(WethContext { weth_address }));
                    path_parsed.route.push(super::PairContextTy::Weth(inner));
                }
                _ => unimplemented!("unknown swap path source"),
            });
            path_parsed
        })
        .collect();

    TokenContext {
        swaps: paths_parsed,
        is_weth,
        weth_address: weth,
    }
}

pub fn get_weth(network: &str) -> String {
    let pegged_token = get_pegged_token(network);

    match network {
        "eth" => return pegged_token.get("WETH").unwrap().to_string(),
        "bsc" => return pegged_token.get("WBNB").unwrap().to_string(),
        "polygon" => return pegged_token.get("WMATIC").unwrap().to_string(),
        "local" => return pegged_token.get("ZERO").unwrap().to_string(),
        // "mumbai" => panic!("Not supported"),
        _ => {
            warn!("Unknown network");
            "".to_string()
        }
    }
}

fn get_pegged_token(network: &str) -> HashMap<String, String> {
    match network {
        "eth" => [
            ("WETH", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            ("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
            ("USDT", "0xdac17f958d2ee523a2206206994597c13d831ec7"),
            ("DAI", "0x6b175474e89094c44da98b954eedeac495271d0f"),
            ("WBTC", "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"),
            ("WMATIC", "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        "bsc" => [
            ("WBNB", "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"),
            ("USDC", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"),
            ("USDT", "0x55d398326f99059ff775485246999027b3197955"),
            ("DAI", "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3"),
            ("WBTC", "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c"),
            ("WETH", "0x2170ed0880ac9a755fd29b2688956bd959f933f8"),
            ("BUSD", "0xe9e7cea3dedca5984780bafc599bd69add087d56"),
            ("CAKE", "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        "polygon" => [
            ("WMATIC", "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"),
            ("USDC", "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"),
            ("USDT", "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"),
            ("DAI", "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"),
            ("WBTC", "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6"),
            ("WETH", "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        "local" => [("ZERO", "0x0000000000000000000000000000000000000000")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        _ => {
            warn!("[Flashloan] Network is not supported");
            HashMap::new()
        }
    }
}

fn get_pair(onchain: &mut OnChainConfig, token: &str, network: &str, is_pegged: bool) -> Vec<PairData> {
    let token = token.to_lowercase();
    info!("fetching pairs for {token}");
    if token == get_weth(network) {
        return vec![];
    }
    let weth = get_weth(network);
    let pegged_tokens = get_pegged_token(network);
    let mut pairs = onchain.get_pair(
        token.as_str(),
        network,
        is_pegged || pegged_tokens.values().contains(&token),
        weth,
    );

    for pair in &mut pairs {
        add_reserve_info(onchain, pair);
    }
    pairs.sort_by(|a, b| {
        let a = get_liquidity_cmp(a);
        let b = get_liquidity_cmp(b);
        b.cmp(&a)
    });

    if pairs.len() > 3 {
        pairs = pairs[0..3].to_vec();
    }
    pairs
}

fn get_all_hops(
    onchain: &mut OnChainConfig,
    token: &str,
    network: &str,
    hop: u32,
    known: &mut HashSet<String>,
) -> HashMap<String, Vec<PairData>> {
    known.insert(token.to_string());

    if hop > MAX_HOPS {
        return HashMap::new();
    }

    let mut hops: HashMap<String, Vec<PairData>> = HashMap::new();
    hops.insert(token.to_string(), get_pair(onchain, token, network, false));

    let pegged_tokens = get_pegged_token(network);

    for i in hops.clone().get(token).unwrap() {
        if pegged_tokens.values().any(|v| v == &i.next) || known.contains(&i.next) {
            continue;
        }
        let next_hops = get_all_hops(onchain, &i.next, network, hop + 1, known);
        hops.extend(next_hops);
    }

    hops
}

fn get_pegged_next_hop(onchain: &mut OnChainConfig, token: &str, network: &str) -> PairData {
    if token == get_weth(network) {
        return PairData {
            src: "pegged_weth".to_string(),
            rate: 1_000_000,
            in_: 0,
            next: "".to_string(),
            pair: "".to_string(),
            initial_reserves_0: "".to_string(),
            initial_reserves_1: "".to_string(),
            src_exact: "".to_string(),
            decimals_0: 0,
            decimals_1: 0,
            in_token: token.to_string(),
        };
    }
    let mut peg_info = get_pair(onchain, token, network, true)
        .first()
        .expect("Unexpected RPC error, consider setting env <ETH_RPC_URL> ")
        .clone();

    add_reserve_info(onchain, &mut peg_info);
    let p0 = i128::from_str_radix(&peg_info.initial_reserves_0, 16).unwrap();
    let p1 = i128::from_str_radix(&peg_info.initial_reserves_1, 16).unwrap();

    if peg_info.in_ == 0 {
        peg_info.rate = (p1 as f64 / p0 as f64 * 1_000_000.0).round() as u32;
    } else {
        peg_info.rate = (p0 as f64 / p1 as f64 * 1_000_000.0).round() as u32;
    }

    PairData {
        src: "pegged".to_string(),
        ..peg_info.clone()
    }
}

/// returns whether the pair is significant
fn add_reserve_info(onchain: &mut OnChainConfig, pair_data: &mut PairData) {
    if pair_data.src == "pegged_weth" {
        return;
    }

    let reserves = onchain.fetch_reserve(&pair_data.pair);
    pair_data.initial_reserves_0 = reserves.0;
    pair_data.initial_reserves_1 = reserves.1;
}

fn get_liquidity_cmp(pair_data: &PairData) -> EVMU256 {
    let reserves_0 = EVMU256::from(i128::from_str_radix(&pair_data.initial_reserves_0, 16).unwrap());
    let reserves_1 = EVMU256::from(i128::from_str_radix(&pair_data.initial_reserves_1, 16).unwrap());

    // bypass for incorrect decimal implementation

    let liquidity = if pair_data.in_ == 0 {
        let min_r0 = if pair_data.decimals_0 == 0 {
            EVMU256::ZERO
        } else {
            EVMU256::from(10).pow(EVMU256::from(pair_data.decimals_0 - 1))
        };

        if min_r0 == EVMU256::ZERO {
            return EVMU256::ZERO;
        }
        reserves_0 / min_r0
    } else {
        let min_r1 = if pair_data.decimals_1 == 0 {
            EVMU256::ZERO
        } else {
            EVMU256::from(10).pow(EVMU256::from(pair_data.decimals_1 - 1))
        };

        if min_r1 == EVMU256::ZERO {
            return EVMU256::ZERO;
        }

        reserves_1 / min_r1
    };

    liquidity
}

fn with_info(routes: Vec<Vec<PairData>>, network: &str, token: &str) -> Info {
    Info {
        routes,
        basic_info: BasicInfo {
            weth: get_weth(network),
            is_weth: token == get_weth(network),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn dfs(
    onchain: &mut OnChainConfig,
    token: &str,
    network: &str,
    path: &mut Vec<PairData>,
    visited: &mut HashSet<String>,
    pegged_tokens: &HashMap<String, String>,
    hops: &HashMap<String, Vec<PairData>>,
    routes: &mut Vec<Vec<PairData>>,
) {
    if pegged_tokens.values().any(|v| v == token) {
        let mut new_path = path.clone();
        new_path.push(get_pegged_next_hop(onchain, token, network));
        routes.push(new_path);
        return;
    }
    visited.insert(token.to_string());
    if !hops.contains_key(token) {
        return;
    }
    for hop in hops.get(token).unwrap() {
        if visited.contains(&hop.next) {
            continue;
        }
        path.push(hop.clone());
        dfs(onchain, &hop.next, network, path, visited, pegged_tokens, hops, routes);
        path.pop();
    }
}

fn find_path_subgraph(onchain: &mut OnChainConfig, token: &str) -> Info {
    let network = onchain.chain_name.clone();
    let pegged_tokens = get_pegged_token(network.as_str());

    if pegged_tokens.values().any(|v| v == token) {
        let hop = get_pegged_next_hop(onchain, token, network.as_str());
        return with_info(vec![vec![hop]], network.as_str(), token);
    }

    let mut known: HashSet<String> = HashSet::new();
    let hops = get_all_hops(onchain, token, network.as_str(), 0, &mut known);

    let mut routes: Vec<Vec<PairData>> = vec![];

    dfs(
        onchain,
        token,
        network.as_str(),
        &mut vec![],
        &mut HashSet::new(),
        &pegged_tokens,
        &hops,
        &mut routes,
    );

    with_info(routes, network.as_str(), token)
}

mod tests {
    use tracing::debug;

    use super::*;
    use crate::evm::{
        onchain::endpoints::Chain::{BSC, ETH},
        types::EVMAddress,
    };

    #[test]
    fn test_get_pegged_next_hop() {
        let mut config = OnChainConfig::new(BSC, 22055611);
        let token = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c";
        let v = get_pegged_next_hop(&mut config, token, "bsc");
        assert!(v.src == "pegged_weth");
    }

    #[test]
    fn test_get_all_hops() {
        let mut config = OnChainConfig::new(BSC, 22055611);
        let mut known: HashSet<String> = HashSet::new();
        let v: HashMap<String, Vec<PairData>> = get_all_hops(
            &mut config,
            "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82",
            "bsc",
            0,
            &mut known,
        );
        assert!(!v.is_empty());
    }

    #[test]
    fn test_get_pair() {
        let mut config = OnChainConfig::new(ETH, 19021411);
        let v = get_pair(&mut config, "0x06450dEe7FD2Fb8E39061434BAbCFC05599a6Fb8", "eth", false);
        assert!(!v.is_empty());
        for p in v {
            println!("pair: {:?}", p);
        }
    }

    #[test]
    fn test_fetch_uniswap_path() {
        let mut config = OnChainConfig::new(BSC, 22055611);
        let v = fetch_uniswap_path(
            &mut config,
            EVMAddress::from_str("0xcff086ead392ccb39c49ecda8c974ad5238452ac").unwrap(),
        );
        assert!(!v.swaps.is_empty());
        assert!(!v.weth_address.is_zero());
    }

    #[test]
    fn test_fetch_uniswap_path_wbnb() {
        let mut config = OnChainConfig::new(BSC, 22055611);
        let v = fetch_uniswap_path(
            &mut config,
            EVMAddress::from_str("0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c").unwrap(),
        );
        assert!(!v.swaps.is_empty());
        assert!(!v.weth_address.is_zero());
    }
}
