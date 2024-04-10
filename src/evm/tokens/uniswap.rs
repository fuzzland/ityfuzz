use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    str::FromStr,
    sync::{Arc, Mutex},
};

use itertools::Itertools;
use lazy_static::lazy_static;
use revm_primitives::Bytecode;
use tracing::{info, warn};

use super::{
    get_uniswap_info,
    v2_transformer::UniswapPairContext,
    weth_transformer::WethContext,
    PathContext,
    TokenContext,
};
use crate::evm::{
    onchain::{endpoints::PairData, ChainConfig},
    tokens::v3_transformer::UniswapV3PairContext,
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

pub fn fetch_uniswap_path(chain: &mut Box<dyn ChainConfig>, token_address: EVMAddress) -> TokenContext {
    let token = format!("{:?}", token_address);
    let info: Info = find_path_subgraph(chain, &token);

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
                .insert($addr, chain.get_contract_code_analyzed($addr, false));
        };
    }

    let paths_parsed = routes
        .iter()
        .map(|pairs| {
            let mut path_parsed: PathContext = Default::default();

            macro_rules! _gen_v2_pair_context {
                ($pair: expr) => {{
                    let inner = UniswapPairContext {
                        pair_address: EVMAddress::from_str($pair.pair.as_str()).expect("failed to parse pair"),
                        next_hop: EVMAddress::from_str($pair.next.as_str()).expect("failed to parse pair"),
                        side: $pair.in_ as u8,
                        uniswap_info: Arc::new(get_uniswap_info($pair.src_exact.as_str())),
                        initial_reserves: ($pair.initial_reserves_0, $pair.initial_reserves_1),
                        in_token_address: EVMAddress::from_str($pair.in_token.as_str()).unwrap(),
                    };
                    register_code!(inner.next_hop);
                    inner
                }};
            }

            macro_rules! gen_v2_pair_context {
                ($pair: expr) => {{
                    let inner = Rc::new(RefCell::new(_gen_v2_pair_context!($pair)));
                    path_parsed.route.push(super::PairContextTy::Uniswap(inner));
                }};
            }

            macro_rules! gen_v3_pair_context {
                ($pair: expr) => {{
                    let pair_address = EVMAddress::from_str($pair.pair.as_str()).expect("failed to parse pair");
                    let fee = chain.get_v3_fee(pair_address);
                    let inner = _gen_v2_pair_context!($pair);
                    register_code!(inner.next_hop);
                    let v3 = Rc::new(RefCell::new(UniswapV3PairContext { fee, inner }));
                    path_parsed.route.push(super::PairContextTy::UniswapV3(v3));
                }};
            }

            pairs.iter().for_each(|pair| match pair.src.as_str() {
                "lp" => {
                    if pair.interface == "uniswapv2" {
                        gen_v2_pair_context!(pair);
                    } else if pair.interface == "uniswapv3" {
                        gen_v3_pair_context!(pair);
                    } else {
                        unimplemented!("unknown interface");
                    }
                }
                "pegged" => {
                    if pair.interface == "uniswapv2" {
                        gen_v2_pair_context!(pair);
                    } else if pair.interface == "uniswapv3" {
                        gen_v3_pair_context!(pair);
                    } else {
                        unimplemented!("unknown interface");
                    }
                    assert_eq!(pair.next, basic_info.weth);
                    let inner = Rc::new(RefCell::new(WethContext {
                        weth_address: EVMAddress::from_str(pair.next.as_str()).expect("failed to parse pair"),
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
            for pair in &path_parsed.route {
                if let super::PairContextTy::UniswapV3(inner) = pair {
                    // println!(
                    //     "registering code for v3 pair: {:?}",
                    //     inner.borrow().inner.uniswap_info.router.unwrap()
                    // );
                    register_code!(inner.borrow().inner.uniswap_info.router.unwrap());
                }
            }

            path_parsed
        })
        .collect();

    TokenContext {
        swaps: paths_parsed,
        is_weth,
        weth_address: weth,
    }
}

fn get_pair(chain: &mut Box<dyn ChainConfig>, token: &str, is_pegged: bool) -> Vec<PairData> {
    let token = token.to_lowercase();
    info!("fetching pairs for {token}");
    if token == chain.get_weth() {
        return vec![];
    }
    let pegged_tokens = chain.get_pegged_token();
    let mut pairs = chain.get_pair(token.as_str(), is_pegged || pegged_tokens.values().contains(&token));

    // println!("original pairs: {:?}", pairs,);
    // println!("token: {:?}", token,);

    for pair in &mut pairs {
        add_reserve_info(chain, pair);
    }
    pairs.sort_by(|a, b| {
        let a = get_liquidity_cmp(a);
        let b = get_liquidity_cmp(b);
        b.cmp(&a)
    });

    if pairs.len() > 3 {
        pairs = pairs[0..3].to_vec();
    }
    // println!("pairs: {:?}", pairs);
    pairs
}

fn get_all_hops(
    chain: &mut Box<dyn ChainConfig>,
    token: &str,
    hop: u32,
    known: &mut HashSet<String>,
) -> HashMap<String, Vec<PairData>> {
    known.insert(token.to_string());

    if hop > MAX_HOPS {
        return HashMap::new();
    }

    let mut hops: HashMap<String, Vec<PairData>> = HashMap::new();
    hops.insert(token.to_string(), get_pair(chain, token, false));

    let pegged_tokens = chain.get_pegged_token();

    for i in hops.clone().get(token).unwrap() {
        if pegged_tokens.values().any(|v| v == &i.next) || known.contains(&i.next) {
            continue;
        }
        let next_hops = get_all_hops(chain, &i.next, hop + 1, known);
        hops.extend(next_hops);
    }

    hops
}

fn get_pegged_next_hop(chain: &mut Box<dyn ChainConfig>, token: &str) -> PairData {
    if token == chain.get_weth() {
        return PairData {
            src: "pegged_weth".to_string(),
            in_: 0,
            next: "".to_string(),
            pair: "".to_string(),
            initial_reserves_0: EVMU256::ZERO,
            initial_reserves_1: EVMU256::ZERO,
            src_exact: "".to_string(),
            decimals_0: 0,
            decimals_1: 0,
            token0: "".to_string(),
            in_token: token.to_string(),
            interface: "weth".to_string(),
            token1: "".to_string(),
        };
    }
    let mut peg_info = get_pair(chain, token, true)
        .first()
        .expect("Unexpected RPC error, consider setting env <ETH_RPC_URL> ")
        .clone();

    add_reserve_info(chain, &mut peg_info);

    PairData {
        src: "pegged".to_string(),
        ..peg_info.clone()
    }
}

/// returns whether the pair is significant
fn add_reserve_info(chain: &mut Box<dyn ChainConfig>, pair_data: &mut PairData) {
    if pair_data.interface == "uniswapv2" {
        let reserves = chain.fetch_reserve(&pair_data.pair);
        if let Some((r0, r1)) = reserves {
            pair_data.initial_reserves_0 = EVMU256::try_from_be_slice(&hex::decode(r0).unwrap()).unwrap();
            pair_data.initial_reserves_1 = EVMU256::try_from_be_slice(&hex::decode(r1).unwrap()).unwrap();
        }
    }
    if pair_data.interface == "uniswapv3" {
        let t0 = EVMAddress::from_str(&pair_data.token0).unwrap();
        let t1 = EVMAddress::from_str(&pair_data.token1).unwrap();
        let lp = EVMAddress::from_str(&pair_data.pair).unwrap();
        let r0 = chain.get_token_balance(t0, lp);
        let r1 = chain.get_token_balance(t1, lp);
        pair_data.initial_reserves_0 = r0;
        pair_data.initial_reserves_1 = r1;
    }
}

fn get_liquidity_cmp(pair_data: &PairData) -> EVMU256 {
    let reserves_0 = pair_data.initial_reserves_0;
    let reserves_1 = pair_data.initial_reserves_1;

    // bypass for incorrect decimal implementation

    if pair_data.in_ == 0 {
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
    }
}

fn with_info(routes: Vec<Vec<PairData>>, token: &str, weth: &str) -> Info {
    Info {
        routes,
        basic_info: BasicInfo {
            weth: weth.to_string(),
            is_weth: token == weth,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn dfs(
    chain: &mut Box<dyn ChainConfig>,
    token: &str,
    path: &mut Vec<PairData>,
    visited: &mut HashSet<String>,
    pegged_tokens: &HashMap<String, String>,
    hops: &HashMap<String, Vec<PairData>>,
    routes: &mut Vec<Vec<PairData>>,
) {
    if pegged_tokens.values().any(|v| v == token) {
        let mut new_path = path.clone();
        new_path.push(get_pegged_next_hop(chain, token));
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
        dfs(chain, &hop.next, path, visited, pegged_tokens, hops, routes);
        path.pop();
    }
}

fn find_path_subgraph(chain: &mut Box<dyn ChainConfig>, token: &str) -> Info {
    let pegged_tokens = chain.get_pegged_token();
    let weth = chain.get_weth();

    if pegged_tokens.values().any(|v| v == token) {
        let hop = get_pegged_next_hop(chain, token);
        return with_info(vec![vec![hop]], token, &weth);
    }

    let mut known: HashSet<String> = HashSet::new();
    let hops = get_all_hops(chain, token, 0, &mut known);

    let mut routes: Vec<Vec<PairData>> = vec![];

    dfs(
        chain,
        token,
        &mut vec![],
        &mut HashSet::new(),
        &pegged_tokens,
        &hops,
        &mut routes,
    );

    with_info(routes, token, &weth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::{
        onchain::endpoints::{
            Chain::{BSC, ETH},
            OnChainConfig,
        },
        types::EVMAddress,
    };

    #[test]
    fn test_get_pegged_next_hop() {
        let mut config: Box<dyn ChainConfig> = Box::new(OnChainConfig::new(BSC, 22055611));
        let token = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c";
        let v = get_pegged_next_hop(&mut config, token);
        assert!(v.src == "pegged_weth");
    }

    #[test]
    fn test_get_all_hops() {
        let mut config: Box<dyn ChainConfig> = Box::new(OnChainConfig::new(BSC, 22055611));
        let mut known: HashSet<String> = HashSet::new();
        let v: HashMap<String, Vec<PairData>> =
            get_all_hops(&mut config, "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82", 0, &mut known);
        assert!(!v.is_empty());
    }

    #[test]
    fn test_get_pair() {
        let mut config: Box<dyn ChainConfig> = Box::new(OnChainConfig::new(ETH, 19021411));
        let v = get_pair(&mut config, "0x06450dEe7FD2Fb8E39061434BAbCFC05599a6Fb8", false);
        assert!(!v.is_empty());
        for p in v {
            println!("pair: {:?}", p);
        }
    }

    #[test]
    fn test_fetch_uniswap_path() {
        let mut config: Box<dyn ChainConfig> = Box::new(OnChainConfig::new(BSC, 22055611));
        let v = fetch_uniswap_path(
            &mut config,
            EVMAddress::from_str("0xcff086ead392ccb39c49ecda8c974ad5238452ac").unwrap(),
        );
        assert!(!v.swaps.is_empty());
        assert!(!v.weth_address.is_zero());
    }

    #[test]
    fn test_fetch_uniswap_path_wbnb() {
        let mut config: Box<dyn ChainConfig> = Box::new(OnChainConfig::new(BSC, 22055611));
        let v = fetch_uniswap_path(
            &mut config,
            EVMAddress::from_str("0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c").unwrap(),
        );
        assert!(!v.swaps.is_empty());
        assert!(!v.weth_address.is_zero());
    }
}
