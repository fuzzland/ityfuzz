import functools
import json
import re
import flask
import requests
from retry import retry

headers = {
    'authority': 'etherscan.io',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
              'application/signed-exchange;v=b3;q=0.9',
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/108.0.0.0 Safari/537.36',
}


def get_endpoint(network):
    if network == "eth":
        return "https://etherscan.io"
    elif network == "bsc":
        return "https://bscscan.com"
    elif network == "polygon":
        return "https://polygonscan.com"
    elif network == "mumbai":
        return "https://mumbai.polygonscan.com"
    else:
        raise Exception("Unknown network")

def get_rpc(network):
    if network == "eth":
        return "https://eth.llamarpc.com"
    elif network == "bsc":
        # BSC mod to geth make it no longer possible to use debug_storageRangeAt
        # so, we use our own node that supports eth_getStorageAll
        return "https://blue-damp-glitter.bsc.discover.quiknode.pro/8364ed151b17ed4619e9effc6237600241c2e65c/"
    elif network == "polygon":
        return "https://polygon-rpc.com/"
    elif network == "mumbai":
        return "https://rpc-mumbai.maticvigil.com"
    else:
        raise Exception("Unknown network")

def get_uniswap_api(network) -> dict:
    if network == "eth":
        return {
            "v2": {
                "uniswapv2": 'https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v2'
            },
            "v3": {
                "uniswapv3": 'https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3'
            }
        }
    elif network == "bsc":
        return {
            "v2": {
                "pancakeswap":'https://api.thegraph.com/subgraphs/name/pancakeswap/pairs',
                "biswap": 'https://api.thegraph.com/subgraphs/name/unchase/biswap'
            },
        }
    elif network == "polygon":
        return {
            "v3": {
                "uniswapv3": 'https://api.thegraph.com/subgraphs/name/ianlapham/uniswap-v3-polygon'
            }
        }
    elif network == "mumbai":
        return {}
    else:
        raise Exception("Unknown network")

def get_pegged_token(network):
    if network == "eth":
        return {
            "WETH": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "DAI": "0x6b175474e89094c44da98b954eedeac495271d0f",
            "WBTC": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
            "WMATIC": "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0",
        }
    elif network == "bsc":
        return {
            "WBNB": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
            "USDC": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
            "USDT": "0x55d398326f99059ff775485246999027b3197955",
            "DAI": "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3",
            "WBTC": "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c",
            "WETH": "0x2170ed0880ac9a755fd29b2688956bd959f933f8",
            "BUSD": "0xe9e7cea3dedca5984780bafc599bd69add087d56",
            "CAKE": "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"
        }
    elif network == "polygon":
        return {
            "WMATIC": "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
            "USDC": "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
            "USDT": "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
            "DAI": "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063",
            "WBTC": "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6",
            "WETH": "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619",
        }
    elif network == "mumbai":
        raise Exception("Not supported")
    else:
        raise Exception("Unknown network")


data = '{  p0: pairs(block:{number:%s},first:10,where :{token0 : \"%s\"}) { \n    id\n    token0 {\n      decimals\n      id\n    }\n    token1 {\n      decimals\n      id\n    }\n  }\n  \n   p1: pairs(block:{number:%s},first:10, where :{token1 : \"%s\"}) { \n    id\n    token0 {\n      decimals\n      id\n    }\n    token1 {\n      decimals\n      id\n    }\n  }\n}'


reserve_cache = {}

def fetch_reserve(pair, network, block):
    if pair in reserve_cache:
        return reserve_cache[pair]
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": pair,
            "data": "0x0902f1ac"
        }, block],
        "id": 1
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    result = response.json()["result"]

    reserve_cache[pair] = (result[2:66], result[66:130])
    return result[2:66], result[66:130]


def get_latest_block(network):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 1
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()["result"]


def get_pair(token, network, block):
    # -50 account for delay in api indexing
    block_int = int(block, 16) if block != "latest" else int(get_latest_block(network), 16) - 50
    next_tokens = []
    api = get_uniswap_api(network)
    if "v2" in api:
        for name, i in api["v2"].items():
            res = requests.post(i, json={
                    "query": data % (block_int, token.lower(), block_int, token.lower())}
                ).json()["data"]
                
            for pair in res["p0"] + res["p1"]:
                reserves = fetch_reserve(pair["id"], network, block)
                next_tokens.append({
                    "src": "v2",
                    "in": 0 if pair["token0"]["id"] == token else 1,
                    "pair": pair["id"],
                    "next": pair["token0"]["id"] if pair["token0"]["id"] != token else pair["token1"]["id"],
                    "decimals0": pair["token0"]["decimals"],
                    "decimals1": pair["token1"]["decimals"],
                    "src_exact": name,
                    "initial_reserves_0": reserves[0],
                    "initial_reserves_1": reserves[1],
                })
    return next_tokens


# max 2 hops
MAX_HOPS = 1
def get_all_hops(token, network, block, hop=0, known=set()):
    known.add(token)
    if hop > MAX_HOPS:
        return {}
    hops = {}
    hops[token] = get_pair(token, network, block)

    for i in hops[token]:
        if i["next"] in get_pegged_token(network).values():
            continue
        if i["next"] in known:
            continue
        hops = {**hops, **get_all_hops(i["next"], network, block, hop + 1, known)}
    return hops


def get_pegged_next_hop(token, network):
    return {"src": "pegged", "rate": fetch_token_price(network, token)[2] if token not in [
        "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
        "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    ] else int(1e6)}


@functools.lru_cache(maxsize=10240)
@retry(tries=10, delay=0.5, backoff=0.3)
def find_path(network, token, block):
    if token in get_pegged_token(network).values():
        return [[get_pegged_next_hop(token, network)]]
    hops = get_all_hops(token, network, block)
    routes = []
    # do a DFS to find all routes
    def dfs(token, path, visited):
        if token in get_pegged_token(network).values():
            routes.append(path + [get_pegged_next_hop(token, network)])
            return
        visited.add(token)
        if token not in hops:
            return
        for i in hops[token]:
            if i["next"] in visited:
                continue
            dfs(i["next"], path + [i], visited.copy())
    dfs(token, [], set())
    return routes


# for path in (find_path("0x056fd409e1d7a124bd7017459dfea2f387b6d5cd", "eth", "16399064")):
#     print(path)

@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_etherscan_token_holder(network, token_address):
    finder = re.compile("/token/" + token_address + "\?a=0x[0-9a-f]{40}'")
    url = f"{get_endpoint(network)}/token/generic-tokenholders2?a={token_address}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    ret = []
    for i in finder.findall(response.text):
        ret.append(i.split("?a=")[1][:-1])
    # todo: fix logic
    if len(ret) < 10:
        return []
    return ret


@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_etherscan_contract_abi(network, token_address):
    finder = re.compile("id='js-copytextarea2' style='height: 200px; max-height: 400px; margin-top: 5px;'>(.+?)</pre>")
    url = f"{get_endpoint(network)}/address/{token_address}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    contract_abi = []
    for i in finder.findall(response.text):
        contract_abi = json.loads(i)

    if "loadIframeSourceProxyRead" in response.text:
        # this is a proxy contract, we need to merge with the implementation contract abi
        base_address_finder = re.compile(" at <a href=\'(.+?)\'>")
        base_address = base_address_finder.findall(response.text)
        if len(base_address) == 0:
            print("Failed to find base address for proxy contract")
        else:
            base_address = base_address[0].split("/")[-1].split("?")[0].split("#")[0]
            res = fetch_etherscan_contract_abi(network, base_address)
            contract_abi += res
    return contract_abi


def get_major_symbol(network):
    if network == "eth":
        return "Eth"
    elif network == "bsc":
        return "BNB"
    elif network == "polygon" or network == "mumbai":
        return "MATIC"
    else:
        raise Exception("Unknown network")


@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_token_price(network, token_address):
    url = f"{get_endpoint(network)}/token/{token_address}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    resp = response.text.replace("\r", "").replace("\t", "").replace("\n", "")
    price_finder = re.compile(f"text-nowrap\'> @ (.+?) {get_major_symbol(network)}</span>")
    price = price_finder.findall(resp)

    decimals_finder = re.compile("Decimals:</div><div class=\"col-md-8\">(.+?)</div>")
    decimals = decimals_finder.findall(resp)

    if len(price) == 0 or len(decimals) == 0:
        return 0, 0, 0
    if int(decimals[0]) > 18:
        price_scaled = float(price[0]) / (10 ** (int(decimals[0]) - 18))
    else:
        price_scaled = float(price[0]) * (10 ** (18 - int(decimals[0])))
    return int(float(price[0]) * 1e6), int(decimals[0]), int(price_scaled * 1e6)

@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_rpc_slot(network, token_address, slot, block):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getStorageAt",
        "params": [token_address, slot, block],
        "id": 1
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()["result"]


@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_rpc_byte_code(network, address, block):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, block],
        "id": 1
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    print(response.json())
    return response.json()["result"]


@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_blk_hash(network, num):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [num, False],
        "id": 1
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()["result"]["hash"]


@functools.lru_cache(maxsize=10240)
@retry(tries=10, delay=0.5, backoff=0.3)
def fetch_rpc_storage_dump(network, address, block, offset=""):
    print(f"fetching {address} {block} {offset}")
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_storageRangeAt",
        "params": [fetch_blk_hash(network, block), 0, address, offset, 100000],
        "id": 1
    }

    response = requests.post(url, json=payload, timeout=15)
    try:
        response.raise_for_status()
    except Exception as e:
        print(response.text)
        raise e

    j = response.json()
    if "result" not in j:
        print(j)
        raise Exception("invalid response")

    res = {}
    if "nextKey" in j["result"] and j["result"]["nextKey"]:
        res = fetch_rpc_storage_dump(network, address, block, offset=j["result"]["nextKey"])
    # this rpc is likely going to fail for a few times
    return {**res, **j["result"]["storage"]}


@functools.lru_cache(maxsize=10240)
@retry(tries=10, delay=0.5, backoff=0.3)
def fetch_rpc_storage_all(network, address, block):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getStorageAll",
        "params": [address, block],
        "id": 1
    }

    response = requests.post(url, json=payload, timeout=7)
    response.raise_for_status()

    return response.json()["result"]


app = flask.Flask(__name__)


@app.route("/holders/<network>/<token_address>", methods=["GET"])
def holders(network, token_address):
    return flask.jsonify(fetch_etherscan_token_holder(network, token_address))


@app.route("/abi/<network>/<token_address>", methods=["GET"])
def abi(network, token_address):
    return flask.jsonify(fetch_etherscan_contract_abi(network, token_address))


@app.route("/slot/<network>/<token_address>/<slot>/<block>", methods=["GET"])
def slot(network, token_address, slot, block):
    return fetch_rpc_slot(network, token_address, slot, block)


@app.route("/bytecode/<network>/<address>/<block>", methods=["GET"])
def bytecode(network, address, block):
    return fetch_rpc_byte_code(network, address, block)


@app.route("/storage_dump/<network>/<address>/<block>", methods=["GET"])
def storage_dump(network, address, block):
    # use debug_storageRangeAt to dump the storage
    # this requires RPC endpoint enabling debug & archive node
    return {"storage": fetch_rpc_storage_dump(network, address, block)}


@app.route("/storage_all/<network>/<address>/<block>", methods=["GET"])
def storage_all(network, address, block):
    # use eth_getStorageAll to dump the storage
    # this requires running a modified geth
    return fetch_rpc_storage_all(network, address, block)


@app.route("/price/<network>/<token_address>", methods=["GET"])
def price(network, token_address):
    return ",".join(map(str, fetch_token_price(network, token_address)))

@app.route("/swap_path/<network>/<token_address>/<block>", methods=["GET"])
def swap_path(network, token_address, block):
    return flask.jsonify(find_path(network, token_address, block))

app.run(port=5003)


