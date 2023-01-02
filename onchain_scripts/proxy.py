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
        return "http://bsc.node1.infra.fuzz.land"
    elif network == "polygon":
        return "https://polygon-rpc.com/"
    elif network == "mumbai":
        return "https://rpc-mumbai.maticvigil.com"
    else:
        raise Exception("Unknown network")


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
        base_address_finder = re.compile("ABI for the implementation contract at <a href=\'(.+?)\'>")
        base_address = base_address_finder.findall(response.text)
        if len(base_address) == 0:
            print("Failed to find base address for proxy contract")
        base_address = base_address[0].split("/")[-1].split("?")[0].split("#")[0]
        res = fetch_etherscan_contract_abi(network, base_address)
        contract_abi += res
    return contract_abi


@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_token_price(network, token_address):
    url = f"{get_endpoint(network)}/token/{token_address}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    resp = response.text.replace("\r", "").replace("\t", "").replace("\n", "")
    price_finder = re.compile("text-nowrap\'> @ (.+?) Eth</span>")
    price = price_finder.findall(resp)

    decimals_finder = re.compile("Decimals:</div><div class=\"col-md-8\">(.+?)</div>")
    decimals = decimals_finder.findall(resp)

    if len(price) == 0 or len(decimals) == 0:
        return 0, 0
    return int(float(price[0]) * 10e5), int(decimals[0])

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
def fetch_rpc_storage_dump(network, address, block):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_storageRangeAt",
        "params": [fetch_blk_hash(network, block), 0, address, "", 1000000000000000],
        "id": 1
    }

    response = requests.post(url, json=payload)
    try:
        response.raise_for_status()
    except Exception as e:
        print(response.text)
        raise e

    j = response.json()
    if "result" not in j:
        print(j)
        raise Exception("invalid response")
    # this rpc is likely going to fail for a few times
    return j["result"]


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

    response = requests.post(url, json=payload)
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
    return fetch_rpc_storage_dump(network, address, block)


@app.route("/storage_all/<network>/<address>/<block>", methods=["GET"])
def storage_all(network, address, block):
    # use eth_getStorageAll to dump the storage
    # this requires running a modified geth
    return fetch_rpc_storage_all(network, address, block)


@app.route("/price/<network>/<token_address>", methods=["GET"])
def price(network, token_address):
    return ",".join(map(str, fetch_token_price(network, token_address)))

app.run(port=5003)


